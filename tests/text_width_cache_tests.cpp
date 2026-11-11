#include "TextWidthCache.h"

#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <new>
#include <stdexcept>
#include <vector>

namespace Allocations {
struct alignas(std::max_align_t) Header {
    size_t bytes;
};
size_t live = 0;
size_t peak = 0;
size_t calls = 0;
}

// Учитываем буферы строк и сам индекс, чтобы тест проверял память, а не
// только логическое число записей. В тесте нет фоновых потоков.
void* operator new(size_t bytes) {
    using namespace Allocations;
    if (bytes > std::numeric_limits<size_t>::max() - sizeof(Header))
        throw std::bad_alloc();
    auto* header = static_cast<Header*>(std::malloc(sizeof(Header) + std::max(bytes, size_t{1})));
    if (!header) throw std::bad_alloc();
    header->bytes = bytes;
    live += bytes;
    peak = std::max(peak, live);
    ++calls;
    return header + 1;
}

void* operator new[](size_t bytes) { return ::operator new(bytes); }
void operator delete(void* pointer) noexcept {
    if (!pointer) return;
    auto* header = static_cast<Allocations::Header*>(pointer) - 1;
    Allocations::live -= header->bytes;
    std::free(header);
}
void operator delete[](void* pointer) noexcept { ::operator delete(pointer); }
void operator delete(void* pointer, size_t) noexcept { ::operator delete(pointer); }
void operator delete[](void* pointer, size_t) noexcept { ::operator delete(pointer); }

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void TestKeysAndFonts() {
    TextWidthCache cache;
    int measured = 0;
    const auto measure = [&](int width) { ++measured; return width; };
    Check(cache.Get(L"", false, [&] { return measure(99); }) == 0 && measured == 0 &&
          cache.empty(), "empty text was measured or cached");
    Check(cache.Get(L"same.exe", false, [&] { return measure(40); }) == 40 &&
          cache.Get(L"same.exe", true, [&] { return measure(55); }) == 55,
          "font weights share a width");
    for (int i = 0; i < 4; ++i) {
        Check(cache.Get(L"same.exe", false, [&] { return measure(99); }) == 40 &&
              cache.Get(L"same.exe", true, [&] { return measure(99); }) == 55,
              "cached font width changed");
    }
    Check(measured == 2 && cache.size() == 2, "a cache hit repeated measurement");

    std::wstring source = L"owned-process-name.exe";
    Check(cache.Get(source, false, [&] { return measure(75); }) == 75,
          "source text was not measured");
    source.assign(L"changed");
    Check(cache.Get(L"owned-process-name.exe", false, [&] { return measure(99); }) == 75 &&
          measured == 3, "cache key depends on the caller's string lifetime");
    for (const auto* text : {L"Процесс.exe", L"خدمة.exe", L"[例子.example]"}) {
        Check(cache.Get(text, false, [&] { return measure(80); }) == 80 &&
              cache.Get(text, false, [&] { return measure(99); }) == 80,
              "Unicode cache key changed");
    }

    const size_t size = cache.size();
    Check(cache.Get(L"retry.exe", false, [&] { return measure(0); }) == 0 &&
          cache.size() == size, "failed measurement was cached");
    Check(cache.Get(L"retry.exe", false, [&] { return measure(45); }) == 45,
          "failed measurement was not retried");
    cache.clear();
    Check(cache.empty(), "clear did not reset the entry count");
    Check(cache.Get(L"same.exe", false, [&] { return measure(90); }) == 90,
          "clear retained the previous font's width");
}

void TestStableWorkingSet() {
    TextWidthCache cache;
    std::vector<std::wstring> keys;
    for (size_t i = 0; i < TextWidthCache::kCapacity / 2; ++i)
        keys.push_back(L"[stable-" + std::to_wstring(i) + L".example]");
    size_t measured = 0;
    for (size_t i = 0; i < keys.size(); ++i) {
        for (bool bold : {false, true}) {
            const int expected = static_cast<int>(i * 2 + (bold ? 2 : 1));
            Check(cache.Get(keys[i], bold, [&] { ++measured; return expected; }) == expected,
                  "initial working set width is wrong");
        }
    }
    const size_t allocations = Allocations::calls;
    for (int pass = 0; pass < 8; ++pass) {
        for (size_t j = 0; j < keys.size(); ++j) {
            const size_t i = pass % 2 ? keys.size() - 1 - j : j;
            for (bool bold : {true, false}) {
                const int expected = static_cast<int>(i * 2 + (bold ? 2 : 1));
                Check(cache.Get(keys[i], bold, [&] { ++measured; return 9999; }) == expected,
                      "working set entry was lost to a hash collision");
            }
        }
    }
    Check(measured == TextWidthCache::kCapacity && Allocations::calls == allocations,
          "stable cache hits measured text or allocated memory");

    Check(cache.Get(L"new.exe", false, [] { return 77; }) == 77 &&
          cache.size() == TextWidthCache::kCapacity, "cache grew beyond its limit");
    Check(cache.Get(keys.back(), true, [] { return 9999; }) ==
          static_cast<int>(TextWidthCache::kCapacity), "eviction removed the wrong slot");
    bool evicted = false;
    Check(cache.Get(keys.front(), false, [&] { evicted = true; return 88; }) == 88 && evicted,
          "oldest entry was not evicted");
}

void TestCollisionChains() {
    TextWidthCache cache;
    std::vector<std::wstring> keys;
    // Весь набор направляем в одну цепочку, чтобы проверить её после вытеснения.
    for (size_t i = 0; keys.size() < TextWidthCache::kCapacity + 32; ++i) {
        std::wstring key = L"collision-" + std::to_wstring(i);
        if ((std::hash<std::wstring_view>{}(key) & (TextWidthCache::kCapacity - 1)) == 0)
            keys.push_back(std::move(key));
    }
    for (size_t i = 0; i < keys.size(); ++i) {
        const int expected = static_cast<int>(i + 1);
        Check(cache.Get(keys[i], false, [&] { return expected; }) == expected &&
              cache.size() <= TextWidthCache::kCapacity, "collision insertion failed");
    }
    for (size_t i = 32; i < keys.size(); ++i) {
        Check(cache.Get(keys[i], false, [] { return -1; }) == static_cast<int>(i + 1),
              "collision chain was damaged during eviction");
    }
    cache.clear();
    Check(cache.Get(keys.front(), false, [] { return 123; }) == 123,
          "refill followed stale chain links");
}

void TestLongTextBypass() {
    TextWidthCache cache;
    std::wstring text(TextWidthCache::kMaxTextLength + 1, L'x');
    const size_t allocations = Allocations::calls;
    int measured = 0;
    for (int i = 0; i < 3; ++i)
        Check(cache.Get(text, false, [&] { ++measured; return 4321; }) == 4321,
              "uncached long text width changed");
    Check(measured == 3 && cache.empty() && Allocations::calls == allocations,
          "overlong text allocated cache storage");
    text.pop_back();
    Check(cache.Get(text, false, [] { return 1234; }) == 1234 && cache.size() == 1 &&
          cache.Get(text, false, [] { return -1; }) == 1234,
          "maximum cacheable text length was rejected");
}

void TestPeakMemoryAndRelease() {
    TextWidthCache cache;
    const size_t baseline = Allocations::live;
    Allocations::peak = baseline;
    wchar_t text[TextWidthCache::kMaxTextLength + 1];
    std::fill(std::begin(text), std::end(text), L'x');
    size_t full = 0;
    for (size_t i = 0; i < 100000; ++i) {
        Check(std::swprintf(text + TextWidthCache::kMaxTextLength - 12, 13,
                            L"%012zu", i) == 12, "could not format the memory test key");
        const int expected = static_cast<int>(i % 1000 + 1);
        Check(cache.Get(std::wstring_view(text, TextWidthCache::kMaxTextLength),
                        i % 2 != 0, [&] { return expected; }) == expected,
              "memory churn returned the wrong width");
        Check(cache.size() == std::min(i + 1, TextWidthCache::kCapacity),
              "entry count exceeded the fixed limit");
        if (i + 1 == TextWidthCache::kCapacity) full = Allocations::live;
        if (i + 1 >= TextWidthCache::kCapacity)
            Check(Allocations::live == full, "memory continued growing after the cache filled");
    }
    const size_t peak = Allocations::peak;
    Check(full > baseline && peak <= full + (TextWidthCache::kMaxTextLength + 64) * sizeof(wchar_t),
          "peak storage exceeded the cache and one replacement key");

    for (size_t i = 0; i < TextWidthCache::kCapacity; ++i) {
        wchar_t small[8]{};
        Check(std::swprintf(small, std::size(small), L"s%06zu", i) == 7,
              "could not format the short key");
        cache.Get(small, false, [] { return 12; });
    }
    const size_t shortKeys = Allocations::live;
    Check(shortKeys + TextWidthCache::kCapacity * TextWidthCache::kMaxTextLength * sizeof(wchar_t) / 2
              < full, "short replacement keys retained the old large string buffers");
    cache.clear();
    Check(cache.empty() && Allocations::live == baseline, "clear retained cache allocations");
    cache.clear();
    Check(Allocations::live == baseline, "repeated clear changed allocation ownership");
    {
        TextWidthCache scoped;
        scoped.Get(L"destruction.exe", true, [] { return 40; });
    }
    Check(Allocations::live == baseline, "destructor retained cache allocations");
    std::cout << "cache memory: full=" << full - baseline << ", peak=" << peak - baseline
              << ", short keys=" << shortKeys - baseline << ", cleared=0 bytes\n";
}
}

int main() {
    try {
        TestKeysAndFonts();
        TestStableWorkingSet();
        TestCollisionChains();
        TestLongTextBypass();
        TestPeakMemoryAndRelease();
        std::cout << "text width cache tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
