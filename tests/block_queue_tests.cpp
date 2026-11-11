// Тест намеренно создаёт сверхвыровненные типы с padding внутри структуры.
#ifdef _MSC_VER
#pragma warning(disable: 4324)
#endif
#include "BlockQueue.h"

#include <algorithm>
#include <array>
#include <concepts>
#include <cstdint>
#include <deque>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <vector>

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct AllocationState {
    size_t bytes = 0;
    size_t blocks = 0;
    size_t allocations = 0;
};

template <class T>
struct CountingAllocator {
    using value_type = T;
    AllocationState* state = nullptr;

    CountingAllocator() = default;
    explicit CountingAllocator(AllocationState& state_) : state(&state_) {}
    template <class U>
    CountingAllocator(const CountingAllocator<U>& other) : state(other.state) {}

    T* allocate(size_t count) {
        T* result = std::allocator<T>{}.allocate(count);
        state->bytes += count * sizeof(T);
        ++state->blocks;
        ++state->allocations;
        return result;
    }
    void deallocate(T* pointer, size_t count) noexcept {
        state->bytes -= count * sizeof(T);
        --state->blocks;
        std::allocator<T>{}.deallocate(pointer, count);
    }
    template <class U>
    bool operator==(const CountingAllocator<U>& other) const { return state == other.state; }
};

template <size_t Words>
struct Record {
    std::array<uint64_t, Words> words{};
};

template <class T>
void TestReleasePaths() {
    AllocationState state;
    {
        BlockQueue<T, CountingAllocator<T>> queue{CountingAllocator<T>(state)};
        const auto checkEmpty = [&] {
            Check(queue.empty() && queue.size() == 0 && queue.begin() == queue.end(),
                  "drained queue is not empty");
            Check(state.bytes == 0 && state.blocks == 0,
                  "empty queue retained data blocks or a pointer map");
        };
        checkEmpty();
        const auto fill = [&] {
            for (size_t i = 0; i < 100000; ++i) {
                T value;
                value.words[0] = i;
                queue.push_back(std::move(value));
            }
            Check(state.bytes > 0 && state.blocks > 1 && state.blocks < 100000,
                  "queue did not allocate records in blocks");
        };

        fill();
        const size_t filledBlocks = state.blocks;
        size_t allocations = state.allocations;
        for (size_t i = 0; i < 99999; ++i) {
            Check(queue.front().words[0] == i, "FIFO order changed");
            queue.pop_front();
        }
        Check(state.allocations == allocations && queue.size() == 1 &&
              state.blocks == 1 && filledBlocks > state.blocks,
              "draining allocated storage or retained fully consumed blocks");
        queue.pop_front();
        checkEmpty();

        fill();
        queue.clear();
        checkEmpty();

        fill();
        auto next = queue.begin();
        while (next != queue.end()) next = queue.erase(next);
        checkEmpty();

        fill();
        const size_t removed = queue.erase_if([](const T&) { return true; });
        Check(removed == 100000, "bulk removal reported the wrong count");
        checkEmpty();

        allocations = state.allocations;
        for (int i = 0; i < 100; ++i) {
            queue.clear();
            Check(queue.erase_if([](const T&) { return true; }) == 0,
                  "empty bulk removal reported removed records");
        }
        Check(state.allocations == allocations,
              "idle empty queue repeatedly allocated replacement storage");
        checkEmpty();

        T value;
        queue.push_back(value);
        Check(queue.size() == 1 && queue.front().words[0] == value.words[0],
              "released queue could not be reused");
    }
    Check(state.bytes == 0 && state.blocks == 0, "queue destruction leaked storage");
}

struct OwnedValue {
    static inline size_t live = 0;
    static inline size_t constructed = 0;
    static inline size_t moves = 0;
    size_t id;
    std::shared_ptr<int> nested;

    explicit OwnedValue(size_t id_) : id(id_) { ++live; ++constructed; }
    OwnedValue(const OwnedValue&) = delete;
    OwnedValue& operator=(const OwnedValue&) = delete;
    OwnedValue(OwnedValue&& other) noexcept : id(other.id), nested(std::move(other.nested)) {
        ++live;
        ++constructed;
        ++moves;
    }
    OwnedValue& operator=(OwnedValue&& other) noexcept {
        id = other.id;
        nested = std::move(other.nested);
        ++moves;
        return *this;
    }
    ~OwnedValue() { --live; }
};

void TestNestedLifetimes() {
    BlockQueue<OwnedValue> queue;
    std::vector<std::weak_ptr<int>> owners;
    for (size_t i = 0; i < 10000; ++i) {
        OwnedValue& value = queue.emplace_back(i);
        value.nested = std::make_shared<int>(static_cast<int>(i));
        owners.push_back(value.nested);
    }
    Check(OwnedValue::live == queue.size() && OwnedValue::constructed == queue.size(),
          "queue constructed unused values");
    const size_t moves = OwnedValue::moves;
    for (size_t i = 0; i < owners.size(); ++i) {
        Check(!owners[i].expired(), "queued nested value was released too early");
        queue.pop_front();
        Check(owners[i].expired(), "popped value retained its nested owner");
    }
    Check(OwnedValue::live == 0 && OwnedValue::moves == moves,
          "FIFO draining moved surviving values or retained an object");

    owners.clear();
    for (size_t i = 0; i < 10000; ++i) {
        OwnedValue& value = queue.emplace_back(i);
        value.nested = std::make_shared<int>(static_cast<int>(i));
        owners.push_back(value.nested);
    }
    queue.erase_if([](const OwnedValue& value) { return value.id % 3 != 0; });
    Check(OwnedValue::live == queue.size() && queue.size() == 3334,
          "bulk removal retained constructed values");
    for (size_t i = 0; i < owners.size(); ++i)
        Check(owners[i].expired() == (i % 3 != 0), "bulk removal retained the wrong nested owners");
    for (auto it = queue.begin(); it != queue.end();) {
        if (it->id % 2 == 0) it = queue.erase(it);
        else ++it;
    }
    for (size_t i = 0; i < owners.size(); ++i)
        Check(owners[i].expired() == (i % 3 != 0 || i % 2 == 0),
              "single removal retained the wrong nested owners");
    const size_t beforeClear = OwnedValue::moves;
    queue.clear();
    Check(OwnedValue::live == 0 && OwnedValue::moves == beforeClear,
          "clear retained values or moved them before destruction");
    for (const auto& owner : owners) Check(owner.expired(), "clear retained nested ownership");
}

void TestErasureAndIteration() {
    static_assert(std::forward_iterator<BlockQueue<size_t>::iterator>);
    static_assert(std::forward_iterator<BlockQueue<size_t>::const_iterator>);
    AllocationState state;
    BlockQueue<size_t, CountingAllocator<size_t>> actual{CountingAllocator<size_t>(state)};
    std::deque<size_t> expected;
    std::mt19937 random(0x44455155);
    for (size_t pass = 0; pass < 20; ++pass) {
        for (size_t i = 0; i < 3000; ++i) {
            const size_t value = random();
            actual.push_back(value);
            expected.push_back(value);
        }
        for (size_t step = 0; step < 1500; ++step) {
            const unsigned operation = random() % 7;
            if (operation < 2 || expected.empty()) {
                const size_t value = random();
                actual.push_back(value);
                expected.push_back(value);
            } else if (operation == 2) {
                actual.pop_front();
                expected.pop_front();
            } else if (operation == 3) {
                const auto index = static_cast<ptrdiff_t>(random() % expected.size());
                const auto next = actual.erase(std::next(actual.begin(), index));
                const auto reference = expected.erase(expected.begin() + index);
                Check(std::distance(actual.begin(), next) == reference - expected.begin(),
                      "single erase returned the wrong iterator");
            } else if (operation == 4) {
                const size_t divisor = 3 + random() % 100;
                const auto remove = [=](size_t value) { return value % divisor == 0; };
                const size_t oldSize = expected.size();
                expected.erase(std::remove_if(expected.begin(), expected.end(), remove), expected.end());
                Check(actual.erase_if(remove) == oldSize - expected.size(),
                      "bulk removal reported the wrong count");
            } else if (operation == 5 && random() % 50 == 0) {
                actual.clear();
                expected.clear();
            } else {
                const auto index = static_cast<ptrdiff_t>(random() % expected.size());
                *std::next(actual.begin(), index) ^= step;
                expected[static_cast<size_t>(index)] ^= step;
            }
            const auto& constant = actual;
            Check(constant.size() == expected.size() && constant.empty() == expected.empty() &&
                  std::equal(constant.begin(), constant.end(), expected.begin(), expected.end()),
                  "queue contents differ from std::deque");
            Check(actual.begin() == constant.begin() && constant.end() == actual.end(),
                  "mutable and constant iterators cannot be compared");
            if (!constant.empty()) {
                Check(constant.front() == expected.front(), "constant access changed the first value");
            } else {
                Check(state.bytes == 0 && state.blocks == 0,
                      "mixed erasure path retained historical storage");
            }
        }
    }
}

// Очередь AskQueue пропускает отложенные запросы, удаляет готовый из середины
// и массово снимает запросы, уже закрытые правилами. Порядок остальных не меняется.
void TestDeferredRequests() {
    struct Item {
        size_t id;
        bool held;
    };
    BlockQueue<Item> queue;
    for (size_t i = 0; i < 1000; ++i) queue.push_back({i, i % 2 == 0});
    for (auto it = queue.begin(); it != queue.end();) {
        if (it->held) ++it;
        else it = queue.erase(it);
    }
    Check(queue.size() == 500, "ready requests were not removed");
    size_t id = 0;
    for (Item& item : queue) {
        Check(item.id == id && item.held, "deferred requests were reordered or removed");
        item.held = false;
        id += 2;
    }
    queue.erase_if([](const Item& item) { return item.id % 4 == 0; });
    id = 2;
    while (!queue.empty()) {
        Check(queue.front().id == id && !queue.front().held,
              "pruning changed the remaining request order");
        queue.erase(queue.begin());
        id += 4;
    }
    Check(id == 1002, "last deferred request was lost");
}

struct alignas(128) AlignedValue {
    uint64_t id;
    explicit AlignedValue(uint64_t id_) : id(id_) {}
};

void TestAlignmentAndLargeValues() {
    BlockQueue<AlignedValue> aligned;
    for (size_t i = 0; i < 1000; ++i) {
        const auto& value = aligned.emplace_back(i);
        Check(reinterpret_cast<uintptr_t>(&value) % alignof(AlignedValue) == 0 && value.id == i,
              "over-aligned queue element is misaligned");
    }
    BlockQueue<std::array<uint8_t, 8192>> large;
    for (size_t i = 0; i < 10; ++i) large.emplace_back().front() = static_cast<uint8_t>(i);
    for (size_t i = 0; i < 10; ++i) {
        Check(large.front().front() == i, "large element order changed");
        large.pop_front();
    }
    Check(large.empty(), "last large element block was retained");
}

struct ThrowingValue {
    static inline bool fail = false;
    static inline size_t live = 0;
    int id;
    explicit ThrowingValue(int id_) : id(id_) {
        if (fail) throw std::runtime_error("expected construction failure");
        ++live;
    }
    ~ThrowingValue() { --live; }
};

void TestConstructionFailure() {
    AllocationState state;
    BlockQueue<ThrowingValue, CountingAllocator<ThrowingValue>> queue{CountingAllocator<ThrowingValue>(state)};
    for (int i = 0; i < 3000; ++i) {
        ThrowingValue::fail = i % 7 == 0;
        const size_t bytes = state.bytes, size = queue.size();
        try {
            queue.emplace_back(i);
            Check(!ThrowingValue::fail, "throwing constructor was not invoked");
        } catch (const std::runtime_error&) {
            Check(ThrowingValue::fail && state.bytes == bytes && queue.size() == size,
                  "failed construction retained a block or changed the queue size");
        }
        Check(ThrowingValue::live == queue.size(), "failed construction retained a live object");
    }
    ThrowingValue::fail = false;
    queue.clear();
    Check(ThrowingValue::live == 0 && state.bytes == 0 && state.blocks == 0,
          "clear after failed construction retained objects or blocks");
}
} // namespace

int main() {
    try {
        TestReleasePaths<Record<2>>();
        TestReleasePaths<Record<3>>();
        TestReleasePaths<Record<7>>();
        TestReleasePaths<Record<10>>();
        TestNestedLifetimes();
        TestErasureAndIteration();
        TestDeferredRequests();
        TestAlignmentAndLargeValues();
        TestConstructionFailure();
        std::cout << "block queue tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
