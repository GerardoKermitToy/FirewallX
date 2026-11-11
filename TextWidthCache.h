#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <string_view>

// Число записей ограничено до вставки, а не после обхода списка. Индекс и
// звенья цепочек помещаются в один фиксированный блок без узлов hash map.
class TextWidthCache {
public:
    static constexpr size_t kCapacity = 512;
    // Обычные имена и SNI помещаются целиком; длинные подписи не дублируем.
    static constexpr size_t kMaxTextLength = 512;

    TextWidthCache() = default;
    TextWidthCache(const TextWidthCache&) = delete;
    TextWidthCache& operator=(const TextWidthCache&) = delete;

    template <class Measure>
    int Get(std::wstring_view text, bool bold, Measure&& measure) {
        if (text.empty()) return 0;
        if (text.size() > kMaxTextLength) [[unlikely]] return measure();

        // Младший бит различает начертания без отдельного сравнения в цепочке.
        const size_t hash = (std::hash<std::wstring_view>{}(text) << 1) | size_t{bold};
        const size_t bucket = Bucket(hash);
        if (storage_) [[likely]] {
            Index index = storage_->heads[bucket];
            while (index != kNone) {
                const Entry& entry = storage_->entries[index];
                if (entry.hash == hash && entry.text == text) return entry.width;
                index = entry.next;
            }
        }

        const int width = measure();
        // Ошибка получения DC не должна оставлять ложную нулевую ширину.
        if (width <= 0) [[unlikely]] return width;

        std::wstring copy(text);
        if (!storage_) [[unlikely]] storage_ = std::make_unique<Storage>();
        Entry& entry = storage_->entries[next_];
        if (size_ == kCapacity) {
            // Циклическое вытеснение не требует обновлять LRU на попаданиях.
            Index* link = &storage_->heads[Bucket(entry.hash)];
            while (*link != next_) link = &storage_->entries[*link].next;
            *link = entry.next;
        } else {
            ++size_;
        }

        // Старый буфер строки освобождается даже при замене длинного ключа коротким.
        entry.text.swap(copy);
        entry.hash = hash;
        entry.width = width;
        entry.next = storage_->heads[bucket];
        storage_->heads[bucket] = next_;
        next_ = static_cast<Index>((next_ + 1) & (kCapacity - 1));
        return width;
    }

    void clear() {
        storage_.reset();
        size_ = 0;
        next_ = 0;
    }
    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

private:
    using Index = uint16_t;
    static constexpr Index kNone = std::numeric_limits<Index>::max();
    static constexpr size_t kBucketCount = kCapacity * 2;
    static_assert(kCapacity < kNone && (kCapacity & (kCapacity - 1)) == 0);

    struct Entry {
        std::wstring text;
        size_t hash = 0;
        int width = 0;
        Index next = kNone;
    };

    struct Storage {
        std::array<Index, kBucketCount> heads;
        std::array<Entry, kCapacity> entries;

        Storage() { heads.fill(kNone); }
    };

    static size_t Bucket(size_t hash) { return hash & (kBucketCount - 1); }

    std::unique_ptr<Storage> storage_;
    size_t size_ = 0;
    Index next_ = 0;
};
