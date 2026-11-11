#pragma once

#include "SnapshotArray.h"

#include <cassert>
#include <cstdint>
#include <limits>
#include <memory>

// Поколения уникальны; forEach передаёт их в одном порядке при каждом вызове
// и сохраняет возвращённый индекс вместе с соединением. Обычное чтение текста
// не требует поиска. Хэш-индекс нужен только для переноса при смене состава.
// Индекс и головы цепочек находятся в одном массиве ровно текущего размера.
// Сам текст имеет отдельного владельца: смена состава переносит только указатель,
// а не пересоздаёт все строковые объекты оставшихся соединений.
template <class T>
class GenerationCache {
public:
    template <class ForEach>
    void Update(size_t count, ForEach&& forEach) {
        if (count == entries_.size()) [[likely]] {
            bool unchanged = true;
            size_t index = 0;
            forEach([&](uint64_t generation) {
                assert(index < count);
                if (entries_[index].generation != generation) unchanged = false;
                return index++;
            });
            assert(index == count);
            if (unchanged) [[likely]] return;
        }

        SnapshotArray<Entry> next;
        next.reset(count);
        size_t index = 0;
        forEach([&](uint64_t generation) {
            assert(index < count);
            Entry& entry = next[index];
            entry.generation = generation;
            if (Entry* previous = Find(generation))
                entry.value = std::move(previous->value);
            else
                entry.value = std::make_unique<T>();
            return index++;
        });
        assert(index == count);

        for (size_t i = 0; i < count; ++i) {
            Entry& entry = next[i];
            size_t& head = next[Bucket(entry.generation, count)].head;
            entry.next = head;
            head = i;
        }
        entries_ = std::move(next);
    }

    void clear() { entries_.reset(); }
    size_t size() const { return entries_.size(); }
    bool empty() const { return entries_.empty(); }
    T& operator[](size_t index) { return *entries_[index].value; }
    const T& operator[](size_t index) const { return *entries_[index].value; }

private:
    static constexpr size_t kNone = std::numeric_limits<size_t>::max();

    struct Entry {
        uint64_t generation = 0;
        size_t head = kNone;
        size_t next = kNone;
        std::unique_ptr<T> value;
    };

    static size_t Bucket(uint64_t generation, size_t count) {
        // Простое взятие остатка плохо распределяет поколения, приходившие
        // вперемежку от нескольких PID с постоянным шагом.
        generation ^= generation >> 30;
        generation *= 0xbf58476d1ce4e5b9ULL;
        generation ^= generation >> 27;
        generation *= 0x94d049bb133111ebULL;
        generation ^= generation >> 31;
        return static_cast<size_t>(generation % count);
    }

    Entry* Find(uint64_t generation) {
        if (entries_.empty()) return nullptr;
        size_t index = entries_[Bucket(generation, entries_.size())].head;
        while (index != kNone) {
            Entry& entry = entries_[index];
            if (entry.generation == generation) return &entry;
            index = entry.next;
        }
        return nullptr;
    }

    SnapshotArray<Entry> entries_;
};
