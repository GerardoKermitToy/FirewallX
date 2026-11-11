#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <utility>

// Массив снимка хранит ровно size элементов, без ёмкости под будущие записи.
// При неизменном размере память используется повторно; при изменении прежние
// элементы не сохраняются: вызывающий код всё равно заполняет снимок заново.
template <class T>
class SnapshotArray {
public:
    SnapshotArray() = default;
    SnapshotArray(const SnapshotArray&) = delete;
    SnapshotArray& operator=(const SnapshotArray&) = delete;

    SnapshotArray(SnapshotArray&& other) noexcept
        : values_(std::move(other.values_)),
          size_(std::exchange(other.size_, 0)) {}

    SnapshotArray& operator=(SnapshotArray&& other) noexcept {
        if (this != &other) {
            values_ = std::move(other.values_);
            size_ = std::exchange(other.size_, 0);
        }
        return *this;
    }

    void reset(size_t size = 0) {
        if (size == size_) [[likely]] return;
        auto values = size ? std::make_unique<T[]>(size) : nullptr;
        values_ = std::move(values);
        size_ = size;
    }

    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }
    T* data() { return values_.get(); }
    const T* data() const { return values_.get(); }
    T& operator[](size_t index) { return values_[index]; }
    const T& operator[](size_t index) const { return values_[index]; }
    T* begin() { return data(); }
    const T* begin() const { return data(); }
    T* end() { return size_ ? data() + size_ : data(); }
    const T* end() const { return size_ ? data() + size_ : data(); }
    std::span<T> span() { return { data(), size_ }; }
    std::span<const T> span() const { return { data(), size_ }; }

private:
    std::unique_ptr<T[]> values_;
    size_t size_ = 0;
};
