#pragma once

#include <algorithm>
#include <cstddef>
#include <memory>
#include <utility>

// Четыре таблицы ОС читаются последовательно в один рабочий буфер. Его рост
// не копирует и не обнуляет старые байты: API сразу перезаписывает результат.
class TableBuffer {
public:
    static constexpr size_t kInitialBytes = 32 * 1024;
    static constexpr size_t kSlackBytes = 8 * 1024;

    TableBuffer() = default;
    TableBuffer(TableBuffer&& other) noexcept
        : bytes_(std::move(other.bytes_)), size_(std::exchange(other.size_, 0)) {}
    TableBuffer& operator=(TableBuffer&& other) noexcept {
        if (this != &other) {
            bytes_ = std::move(other.bytes_);
            size_ = std::exchange(other.size_, 0);
        }
        return *this;
    }

    size_t size() const { return size_; }
    unsigned char* data() { return bytes_.get(); }
    const unsigned char* data() const { return bytes_.get(); }

    void reset(size_t size = 0) {
        if (size == size_) return;
        auto bytes = size ? std::make_unique_for_overwrite<unsigned char[]>(size) : nullptr;
        bytes_ = std::move(bytes);
        size_ = size;
    }

    // Уборка после чтения всех категорий: сохраняем место под наибольшую
    // актуальную таблицу, а не уменьшаем и растим буфер между семействами.
    void Trim(size_t used, size_t minimum = kInitialBytes) {
        if (!used) {
            reset();
            return;
        }
        const size_t target = std::max(minimum, used + kSlackBytes);
        if (target <= size_ / 4) [[unlikely]] reset(target);
    }

private:
    std::unique_ptr<unsigned char[]> bytes_;
    size_t size_ = 0;
};
