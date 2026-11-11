#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace read_buffer {

// Политика выполняется только владельцем буфера, между операциями I/O.
// Считаются целые записи, а не фрагменты чтения; таймеров и потоков здесь нет.
template <size_t BaselineCapacity>
class Buffer {
public:
    static constexpr unsigned kUnderusedRecordCount = 128;
    static constexpr size_t kUnderusedRatio = 4;

    Buffer() = default;
    ~Buffer() { Reset(); }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    uint8_t* Data() const noexcept { return data_; }
    size_t Capacity() const noexcept { return capacity_; }

    bool Reserve(size_t required, size_t used = 0) noexcept {
        if (required <= capacity_) [[likely]] return true;
        if (used > capacity_) [[unlikely]] return false;
        if (required <= BaselineCapacity) {
            baseline_ = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), 0, BaselineCapacity));
            if (!baseline_) [[unlikely]] return false;
            data_ = baseline_;
            capacity_ = BaselineCapacity;
            return true;
        }
        size_t target = GrowthCapacity(required);
        if (required <= reservedCapacity_) {
            // После частичного уменьшения адреса ещё зарезервированы: возвращаем
            // commit без смены указателя и копирования уже принятого payload.
            if (target > reservedCapacity_) target = reservedCapacity_;
            if (!VirtualAlloc(data_ + capacity_, target - capacity_, MEM_COMMIT, PAGE_READWRITE)) [[unlikely]]
                return false;
            capacity_ = target;
            ResetUsage();
            return true;
        }
        auto* grown = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, target, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!grown) [[unlikely]] return false;
        if (used) std::memcpy(grown, data_, used);
        ReleaseLarge();
        data_ = grown;
        capacity_ = reservedCapacity_ = target;
        return true;
    }

    void RecordCompleted(size_t size) noexcept {
        if (capacity_ <= BaselineCapacity) [[likely]] return;
        if (size > capacity_ / kUnderusedRatio) {
            ResetUsage();
            return;
        }
        if (quietPeak_ < size) quietPeak_ = size;
        if (quietRecords_ < kUnderusedRecordCount) ++quietRecords_;
    }

    bool NeedsTrim(size_t required = 0) const noexcept {
        return capacity_ > BaselineCapacity && quietRecords_ == kUnderusedRecordCount &&
            required <= capacity_ / kUnderusedRatio;
    }

    // Вызывается только после callback и завершения I/O. required учитывает
    // полную длину следующей незавершённой записи, если её заголовок уже известен.
    bool Trim(size_t used = 0, size_t required = 0) noexcept {
        if (required < used) required = used;
        if (!NeedsTrim(required)) return true;
        if (required < quietPeak_) required = quietPeak_;
        if (required <= BaselineCapacity) return Compact(used);

        const size_t target = GrowthCapacity(required);
        if (!VirtualFree(data_ + target, capacity_ - target, MEM_DECOMMIT)) return false;
        capacity_ = target;
        ResetUsage();
        return true;
    }

    void ReleaseLarge() noexcept {
        if (data_ && data_ != baseline_) VirtualFree(data_, 0, MEM_RELEASE);
        data_ = baseline_;
        capacity_ = baseline_ ? BaselineCapacity : 0;
        reservedCapacity_ = 0;
        ResetUsage();
    }

    // При возврате к базовой ёмкости копируется только остаток следующей записи.
    // Полностью обработанные payload не копируются даже при частичном уменьшении.
    bool Compact(size_t used) noexcept {
        if (capacity_ <= BaselineCapacity || used > BaselineCapacity) return true;
        if (used && !baseline_) {
            baseline_ = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), 0, BaselineCapacity));
            if (!baseline_) return false;
        }
        if (used) std::memcpy(baseline_, data_, used);
        ReleaseLarge();
        return true;
    }

    void Reset() noexcept {
        ReleaseLarge();
        if (baseline_) HeapFree(GetProcessHeap(), 0, baseline_);
        baseline_ = data_ = nullptr;
        capacity_ = 0;
    }

private:
    // Запас 25% и округление до 64 KiB исключают рост на каждом небольшом
    // изменении снимка. Переполнение не превращается в ограничение длины.
    static size_t GrowthCapacity(size_t required) noexcept {
        constexpr size_t granularity = 64 * 1024;
        const size_t extra = required / 4;
        if (required > SIZE_MAX - extra) return required;
        const size_t target = required + extra;
        if (target > SIZE_MAX - (granularity - 1)) return target;
        return (target + granularity - 1) & ~(granularity - 1);
    }

    void ResetUsage() noexcept {
        quietPeak_ = 0;
        quietRecords_ = 0;
    }

    uint8_t* baseline_ = nullptr;
    uint8_t* data_ = nullptr;
    size_t capacity_ = 0;
    size_t reservedCapacity_ = 0;
    size_t quietPeak_ = 0;
    unsigned quietRecords_ = 0;
};

} // namespace read_buffer
