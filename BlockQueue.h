#pragma once
#include <cstddef>
#include <iterator>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

// MSVC deque выделяет для этих записей блоки на один элемент и сохраняет их
// после удаления. Здесь один блок вмещает около 4 КиБ записей; опустевшие блоки
// сразу освобождаются, карты указателей и резерва у пустой очереди нет.
template <class T, class Allocator = std::allocator<T>>
class BlockQueue {
    static constexpr size_t kHeaderBytes = 2 * sizeof(void*) + 2 * sizeof(size_t);
    static constexpr size_t kBlockCapacity = sizeof(T) < 4096 - kHeaderBytes
        ? (4096 - kHeaderBytes) / sizeof(T) : 1;

    struct Block {
        Block* prev = nullptr;
        Block* next = nullptr;
        size_t begin = 0;
        size_t end = 0;
        alignas(T) std::byte storage[kBlockCapacity * sizeof(T)];

        // Не инициализируем свободные места: T существует только у живых записей.
        Block() noexcept {}
        T* Slot(size_t index) {
            return reinterpret_cast<T*>(storage + index * sizeof(T));
        }
        T& Value(size_t index) { return *std::launder(Slot(index)); }
    };

    using BlockAllocator = typename std::allocator_traits<Allocator>::template rebind_alloc<Block>;
    using BlockTraits = std::allocator_traits<BlockAllocator>;

    template <bool Const>
    class Iterator {
        friend class BlockQueue;
        template <bool> friend class Iterator;
        Block* block_ = nullptr;
        size_t index_ = 0;

        Iterator(Block* block, size_t index) : block_(block), index_(index) {}

    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using reference = std::conditional_t<Const, const T&, T&>;
        using pointer = std::conditional_t<Const, const T*, T*>;

        Iterator() = default;
        template <bool Other, std::enable_if_t<Const && !Other, int> = 0>
        Iterator(const Iterator<Other>& other) : block_(other.block_), index_(other.index_) {}
        reference operator*() const { return block_->Value(index_); }
        pointer operator->() const { return std::addressof(operator*()); }
        Iterator& operator++() {
            if (++index_ == block_->end) {
                block_ = block_->next;
                index_ = block_ ? block_->begin : 0;
            }
            return *this;
        }
        Iterator operator++(int) {
            Iterator previous = *this;
            ++*this;
            return previous;
        }
        template <bool Other>
        bool operator==(const Iterator<Other>& other) const {
            return block_ == other.block_ && index_ == other.index_;
        }
    };

public:
    using iterator = Iterator<false>;
    using const_iterator = Iterator<true>;

    BlockQueue() = default;
    explicit BlockQueue(const Allocator& allocator) : allocator_(allocator) {}
    BlockQueue(const BlockQueue&) = delete;
    BlockQueue& operator=(const BlockQueue&) = delete;
    ~BlockQueue() { clear(); }

    bool empty() const { return size_ == 0; }
    size_t size() const { return size_; }
    T& front() { return head_->Value(head_->begin); }
    const T& front() const { return head_->Value(head_->begin); }
    iterator begin() { return {head_, head_ ? head_->begin : 0}; }
    const_iterator begin() const { return {head_, head_ ? head_->begin : 0}; }
    iterator end() { return {}; }
    const_iterator end() const { return {}; }

    template <class... Args>
    T& emplace_back(Args&&... args) {
        if (!tail_ || tail_->end == kBlockCapacity)
            return AppendBlock(std::forward<Args>(args)...);
        T* value = std::construct_at(tail_->Slot(tail_->end), std::forward<Args>(args)...);
        ++tail_->end;
        ++size_;
        return *value;
    }

    void push_back(const T& value) { emplace_back(value); }
    void push_back(T&& value) { emplace_back(std::move(value)); }

    void pop_front() {
        std::destroy_at(std::addressof(head_->Value(head_->begin++)));
        --size_;
        if (head_->begin == head_->end) RemoveBlock(head_);
    }

    // Удаление из середины сдвигает только хвост своего блока, а не очередь.
    // Итераторы удалённого блока и сдвинутого хвоста становятся недействительны.
    iterator erase(const_iterator position) {
        Block* block = position.block_;
        const size_t index = position.index_;
        if (index == block->begin) {
            std::destroy_at(std::addressof(block->Value(block->begin++)));
        } else {
            for (size_t i = index; i + 1 < block->end; ++i)
                block->Value(i) = std::move(block->Value(i + 1));
            std::destroy_at(std::addressof(block->Value(--block->end)));
        }
        --size_;
        if (block->begin == block->end) {
            Block* next = block->next;
            RemoveBlock(block);
            return {next, next ? next->begin : 0};
        }
        const size_t nextIndex = index < block->begin ? block->begin : index;
        if (nextIndex < block->end) return {block, nextIndex};
        Block* next = block->next;
        return {next, next ? next->begin : 0};
    }

    // Один проход с сохранением порядка. Сначала уплотняем живые записи внутри
    // блока, затем уничтожаем его хвост; пустой блок сразу возвращаем аллокатору.
    template <class Predicate>
    size_t erase_if(Predicate&& predicate) {
        size_t removed = 0;
        for (Block* block = head_; block;) {
            Block* next = block->next;
            size_t write = block->begin;
            for (size_t read = block->begin; read < block->end; ++read) {
                if (predicate(block->Value(read))) continue;
                if (write != read) block->Value(write) = std::move(block->Value(read));
                ++write;
            }
            const size_t count = block->end - write;
            DestroyTail(block, write);
            block->end = write;
            size_ -= count;
            removed += count;
            if (block->begin == block->end) RemoveBlock(block);
            block = next;
        }
        return removed;
    }

    void clear() {
        while (head_) {
            Block* block = head_;
            head_ = block->next;
            DestroyTail(block, block->begin);
            FreeBlock(block);
        }
        tail_ = nullptr;
        size_ = 0;
    }

private:
    template <class... Args>
    T& AppendBlock(Args&&... args) {
        Block* block = BlockTraits::allocate(allocator_, 1);
        std::construct_at(block);
        try {
            std::construct_at(block->Slot(0), std::forward<Args>(args)...);
        } catch (...) {
            FreeBlock(block);
            throw;
        }
        block->end = 1;
        block->prev = tail_;
        if (tail_) tail_->next = block;
        else head_ = block;
        tail_ = block;
        ++size_;
        return block->Value(0);
    }

    void RemoveBlock(Block* block) {
        if (block->prev) block->prev->next = block->next;
        else head_ = block->next;
        if (block->next) block->next->prev = block->prev;
        else tail_ = block->prev;
        FreeBlock(block);
    }

    static void DestroyTail(Block* block, size_t first) {
        // Все текущие записи очередей тривиальны: при очистке достаточно вернуть
        // блоки, без пустого цикла уничтожения по каждому элементу.
        if constexpr (!std::is_trivially_destructible_v<T>) {
            for (size_t i = first; i < block->end; ++i)
                std::destroy_at(std::addressof(block->Value(i)));
        }
    }

    void FreeBlock(Block* block) {
        std::destroy_at(block);
        BlockTraits::deallocate(allocator_, block, 1);
    }

    [[no_unique_address]] BlockAllocator allocator_;
    Block* head_ = nullptr;
    Block* tail_ = nullptr;
    size_t size_ = 0;
};
