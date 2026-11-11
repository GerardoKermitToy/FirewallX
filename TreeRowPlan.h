#pragma once
#include <cstddef>
#include <vector>

// План хранит только группы и индексы выбранных соединений, но не тяжёлые
// строки UI. Число итоговых строк известно до выделения массива Row.
class TreeRowPlan {
public:
    struct Source {
        size_t index = 0;
        size_t childCount = 0;
        bool expanded = false;
        bool matches = false;
        bool sharedChildMatch = false;
    };

    struct Group {
        size_t source = 0;
        size_t childBegin = 0;
        size_t childCount = 0;
        bool expanded = false;
        bool allChildren = true;
    };

    explicit TreeRowPlan(bool filtering) : filtering_(filtering) {}

    template <class MatchChild>
    void AddGroup(const Source& source, MatchChild&& matchChild) {
        if (!filtering_) {
            AddVisible(source, source.expanded ? source.childCount : 0,
                       source.expanded, true);
            return;
        }
        if (source.sharedChildMatch && source.childCount) {
            AddVisible(source, source.childCount, true, true);
            return;
        }
        if (source.matches) {
            bool expanded = source.expanded;
            // Совпавшая группа показывает всех детей, если раскрыта либо
            // найден хотя бы один ребёнок. После первого совпадения поиск не нужен.
            for (size_t i = 0; !expanded && i < source.childCount; ++i)
                expanded = matchChild(i);
            AddVisible(source, expanded ? source.childCount : 0, expanded, true);
            return;
        }

        const size_t begin = children_.size();
        for (size_t i = 0; i < source.childCount; ++i)
            if (matchChild(i)) children_.push_back(i);
        const size_t count = children_.size() - begin;
        if (count) AddVisible(source, count, true, false, begin);
    }

    const std::vector<Group>& groups() const { return groups_; }
    size_t rowCount() const { return rowCount_; }
    size_t ChildIndex(const Group& group, size_t index) const {
        return group.allChildren ? index : children_[group.childBegin + index];
    }

private:
    void AddVisible(const Source& source, size_t childCount, bool expanded,
                    bool allChildren, size_t childBegin = 0) {
        groups_.push_back({source.index, childBegin, childCount, expanded, allChildren});
        rowCount_ += 1 + childCount;
    }

    bool filtering_;
    size_t rowCount_ = 0;
    std::vector<Group> groups_;
    std::vector<size_t> children_;
};
