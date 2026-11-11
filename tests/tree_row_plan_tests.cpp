#include "TreeRowPlan.h"
#include "NumberText.h"

#include <array>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct ExpectedGroup {
    size_t source;
    bool expanded;
    std::vector<size_t> children;
};

// Прежняя семантика: проверяются все дети, затем решается видимость группы.
void AddExpected(std::vector<ExpectedGroup>& expected, bool filtering,
                 const TreeRowPlan::Source& source, const std::vector<bool>& hits) {
    size_t hitCount = 0;
    for (bool hit : hits) if (source.sharedChildMatch || hit) ++hitCount;
    if (filtering && !source.matches && !hitCount) return;
    const bool expanded = source.expanded || (filtering && hitCount != 0);
    ExpectedGroup group{source.index, expanded, {}};
    if (expanded) {
        for (size_t i = 0; i < hits.size(); ++i)
            if (!filtering || source.matches || source.sharedChildMatch || hits[i])
                group.children.push_back(i);
    }
    expected.push_back(std::move(group));
}

void Compare(const TreeRowPlan& plan, const std::vector<ExpectedGroup>& expected) {
    Check(plan.groups().size() == expected.size(), "visible group count changed");
    size_t rows = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        const auto& actual = plan.groups()[i];
        const auto& wanted = expected[i];
        Check(actual.source == wanted.source && actual.expanded == wanted.expanded &&
              actual.childCount == wanted.children.size(), "group visibility or expansion changed");
        for (size_t j = 0; j < wanted.children.size(); ++j)
            Check(plan.ChildIndex(actual, j) == wanted.children[j], "child order or selection changed");
        rows += 1 + wanted.children.size();
    }
    Check(plan.rowCount() == rows, "exact output size is wrong");
}

void TestAllVisibilityCombinations() {
    for (bool filtering : {false, true}) {
        for (bool expanded : {false, true}) {
            for (bool matched : {false, true}) {
                for (bool shared : {false, true}) {
                    for (size_t count = 0; count <= 8; ++count) {
                        for (unsigned mask = 0; mask < (1u << count); ++mask) {
                            TreeRowPlan plan(filtering);
                            TreeRowPlan::Source source{37, count, expanded, matched, shared};
                            std::vector<bool> hits(count);
                            for (size_t i = 0; i < count; ++i) hits[i] = (mask & (1u << i)) != 0;
                            std::array<unsigned, 8> calls{};
                            plan.AddGroup(source, [&](size_t i) {
                                Check(++calls[i] == 1, "child was filtered twice");
                                return hits[i];
                            });
                            std::vector<ExpectedGroup> expected;
                            AddExpected(expected, filtering, source, hits);
                            Compare(plan, expected);
                            if (!filtering || (matched && expanded) || (shared && count))
                                for (unsigned call : calls)
                                    Check(call == 0, "unnecessary child filtering was performed");
                        }
                    }
                }
            }
        }
    }
}

void TestMixedGroupsAndReordering() {
    std::mt19937 random(0x574f5253);
    for (int pass = 0; pass < 120; ++pass) {
        const bool filtering = pass % 3 != 0;
        TreeRowPlan plan(filtering);
        std::vector<ExpectedGroup> expected;
        for (size_t index = 0; index < 70; ++index) {
            const size_t count = random() % 40;
            TreeRowPlan::Source source{1000 - index, count,
                random() % 2 != 0, random() % 5 == 0, random() % 7 == 0};
            std::vector<bool> hits(count);
            for (size_t i = 0; i < count; ++i) hits[i] = random() % 9 == 0;
            plan.AddGroup(source, [&](size_t i) { return hits[i]; });
            AddExpected(expected, filtering, source, hits);
        }
        Compare(plan, expected);
    }
}

struct CountedRow {
    static inline size_t live = 0;
    static inline size_t constructed = 0;
    std::shared_ptr<int> nested;
    size_t groupRow = 0;
    bool lastChild = false;

    CountedRow() { ++live; ++constructed; }
    ~CountedRow() { --live; }
    CountedRow(const CountedRow&) = delete;
    CountedRow& operator=(const CountedRow&) = delete;
    CountedRow(CountedRow&& other) noexcept
        : nested(std::move(other.nested)), groupRow(other.groupRow), lastChild(other.lastChild) {
        ++live;
        ++constructed;
    }
};

std::vector<CountedRow> MakeRows(size_t count) {
    std::vector<CountedRow> rows;
    rows.reserve(count);
    for (size_t i = 0; i < count; ++i) rows.emplace_back();
    return rows;
}

void TestExactStorageAndEmptyResult() {
    constexpr size_t count = 100000;
    auto rows = MakeRows(count + 1);
    rows[0].nested = std::make_shared<int>(1);
    rows[count].nested = std::make_shared<int>(2);
    std::weak_ptr<int> first = rows[0].nested, last = rows[count].nested;
    const size_t before = CountedRow::constructed;

    TreeRowPlan empty(true);
    size_t calls = 0;
    empty.AddGroup({0, count, true, false, false}, [&](size_t) { ++calls; return false; });
    Check(empty.rowCount() == 0 && empty.groups().empty() && calls == count,
          "empty filter result reserved rows or skipped filtering");
    rows = MakeRows(empty.rowCount());
    Check(rows.empty() && rows.capacity() == 0 && CountedRow::live == 0 &&
          CountedRow::constructed == before && first.expired() && last.expired(),
          "empty result retained row storage or nested ownership");

    TreeRowPlan sparse(true);
    calls = 0;
    sparse.AddGroup({9, count, false, false, false}, [&](size_t i) {
        ++calls;
        return i % 1000 == 0;
    });
    rows = MakeRows(sparse.rowCount());
    Check(calls == count && rows.size() == 101 && rows.capacity() == 101 && CountedRow::live == 101 &&
          CountedRow::constructed == before + 101, "sparse result allocated rejected rows");
    size_t next = 0;
    for (const auto& group : sparse.groups()) {
        const size_t groupRow = next++;
        for (size_t i = 0; i < group.childCount; ++i) {
            rows[next].groupRow = groupRow;
            rows[next++].lastChild = i + 1 == group.childCount;
        }
    }
    Check(next == rows.size() && rows[100].lastChild && !rows[99].lastChild &&
          rows[1].groupRow == 0, "group or last-child row indices changed");
    std::vector<CountedRow>().swap(rows);
    Check(CountedRow::live == 0 && rows.capacity() == 0, "small result was not released");
}

void TestNumberFormatting() {
    const auto verify = [](uint64_t value) {
        std::wstring expected = std::to_wstring(value);
        for (size_t index = expected.size(); index > 3;) {
            index -= 3;
            expected.insert(index, 1, L' ');
        }
        wchar_t buffer[32];
        const std::wstring_view actual = FormatNumberView(value, buffer);
        Check(actual == expected && actual.data()[actual.size()] == L'\0',
              "allocation-free counter text differs from the displayed format");
    };
    verify(0);
    verify(1);
    for (uint64_t value = 10; value < 10000000000000000000ull; value *= 10) {
        verify(value - 1);
        verify(value);
        verify(value + 1);
    }
    verify(10000000000000000000ull);
    verify(std::numeric_limits<uint64_t>::max());
    std::mt19937_64 random(0x4e554d42);
    for (int i = 0; i < 10000; ++i) verify(random());
}

void TestSharedMatchAndEarlyExit() {
    TreeRowPlan shared(true);
    shared.AddGroup({1, 100000, false, false, true}, [](size_t) -> bool {
        throw std::runtime_error("shared child match repeated per-child filtering");
    });
    Check(shared.rowCount() == 100001 && shared.groups()[0].allChildren &&
          shared.ChildIndex(shared.groups()[0], 99999) == 99999,
          "shared match did not select the complete group");

    TreeRowPlan collapsed(true);
    size_t calls = 0;
    collapsed.AddGroup({2, 100000, false, true, false}, [&](size_t i) {
        ++calls;
        return i == 3;
    });
    Check(calls == 4 && collapsed.rowCount() == 100001 && collapsed.groups()[0].expanded,
          "matching collapsed group did not stop after its first child hit");
}
}

int main() {
    try {
        TestAllVisibilityCombinations();
        TestMixedGroupsAndReordering();
        TestExactStorageAndEmptyResult();
        TestNumberFormatting();
        TestSharedMatchAndEarlyExit();
        std::cout << "tree row plan tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
