#include "GenerationCache.h"

#include <algorithm>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <vector>

namespace {

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct Text {
    Text() { ++live; ++constructed; }
    ~Text() { --live; }
    Text(const Text&) = delete;
    Text& operator=(const Text&) = delete;
    Text(Text&&) = delete;
    Text& operator=(Text&&) = delete;

    std::wstring remote, status;
    std::shared_ptr<int> owner;
    static inline size_t live = 0, constructed = 0;
};

struct Connection {
    uint64_t generation = 0;
    size_t textIndex = 0;
};

void Update(GenerationCache<Text>& cache, std::span<Connection> connections) {
    cache.Update(connections.size(), [&](auto indexOf) {
        for (Connection& connection : connections)
            connection.textIndex = indexOf(connection.generation);
    });
    Check(cache.size() == connections.size() && Text::live == cache.size(),
          "cache kept spare or old elements");
}

void TestLifetimeAndShrink() {
    static_assert(!std::is_copy_constructible_v<GenerationCache<Text>>);
    static_assert(std::is_nothrow_move_constructible_v<GenerationCache<Text>>);
    GenerationCache<Text> cache;
    std::vector<Connection> connections(1536);
    for (size_t i = 0; i < connections.size(); ++i)
        connections[i].generation = i + 1;
    Update(cache, connections);

    std::vector<std::weak_ptr<int>> owners;
    for (const Connection& connection : connections) {
        Text& text = cache[connection.textIndex];
        text.remote = std::wstring(64, L'x') + std::to_wstring(connection.generation);
        text.status = std::to_wstring(connection.generation);
        text.owner = std::make_shared<int>(static_cast<int>(connection.generation));
        owners.push_back(text.owner);
    }

    Text* first = &cache[0];
    const wchar_t* remote = first->remote.data();
    const size_t constructed = Text::constructed;
    for (int i = 0; i < 5; ++i) Update(cache, connections);
    Check(&cache[0] == first && cache[0].remote.data() == remote &&
          Text::constructed == constructed,
          "unchanged cache allocated, moved or rebuilt text");

    connections = { {1}, {768}, {1536} };
    Update(cache, connections);
    for (const Connection& connection : connections) {
        const Text& text = cache[connection.textIndex];
        Check(text.owner && *text.owner == static_cast<int>(connection.generation) &&
              text.status == std::to_wstring(connection.generation),
              "shrinking lost surviving text");
    }
    Check(&cache[0] == first && cache[0].remote.data() == remote &&
          Text::constructed == constructed, "shrinking rebuilt surviving text");
    for (size_t i = 0; i < owners.size(); ++i) {
        const bool kept = i == 0 || i == 767 || i == 1535;
        Check(owners[i].expired() != kept, "shrinking kept removed nested ownership");
    }

    connections.clear();
    Update(cache, connections);
    Check(cache.empty() && Text::live == 0, "empty update kept allocated elements");
    for (const auto& owner : owners)
        Check(owner.expired(), "empty update kept a string owner");
}

void TestReorderAndReplacement() {
    GenerationCache<Text> cache;
    std::vector<Connection> connections = { {91}, {2}, {700}, {33} };
    Update(cache, connections);
    for (const Connection& connection : connections) {
        Text& text = cache[connection.textIndex];
        text.status = std::to_wstring(connection.generation);
        text.owner = std::make_shared<int>(static_cast<int>(connection.generation));
    }
    const std::weak_ptr<int> removed = cache[connections[0].textIndex].owner;

    // Как при сортировке по причине: индекс перемещается вместе с ConnItem,
    // а компаратор читает кэш напрямую и не зависит от позиции соединения.
    std::sort(connections.begin(), connections.end(), [&](const auto& a, const auto& b) {
        return cache[a.textIndex].status < cache[b.textIndex].status;
    });
    for (const Connection& connection : connections)
        Check(cache[connection.textIndex].status == std::to_wstring(connection.generation),
              "sorting disconnected text from its generation");
    Update(cache, connections);
    for (const Connection& connection : connections)
        Check(cache[connection.textIndex].status == std::to_wstring(connection.generation),
              "reordered cache lost text");

    connections = { {33}, {700}, {92}, {2} };
    Update(cache, connections);
    Check(removed.expired(), "same-size replacement retained the old generation");
    for (const Connection& connection : connections) {
        const Text& text = cache[connection.textIndex];
        if (connection.generation == 92)
            Check(text.status.empty() && !text.owner, "new generation inherited old text");
        else
            Check(text.status == std::to_wstring(connection.generation) && text.owner,
                  "same-size replacement discarded surviving text");
    }

    cache.clear();
    Check(cache.empty() && Text::live == 0, "explicit clear retained elements");
    Update(cache, connections);
    for (const Connection& connection : connections)
        Check(cache[connection.textIndex].status.empty(), "clear retained localized text");
}

void TestChurnAndCollisions() {
    GenerationCache<Text> cache;
    std::vector<Connection> connections;
    std::unordered_set<uint64_t> previous;
    for (uint64_t step = 0; step < 120; ++step) {
        const size_t count = step % 12 == 0 ? 0 : 1024 + static_cast<size_t>(step % 7);
        connections.resize(count);
        for (size_t i = 0; i < count; ++i)
            connections[i].generation = (step * 11 + i + 1) * 65536;
        if (step % 2)
            std::reverse(connections.begin(), connections.end());
        Update(cache, connections);
        for (const Connection& connection : connections) {
            Text& text = cache[connection.textIndex];
            const auto expected = std::to_wstring(connection.generation);
            Check(previous.count(connection.generation) ? text.status == expected
                                                        : text.status.empty(),
                  "hash chain lost or mixed cached text");
            text.status = expected;
        }
        previous.clear();
        for (const Connection& connection : connections)
            previous.insert(connection.generation);
    }
}

} // namespace

int main() {
    try {
        TestLifetimeAndShrink();
        Check(Text::live == 0, "cache destruction retained elements");
        TestReorderAndReplacement();
        Check(Text::live == 0, "replacement test retained elements");
        TestChurnAndCollisions();
        Check(Text::live == 0, "churn retained elements");
        std::cout << "generation cache tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
