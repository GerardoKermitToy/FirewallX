#pragma once

#include <cmath>
#include <cstddef>

// Вызывается после пакетной уборки, а не из find/emplace/erase. Сжимаем лишь
// сильно опустевшую таблицу; двукратный запас не даёт повторять перенос при
// небольших колебаниях нагрузки. Хэши и сравнения наших таблиц не бросают.
template <class Table>
void TrimHashTable(Table& table) {
    const size_t buckets = table.bucket_count();
    size_t target = 0;
    if (table.empty()) {
        if (buckets <= 8) return;
    } else {
        if (buckets <= 64) return;
        const double needed = static_cast<double>(table.size()) / table.max_load_factor();
        if (needed > static_cast<double>(buckets) / 8.0) [[likely]] return;
        target = static_cast<size_t>(std::ceil(needed * 2.0));
    }
    // MSVC rehash/reserve не уменьшают bucket_count. merge переносит сами
    // узлы, сохраняя адреса записей и их вложенные ресурсы, без новых узлов.
    Table compact(target, table.hash_function(), table.key_eq(), table.get_allocator());
    compact.max_load_factor(table.max_load_factor());
    compact.merge(table);
    table.swap(compact);
}

// Для редко редактируемых векторов и строк. Пустой контейнер освобождается
// полностью, непустой — только после четырёхкратного падения размера.
template <class Container>
void TrimCapacity(Container& values) {
    if (!values.capacity()) return;
    if (values.empty()) {
        Container empty(values.get_allocator());
        empty.swap(values);
    } else if (values.size() <= values.capacity() / 4) {
        values.shrink_to_fit();
    }
}
