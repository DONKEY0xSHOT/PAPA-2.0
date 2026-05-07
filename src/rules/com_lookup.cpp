#include "papa/rules/com_lookup.h"

#include <algorithm>
#include <span>
#include <string_view>

namespace papa::rules {

const ComEntry* lookup_com(ComKind kind, std::string_view name) noexcept {
    const std::span<const ComEntry> table =
        (kind == ComKind::kClass) ? com_class_table() : com_interface_table();

    // Tables are sorted by name so binary search keeps lookup logarithmic
    // even when future generations grow each table to thousands of entries
    const auto it = std::lower_bound(table.begin(), table.end(), name,
        [](const ComEntry& entry, std::string_view target) {
            return entry.name < target;
        });
    if (it == table.end() || it->name != name) {
        return nullptr;
    }
    return &(*it);
}

}  // namespace papa::rules
