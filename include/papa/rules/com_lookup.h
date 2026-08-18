#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace papa::rules {

enum class ComKind : std::uint8_t {
    kClass,
    kInterface,
};

// One row of the COM lookup tables, holding the little-endian binary GUID and the
// canonical string form. Each table is sorted by name for binary search
struct ComEntry {
    std::string_view              name;
    std::string_view              guid_string;
    std::array<std::byte, 16>     guid_bytes;
};

// Look up an entry by name within the requested table. Returns a pointer into the
// static table or nullptr when no entry matches
[[nodiscard]] const ComEntry* lookup_com(ComKind kind, std::string_view name) noexcept;

// Test-facing accessors for the underlying tables
// Defined in com_classes.cpp and com_interfaces.cpp respectively
[[nodiscard]] std::span<const ComEntry> com_class_table()     noexcept;
[[nodiscard]] std::span<const ComEntry> com_interface_table() noexcept;

}  // namespace papa::rules
