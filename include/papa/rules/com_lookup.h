#pragma once

#include "papa/exceptions.h"

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

// The 16 bytes of a braced GUID string, in the order of Python's uuid.UUID(s).bytes_le
// Throws PapaInvariantError on a malformed string, so a bad constant table entry fails to compile
[[nodiscard]] constexpr std::array<std::byte, 16> bytes_le(std::string_view guid) {
    constexpr std::size_t kBracedGuidLength = 38;
    if (guid.size() != kBracedGuidLength || guid.front() != '{' || guid.back() != '}' ||
        guid[9] != '-' || guid[14] != '-' || guid[19] != '-' || guid[24] != '-') {
        throw PapaInvariantError("malformed GUID string");
    }
    const auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') { return static_cast<unsigned>(c - '0'); }
        if (c >= 'a' && c <= 'f') { return static_cast<unsigned>(c - 'a' + 10); }
        if (c >= 'A' && c <= 'F') { return static_cast<unsigned>(c - 'A' + 10); }
        throw PapaInvariantError("malformed GUID string");
    };
    // Where each output byte's two hex digits start in the text
    // The first three fields are stored little-endian, the last two in text order
    constexpr std::array<std::size_t, 16> kHexOffset = {
        7, 5, 3, 1, 12, 10, 17, 15, 20, 22, 25, 27, 29, 31, 33, 35};
    std::array<std::byte, 16> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::size_t at = kHexOffset[i];
        out[i] = static_cast<std::byte>((nibble(guid[at]) << 4U) | nibble(guid[at + 1]));
    }
    return out;
}

// One row of the COM lookup tables, holding the canonical string form and the
// little-endian binary GUID derived from it. Each table is sorted by name for binary search
struct ComEntry {
    constexpr ComEntry(std::string_view entry_name, std::string_view guid)
        : name(entry_name), guid_string(guid), guid_bytes(bytes_le(guid)) {}

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
