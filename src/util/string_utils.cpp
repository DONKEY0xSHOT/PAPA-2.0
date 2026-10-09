#include "papa/util/string_utils.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace papa::util {

namespace {

// Printable ASCII lookup table
// Built once at translation-unit init so the per-byte test is a pure load
constexpr std::array<bool, 256> make_ascii_printable_table() noexcept {
    std::array<bool, 256> t{};
    // Printable ASCII range: space (0x20) through tilde (0x7E) inclusive
    constexpr std::uint8_t kAsciiSpace = 0x20;
    constexpr std::uint8_t kAsciiTilde = 0x7E;
    for (std::uint8_t i = kAsciiSpace; i <= kAsciiTilde; ++i) {
        t[i] = true;
    }
    // CAPA also accepts tab inside extracted strings
    t[0x09] = true;
    return t;
}

constexpr std::array<bool, 256> kAsciiPrintable = make_ascii_printable_table();

// Lowercase a single byte if it is an ASCII uppercase letter
[[nodiscard]] constexpr char ascii_lower_byte(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        // Bit 0x20 toggles letter case in ASCII
        return static_cast<char>(static_cast<unsigned char>(c) | 0x20);
    }
    return c;
}

}  // namespace

std::string to_lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(ascii_lower_byte(c));
    }
    return out;
}

bool is_ascii_printable(std::uint8_t c) noexcept {
    return kAsciiPrintable[c];
}

bool is_ascii_printable(std::string_view s) noexcept {
    for (char c : s) {
        if (!kAsciiPrintable[static_cast<std::uint8_t>(c)]) { return false; }
    }
    return true;
}

bool is_utf16le_printable(std::span<const std::byte> bytes) noexcept {
    if ((bytes.size() % 2U) != 0U) { return false; }
    for (std::size_t i = 0; i + 1U < bytes.size(); i += 2U) {
        const auto low  = static_cast<std::uint8_t>(bytes[i]);
        const auto high = static_cast<std::uint8_t>(bytes[i + 1U]);
        if (high != 0U) { return false; }
        if (!kAsciiPrintable[low]) { return false; }
    }
    return true;
}

}  // namespace papa::util
