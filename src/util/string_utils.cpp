#include "papa/util/string_utils.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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

// Append one Unicode code point as UTF-8 bytes
void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80U) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800U) {
        out.push_back(static_cast<char>(0xC0U | (cp >> 6)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
    } else if (cp < 0x10000U) {
        out.push_back(static_cast<char>(0xE0U | (cp >> 12)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
    } else {
        out.push_back(static_cast<char>(0xF0U | (cp >> 18)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 12) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
    }
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

std::string_view trim_nul(std::string_view s) noexcept {
    const auto pos = s.find('\0');
    return pos == std::string_view::npos ? s : s.substr(0, pos);
}

bool ends_with(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size() &&
           s.substr(s.size() - suffix.size()) == suffix;
}

bool starts_with(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() &&
           s.substr(0, prefix.size()) == prefix;
}

bool ends_with_ci(std::string_view s, std::string_view suffix) noexcept {
    if (s.size() < suffix.size()) { return false; }
    const auto offset = s.size() - suffix.size();
    for (std::size_t i = 0; i < suffix.size(); ++i) {
        if (ascii_lower_byte(s[offset + i]) != ascii_lower_byte(suffix[i])) {
            return false;
        }
    }
    return true;
}

std::string remove_suffix_ci(std::string_view s, std::string_view suffix) {
    if (!ends_with_ci(s, suffix)) { return std::string(s); }
    return std::string(s.substr(0, s.size() - suffix.size()));
}

std::vector<std::string_view> split(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == sep) {
            out.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    out.emplace_back(s.substr(start));
    return out;
}

std::string join(std::span<const std::string_view> parts, std::string_view sep) {
    std::string out;
    std::size_t total = 0;
    for (const auto& p : parts) { total += p.size(); }
    if (!parts.empty()) {
        total += sep.size() * (parts.size() - 1);
    }
    out.reserve(total);
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) { out.append(sep); }
        out.append(parts[i]);
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

std::optional<std::string>
decode_utf16le_nul_trim(std::span<const std::byte> bytes) {
    if ((bytes.size() % 2U) != 0U) { return std::nullopt; }

    // Surrogate range constants
    constexpr std::uint32_t kHighSurrogateMin = 0xD800U;
    constexpr std::uint32_t kHighSurrogateMax = 0xDBFFU;
    constexpr std::uint32_t kLowSurrogateMin  = 0xDC00U;
    constexpr std::uint32_t kLowSurrogateMax  = 0xDFFFU;
    constexpr std::uint32_t kSurrogateOffset  = 0x10000U;
    constexpr std::uint32_t kSurrogateMask    = 0x3FFU;
    constexpr std::uint32_t kHighShift        = 10U;

    std::string out;
    out.reserve(bytes.size());
    for (std::size_t i = 0; i + 1U < bytes.size(); i += 2U) {
        const std::uint32_t unit =
            static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[i])) |
            (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[i + 1U])) << 8U);

        if (unit == 0U) { break; }

        if (unit >= kHighSurrogateMin && unit <= kHighSurrogateMax) {
            // Need a paired low surrogate
            if (i + 3U >= bytes.size()) { return std::nullopt; }
            const std::uint32_t low =
                static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[i + 2U])) |
                (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[i + 3U])) << 8U);
            if (low < kLowSurrogateMin || low > kLowSurrogateMax) {
                return std::nullopt;
            }
            const std::uint32_t cp = kSurrogateOffset +
                (((unit - kHighSurrogateMin) & kSurrogateMask) << kHighShift) +
                ((low - kLowSurrogateMin) & kSurrogateMask);
            append_utf8(out, cp);
            i += 2U;
        } else if (unit >= kLowSurrogateMin && unit <= kLowSurrogateMax) {
            // Stray low surrogate
            return std::nullopt;
        } else {
            append_utf8(out, unit);
        }
    }
    return out;
}

}  // namespace papa::util
