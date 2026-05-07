#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace papa::util {

// Lowercase ASCII letters in place
// Bytes outside the A-Z range pass through unchanged so UTF-8 sequences are safe
[[nodiscard]] std::string to_lower_ascii(std::string_view s);

// Return the prefix of s up to (but not including) the first NUL byte
// Used to slice fixed-width PE name fields without copying
[[nodiscard]] std::string_view trim_nul(std::string_view s) noexcept;

// Suffix and prefix tests
[[nodiscard]] bool ends_with(std::string_view s, std::string_view suffix) noexcept;
[[nodiscard]] bool starts_with(std::string_view s, std::string_view prefix) noexcept;

// Case-insensitive ends_with for the given ASCII suffix
[[nodiscard]] bool ends_with_ci(std::string_view s, std::string_view suffix) noexcept;

// Drop suffix from s when it matches case-insensitively, otherwise return s
[[nodiscard]] std::string remove_suffix_ci(std::string_view s, std::string_view suffix);

// Tokenize on a single separator
// The returned views remain valid only while the input does
[[nodiscard]] std::vector<std::string_view> split(std::string_view s, char sep);

// Concatenate parts inserting sep between every pair
[[nodiscard]] std::string join(std::span<const std::string_view> parts, std::string_view sep);

// One-byte printability test for the CAPA ASCII set: TAB plus space..tilde
[[nodiscard]] bool is_ascii_printable(std::uint8_t c) noexcept;

// True when every byte of s is ASCII-printable
// Empty input returns true so callers can use it as a precondition
[[nodiscard]] bool is_ascii_printable(std::string_view s) noexcept;

// True when bytes are an even-length UTF-16LE sequence whose code units are
// all printable ASCII (high-byte zero plus printable low-byte)
[[nodiscard]] bool is_utf16le_printable(std::span<const std::byte> bytes) noexcept;

// Decode a UTF-16LE buffer to UTF-8 stopping at the first NUL code unit
// Returns std::nullopt when bytes has odd length or contains an unpaired surrogate
// Non-printable code points are accepted because the caller chooses when to filter
[[nodiscard]] std::optional<std::string>
decode_utf16le_nul_trim(std::span<const std::byte> bytes);

}  // namespace papa::util
