#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace papa::util {

// Return a copy of s with its ASCII letters lowercased
// Bytes outside the A-Z range pass through unchanged so UTF-8 sequences are safe
[[nodiscard]] std::string to_lower_ascii(std::string_view s);

// One-byte printability test for the CAPA ASCII set: TAB plus space..tilde
[[nodiscard]] bool is_ascii_printable(std::uint8_t c) noexcept;

// True when every byte of s is ASCII-printable
// Empty input returns true so callers can use it as a precondition
[[nodiscard]] bool is_ascii_printable(std::string_view s) noexcept;

// True when bytes are an even-length UTF-16LE sequence whose code units are
// all printable ASCII (high-byte zero plus printable low-byte)
[[nodiscard]] bool is_utf16le_printable(std::span<const std::byte> bytes) noexcept;

}  // namespace papa::util
