// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the PAPA authors

#include <ostream>

#include "doctest.h"

#include "papa/util/string_utils.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using papa::util::decode_utf16le_nul_trim;
using papa::util::ends_with;
using papa::util::ends_with_ci;
using papa::util::is_ascii_printable;
using papa::util::is_utf16le_printable;
using papa::util::join;
using papa::util::remove_suffix_ci;
using papa::util::split;
using papa::util::starts_with;
using papa::util::to_lower_ascii;
using papa::util::trim_nul;

TEST_CASE("string_utils: to_lower_ascii lowercases ASCII letters only") {
    CHECK(to_lower_ascii("Hello, WORLD") == "hello, world");
    CHECK(to_lower_ascii("") == "");
    // High bytes pass through unchanged so UTF-8 is safe
    CHECK(to_lower_ascii(std::string("caf\xC3\x89")) == std::string("caf\xC3\x89"));
}

TEST_CASE("string_utils: trim_nul cuts at the first NUL byte") {
    CHECK(trim_nul(std::string_view{"abc\0xyz", 7}) == "abc");
    CHECK(trim_nul("no nul here") == "no nul here");
    CHECK(trim_nul("") == "");
}

TEST_CASE("string_utils: starts_with and ends_with case-sensitive") {
    CHECK(starts_with("kernel32.CreateFileA", "kernel32"));
    CHECK_FALSE(starts_with("kernel32.CreateFileA", "Kernel32"));
    CHECK(ends_with("kernel32.dll", ".dll"));
    CHECK_FALSE(ends_with("kernel32.dll", ".DLL"));
    CHECK(starts_with("xyz", ""));
    CHECK(ends_with("xyz", ""));
}

TEST_CASE("string_utils: ends_with_ci ignores case on the suffix") {
    CHECK(ends_with_ci("kernel32.DLL", ".dll"));
    CHECK(ends_with_ci("kernel32.dll", ".DLL"));
    CHECK_FALSE(ends_with_ci("kernel32.so", ".dll"));
    CHECK(ends_with_ci("foo", ""));
}

TEST_CASE("string_utils: remove_suffix_ci removes only when matched") {
    CHECK(remove_suffix_ci("kernel32.DLL", ".dll") == "kernel32");
    CHECK(remove_suffix_ci("kernel32.so",  ".dll") == "kernel32.so");
}

TEST_CASE("string_utils: split tokenizes on a single byte separator") {
    auto parts = split("a,b,,c", ',');
    REQUIRE(parts.size() == 4);
    CHECK(parts[0] == "a");
    CHECK(parts[1] == "b");
    CHECK(parts[2] == "");
    CHECK(parts[3] == "c");
}

TEST_CASE("string_utils: join inserts separator between non-empty parts") {
    const std::array<std::string_view, 3> parts{"a", "b", "c"};
    CHECK(join(parts, "/") == "a/b/c");

    const std::array<std::string_view, 1> one{"solo"};
    CHECK(join(one, "/") == "solo");

    const std::array<std::string_view, 0> none{};
    CHECK(join(none, "/") == "");
}

TEST_CASE("string_utils: is_ascii_printable accepts printable bytes and tab") {
    CHECK(is_ascii_printable(static_cast<std::uint8_t>(' ')));
    CHECK(is_ascii_printable(static_cast<std::uint8_t>('A')));
    CHECK(is_ascii_printable(static_cast<std::uint8_t>('~')));
    CHECK(is_ascii_printable(static_cast<std::uint8_t>('\t')));
    // Newline and NUL are not printable for our purposes
    CHECK_FALSE(is_ascii_printable(static_cast<std::uint8_t>('\n')));
    CHECK_FALSE(is_ascii_printable(static_cast<std::uint8_t>(0x00)));
    CHECK_FALSE(is_ascii_printable(static_cast<std::uint8_t>(0xFF)));
}

TEST_CASE("string_utils: is_ascii_printable accepts only fully-printable strings") {
    CHECK(is_ascii_printable(""));
    CHECK(is_ascii_printable("Hello, World!"));
    CHECK_FALSE(is_ascii_printable(std::string_view{"hi\0", 3}));
}

TEST_CASE("string_utils: is_utf16le_printable detects ASCII-encoded UTF-16LE") {
    const std::array<std::byte, 10> hello{
        std::byte{'h'}, std::byte{0x00},
        std::byte{'e'}, std::byte{0x00},
        std::byte{'l'}, std::byte{0x00},
        std::byte{'l'}, std::byte{0x00},
        std::byte{'o'}, std::byte{0x00},
    };
    CHECK(is_utf16le_printable(hello));

    const std::array<std::byte, 4> non_ascii{
        std::byte{'h'}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01},   // high byte non-zero
    };
    CHECK_FALSE(is_utf16le_printable(non_ascii));

    const std::array<std::byte, 3> odd_len{
        std::byte{'h'}, std::byte{0x00}, std::byte{'i'},
    };
    CHECK_FALSE(is_utf16le_printable(odd_len));
}

TEST_CASE("string_utils: decode_utf16le_nul_trim handles ASCII and Latin-1") {
    const std::array<std::byte, 12> s{
        std::byte{'h'}, std::byte{0x00},
        std::byte{'e'}, std::byte{0x00},
        std::byte{'l'}, std::byte{0x00},
        std::byte{'l'}, std::byte{0x00},
        std::byte{'o'}, std::byte{0x00},
        // U+00E9 e-acute encoded as UTF-16LE 0xE9 0x00
        std::byte{0xE9}, std::byte{0x00},
    };
    auto r = decode_utf16le_nul_trim(s);
    REQUIRE(r.has_value());
    // U+00E9 in UTF-8 is 0xC3 0xA9
    CHECK(*r == std::string("hello\xC3\xA9"));
}

TEST_CASE("string_utils: decode_utf16le_nul_trim stops at NUL code unit") {
    const std::array<std::byte, 8> s{
        std::byte{'h'}, std::byte{0x00},
        std::byte{'i'}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},     // stop here
        std::byte{'X'}, std::byte{0x00},      // ignored
    };
    auto r = decode_utf16le_nul_trim(s);
    REQUIRE(r.has_value());
    CHECK(*r == "hi");
}

TEST_CASE("string_utils: decode_utf16le_nul_trim decodes a surrogate pair") {
    // U+1F600 GRINNING FACE: high D83D, low DE00
    // UTF-16LE bytes: 3D D8 00 DE
    const std::array<std::byte, 4> s{
        std::byte{0x3D}, std::byte{0xD8},
        std::byte{0x00}, std::byte{0xDE},
    };
    auto r = decode_utf16le_nul_trim(s);
    REQUIRE(r.has_value());
    // U+1F600 in UTF-8 is F0 9F 98 80
    CHECK(*r == std::string("\xF0\x9F\x98\x80"));
}

TEST_CASE("string_utils: decode_utf16le_nul_trim rejects unpaired surrogate") {
    const std::array<std::byte, 2> low_only{
        std::byte{0x00}, std::byte{0xDC},
    };
    auto r = decode_utf16le_nul_trim(low_only);
    CHECK_FALSE(r.has_value());

    const std::array<std::byte, 2> dangling_high{
        std::byte{0x3D}, std::byte{0xD8},
    };
    CHECK_FALSE(decode_utf16le_nul_trim(dangling_high).has_value());
}

TEST_CASE("string_utils: decode_utf16le_nul_trim rejects odd-length input") {
    const std::array<std::byte, 3> s{
        std::byte{'a'}, std::byte{0x00}, std::byte{'b'},
    };
    CHECK_FALSE(decode_utf16le_nul_trim(s).has_value());
}
