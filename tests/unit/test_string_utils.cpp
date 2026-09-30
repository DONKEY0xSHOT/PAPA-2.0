#include <ostream>

#include "doctest.h"

#include "papa/util/string_utils.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

using papa::util::is_ascii_printable;
using papa::util::is_utf16le_printable;
using papa::util::to_lower_ascii;

TEST_CASE("string_utils: to_lower_ascii lowercases ASCII letters only") {
    CHECK(to_lower_ascii("Hello, WORLD") == "hello, world");
    CHECK(to_lower_ascii("") == "");
    // High bytes pass through unchanged so UTF-8 is safe
    CHECK(to_lower_ascii(std::string("caf\xC3\x89")) == std::string("caf\xC3\x89"));
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
