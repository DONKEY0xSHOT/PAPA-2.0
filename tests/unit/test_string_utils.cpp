#include <ostream>

#include "doctest.h"

#include "papa/util/string_utils.h"

#include "test_support.h"

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
    const auto hello = papa_tests::bytes('h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00);
    CHECK(is_utf16le_printable(hello));

    // The second unit's high byte is non-zero
    const auto non_ascii = papa_tests::bytes('h', 0x00, 0x00, 0x01);
    CHECK_FALSE(is_utf16le_printable(non_ascii));

    const auto odd_len = papa_tests::bytes('h', 0x00, 'i');
    CHECK_FALSE(is_utf16le_printable(odd_len));
}
