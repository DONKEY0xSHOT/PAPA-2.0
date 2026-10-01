#include <ostream>

#include "doctest.h"

#include "papa/util/string_utils.h"

#include "test_support.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using papa::util::is_ascii_printable;
using papa::util::is_utf16le_printable;
using papa::util::to_lower_ascii;

TEST_CASE("string_utils: to_lower_ascii lowercases ASCII letters only") {
    CHECK(to_lower_ascii("Hello, WORLD") == "hello, world");
    CHECK(to_lower_ascii("") == "");
    // High bytes pass through unchanged so UTF-8 is safe
    CHECK(to_lower_ascii(std::string("caf\xC3\x89")) == std::string("caf\xC3\x89"));
}

TEST_CASE("string_utils: is_ascii_printable accepts printable bytes and tab, and strings made only of them") {
    // Newline, NUL and high bytes are not printable for our purposes
    struct Row {
        std::string_view label;
        std::string_view text;
        bool             printable;
    };
    const std::vector<Row> rows{
        {"a space", " ", true},
        {"a letter", "A", true},
        {"a tilde", "~", true},
        {"a tab", "\t", true},
        {"a newline", "\n", false},
        {"a NUL", std::string_view{"\0", 1}, false},
        {"0xFF", "\xFF", false},
        {"an empty string", "", true},
        {"a printable string", "Hello, World!", true},
        {"a string ending in NUL", std::string_view{"hi\0", 3}, false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(is_ascii_printable(row.text) == row.printable);
        if (row.text.size() == 1) {
            CHECK(is_ascii_printable(static_cast<std::uint8_t>(row.text[0])) == row.printable);
        }
    }
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
