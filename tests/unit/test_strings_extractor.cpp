#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/strings.h"

#include "papa/constants.h"

#include "test_support.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using papa::features::extractors::strings::ExtractedString;
using papa::features::extractors::strings::extract_ascii_strings;
using papa::features::extractors::strings::extract_unicode_strings;
using papa::features::extractors::strings::is_in_repeat_fill_region;

namespace {

// The strings an extractor is expected to return, in order
struct Found {
    std::string_view value;
    std::uint64_t    offset;
};

void check_found(const std::vector<ExtractedString>& got, const std::vector<Found>& want) {
    CHECK(got.size() == want.size());
    for (std::size_t i = 0; i < got.size() && i < want.size(); ++i) {
        CAPTURE(i);
        CHECK(got[i].value == want[i].value);
        CHECK(got[i].offset == want[i].offset);
    }
}

[[nodiscard]] std::vector<std::byte> bytes_of(std::string_view text) {
    const auto view = papa_tests::text_bytes(text);
    return {view.begin(), view.end()};
}

}  // namespace

TEST_CASE("strings: extract_ascii_strings returns each printable run of at least min_len outside fill regions") {
    struct Row {
        std::string_view           label;
        std::vector<std::byte>     buf;
        std::optional<std::size_t> min_len;
        std::vector<Found>         found;
    };
    const std::vector<Row> rows{
        // "ab" is below the default min length of 4
        {"runs above the default min_len",
         bytes_of(std::string_view{"\x01HelloWorld\x00" "ab\x00Greetings", 24}), std::nullopt,
         {{"HelloWorld", 1}, {"Greetings", 15}}},
        {"a custom minimum length", bytes_of(std::string_view{"\x00" "abc\x00", 5}), 3,
         {{"abc", 1}}},
        {"a trailing run at the end of the buffer",
         bytes_of(std::string_view{"\x00" "TailString", 11}), std::nullopt, {{"TailString", 1}}},
        // The buffer is uniform 'A', so every window centered on a run holds only 0x41
        {"runs in a fill region are suppressed", std::vector<std::byte>(4096, std::byte{0x41}), 4,
         {}},
        {"an empty input", {}, std::nullopt, {}},
        {"a zero min_len", bytes_of("hi"), 0, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        check_found(row.min_len.has_value() ? extract_ascii_strings(row.buf, *row.min_len)
                                            : extract_ascii_strings(row.buf),
                    row.found);
    }
}

TEST_CASE("strings: extract_unicode_strings decodes 2-byte-aligned UTF-16LE runs and stops at a non-printable unit") {
    struct Row {
        std::string_view       label;
        std::vector<std::byte> buf;
        std::vector<Found>     found;
    };
    const std::vector<Row> rows{
        {"an aligned run", bytes_of(std::string_view{"H\0e\0l\0l\0o\0", 10}), {{"Hello", 0}}},
        {"a NUL code unit ends a run",
         bytes_of(std::string_view{"A\0B\0C\0D\0\0\0X\0Y\0Z\0" "1\0", 18}),
         {{"ABCD", 0}, {"XYZ1", 10}}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        check_found(extract_unicode_strings(row.buf), row.found);
    }
}

TEST_CASE("strings: is_in_repeat_fill_region holds only on a window of one repeated 0x00 or 0xFF byte") {
    struct Row {
        std::string_view label;
        std::byte        fill;
        bool             poke;
        std::uint64_t    offset;
        bool             in_fill;
    };
    const std::vector<Row> rows{
        {"an all-zero window", std::byte{0x00}, false, 1024, true},
        {"an all-FF window at the start", std::byte{0xFF}, false, 0, true},
        {"an all-FF window at the end", std::byte{0xFF}, false, 4095, true},
        // An 'X' at 1000 sits inside the window around 1024
        {"a mixed window", std::byte{0x00}, true, 1024, false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        std::vector<std::byte> buf(4096, row.fill);
        if (row.poke) { buf[1000] = std::byte{'X'}; }
        CHECK(is_in_repeat_fill_region(buf, row.offset) == row.in_fill);
    }
}
