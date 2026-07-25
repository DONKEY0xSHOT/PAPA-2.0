#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/strings.h"

#include "papa/constants.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using papa::features::extractors::strings::ExtractedString;
using papa::features::extractors::strings::extract_ascii_strings;
using papa::features::extractors::strings::extract_unicode_strings;
using papa::features::extractors::strings::is_in_repeat_fill_region;

namespace {

[[nodiscard]] std::span<const std::byte> as_bytes(const std::string& s) {
    return std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(s.data()), s.size());
}

[[nodiscard]] bool contains_value(const std::vector<ExtractedString>& v, std::string_view s) {
    return std::any_of(v.begin(), v.end(),
        [&](const ExtractedString& e) { return e.value == s; });
}

}  // namespace

TEST_CASE("strings: extract_ascii_strings finds runs above min_len") {
    const std::string buf = std::string("\x01HelloWorld\x00", 12) + "ab" + std::string("\x00Greetings", 10);
    auto found = extract_ascii_strings(as_bytes(buf));
    CHECK(contains_value(found, "HelloWorld"));
    CHECK(contains_value(found, "Greetings"));
    // "ab" is below the default min length of 4
    CHECK_FALSE(contains_value(found, "ab"));
}

TEST_CASE("strings: extract_ascii_strings honors a custom minimum length") {
    const std::string buf = std::string("\x00", 1) + "abc" + std::string("\x00", 1);
    auto found = extract_ascii_strings(as_bytes(buf), 3);
    REQUIRE(found.size() == 1);
    CHECK(found[0].value == "abc");
    CHECK(found[0].offset == 1);
}

TEST_CASE("strings: extract_ascii_strings recovers a trailing run at EOB") {
    const std::string buf = std::string("\x00prefix") + "TailString";
    auto found = extract_ascii_strings(as_bytes(buf));
    CHECK(contains_value(found, "TailString"));
}

TEST_CASE("strings: extract_unicode_strings decodes UTF-16LE") {
    std::vector<std::byte> buf;
    // 'X' to delimit
    buf.push_back(std::byte{0x01});
    // "Hi" in UTF-16LE
    buf.push_back(std::byte{'H'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'e'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'l'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'l'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'o'}); buf.push_back(std::byte{0x00});
    auto found = extract_unicode_strings(buf);
    // The leading 0x01 byte misaligns the run start by one
    // The extractor walks in 2-byte steps from byte 0, so the run is found at 1
    // No printable pair forms there, so we instead expect zero or one matches
    // Re-test with an aligned buffer:
    std::vector<std::byte> aligned;
    aligned.push_back(std::byte{'H'}); aligned.push_back(std::byte{0x00});
    aligned.push_back(std::byte{'e'}); aligned.push_back(std::byte{0x00});
    aligned.push_back(std::byte{'l'}); aligned.push_back(std::byte{0x00});
    aligned.push_back(std::byte{'l'}); aligned.push_back(std::byte{0x00});
    aligned.push_back(std::byte{'o'}); aligned.push_back(std::byte{0x00});
    auto found2 = extract_unicode_strings(aligned);
    REQUIRE(found2.size() == 1);
    CHECK(found2[0].value == "Hello");
    CHECK(found2[0].offset == 0);
}

TEST_CASE("strings: extract_unicode_strings stops at non-printable code unit") {
    std::vector<std::byte> buf;
    buf.push_back(std::byte{'A'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'B'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'C'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'D'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x00}); buf.push_back(std::byte{0x00});  // NUL terminator
    buf.push_back(std::byte{'X'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'Y'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'Z'}); buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{'1'}); buf.push_back(std::byte{0x00});
    auto found = extract_unicode_strings(buf);
    REQUIRE(found.size() == 2);
    CHECK(found[0].value == "ABCD");
    CHECK(found[1].value == "XYZ1");
}

TEST_CASE("strings: is_in_repeat_fill_region detects all-zero windows") {
    std::vector<std::byte> buf(4096, std::byte{0x00});
    CHECK(is_in_repeat_fill_region(buf, 1024));
}

TEST_CASE("strings: is_in_repeat_fill_region detects all-FF windows") {
    std::vector<std::byte> buf(4096, std::byte{0xFF});
    CHECK(is_in_repeat_fill_region(buf, 0));
    CHECK(is_in_repeat_fill_region(buf, 4095));
}

TEST_CASE("strings: is_in_repeat_fill_region rejects mixed windows") {
    std::vector<std::byte> buf(4096, std::byte{0x00});
    buf[1000] = std::byte{'X'};
    CHECK_FALSE(is_in_repeat_fill_region(buf, 1024));
}

TEST_CASE("strings: extract_ascii suppresses runs in fill regions") {
    // Build a buffer that is mostly 0x41 padding
    // The printable run inside is suppressed
    std::vector<std::byte> buf(4096, std::byte{0x41});
    // The buffer is uniform 'A' so any printable run would normally trigger
    // But the entire window centered on any offset contains only 0x41
    auto found = extract_ascii_strings(buf, 4);
    CHECK(found.empty());
}

TEST_CASE("strings: extract_ascii_strings rejects empty inputs and zero min_len") {
    auto found = extract_ascii_strings(std::span<const std::byte>{});
    CHECK(found.empty());
    std::vector<std::byte> buf{std::byte{'h'}, std::byte{'i'}};
    auto none = extract_ascii_strings(buf, 0);
    CHECK(none.empty());
}
