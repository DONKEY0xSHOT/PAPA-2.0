#include <ostream>

#include "doctest.h"

#include "papa/constants.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <string_view>
#include "fixture_paths.h"

namespace {

// Paths to stock binaries used as parser fixtures
const auto kNotepad = papa_tests::fixture_path("notepad.exe");
const auto kChrome = papa_tests::fixture_path("chrome.exe");
const auto kCff = papa_tests::fixture_path("CFF Explorer.exe");
const auto kCapa = papa_tests::fixture_path("capa.exe");

[[nodiscard]] bool has_section(const papa::pe::PeImage& img, std::string_view name) {
    const auto secs = img.sections();
    return std::any_of(secs.begin(), secs.end(),
        [&](const papa::pe::ParsedSection& s) { return s.name == name; });
}

[[nodiscard]] bool has_import_from(const papa::pe::PeImage& img, std::string_view dll) {
    const auto imps = img.imports();
    return std::any_of(imps.begin(), imps.end(),
        [&](const papa::pe::ParsedImport& p) { return p.dll == dll; });
}

}  // namespace

TEST_CASE("parse_file rejects a non-existent path") {
    const auto res = papa::pe::PeParser::parse_file("C:/does/not/exist/xxx.exe");
    CHECK_FALSE(res.has_value());
    CHECK(res.error().kind == papa::ErrorKind::kIoError);
}

TEST_CASE("parse rejects a buffer without MZ") {
    std::vector<std::byte> junk(128, std::byte{0x00});
    const auto res = papa::pe::PeParser::parse(std::move(junk));
    CHECK_FALSE(res.has_value());
    CHECK(res.error().kind == papa::ErrorKind::kNotPe);
}

TEST_CASE("parses notepad.exe and enumerates headers") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    const auto& img = *res;

    CHECK(img.machine() == papa::constants::kImageFileMachineAmd64);
    CHECK(img.is_64bit());
    CHECK(img.image_base() != 0);
    CHECK(img.entry_point_rva() != 0);
    CHECK(img.size_of_image() > 0);
    CHECK(img.sections().size() > 0);
    CHECK(has_section(img, ".text"));
    CHECK(has_import_from(img, "kernel32"));
}

TEST_CASE("parses chrome.exe") {
    if (!std::filesystem::exists(kChrome)) {
        MESSAGE("fixture missing: " << kChrome);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kChrome);
    REQUIRE(res.has_value());
    const auto& img = *res;

    CHECK(img.size_of_image() > 0);
    CHECK(img.sections().size() > 0);
    CHECK(has_section(img, ".text"));
}

TEST_CASE("parses CFF Explorer.exe") {
    if (!std::filesystem::exists(kCff)) {
        MESSAGE("fixture missing: " << kCff);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kCff);
    REQUIRE(res.has_value());
    const auto& img = *res;

    CHECK(img.sections().size() > 0);
}

TEST_CASE("parses capa.exe") {
    if (!std::filesystem::exists(kCapa)) {
        MESSAGE("fixture missing: " << kCapa);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kCapa);
    REQUIRE(res.has_value());
    const auto& img = *res;

    CHECK(img.sections().size() > 0);
    CHECK(img.size_of_image() > 0);
}

TEST_CASE("read_at_rva rejects out-of-bounds access") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    const auto& img = *res;

    const std::uint64_t huge_rva = std::uint64_t{img.size_of_image()} + 0x10000ULL;
    const auto oob = img.read_at_rva(huge_rva, 16);
    CHECK_FALSE(oob.has_value());
    CHECK(oob.error().kind == papa::ErrorKind::kOutOfBounds);
}

TEST_CASE("read_at_file_offset rejects out-of-bounds access") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    const auto& img = *res;

    const std::uint64_t past_eof = img.raw_buffer().size() + 1;
    const auto oob = img.read_at_file_offset(past_eof, 8);
    CHECK_FALSE(oob.has_value());
    CHECK(oob.error().kind == papa::ErrorKind::kOutOfBounds);
}

TEST_CASE("read_at_file_offset zero-size at end is allowed") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    const auto& img = *res;

    const auto ok = img.read_at_file_offset(img.raw_buffer().size(), 0);
    CHECK(ok.has_value());
    CHECK(ok->size() == 0);
}

TEST_CASE("section_containing_rva maps entry point back to a section") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    const auto& img = *res;

    const auto* s = img.section_containing_rva(img.entry_point_rva());
    REQUIRE(s != nullptr);
    CHECK((s->characteristics & papa::constants::kImageScnMemRead) != 0);
}

TEST_CASE("imports carry lowercased dll names with no extension") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    const auto& img = *res;

    for (const auto& imp : img.imports()) {
        CHECK_FALSE(imp.dll.empty());
        // lowercase
        for (char c : imp.dll) {
            CHECK((c < 'A' || c > 'Z'));
        }
        // extension stripped
        CHECK(imp.dll.find(".dll") == std::string::npos);
        CHECK(imp.dll.find(".drv") == std::string::npos);
    }
}
