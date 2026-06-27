// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the PAPA authors

// MSVC: <ostream> must precede doctest so std::string pretty-printing compiles
#include <ostream>

#include "doctest.h"

#include "papa/constants.h"
#include "papa/pe/ordinal_names.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include "fixture_paths.h"

namespace {

// Paths to stock binaries used as parser fixtures
const auto kNotepad = papa_tests::fixture_path("notepad.exe");
const auto kChrome = papa_tests::fixture_path("chrome.exe");
const auto kCff = papa_tests::fixture_path("CFF Explorer.exe");
const auto kCapa = papa_tests::fixture_path("capa.exe");
const auto kEverything = papa_tests::fixture_path("Everything.exe");

[[nodiscard]] std::optional<std::uint32_t> read_u32_at_rva(
    const papa::pe::PeImage& img, std::uint64_t rva) {
    auto bytes = img.read_at_rva(rva, sizeof(std::uint32_t));
    if (!bytes) { return std::nullopt; }
    std::uint32_t value = 0;
    std::memcpy(&value, bytes->data(), sizeof(value));
    return value;
}

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

TEST_CASE("lookup_ordinal_name resolves ws2_32 ordinals like vivisect ordlookup") {
    using papa::pe::lookup_ordinal_name;
    CHECK(lookup_ordinal_name("ws2_32", 6) == "getsockname");
    CHECK(lookup_ordinal_name("ws2_32", 1) == "accept");
    CHECK(lookup_ordinal_name("ws2_32", 115) == "WSAStartup");
    // wsock32.dll shares the ws2_32 table in vivisect's ordlookup.
    CHECK(lookup_ordinal_name("wsock32", 6) == "getsockname");
    // A DLL not in the database, or an unknown ordinal, stays unresolved.
    CHECK_FALSE(lookup_ordinal_name("kernel32", 6).has_value());
    CHECK_FALSE(lookup_ordinal_name("ws2_32", 99999).has_value());
}

TEST_CASE("parses Everything.exe and resolves ws2_32 ordinal imports to names") {
    if (!std::filesystem::exists(kEverything)) {
        MESSAGE("fixture missing: " << kEverything);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kEverything);
    REQUIRE(res.has_value());
    const auto& img = *res;

    // Everything imports ws2_32 by ordinal. vivisect's ordlookup names #6
    // getsockname, so papa must resolve it (and clear by_ordinal) for the
    // get-local-IPv4 rule's `api: getsockname` to match.
    const auto imps = img.imports();
    const bool has_getsockname = std::any_of(imps.begin(), imps.end(),
        [](const papa::pe::ParsedImport& p) {
            return p.dll == "ws2_32" && p.name == "getsockname" && !p.by_ordinal;
        });
    CHECK(has_getsockname);
}

TEST_CASE("parses Everything.exe base relocations including the .text island pointers") {
    if (!std::filesystem::exists(kEverything)) {
        MESSAGE("fixture missing: " << kEverything);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kEverything);
    REQUIRE(res.has_value());
    const auto& img = *res;

    CHECK_FALSE(img.is_64bit());
    CHECK(img.image_base() == 0x400000ULL);

    const auto relocs = img.relocations();
    REQUIRE_FALSE(relocs.empty());

    // Faithful to vivisect PE.getRelocations: every base-relocation entry is
    // retained, including the type-0 ABSOLUTE block padding. Everything.exe
    // carries 25697 HIGHLOW fixups plus 159 ABSOLUTE padding entries.
    std::size_t highlow = 0;
    std::size_t absolute = 0;
    for (const auto& r : relocs) {
        if (r.type == 3) { ++highlow; }
        else if (r.type == 0) { ++absolute; }
    }
    CHECK(highlow == 25697);
    CHECK(absolute == 159);

    // The three socket-island entry pointers are stored at reloc SITES inside
    // .text (RVAs 0x925f0 / 0x9539c / 0x95b14). A data-only pointer scan skips
    // .text, which is why the island is unrecovered. Each site is a HIGHLOW
    // fixup whose stored dword is an island function entry.
    struct SiteExpectation {
        std::uint32_t rva;
        std::uint32_t value;
    };
    constexpr std::array<SiteExpectation, 3> kIslandSites{{
        {0x925f0u, 0x00492230u},
        {0x9539cu, 0x00493d20u},
        {0x95b14u, 0x00493570u},
    }};
    for (const auto& site : kIslandSites) {
        const bool present = std::any_of(relocs.begin(), relocs.end(),
            [&](const papa::pe::ParsedRelocation& r) {
                return r.rva == site.rva && r.type == 3;
            });
        CHECK(present);
        const auto dword = read_u32_at_rva(img, site.rva);
        REQUIRE(dword.has_value());
        CHECK(*dword == site.value);
    }
}
