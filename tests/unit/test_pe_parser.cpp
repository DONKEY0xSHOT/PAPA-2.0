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
#include <vector>
#include "fixture_paths.h"
#include "pe_builder.h"

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
    // wsock32.dll shares the ws2_32 table in vivisect's ordlookup
    CHECK(lookup_ordinal_name("wsock32", 6) == "getsockname");
    // A DLL not in the database, or an unknown ordinal, stays unresolved
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

    // Everything imports ws2_32 by ordinal
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

    // Faithful to vivisect PE.getRelocations: every base-relocation entry is retained,
    // including the type-0 ABSOLUTE block padding
    std::size_t highlow = 0;
    std::size_t absolute = 0;
    for (const auto& r : relocs) {
        if (r.type == 3) { ++highlow; }
        else if (r.type == 0) { ++absolute; }
    }
    CHECK(highlow == 25697);
    CHECK(absolute == 159);

    // The three socket-island entry pointers are stored at reloc sites inside .text.
    // Each site is a HIGHLOW fixup whose stored dword is an island function entry
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

TEST_CASE("readable_bytes_at_rva is bounded by the file and the section's raw data") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    const auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    const papa::pe::PeImage& img = *res;

    // An unmapped RVA supplies nothing
    CHECK(img.readable_bytes_at_rva(0xF0000000u) == 0);

    // Inside a real section the answer is non-zero and never exceeds the file
    const auto secs = img.sections();
    REQUIRE_FALSE(secs.empty());
    const papa::pe::ParsedSection& text = secs.front();
    const std::size_t avail = img.readable_bytes_at_rva(text.virtual_address);
    CHECK(avail > 0);
    CHECK(avail <= img.raw_buffer().size());
    // and it stops at the end of that section's raw bytes
    CHECK(avail <= text.raw_size);

    // One byte before the section's raw end supplies exactly one byte
    const std::uint64_t last_rva =
        std::uint64_t{text.virtual_address} + text.raw_size - 1U;
    CHECK(img.readable_bytes_at_rva(last_rva) == 1U);
}

TEST_CASE("a crafted export count cannot drive a huge allocation") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    const auto base = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(base.has_value());
    const std::size_t honest_exports = base->exports().size();

    // Locate the export directory by walking the headers, then overwrite.
    // NumberOfFunctions and NumberOfNames with 0xFFFFFFFF
    const auto src = base->raw_buffer();
    const auto read_u32_at = [&src](std::size_t off) -> std::uint32_t {
        std::uint32_t v = 0;
        std::memcpy(&v, src.data() + off, sizeof(v));
        return v;
    };
    const std::uint32_t e_lfanew = read_u32_at(0x3CU);
    const std::size_t   opt_off  = std::size_t{e_lfanew} + 4U + 20U;
    std::uint16_t       magic    = 0;
    std::memcpy(&magic, src.data() + opt_off, sizeof(magic));
    // The export directory is entry 0 of the data-directory array, which follows
    // the optional header (0x60 into it for PE32, 0x70 for PE32+)
    const std::size_t   dd_off  = opt_off + (magic == 0x20BU ? 0x70U : 0x60U);
    const std::uint32_t dd_rva  = read_u32_at(dd_off);
    if (dd_rva == 0) {
        MESSAGE("fixture has no export directory, skipping");
        return;
    }
    const auto dir_off = base->rva_to_file_offset(dd_rva);
    REQUIRE(dir_off.has_value());

    std::vector<std::byte> buf(src.begin(), src.end());
    // IMAGE_EXPORT_DIRECTORY: NumberOfFunctions at +0x14, NumberOfNames at +0x18
    const std::size_t     n_funcs_off = static_cast<std::size_t>(*dir_off) + 0x14U;
    REQUIRE(n_funcs_off + 8U <= buf.size());
    for (std::size_t i = 0; i < 8U; ++i) {
        buf[n_funcs_off + i] = std::byte{0xFFU};
    }

    const auto crafted = papa::pe::PeParser::parse(std::move(buf));
    REQUIRE(crafted.has_value());
    // The clamp holds the list to what the image can actually supply, so the
    // parse stays bounded rather than attempting a multi-gigabyte allocation
    CHECK(crafted->exports().size() <= papa::constants::kMaxExportsPerImage);
    CHECK(crafted->exports().size() <=
          crafted->raw_buffer().size() / sizeof(std::uint32_t));
    CHECK(crafted->exports().size() >= honest_exports);
}

TEST_CASE("a crafted section count cannot drive a huge allocation") {
    // NumberOfSections is a raw 16-bit header field
    papa_tests::PeBuilder b;
    b.code = std::vector<std::uint8_t>{0xC3};
    std::vector<std::byte> buf = b.build();

    std::uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, buf.data() + 0x3CU, sizeof(e_lfanew));
    // IMAGE_FILE_HEADER follows the 4-byte signature, NumberOfSections at +2
    const std::size_t n_sections_off = std::size_t{e_lfanew} + 4U + 2U;
    REQUIRE(n_sections_off + 2U <= buf.size());
    buf[n_sections_off]      = std::byte{0xFFU};
    buf[n_sections_off + 1U] = std::byte{0xFFU};

    // Either the truncated table is rejected or the clamp holds the list to something
    // the image could plausibly supply
    const auto crafted = papa::pe::PeParser::parse(std::move(buf));
    if (crafted.has_value()) {
        CHECK(crafted->sections().size() <= papa::constants::kMaxSectionsPerImage);
    }
}

TEST_CASE("a real image maps far below the discovery emulator byte budget") {
    // The budget only exists to stop a crafted section table asking for far more than
    // the sample occupies, so a well-formed image has to sit well under it
    papa_tests::PeBuilder b;
    b.code = std::vector<std::uint8_t>{0x48, 0x31, 0xC0, 0xC3};
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());

    std::size_t declared = 0;
    for (const auto& s : img->sections()) {
        declared += s.raw_size;
    }
    CHECK(declared < papa::constants::kMaxEmuImageBytes);
    CHECK(declared <= img->raw_buffer().size());
}
