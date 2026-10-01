// MSVC: <ostream> must precede doctest so std::string pretty-printing compiles
#include <ostream>

#include "doctest.h"

#include "papa/constants.h"
#include "papa/pe/ordinal_names.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>
#include "pe_builder.h"

namespace {

[[nodiscard]] std::uint32_t u32_at(std::span<const std::byte> buf, std::size_t off) {
    std::uint32_t v = 0;
    std::memcpy(&v, buf.data() + off, sizeof v);
    return v;
}

}  // namespace

TEST_CASE("parse_file rejects a non-existent path") {
    const auto res = papa::pe::PeParser::parse_file("C:/does/not/exist/xxx.exe");
    CHECK_FALSE(res.has_value());
    CHECK(res.error().kind == papa::ErrorKind::kIoError);
}

TEST_CASE("parse_file reads an image from disk and rejects an empty file") {
    const auto dir = std::filesystem::temp_directory_path() / "papa_unit_parse_file";
    std::filesystem::create_directories(dir);
    papa_tests::PeBuilder b;
    b.code         = {0x90, 0xC3};
    b.entry_offset = 1;
    const auto bytes = b.build();
    {
        std::ofstream out(dir / "sample.exe", std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        std::ofstream empty(dir / "empty.exe", std::ios::binary);
    }

    const auto img = papa::pe::PeParser::parse_file(dir / "sample.exe");
    const auto empty = papa::pe::PeParser::parse_file(dir / "empty.exe");
    std::filesystem::remove_all(dir);

    REQUIRE(img.has_value());
    CHECK(img->raw_buffer().size() == bytes.size());
    CHECK(img->entry_point_rva() == papa_tests::PeBuilder::kTextRva + 1U);
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error().kind == papa::ErrorKind::kIoError);
}

TEST_CASE("parse rejects a buffer without MZ") {
    std::vector<std::byte> junk(128, std::byte{0x00});
    const auto res = papa::pe::PeParser::parse(std::move(junk));
    CHECK_FALSE(res.has_value());
    CHECK(res.error().kind == papa::ErrorKind::kNotPe);
}

TEST_CASE("pe_image: the bounded readers stay inside the file and its sections") {
    using papa_tests::PeBuilder;
    PeBuilder b;
    b.code           = std::vector<std::uint8_t>(0x10, 0x90);
    b.data           = std::vector<std::uint8_t>(0x10, 0x11);
    b.extra_sections = {
        {".bss2", std::vector<std::uint8_t>(0x10, 0xAB),
         PeBuilder::kScnInitializedData | PeBuilder::kScnRead, 0x2000},
        {".noread", {1, 2, 3, 4}, PeBuilder::kScnInitializedData, 0},
    };
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    // .text, an empty .rdata, .data, .bss2 and .noread
    REQUIRE(img->sections().size() == 5);
    const std::uint64_t text      = PeBuilder::kTextRva;
    const std::uint64_t bss       = b.section_rva(".bss2");
    const std::uint64_t file_size = img->raw_buffer().size();
    const std::uint64_t unmapped  = 0xF0000000U;

    enum class Reader { kRva, kFileOffset, kSection, kReadable, kProbe };
    struct Row {
        std::string_view label;
        Reader           reader;
        std::uint64_t    at;
        std::size_t      n;
        // bytes read or -1 when out of bounds, the section index or -1, the readable
        // count, or 1 when probe_readable holds
        std::int64_t     expected;
    };
    const std::vector<Row> rows{
        {"read the code", Reader::kRva, text, 4, 4},
        {"read past the image", Reader::kRva, img->size_of_image() + 0x10000U, 16, -1},
        {"read a header rva straight from the file", Reader::kRva, 0, 2, 2},
        {"read a section's zero fill", Reader::kRva, bss + 0x1000U, 1, -1},
        {"read past the end of the file", Reader::kFileOffset, file_size + 1U, 8, -1},
        {"read zero bytes at the end of the file", Reader::kFileOffset, file_size, 0, 0},
        {"read across the end of the file", Reader::kFileOffset, file_size - 1U, 2, -1},
        {"the entry point is in .text", Reader::kSection, img->entry_point_rva(), 0, 0},
        {"a header rva is in no section", Reader::kSection, 0x10, 0, -1},
        {"an unmapped rva is in no section", Reader::kSection, unmapped, 0, -1},
        {"a virtual tail belongs to its section", Reader::kSection, bss + 0x1FFFU, 0, 3},
        {"nothing is readable when unmapped", Reader::kReadable, unmapped, 0, 0},
        {"the code reads to its raw end", Reader::kReadable, text, 0, PeBuilder::kFileAlign},
        {"the last raw byte reads alone", Reader::kReadable, text + PeBuilder::kFileAlign - 1U,
         0, 1},
        {"a header rva reads to the end of the file", Reader::kReadable, 0x10, 0,
         static_cast<std::int64_t>(file_size) - 0x10},
        {"a zero fill reads nothing", Reader::kReadable, bss + 0x1000U, 0, 0},
        {"probe inside the code", Reader::kProbe, text, 4, 1},
        {"probe up to the raw end", Reader::kProbe, text + PeBuilder::kFileAlign - 4U, 4, 1},
        {"probe across the raw end", Reader::kProbe, text + PeBuilder::kFileAlign - 3U, 4, 0},
        {"probe a section without read access", Reader::kProbe, b.section_rva(".noread"), 1, 0},
        {"probe an unmapped rva", Reader::kProbe, unmapped, 1, 0},
        {"probe a length that wraps", Reader::kProbe, text,
         std::numeric_limits<std::size_t>::max(), 0},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        std::int64_t got = 0;
        switch (row.reader) {
            case Reader::kRva:
            case Reader::kFileOffset: {
                const auto r = row.reader == Reader::kRva
                                   ? img->read_at_rva(row.at, row.n)
                                   : img->read_at_file_offset(row.at, row.n);
                if (r.has_value()) {
                    got = static_cast<std::int64_t>(r->size());
                } else {
                    CHECK(r.error().kind == papa::ErrorKind::kOutOfBounds);
                    got = -1;
                }
                break;
            }
            case Reader::kSection: {
                const auto* s = img->section_containing_rva(row.at);
                got = s == nullptr ? -1 : s - img->sections().data();
                break;
            }
            case Reader::kReadable:
                got = static_cast<std::int64_t>(img->readable_bytes_at_rva(row.at));
                break;
            case Reader::kProbe:
                got = img->probe_readable(row.at, row.n) ? 1 : 0;
                break;
        }
        CHECK(got == row.expected);
    }
}

TEST_CASE("normalize_dll_name lowercases and strips known extensions") {
    using papa::pe::normalize_dll_name;
    CHECK(normalize_dll_name("KERNEL32.DLL") == "kernel32");
    CHECK(normalize_dll_name("kernel32.dll") == "kernel32");
    CHECK(normalize_dll_name("WS2_32.DLL")   == "ws2_32");
    CHECK(normalize_dll_name("driver.drv")   == "driver");
    CHECK(normalize_dll_name("libc.so")      == "libc");
    // Unknown extension is preserved
    CHECK(normalize_dll_name("Mod.exe")      == "mod.exe");
    // No extension
    CHECK(normalize_dll_name("KERNEL32")     == "kernel32");
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

TEST_CASE("parse names the ordinal imports of a 32-bit image the ordinal table knows") {
    papa_tests::PeBuilder b;
    b.x64     = false;
    b.code    = {0xC3};
    b.imports = {
        {"WS2_32.dll", {"#6", "#9999"}},
        {"wsock32.dll", {"#1"}},
        {"kernel32.dll", {"#6", "ExitProcess"}},
    };
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());

    struct Row {
        std::string_view dll_spec;
        std::string_view fn_spec;
        std::string_view dll;
        std::string_view name;
        std::uint32_t    ordinal;
        bool             by_ordinal;
    };
    const std::vector<Row> rows{
        {"WS2_32.dll", "#6", "ws2_32", "getsockname", 6, false},
        {"WS2_32.dll", "#9999", "ws2_32", "", 9999, true},
        {"wsock32.dll", "#1", "wsock32", "accept", 1, false},
        {"kernel32.dll", "#6", "kernel32", "", 6, true},
        {"kernel32.dll", "ExitProcess", "kernel32", "ExitProcess", 0, false},
    };
    const auto imps = img->imports();
    REQUIRE(imps.size() == rows.size());
    for (std::size_t i = 0; i < rows.size(); ++i) {
        CAPTURE(rows[i].fn_spec);
        CHECK(imps[i].dll == rows[i].dll);
        CHECK(imps[i].name == rows[i].name);
        CHECK(imps[i].ordinal == rows[i].ordinal);
        CHECK(imps[i].by_ordinal == rows[i].by_ordinal);
        CHECK(imps[i].iat_va == b.iat_va(rows[i].dll_spec, rows[i].fn_spec));
    }
}

TEST_CASE("parse keeps every base relocation with its block padding, and the sites hold the pointers") {
    papa_tests::PeBuilder b;
    b.x64 = false;
    b.code.assign(0x1100, 0x90);
    // Three sites on the first code page and one on the second, so each block is padded
    // with an ABSOLUTE entry
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> sites{
        {0x0010, 0x40}, {0x0020, 0x50}, {0x0030, 0x60}, {0x1004, 0x1080}};
    for (const auto& [site, target] : sites) {
        b.reloc_code_offsets.push_back(site);
        papa_tests::detail::poke(b.code, site, static_cast<std::uint32_t>(b.code_va(target)));
    }
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());

    const std::vector<std::pair<std::uint32_t, std::uint32_t>> expected{
        {0x1010, 3}, {0x1020, 3}, {0x1030, 3}, {0x1000, 0}, {0x2004, 3}, {0x2000, 0}};
    std::vector<std::pair<std::uint32_t, std::uint32_t>> got;
    for (const papa::pe::ParsedRelocation& r : img->relocations()) {
        got.emplace_back(r.rva, r.type);
    }
    CHECK(got == expected);

    for (const auto& [site, target] : sites) {
        CAPTURE(site);
        const auto slot = img->read_at_rva(papa_tests::PeBuilder::kTextRva + site, 4);
        REQUIRE(slot.has_value());
        CHECK(u32_at(*slot, 0) == b.code_va(target));
    }
}

TEST_CASE("a crafted export count cannot drive a huge allocation") {
    papa_tests::PeBuilder b;
    b.code    = {0x33, 0xC0, 0xC3, 0xCC, 0x33, 0xC0, 0xC3};
    b.exports = {{"First", 0x00, ""}, {"Second", 0x04, ""}};
    auto       bytes  = b.build();
    const auto honest = papa::pe::PeParser::parse(bytes);
    REQUIRE(honest.has_value());
    REQUIRE(honest->exports().size() == 2);

    // NumberOfFunctions and NumberOfNames sit at +0x14 and +0x18 of the export directory
    const std::uint32_t dir_rva = u32_at(bytes, b.header_layout().data_directory(0));
    const auto          dir     = honest->rva_to_file_offset(dir_rva);
    REQUIRE(dir.has_value());
    std::memset(bytes.data() + *dir + 0x14U, 0xFF, 8);
    const auto crafted = papa::pe::PeParser::parse(bytes);
    REQUIRE(crafted.has_value());

    // The count is clamped to the function slots .rdata actually holds, so every
    // non-zero dword from AddressOfFunctions to the end of its raw data is an export
    const auto*         rdata     = honest->section_containing_rva(dir_rva);
    REQUIRE(rdata != nullptr);
    const auto          functions = honest->rva_to_file_offset(u32_at(bytes, *dir + 0x1CU));
    REQUIRE(functions.has_value());
    std::size_t nonzero = 0;
    for (std::size_t off = *functions; off + 4U <= rdata->raw_offset + rdata->raw_size;
         off += 4U) {
        nonzero += u32_at(bytes, off) != 0U ? 1U : 0U;
    }
    CHECK(crafted->exports().size() == nonzero);
    REQUIRE(crafted->exports().size() > 2);
    CHECK(crafted->exports()[0].va == b.code_va(0x00));
    CHECK(crafted->exports()[1].va == b.code_va(0x04));
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
