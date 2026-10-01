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
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string>
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

template <typename T>
void put(std::vector<std::byte>& buf, std::size_t off, T value) {
    std::memcpy(buf.data() + off, &value, sizeof value);
}

// An image with every structure the parser walks: named and ordinal imports, a delay
// import, exports with a forwarder, a TLS callback, a relocation and, on x64, .pdata
[[nodiscard]] papa_tests::PeBuilder rich_builder(bool x64) {
    papa_tests::PeBuilder b;
    b.x64 = x64;
    const std::uint32_t first  = b.add_function({0x33, 0xC0, 0xC3});
    const std::uint32_t second = b.add_function({0x90, 0xC3});
    // A pointer slot holding the first function's address, listed for relocation
    const auto slot = static_cast<std::uint32_t>(b.code.size());
    b.code.resize(b.code.size() + 8U, 0);
    if (x64) {
        papa_tests::detail::poke(b.code, slot, b.code_va(first));
    } else {
        papa_tests::detail::poke(b.code, slot, static_cast<std::uint32_t>(b.code_va(first)));
    }
    b.reloc_code_offsets = {slot};
    b.entry_offset       = second;
    b.imports            = {{"KERNEL32.dll", {"ExitProcess", "GetTickCount"}},
                            {"ws2_32.dll", {"#6"}}};
    b.delay_imports      = {{"user32.dll", {"MessageBoxA"}}};
    b.exports            = {{"First", first, ""},
                            {"Second", second, ""},
                            {"Forwarded", 0, "ntdll.RtlAllocateHeap"}};
    b.tls_callbacks      = {second};
    b.data               = {1, 2, 3, 4};
    return b;
}

// A rich image, its header layout, its bytes and their honest parse
struct Sample {
    papa_tests::PeBuilder             builder;
    papa_tests::HeaderLayout          layout;
    std::vector<std::byte>            bytes;
    papa::Expected<papa::pe::PeImage> honest;

    explicit Sample(bool x64)
        : builder(rich_builder(x64)),
          layout(builder.header_layout()),
          bytes(builder.build()),
          honest(papa::pe::PeParser::parse(bytes)) {}

    /// File offset of the structure that data directory index points at
    [[nodiscard]] std::size_t dir_offset(std::size_t index) const {
        const auto off = honest->rva_to_file_offset(u32_at(bytes, layout.data_directory(index)));
        REQUIRE(off.has_value());
        return static_cast<std::size_t>(*off);
    }
};

// The first way the readers of an image serve bytes outside its own buffer, or past
// what readable_bytes_at_rva promises, and empty when they never do
[[nodiscard]] std::string reader_violation(const papa::pe::PeImage& img) {
    const auto buf = img.raw_buffer();
    for (const papa::pe::ParsedSection& s : img.sections()) {
        const std::size_t n = img.readable_bytes_at_rva(s.virtual_address);
        if (n > 0U) {
            const auto run = img.read_at_rva(s.virtual_address, n);
            if (!run.has_value()) { return s.name + " does not read its readable bytes"; }
            if (run->data() < buf.data() || run->data() + run->size() > buf.data() + buf.size()) {
                return s.name + " reads outside the buffer";
            }
        }
        if (img.read_at_rva(std::uint64_t{s.virtual_address} + n, 1).has_value()) {
            return s.name + " reads past its readable bytes";
        }
    }
    if (!img.read_at_file_offset(buf.size(), 0).has_value()) {
        return "an empty read at the end of the file fails";
    }
    if (img.read_at_file_offset(buf.size(), 1).has_value()) {
        return "a read past the end of the file succeeds";
    }
    return {};
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

TEST_CASE("parse rejects each malformed header with its error and survives a bad section or count") {
    using papa::ErrorKind;
    using papa::pe::PeImage;
    const Sample x64(true);
    const Sample x86(false);
    REQUIRE(x64.honest.has_value());
    REQUIRE(x86.honest.has_value());

    using Buf    = std::vector<std::byte>;
    using Patch  = std::function<void(Buf&, const Sample&)>;
    using Verify = std::function<void(const PeImage&, const Sample&)>;
    const Patch none = [](Buf&, const Sample&) {};

    // The honest image carries every directory, so the rows below break live ones
    const Verify every_directory = [](const PeImage& img, const Sample& s) {
        const std::vector<std::string_view> names{"ExitProcess", "GetTickCount", "getsockname",
                                                  "MessageBoxA"};
        REQUIRE(img.imports().size() == names.size());
        for (std::size_t i = 0; i < names.size(); ++i) {
            CHECK(img.imports()[i].name == names[i]);
            CHECK(img.imports()[i].delayed == (i == 3U));
        }
        REQUIRE(img.exports().size() == 3U);
        CHECK(img.exports()[2].forwarder == "ntdll.RtlAllocateHeap");
        REQUIRE(img.tls_callbacks_va().size() == 1U);
        CHECK(img.tls_callbacks_va()[0] == s.builder.code_va(s.builder.entry_offset));
        CHECK_FALSE(img.relocations().empty());
    };
    // A count clamped to the function slots .rdata holds makes every non-zero dword from
    // AddressOfFunctions to the end of its raw data an export
    const Verify clamped_exports = [](const PeImage& img, const Sample& s) {
        const std::size_t dir   = s.dir_offset(0);
        const auto*       rdata = s.honest->section_containing_rva(
            u32_at(s.bytes, s.layout.data_directory(0)));
        const auto functions = s.honest->rva_to_file_offset(u32_at(s.bytes, dir + 0x1CU));
        REQUIRE(rdata != nullptr);
        REQUIRE(functions.has_value());
        std::size_t nonzero = 0;
        for (std::size_t off = *functions; off + 4U <= rdata->raw_offset + rdata->raw_size;
             off += 4U) {
            nonzero += u32_at(s.bytes, off) != 0U ? 1U : 0U;
        }
        CHECK(img.exports().size() == nonzero);
        REQUIRE(img.exports().size() > 3U);
        CHECK(img.exports()[0].va == s.builder.code_va(s.builder.exports[0].code_offset));
        CHECK(img.exports()[1].va == s.builder.code_va(s.builder.exports[1].code_offset));
    };
    const Verify code_unreadable = [](const PeImage& img, const Sample& s) {
        const auto code = img.read_at_rva(papa_tests::PeBuilder::kTextRva, 1);
        CHECK_FALSE(code.has_value());
        if (!code.has_value()) { CHECK(code.error().kind == ErrorKind::kOutOfBounds); }
        CHECK(img.readable_bytes_at_rva(papa_tests::PeBuilder::kTextRva) == 0U);
        CHECK(img.imports().size() == s.honest->imports().size());
    };
    const Verify no_callbacks = [](const PeImage& img, const Sample& s) {
        CHECK(img.tls_callbacks_va().empty());
        CHECK(img.imports().size() == s.honest->imports().size());
        CHECK(img.exports().size() == s.honest->exports().size());
    };

    // An address that no section or header covers
    constexpr std::uint64_t kUnmapped = 0x7FFF0000U;
    struct Row {
        std::string_view         label;
        bool                     x64;
        Patch                    patch;
        std::optional<ErrorKind> kind;  // nullopt when the image parses
        std::string_view         detail;
        Verify                   verify;
    };
    const std::vector<Row> rows{
        {"the honest PE32+ image", true, none, std::nullopt, "", every_directory},
        {"the honest PE32 image", false, none, std::nullopt, "", every_directory},
        {"a buffer shorter than the DOS header", true, [](Buf& b, const Sample&) { b.resize(0x30); },
         ErrorKind::kNotPe, "buffer too small for DOS header", {}},
        {"no MZ signature", true, [](Buf& b, const Sample&) { put<std::uint16_t>(b, 0, 0x5A5AU); },
         ErrorKind::kNotPe, "missing MZ signature", {}},
        {"e_lfanew past the end of the file", true,
         [](Buf& b, const Sample& s) {
             put(b, s.layout.e_lfanew, static_cast<std::uint32_t>(b.size()));
         },
         ErrorKind::kBadPe, "e_lfanew out of range", {}},
        {"a negative e_lfanew", true,
         [](Buf& b, const Sample& s) { put<std::uint32_t>(b, s.layout.e_lfanew, 0x80000000U); },
         ErrorKind::kBadPe, "e_lfanew out of range", {}},
        {"e_lfanew leaving no room for the PE signature", true,
         [](Buf& b, const Sample& s) {
             put(b, s.layout.e_lfanew, static_cast<std::uint32_t>(b.size() - 2U));
         },
         ErrorKind::kBadPe, "NT header truncated", {}},
        {"a bad NT signature", true,
         [](Buf& b, const Sample& s) { put<std::uint32_t>(b, s.layout.nt_headers, 0x00014550U); },
         ErrorKind::kNotPe, "missing PE signature", {}},
        {"a cut file header", true,
         [](Buf& b, const Sample& s) { b.resize(s.layout.file_header + 10U); },
         ErrorKind::kBadPe, "file header truncated", {}},
        {"a cut optional header magic", true,
         [](Buf& b, const Sample& s) { b.resize(s.layout.optional_header + 1U); },
         ErrorKind::kBadPe, "optional header truncated", {}},
        {"a cut PE32+ optional header", true,
         [](Buf& b, const Sample& s) { b.resize(s.layout.optional_header + 64U); },
         ErrorKind::kBadPe, "PE32+ optional header truncated", {}},
        {"a cut PE32 optional header", false,
         [](Buf& b, const Sample& s) { b.resize(s.layout.optional_header + 64U); },
         ErrorKind::kBadPe, "PE32 optional header truncated", {}},
        {"a cut data directory table", true,
         [](Buf& b, const Sample& s) { b.resize(s.layout.data_directory(3)); },
         ErrorKind::kBadPe, "data directory truncated", {}},
        {"NumberOfSections 0xFFFF", true,
         [](Buf& b, const Sample& s) { put<std::uint16_t>(b, s.layout.file_header + 2U, 0xFFFFU); },
         ErrorKind::kBadPe, "section header truncated", {}},
        {"a .text raw pointer past the end of the file", true,
         [](Buf& b, const Sample& s) {
             put<std::uint32_t>(b, s.layout.section_header(0) + 20U, 0x10000000U);
         },
         std::nullopt, "", code_unreadable},
        {"export counts of 0xFFFFFFFF", true,
         [](Buf& b, const Sample& s) {
             // NumberOfFunctions and NumberOfNames sit at +0x14 and +0x18
             put<std::uint32_t>(b, s.dir_offset(0) + 0x14U, 0xFFFFFFFFU);
             put<std::uint32_t>(b, s.dir_offset(0) + 0x18U, 0xFFFFFFFFU);
         },
         std::nullopt, "", clamped_exports},
        {"an unmapped PE32+ TLS callback array", true,
         [](Buf& b, const Sample& s) {
             put<std::uint64_t>(b, s.dir_offset(9) + 24U, s.builder.base() + kUnmapped);
         },
         std::nullopt, "", no_callbacks},
        {"an unmapped PE32 TLS callback array", false,
         [](Buf& b, const Sample& s) {
             put(b, s.dir_offset(9) + 12U, static_cast<std::uint32_t>(s.builder.base() + kUnmapped));
         },
         std::nullopt, "", no_callbacks},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const Sample& s   = row.x64 ? x64 : x86;
        Buf           buf = s.bytes;
        row.patch(buf, s);
        const auto r = papa::pe::PeParser::parse(std::move(buf));
        if (row.kind.has_value()) {
            CHECK_FALSE(r.has_value());
            if (r.has_value()) { continue; }
            CHECK(r.error().kind == *row.kind);
            CHECK(r.error().detail.find(row.detail) != std::string::npos);
            continue;
        }
        CHECK(r.has_value());
        if (!r.has_value()) { continue; }
        CHECK(reader_violation(*r) == "");
        row.verify(*r, s);
    }
}

TEST_CASE("parse survives every prefix of a rich image, failing with a pe error or yielding bounded readers") {
    using papa::ErrorKind;
    for (const bool x64 : {true, false}) {
        CAPTURE(x64);
        const Sample s(x64);
        REQUIRE(s.honest.has_value());
        std::size_t not_pe        = 0;
        std::size_t bad_pe        = 0;
        std::size_t parsed        = 0;
        std::size_t problem_count = 0;
        std::string problems;
        for (std::size_t n = 0; n < s.bytes.size(); ++n) {
            const auto r = papa::pe::PeParser::parse(std::vector<std::byte>(
                s.bytes.begin(), s.bytes.begin() + static_cast<std::ptrdiff_t>(n)));
            std::string problem;
            if (r.has_value()) {
                ++parsed;
                problem = reader_violation(*r);
            } else if (r.error().kind == ErrorKind::kNotPe) {
                ++not_pe;
            } else if (r.error().kind == ErrorKind::kBadPe) {
                ++bad_pe;
            } else if (r.error().kind != ErrorKind::kOutOfBounds) {
                problem = "an unexpected error kind, " + r.error().detail;
            }
            // The first few problems name their prefix, and the rest are only counted
            if (!problem.empty() && ++problem_count <= 8U) {
                problems.append(std::to_string(n)).append(" bytes: ").append(problem).append("\n");
            }
        }
        CHECK(problems == "");
        CHECK(problem_count == 0U);
        // The short cuts lose the DOS or NT headers, and the long ones keep every directory
        CHECK(not_pe > 0U);
        CHECK(bad_pe > 0U);
        CHECK(parsed > 0U);
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
