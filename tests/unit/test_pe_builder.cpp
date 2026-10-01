// The synthetic-PE builder is the foundation the fixture-free tests stand on, so it
// is verified against the real parser first

#include <ostream>

#include "doctest.h"

#include "pe_builder.h"

#include "papa/constants.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"
#include "papa/features/extractors/papa_native/viv/entrypoints.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

// A handful of x64 instructions forming two small functions
std::vector<std::uint8_t> sample_x64_code() {
    return {
        0x48, 0x83, 0xEC, 0x28,        // 0x00 sub rsp, 0x28
        0x33, 0xC0,                    // 0x04 xor eax, eax
        0x48, 0x83, 0xC4, 0x28,        // 0x06 add rsp, 0x28
        0xC3,                          // 0x0A ret
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC,  // 0x0B padding
        0x48, 0x83, 0xEC, 0x28,        // 0x10 sub rsp, 0x28
        0xC3,                          // 0x14 ret
    };
}

}  // namespace

TEST_CASE("pe_builder: a minimal x64 image parses with the expected headers") {
    papa_tests::PeBuilder b;
    b.x64  = true;
    b.code = sample_x64_code();

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    CHECK(img->is_64bit());
    CHECK(img->machine() == papa::constants::kImageFileMachineAmd64);
    CHECK(img->image_base() == 0x140000000ULL);
    CHECK(img->entry_point_rva() == papa_tests::PeBuilder::kTextRva);
    CHECK(img->size_of_image() > 0);
}

TEST_CASE("pe_builder: a minimal x86 image parses as 32-bit") {
    papa_tests::PeBuilder b;
    b.x64  = false;
    b.code = {0x55, 0x8B, 0xEC, 0x5D, 0xC3};  // push ebp / mov ebp,esp / pop ebp / ret

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    CHECK_FALSE(img->is_64bit());
    CHECK(img->machine() == papa::constants::kImageFileMachineI386);
    CHECK(img->image_base() == 0x400000ULL);
}

TEST_CASE("pe_builder: the code section is readable back at its virtual address") {
    papa_tests::PeBuilder b;
    b.code = sample_x64_code();

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    const auto read = img->read_at_rva(papa_tests::PeBuilder::kTextRva, b.code.size());
    REQUIRE(read.has_value());
    REQUIRE(read->size() == b.code.size());
    for (std::size_t i = 0; i < b.code.size(); ++i) {
        CHECK(static_cast<std::uint8_t>((*read)[i]) == b.code[i]);
    }

    const auto* text = img->section_containing_rva(papa_tests::PeBuilder::kTextRva);
    REQUIRE(text != nullptr);
    CHECK(text->name == ".text");
    CHECK((text->characteristics & papa::constants::kImageScnMemExecute) != 0);
}

TEST_CASE("pe_builder: imports come back with normalized dll names and symbols") {
    papa_tests::PeBuilder b;
    b.code    = sample_x64_code();
    b.imports = {
        {"kernel32.dll", {"WriteFile", "CreateFileW", "ExitProcess"}},
        {"advapi32.dll", {"RegOpenKeyExW"}},
    };

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    const auto imps = img->imports();
    REQUIRE(imps.size() == 4);

    const auto has = [&imps](std::string_view dll, std::string_view fn) {
        return std::any_of(imps.begin(), imps.end(),
                           [&](const papa::pe::ParsedImport& p) {
                               return p.dll == dll && p.name == fn;
                           });
    };
    // The parser lowercases the DLL and strips the extension
    CHECK(has("kernel32", "WriteFile"));
    CHECK(has("kernel32", "CreateFileW"));
    CHECK(has("kernel32", "ExitProcess"));
    CHECK(has("advapi32", "RegOpenKeyExW"));

    // Every import has a distinct IAT slot inside the image
    for (const papa::pe::ParsedImport& p : imps) {
        CHECK(p.iat_va > img->image_base());
    }
}

TEST_CASE("pe_builder: exports come back named and pointing into the code") {
    papa_tests::PeBuilder b;
    b.code    = sample_x64_code();
    b.exports = {{"DoWork", 0x00}, {"Helper", 0x10}};

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    const auto exps = img->exports();
    REQUIRE(exps.size() == 2);

    const auto find = [&exps](std::string_view name) -> const papa::pe::ParsedExport* {
        for (const auto& e : exps) {
            if (e.name == name) {
                return &e;
            }
        }
        return nullptr;
    };
    const auto* work = find("DoWork");
    REQUIRE(work != nullptr);
    CHECK(work->va == img->image_base() + papa_tests::PeBuilder::kTextRva);
    CHECK_FALSE(work->forwarder.has_value());

    const auto* helper = find("Helper");
    REQUIRE(helper != nullptr);
    CHECK(helper->va == img->image_base() + papa_tests::PeBuilder::kTextRva + 0x10);
}

TEST_CASE("pe_builder: base relocations come back at the requested sites") {
    papa_tests::PeBuilder b;
    b.code               = sample_x64_code();
    b.reloc_code_offsets = {0x04, 0x10};

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    const auto relocs = img->relocations();
    REQUIRE(relocs.size() >= 2);

    const auto has_site = [&relocs](std::uint32_t rva) {
        return std::any_of(relocs.begin(), relocs.end(),
                           [rva](const papa::pe::ParsedRelocation& r) {
                               return r.rva == rva && r.type == 10;  // DIR64
                           });
    };
    CHECK(has_site(papa_tests::PeBuilder::kTextRva + 0x04));
    CHECK(has_site(papa_tests::PeBuilder::kTextRva + 0x10));
}

TEST_CASE("pe_builder: TLS callbacks come back as virtual addresses") {
    papa_tests::PeBuilder b;
    b.code          = sample_x64_code();
    b.tls_callbacks = {0x10};

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    const auto callbacks = img->tls_callbacks_va();
    REQUIRE(callbacks.size() == 1);
    CHECK(callbacks[0] == img->image_base() + papa_tests::PeBuilder::kTextRva + 0x10);
}

TEST_CASE("pe_builder: an x64 image carries a walkable .pdata table") {
    papa_tests::PeBuilder b;
    b.code            = sample_x64_code();
    b.pdata_functions = {{0x00, 0x0B}, {0x10, 0x15}};

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    const auto* pdata = img->section_containing_rva(b.section_rva(".pdata"));
    REQUIRE(pdata != nullptr);
    CHECK(pdata->name == ".pdata");

    // The exception-directory walk must yield both begins, which means each
    // record's UNWIND_INFO parsed as version 1
    const auto begins = papa::features::extractors::papa_native::viv::
        pdata_function_begins(*img);
    REQUIRE(begins.size() == 2);
    CHECK(begins[0] == img->image_base() + papa_tests::PeBuilder::kTextRva + 0x00);
    CHECK(begins[1] == img->image_base() + papa_tests::PeBuilder::kTextRva + 0x10);
}

TEST_CASE("pe_builder: sections sit back to back on page boundaries and size the image") {
    papa_tests::PeBuilder b;
    b.code.assign(0x1800, 0x90);  // spills onto a second code page
    b.code.back()        = 0xC3;
    b.imports            = {{"kernel32.dll", {"WriteFile"}}};
    b.pdata_functions    = {{0x00, 0x1800}};
    b.reloc_code_offsets = {0x04};

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    const auto sections = img->sections();
    REQUIRE(sections.size() == 4);
    const std::array<std::string_view, 4> names{".text", ".rdata", ".pdata", ".reloc"};
    const std::array<std::uint32_t, 4>    vas{0x1000, 0x3000, 0x4000, 0x5000};
    for (std::size_t i = 0; i < sections.size(); ++i) {
        CAPTURE(i);
        CHECK(sections[i].name == names[i]);
        CHECK(sections[i].virtual_address == vas[i]);
        CHECK(b.section_rva(names[i]) == vas[i]);
    }
    CHECK(sections[0].virtual_size == 0x1800);
    CHECK(img->size_of_image() == 0x6000);

    // The code past the first page reads back instead of overlapping .rdata
    const auto tail = img->read_at_rva(papa_tests::PeBuilder::kTextRva + 0x17FF, 1);
    REQUIRE(tail.has_value());
    CHECK(static_cast<std::uint8_t>((*tail)[0]) == 0xC3);
}

TEST_CASE("pe_builder: base relocations get one block per code page, padded with ABSOLUTE") {
    papa_tests::PeBuilder b;
    b.x64 = false;
    b.code.assign(0x1100, 0x90);
    b.reloc_code_offsets = {0x10, 0x20, 0x1004};

    const auto bytes = b.build();
    auto       img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());

    // The second page has one site, so its block carries a type-0 pad entry at offset 0
    const std::vector<std::pair<std::uint32_t, std::uint32_t>> expected{
        {0x1010, 3}, {0x1020, 3}, {0x2004, 3}, {0x2000, 0}};
    std::vector<std::pair<std::uint32_t, std::uint32_t>> got;
    for (const papa::pe::ParsedRelocation& r : img->relocations()) {
        got.emplace_back(r.rva, r.type);
    }
    CHECK(got == expected);
}

TEST_CASE("pe_builder: entry_offset moves the entry point into the code") {
    papa_tests::PeBuilder b;
    b.code         = sample_x64_code();
    b.entry_offset = 0x10;

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    CHECK(img->entry_point_rva() == papa_tests::PeBuilder::kTextRva + 0x10);
}

TEST_CASE("pe_builder: an import spelled #N is taken by ordinal") {
    papa_tests::PeBuilder b;
    b.code    = sample_x64_code();
    b.imports = {{"ws2_32.dll", {"#6"}}, {"kernel32.dll", {"#6", "ExitProcess"}}};

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    const auto imps = img->imports();
    REQUIRE(imps.size() == 3);

    // ws2_32 is in the parser's ordinal table, so #6 resolves to its name
    CHECK(imps[0].dll == "ws2_32");
    CHECK(imps[0].name == "getsockname");
    CHECK(imps[0].ordinal == 6);
    CHECK_FALSE(imps[0].by_ordinal);
    CHECK(imps[0].iat_va == b.iat_va("ws2_32.dll", "#6"));

    CHECK(imps[1].dll == "kernel32");
    CHECK(imps[1].name.empty());
    CHECK(imps[1].ordinal == 6);
    CHECK(imps[1].by_ordinal);
    CHECK(imps[1].iat_va == b.iat_va("kernel32.dll", "#6"));

    CHECK(imps[2].name == "ExitProcess");
    CHECK_FALSE(imps[2].by_ordinal);
}

TEST_CASE("pe_builder: delay imports come back through directory 13 marked delayed") {
    papa_tests::PeBuilder b;
    b.code          = sample_x64_code();
    b.imports       = {{"kernel32.dll", {"ExitProcess"}}};
    b.delay_imports = {{"USER32.dll", {"MessageBoxA", "MessageBoxW"}}, {"ws2_32.dll", {"#6"}}};

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    const auto imps = img->imports();
    REQUIRE(imps.size() == 4);

    CHECK(imps[0].name == "ExitProcess");
    CHECK_FALSE(imps[0].delayed);
    struct Row {
        std::string_view dll_spec;
        std::string_view fn_spec;
        std::string_view dll;
        std::string_view name;
    };
    const std::array<Row, 3> rows{{
        {"USER32.dll", "MessageBoxA", "user32", "MessageBoxA"},
        {"USER32.dll", "MessageBoxW", "user32", "MessageBoxW"},
        {"ws2_32.dll", "#6", "ws2_32", "getsockname"},
    }};
    for (std::size_t i = 0; i < rows.size(); ++i) {
        CAPTURE(rows[i].fn_spec);
        const papa::pe::ParsedImport& imp = imps[i + 1];
        CHECK(imp.delayed);
        CHECK(imp.dll == rows[i].dll);
        CHECK(imp.name == rows[i].name);
        CHECK(imp.iat_va == b.iat_va(rows[i].dll_spec, rows[i].fn_spec));
    }
}

TEST_CASE("pe_builder: a forwarded export carries its forwarder and no address") {
    papa_tests::PeBuilder b;
    b.code    = sample_x64_code();
    b.exports = {{"Local", 0x10, ""}, {"HeapAlloc", 0, "ntdll.RtlAllocateHeap"}};

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    const auto exps = img->exports();
    REQUIRE(exps.size() == 2);

    CHECK(exps[0].name == "Local");
    CHECK(exps[0].va == b.code_va(0x10));
    CHECK_FALSE(exps[0].forwarder.has_value());

    CHECK(exps[1].name == "HeapAlloc");
    CHECK(exps[1].ordinal == 2);
    CHECK(exps[1].va == 0);
    REQUIRE(exps[1].forwarder.has_value());
    CHECK(*exps[1].forwarder == "ntdll.RtlAllocateHeap");
}

TEST_CASE("pe_builder: the data section is read-write and data_va addresses its bytes") {
    papa_tests::PeBuilder b;
    b.code = sample_x64_code();
    b.data = {0x10, 0x20, 0x30, 0x40, 0x50};

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());

    const auto* data = img->section_containing_rva(b.data_va(0) - img->image_base());
    REQUIRE(data != nullptr);
    CHECK(data->name == ".data");
    CHECK(data->virtual_address == 0x3000);
    CHECK((data->characteristics & papa_tests::PeBuilder::kScnWrite) != 0);
    CHECK((data->characteristics & papa_tests::PeBuilder::kScnRead) != 0);
    CHECK((data->characteristics & papa_tests::PeBuilder::kScnExecute) == 0);

    const auto read = img->read_at_rva(b.data_va(2) - img->image_base(), 3);
    REQUIRE(read.has_value());
    CHECK(static_cast<std::uint8_t>((*read)[0]) == 0x30);
    CHECK(static_cast<std::uint8_t>((*read)[2]) == 0x50);
}

TEST_CASE("pe_builder: an extra section keeps its name, flags and a virtual size past raw") {
    using papa_tests::PeBuilder;
    PeBuilder b;
    b.code           = sample_x64_code();
    b.extra_sections = {{".upx0", std::vector<std::uint8_t>(0x10, 0xAB),
                         PeBuilder::kScnUninitializedData | PeBuilder::kScnRead |
                             PeBuilder::kScnWrite | PeBuilder::kScnExecute,
                         0x3000}};

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    REQUIRE(img->sections().size() == 3);

    const papa::pe::ParsedSection& upx = img->sections()[2];
    CHECK(upx.name == ".upx0");
    CHECK(upx.virtual_address == b.section_rva(".upx0"));
    CHECK(upx.virtual_size == 0x3000);
    CHECK(upx.raw_size == PeBuilder::kFileAlign);
    CHECK(upx.characteristics == (PeBuilder::kScnUninitializedData | PeBuilder::kScnRead |
                                  PeBuilder::kScnWrite | PeBuilder::kScnExecute));
    CHECK(img->size_of_image() == upx.virtual_address + 0x3000);

    // Readable bytes stop where the raw data does, though the section maps on
    CHECK(img->readable_bytes_at_rva(upx.virtual_address + 0x10) == PeBuilder::kFileAlign - 0x10);
    CHECK(img->section_containing_rva(upx.virtual_address + 0x2000) == &upx);
    CHECK(img->readable_bytes_at_rva(upx.virtual_address + 0x2000) == 0);
}

TEST_CASE("pe_builder: add_function places functions on 16-byte boundaries with .pdata rows") {
    papa_tests::PeBuilder b;
    std::vector<std::uint32_t> offsets;
    for (int i = 0; i < 300; ++i) {
        offsets.push_back(b.add_function({0x33, 0xC0, 0xC3}));  // xor eax,eax / ret
    }
    std::vector<std::uint32_t> aligned;
    std::vector<std::uint64_t> expected;
    for (std::uint32_t i = 0; i < 300; ++i) {
        aligned.push_back(i * 16U);
        expected.push_back(b.code_va(i * 16U));
    }
    CHECK(offsets == aligned);
    REQUIRE(b.code.size() > 0x1000);  // the code spans pages
    CHECK(b.code[0x13] == 0xCC);       // padding between functions is int3

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    CHECK(papa::features::extractors::papa_native::viv::pdata_function_begins(*img) == expected);
}

TEST_CASE("pe_builder: the header layout locates the headers build writes") {
    for (const bool x64 : {true, false}) {
        CAPTURE(x64);
        papa_tests::PeBuilder b;
        b.x64     = x64;
        b.code    = sample_x64_code();
        b.imports = {{"kernel32.dll", {"ExitProcess"}}};
        const auto bytes = b.build();
        const auto l     = b.header_layout();
        auto       img   = papa::pe::PeParser::parse(bytes);
        REQUIRE(img.has_value());

        const auto u16 = [&bytes](std::size_t off) {
            std::uint16_t v = 0;
            std::memcpy(&v, bytes.data() + off, sizeof v);
            return v;
        };
        const auto u32 = [&bytes](std::size_t off) {
            std::uint32_t v = 0;
            std::memcpy(&v, bytes.data() + off, sizeof v);
            return v;
        };
        CHECK(u32(l.e_lfanew) == l.nt_headers);
        CHECK(u32(l.nt_headers) == 0x00004550U);
        CHECK(u16(l.file_header) == img->machine());
        CHECK(std::size_t{u16(l.file_header + 2U)} == l.section_count);
        CHECK(u16(l.optional_header) == static_cast<std::uint16_t>(x64 ? 0x20BU : 0x10BU));
        CHECK(u32(l.data_directories - 4U) == 16U);
        CHECK(u32(l.data_directory(1)) == b.section_rva(".rdata"));
        CHECK(u32(l.optional_header + 60U) == l.size_of_headers);
        CHECK(l.section_count == img->sections().size());
        CHECK(std::memcmp(bytes.data() + l.section_header(1), ".rdata", 6) == 0);
        CHECK(u32(l.section_header(0) + 20U) == l.size_of_headers);
    }
}

TEST_CASE("pe_builder: iat_va is known before build and matches the parsed IAT") {
    papa_tests::PeBuilder b;
    b.code    = sample_x64_code();
    b.imports = {
        {"kernel32.dll", {"WriteFile", "ExitProcess"}},
        {"advapi32.dll", {"RegOpenKeyExW"}},
    };
    const std::uint64_t write_file = b.iat_va("kernel32.dll", "WriteFile");
    const std::uint64_t exit       = b.iat_va("kernel32.dll", "ExitProcess");
    const std::uint64_t reg_open   = b.iat_va("advapi32.dll", "RegOpenKeyExW");
    CHECK(b.iat_va("kernel32.dll", "CreateFileW") == 0);
    CHECK(b.iat_va("advapi32", "RegOpenKeyExW") == 0);  // spelled as in the spec

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    const auto imps = img->imports();
    REQUIRE(imps.size() == 3);
    CHECK(imps[0].iat_va == write_file);
    CHECK(imps[1].iat_va == exit);
    CHECK(imps[2].iat_va == reg_open);
}
