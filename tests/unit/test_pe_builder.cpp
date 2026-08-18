// The synthetic-PE builder is the foundation the fixture-free tests stand on, so it
// is verified against the real parser first

#include <ostream>

#include "doctest.h"

#include "pe_builder.h"

#include "papa/constants.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"
#include "papa/features/extractors/papa_native/cfg.h"

#include <algorithm>
#include <cstdint>
#include <string>
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

    const auto* pdata = img->section_containing_rva(papa_tests::PeBuilder::kPdataRva);
    REQUIRE(pdata != nullptr);
    CHECK(pdata->name == ".pdata");

    // The exception-directory walk must yield both begins, which means each
    // record's UNWIND_INFO parsed as version 1
    const auto begins = papa::features::extractors::papa_native::cfg::
        pdata_function_begins(*img);
    REQUIRE(begins.size() == 2);
    CHECK(begins[0] == img->image_base() + papa_tests::PeBuilder::kTextRva + 0x00);
    CHECK(begins[1] == img->image_base() + papa_tests::PeBuilder::kTextRva + 0x10);
}
