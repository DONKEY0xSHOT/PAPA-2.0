// End-to-end coverage over a PE this suite builds itself

#include <ostream>

#include "doctest.h"

#include "pe_builder.h"
#include "test_support.h"

#include "papa/capabilities/static_.h"
#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/extractor.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/pe/pe_parser.h"
#include "papa/rules/ruleset.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace pn = papa::features::extractors::papa_native;

namespace {

// Two x64 functions. The first calls WriteFile through its IAT slot and then returns,
// the second is a small leaf
struct SyntheticImage {
    std::vector<std::byte> bytes;
    std::uint64_t          write_file_iat{0};
};

SyntheticImage build_calling_writefile() {
    papa_tests::PeBuilder b;
    b.x64     = true;
    b.imports = {{"kernel32.dll", {"WriteFile", "ExitProcess"}}};
    b.exports = {{"Start", 0x00}};

    // 0x00 sub rsp,0x28 | 0x04 call [rip+X] | 0x0A add rsp,0x28 | 0x0E ret
    // 0x10 xor eax,eax  | 0x12 ret
    b.code = {
        0x48, 0x83, 0xEC, 0x28,
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x28,
        0xC3,
        0xCC,
        0x33, 0xC0,
        0xC3,
    };
    b.pdata_functions = {{0x00, 0x0F}, {0x10, 0x13}};

    const std::uint64_t iat = b.iat_va("kernel32.dll", "WriteFile");
    REQUIRE(iat != 0);

    // rip-relative displacement from the end of the 6-byte call at 0x04
    papa_tests::detail::poke(b.code, 6, static_cast<std::int32_t>(iat - b.code_va(0x0A)));

    return {b.build(), iat};
}

}  // namespace

TEST_CASE("pipeline: a synthetic PE is parsed, recovered, and its functions found") {
    const SyntheticImage synth = build_calling_writefile();
    auto                 img   = papa::pe::PeParser::parse(synth.bytes);
    REQUIRE(img.has_value());

    auto backend = pn::PapaNativeBackend::build(*img, papa_tests::shared_flirt_sigs());
    REQUIRE(backend.has_value());

    // The backend keeps the image it was given and decodes at its bitness
    CHECK(&backend->image() == &*img);
    CHECK(backend->disassembler().is_64bit());

    // Both .pdata begins are recovered as functions
    const std::uint64_t base  = img->image_base() + papa_tests::PeBuilder::kTextRva;
    const auto&         funcs = backend->functions();
    REQUIRE(funcs.size() >= 2);

    const auto has_fn = [&funcs](std::uint64_t va) {
        return std::any_of(funcs.begin(), funcs.end(),
                           [va](const pn::Function& f) { return f.va == va; });
    };
    CHECK(has_fn(base + 0x00));
    CHECK(has_fn(base + 0x10));

    // The import table indexes every row by its own IAT slot, which is what names a call
    REQUIRE(backend->imports().by_iat_va.size() == img->imports().size());
    for (const papa::pe::ParsedImport& row : img->imports()) {
        CAPTURE(row.name);
        CHECK(backend->imports().by_iat_va.at(row.iat_va) == &row);
    }
    CHECK(backend->imports().by_iat_va.count(synth.write_file_iat) == 1);
}

TEST_CASE("pipeline: the extractor emits an api feature for the imported call") {
    const SyntheticImage synth = build_calling_writefile();
    auto                 img   = papa::pe::PeParser::parse(synth.bytes);
    REQUIRE(img.has_value());
    auto backend = pn::PapaNativeBackend::build(*img, papa_tests::shared_flirt_sigs());
    REQUIRE(backend.has_value());

    pn::PapaNativeStaticExtractor extractor(std::move(*backend));

    // Walk every instruction of every function looking for api(WriteFile)
    bool found = false;
    for (const auto& fh : extractor.get_functions()) {
        for (const auto& bb : extractor.get_basic_blocks(fh)) {
            for (const auto& ih : extractor.get_instructions(fh, bb)) {
                for (const auto& fa : extractor.extract_insn_features(fh, bb, ih)) {
                    if (fa.first && fa.first->tag() == papa::features::FeatureTag::kApi &&
                        static_cast<const papa::features::Api&>(*fa.first)
                                .value()
                                .find("WriteFile") != std::string::npos) {
                        found = true;
                    }
                }
            }
        }
    }
    CHECK(found);
}

TEST_CASE("pipeline: a rule matches end to end against a synthetic PE") {
    const SyntheticImage synth = build_calling_writefile();
    auto                 img   = papa::pe::PeParser::parse(synth.bytes);
    REQUIRE(img.has_value());
    auto backend = pn::PapaNativeBackend::build(*img, papa_tests::shared_flirt_sigs());
    REQUIRE(backend.has_value());
    pn::PapaNativeStaticExtractor extractor(std::move(*backend));

    // A function-scope rule over the api feature the call produces, and a file-scope
    // rule over a section name
    const auto ruleset = papa_tests::ruleset(
        {papa_tests::rule_yaml("write file synthetic", "function", {"api: WriteFile"}),
         papa_tests::rule_yaml("has text section", "file", {"section: .text"})});

    const auto caps = papa::capabilities::static_::find_static_capabilities(
        ruleset, extractor);
    REQUIRE(caps.has_value());

    CHECK(caps->all_matches.count("write file synthetic") == 1);
    REQUIRE(caps->all_matches.count("has text section") == 1);
    REQUIRE(caps->all_matches.at("has text section").size() == 1);
    CHECK(caps->all_matches.at("has text section")[0].first == papa_tests::va(img->image_base()));
}

TEST_CASE("pipeline: the library check finds an import thunk by its entry VA") {
    papa_tests::PeBuilder b;
    b.imports = {{"kernel32.dll", {"ExitProcess"}}};
    // 0x00 xor eax,eax | 0x02 ret | 0x03 int3 | 0x04 jmp [rip+X]
    b.code            = {0x33, 0xC0, 0xC3, 0xCC, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    b.pdata_functions = {{0x00, 0x03}, {0x04, 0x0A}};
    const std::uint64_t text = b.code_va(0);
    const std::uint64_t iat  = b.iat_va("kernel32.dll", "ExitProcess");
    papa_tests::detail::poke(b.code, 6, static_cast<std::int32_t>(iat - (text + 0x0A)));

    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    auto backend = pn::PapaNativeBackend::build(*img, papa_tests::shared_flirt_sigs());
    REQUIRE(backend.has_value());
    const pn::PapaNativeStaticExtractor extractor(std::move(*backend));

    namespace pf = papa::features;
    CHECK(extractor.is_library_function(papa_tests::va(text + 0x04)));
    CHECK_FALSE(extractor.is_library_function(papa_tests::va(text + 0x00)));
    CHECK_FALSE(extractor.is_library_function(papa_tests::va(text + 0x02)));
    CHECK_FALSE(extractor.is_library_function(pf::Address{pf::NoAddress{}}));
}
