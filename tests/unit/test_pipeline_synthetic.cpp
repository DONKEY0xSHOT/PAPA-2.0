// End-to-end coverage over a PE this suite builds itself

#include <ostream>

#include "doctest.h"

#include "pe_builder.h"

#include "papa/capabilities/static_.h"
#include "papa/engine.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/extractor.h"
#include "papa/pe/pe_parser.h"
#include "papa/rules/parser.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <algorithm>
#include <cstdint>
#include <memory>
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

    // First pass: find where WriteFile's IAT slot landed
    auto probe = papa::pe::PeParser::parse(b.build());
    REQUIRE(probe.has_value());
    std::uint64_t iat = 0;
    for (const papa::pe::ParsedImport& imp : probe->imports()) {
        if (imp.name == "WriteFile") {
            iat = imp.iat_va;
        }
    }
    REQUIRE(iat != 0);

    // rip-relative displacement from the end of the 6-byte call at 0x04
    const std::uint64_t next_insn =
        probe->image_base() + papa_tests::PeBuilder::kTextRva + 0x0A;
    const auto disp = static_cast<std::int32_t>(iat - next_insn);
    b.code[6] = static_cast<std::uint8_t>(disp & 0xFF);
    b.code[7] = static_cast<std::uint8_t>((disp >> 8) & 0xFF);
    b.code[8] = static_cast<std::uint8_t>((disp >> 16) & 0xFF);
    b.code[9] = static_cast<std::uint8_t>((disp >> 24) & 0xFF);

    return {b.build(), iat};
}

}  // namespace

TEST_CASE("pipeline: a synthetic PE is parsed, recovered, and its functions found") {
    const SyntheticImage synth = build_calling_writefile();
    auto                 img   = papa::pe::PeParser::parse(synth.bytes);
    REQUIRE(img.has_value());

    auto backend = pn::PapaNativeBackend::build(*img);
    REQUIRE(backend.has_value());

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

    // The import table is indexed by IAT slot, which is what names a call
    CHECK_FALSE(backend->imports().by_iat_va.empty());
    CHECK(backend->imports().by_iat_va.count(synth.write_file_iat) == 1);
}

TEST_CASE("pipeline: the extractor emits an api feature for the imported call") {
    const SyntheticImage synth = build_calling_writefile();
    auto                 img   = papa::pe::PeParser::parse(synth.bytes);
    REQUIRE(img.has_value());
    auto backend = pn::PapaNativeBackend::build(*img);
    REQUIRE(backend.has_value());

    pn::PapaNativeStaticExtractor extractor(std::move(*backend));

    // Walk every instruction of every function looking for api(WriteFile)
    bool found = false;
    for (const auto& fh : extractor.get_functions()) {
        for (const auto& bb : extractor.get_basic_blocks(fh)) {
            for (const auto& ih : extractor.get_instructions(fh, bb)) {
                for (const auto& fa : extractor.extract_insn_features(fh, bb, ih)) {
                    if (fa.first && fa.first->to_string().find("WriteFile") !=
                                        std::string::npos) {
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
    auto backend = pn::PapaNativeBackend::build(*img);
    REQUIRE(backend.has_value());
    pn::PapaNativeStaticExtractor extractor(std::move(*backend));

    // A minimal function-scope rule over the api feature the call produces
    const std::string yaml = R"(rule:
  meta:
    name: write file synthetic
    scopes:
      static: function
      dynamic: unsupported
  features:
    - api: WriteFile
)";
    auto parsed = papa::rules::RuleParser::parse(yaml, "synthetic.yml");
    REQUIRE(parsed.has_value());
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(std::move(*parsed));
    auto ruleset = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(ruleset.has_value());

    const auto caps = papa::capabilities::static_::find_static_capabilities(
        *ruleset, extractor);
    REQUIRE(caps.has_value());

    const bool matched = caps->all_matches.count("write file synthetic") == 1;
    CHECK(matched);
}
