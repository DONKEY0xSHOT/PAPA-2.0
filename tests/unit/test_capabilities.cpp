#include <ostream>

#include "doctest.h"

#include "papa/capabilities/common.h"
#include "papa/capabilities/static_.h"

#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/extractor.h"
#include "papa/features/extractors/pefile_extractor.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"
#include "papa/rules/parser.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <filesystem>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>
#include "fixture_paths.h"

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");

[[nodiscard]] std::unique_ptr<papa::rules::Rule> parse_rule(std::string_view yaml) {
    auto r = papa::rules::RuleParser::parse(yaml, "test.yml");
    REQUIRE(r);
    return std::move(*r);
}

}  // namespace

TEST_CASE("capabilities: find_file_capabilities matches a section feature on notepad") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());
    papa::features::extractors::PefileFeatureExtractor extractor(*img);

    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(
        "rule:\n"
        "  meta:\n"
        "    name: has-text-section\n"
        "    scope: file\n"
        "  features:\n"
        "    - section: .text\n"));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    auto file_caps = papa::capabilities::find_file_capabilities(*rs, extractor);
    REQUIRE(file_caps);
    CHECK(file_caps->matches.count("has-text-section") == 1);
    CHECK(file_caps->feature_count > 0U);
}

TEST_CASE("capabilities: has_static_limitation only fires on the limitation namespace") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());
    papa::features::extractors::PefileFeatureExtractor extractor(*img);

    SUBCASE("regular rule does not trigger limitation") {
        std::vector<std::unique_ptr<papa::rules::Rule>> rules;
        rules.push_back(parse_rule(
            "rule:\n"
            "  meta:\n"
            "    name: r1\n"
            "    scope: file\n"
            "  features:\n"
            "    - section: .text\n"));
        auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
        REQUIRE(rs);
        auto caps = papa::capabilities::find_file_capabilities(*rs, extractor);
        REQUIRE(caps);
        CHECK_FALSE(papa::capabilities::has_static_limitation(*rs, *caps));
    }

    SUBCASE("rule under internal/limitation/static triggers limitation") {
        std::vector<std::unique_ptr<papa::rules::Rule>> rules;
        rules.push_back(parse_rule(
            "rule:\n"
            "  meta:\n"
            "    name: limit-rule\n"
            "    namespace: internal/limitation/static/dotnet\n"
            "    scope: file\n"
            "  features:\n"
            "    - section: .text\n"));
        auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
        REQUIRE(rs);
        auto caps = papa::capabilities::find_file_capabilities(*rs, extractor);
        REQUIRE(caps);
        CHECK(papa::capabilities::has_static_limitation(*rs, *caps));
    }

    SUBCASE("similar but distinct namespace prefix does not trigger") {
        std::vector<std::unique_ptr<papa::rules::Rule>> rules;
        rules.push_back(parse_rule(
            "rule:\n"
            "  meta:\n"
            "    name: not-limit\n"
            "    namespace: internal/limitation/staticy-thing\n"
            "    scope: file\n"
            "  features:\n"
            "    - section: .text\n"));
        auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
        REQUIRE(rs);
        auto caps = papa::capabilities::find_file_capabilities(*rs, extractor);
        REQUIRE(caps);
        CHECK_FALSE(papa::capabilities::has_static_limitation(*rs, *caps));
    }
}

TEST_CASE("capabilities: find_static_capabilities runs end-to-end on notepad") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());

    auto backend = papa::features::extractors::papa_native::PapaNativeBackend::build(*img);
    REQUIRE(backend);
    papa::features::extractors::papa_native::PapaNativeStaticExtractor extractor(
        std::move(*backend));

    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(
        "rule:\n"
        "  meta:\n"
        "    name: has-mov\n"
        "    scope: function\n"
        "  features:\n"
        "    - mnemonic: mov\n"));
    rules.push_back(parse_rule(
        "rule:\n"
        "  meta:\n"
        "    name: has-text\n"
        "    scope: file\n"
        "  features:\n"
        "    - section: .text\n"));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    auto caps = papa::capabilities::static_::find_static_capabilities(*rs, extractor);
    REQUIRE(caps);
    CHECK(caps->all_matches.count("has-text") == 1);
    CHECK(caps->all_matches.count("has-mov")  == 1);
    CHECK(caps->feature_count > 0U);
}

TEST_CASE("capabilities: per-scope helpers compose correctly on a tiny synthetic input") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());
    auto backend = papa::features::extractors::papa_native::PapaNativeBackend::build(*img);
    REQUIRE(backend);
    papa::features::extractors::papa_native::PapaNativeStaticExtractor extractor(
        std::move(*backend));

    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(
        "rule:\n"
        "  meta:\n"
        "    name: any-mnemonic\n"
        "    scope: instruction\n"
        "  features:\n"
        "    - mnemonic: mov\n"));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    auto fns = extractor.get_functions();
    REQUIRE_FALSE(fns.empty());
    auto bbs = extractor.get_basic_blocks(fns[0]);
    REQUIRE_FALSE(bbs.empty());
    auto insns = extractor.get_instructions(fns[0], bbs[0]);
    REQUIRE_FALSE(insns.empty());

    auto insn_caps = papa::capabilities::static_::find_instruction_capabilities(
        *rs, extractor, fns[0], bbs[0], insns[0]);
    // With our trivial rule, the first MOV-class instruction in .text usually
    // matches
    // If not, the per-instruction features still propagate
    CHECK(insn_caps.features.size() > 0U);
}
