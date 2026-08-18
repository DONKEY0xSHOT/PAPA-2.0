#include <ostream>

#include "doctest.h"

#include "papa/capabilities/common.h"
#include "papa/capabilities/static_.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/file.h"
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
#include <string>
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
    // With our trivial rule, the first MOV-class instruction in .text usually matches.
    // If not, the per-instruction features still propagate
    CHECK(insn_caps.features.size() > 0U);
}

namespace {

// Minimal extractor that yields exactly the file features a test asks for. The gate
// only reads globals and file features, so the per-function half is empty
class FakeFileExtractor final : public papa::features::extractors::StaticFeatureExtractor {
public:
    explicit FakeFileExtractor(std::vector<papa::features::FeaturePtr> feats)
        : feats_(std::move(feats)) {}

    [[nodiscard]] papa::features::Address get_base_address() const override {
        return papa::features::Address{papa::features::AbsoluteVirtualAddress{0x400000}};
    }
    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_global_features() const override { return {}; }

    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_file_features() const override {
        std::vector<papa::features::extractors::FeatureWithAddress> out;
        const papa::features::Address a{papa::features::AbsoluteVirtualAddress{0x400000}};
        out.reserve(feats_.size());
        for (const auto& f : feats_) { out.emplace_back(f, a); }
        return out;
    }

    [[nodiscard]] std::vector<papa::features::extractors::FunctionHandle>
    get_functions() const override { return {}; }
    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_function_features(const papa::features::extractors::FunctionHandle&) const override { return {}; }
    [[nodiscard]] std::vector<papa::features::extractors::BBHandle>
    get_basic_blocks(const papa::features::extractors::FunctionHandle&) const override { return {}; }
    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_basic_block_features(const papa::features::extractors::FunctionHandle&,
                                 const papa::features::extractors::BBHandle&) const override { return {}; }
    [[nodiscard]] std::vector<papa::features::extractors::InsnHandle>
    get_instructions(const papa::features::extractors::FunctionHandle&,
                     const papa::features::extractors::BBHandle&) const override { return {}; }
    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_insn_features(const papa::features::extractors::FunctionHandle&,
                          const papa::features::extractors::BBHandle&,
                          const papa::features::extractors::InsnHandle&) const override { return {}; }

private:
    std::vector<papa::features::FeaturePtr> feats_;
};

[[nodiscard]] bool gate_contains(const std::vector<const papa::rules::Rule*>& gate,
                                 std::string_view name) {
    for (const auto* r : gate) { if (r->name() == name) { return true; } }
    return false;
}

// A file-scope rule keyed on a single section name, in the given namespace
[[nodiscard]] std::string section_rule(std::string_view name, std::string_view ns,
                                       std::string_view section) {
    return std::string("rule:\n  meta:\n    name: ").append(name)
        .append("\n    namespace: ").append(ns)
        .append("\n    scopes:\n      static: file\n      dynamic: unsupported\n")
        .append("  features:\n    - section: ").append(section).append("\n");
}

// A file-scope rule that fires when the referenced rule or namespace matched
[[nodiscard]] std::string match_rule(std::string_view name, std::string_view ns,
                                     std::string_view ref) {
    return std::string("rule:\n  meta:\n    name: ").append(name)
        .append("\n    namespace: ").append(ns)
        .append("\n    scopes:\n      static: file\n      dynamic: unsupported\n")
        .append("  features:\n    - match: ").append(ref).append("\n");
}

}  // namespace

TEST_CASE("limitation gate: closure follows a reference by rule name") {
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(section_rule("packer-sig", "anti-analysis/packer/upx", ".upx0")));
    rules.push_back(parse_rule(match_rule("lim", "internal/limitation/static", "packer-sig")));
    rules.push_back(parse_rule(section_rule("unrelated", "host-interaction/file", ".text")));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    const auto gate = papa::capabilities::limitation_gate_rules(*rs);
    CHECK(gate_contains(gate, "lim"));
    CHECK(gate_contains(gate, "packer-sig"));
    CHECK_FALSE(gate_contains(gate, "unrelated"));
}

TEST_CASE("limitation gate: closure expands a namespace reference to every rule beneath it") {
    // This is how every real limitation rule is written, so getting it wrong
    // would silently stop packed samples from being detected
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(section_rule("upx", "anti-analysis/packer/upx", ".upx0")));
    rules.push_back(parse_rule(section_rule("aspack", "anti-analysis/packer/aspack", ".aspack")));
    rules.push_back(parse_rule(section_rule("deep", "anti-analysis/packer/x/y/z", ".deep")));
    rules.push_back(parse_rule(section_rule("sibling", "anti-analysis/obfuscation", ".obf")));
    rules.push_back(parse_rule(match_rule("lim", "internal/limitation/static", "anti-analysis/packer")));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    const auto gate = papa::capabilities::limitation_gate_rules(*rs);
    CHECK(gate_contains(gate, "upx"));
    CHECK(gate_contains(gate, "aspack"));
    CHECK(gate_contains(gate, "deep"));      // nested below the referenced prefix
    CHECK_FALSE(gate_contains(gate, "sibling"));  // shares a parent, not the prefix
}

TEST_CASE("limitation gate: closure is transitive") {
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(section_rule("leaf", "a/leaf", ".leaf")));
    rules.push_back(parse_rule(match_rule("mid", "a/mid", "leaf")));
    rules.push_back(parse_rule(match_rule("lim", "internal/limitation/static", "mid")));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    const auto gate = papa::capabilities::limitation_gate_rules(*rs);
    CHECK(gate_contains(gate, "lim"));
    CHECK(gate_contains(gate, "mid"));
    CHECK(gate_contains(gate, "leaf"));
}

TEST_CASE("limitation gate: closure keeps topological order") {
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(match_rule("lim", "internal/limitation/static", "mid")));
    rules.push_back(parse_rule(match_rule("mid", "a/mid", "leaf")));
    rules.push_back(parse_rule(section_rule("leaf", "a/leaf", ".leaf")));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    const auto gate = papa::capabilities::limitation_gate_rules(*rs);
    // A dependency has to be evaluated before the rule that references it or
    // the injected match feature would not be visible yet
    std::size_t i_leaf = 0, i_mid = 0, i_lim = 0;
    for (std::size_t i = 0; i < gate.size(); ++i) {
        if (gate[i]->name() == "leaf") { i_leaf = i; }
        if (gate[i]->name() == "mid")  { i_mid = i; }
        if (gate[i]->name() == "lim")  { i_lim = i; }
    }
    CHECK(i_leaf < i_mid);
    CHECK(i_mid < i_lim);
}

TEST_CASE("limitation gate: a corpus with no limitation rule produces an empty gate") {
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(section_rule("a", "host-interaction/file", ".text")));
    rules.push_back(parse_rule(section_rule("b", "anti-analysis/packer/upx", ".upx0")));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    CHECK(papa::capabilities::limitation_gate_rules(*rs).empty());
}

TEST_CASE("limitation gate: a near-miss namespace is not treated as a limitation") {
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(section_rule("x", "internal/limitation/static_other", ".text")));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    CHECK(papa::capabilities::limitation_gate_rules(*rs).empty());
}

TEST_CASE("limitation gate: verdict always agrees with the full file-scope pass") {
    // The gate exists only to answer has_static_limitation
    auto build = [] {
        std::vector<std::unique_ptr<papa::rules::Rule>> rules;
        rules.push_back(parse_rule(section_rule("upx", "anti-analysis/packer/upx", ".upx0")));
        rules.push_back(parse_rule(section_rule("noise1", "host-interaction/file", ".text")));
        rules.push_back(parse_rule(section_rule("noise2", "communication/http", ".data")));
        rules.push_back(parse_rule(match_rule("lim", "internal/limitation/static", "anti-analysis/packer")));
        auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
        REQUIRE(rs);
        return std::move(*rs);
    };

    const auto section = [](std::string_view n) -> papa::features::FeaturePtr {
        return std::make_shared<const papa::features::Section>(std::string(n));
    };

    struct Case {
        const char*                             label;
        std::vector<papa::features::FeaturePtr> feats;
        bool                                    expect_limited;
    };
    const std::vector<Case> cases = {
        {"packed sample",            {section(".upx0"), section(".text")}, true},
        {"clean sample",             {section(".text"), section(".data")}, false},
        {"no features at all",       {},                                   false},
        {"only unrelated matches",   {section(".data")},                   false},
    };

    for (const auto& c : cases) {
        CAPTURE(c.label);
        const auto rs = build();
        FakeFileExtractor extractor(c.feats);

        auto gate_caps = papa::capabilities::find_limitation_capabilities(rs, extractor);
        REQUIRE(gate_caps);
        auto full_caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(full_caps);

        const bool via_gate = papa::capabilities::has_static_limitation(rs, *gate_caps);
        const bool via_full = papa::capabilities::has_static_limitation(rs, *full_caps);
        CHECK(via_gate == via_full);
        CHECK(via_gate == c.expect_limited);
    }
}

TEST_CASE("limitation gate: a reference under not: is still in the closure") {
    // Monotonicity does not hold through a negation
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(section_rule("decoy", "misc/decoy", ".text")));
    rules.push_back(parse_rule(
        "rule:\n"
        "  meta:\n"
        "    name: lim-not\n"
        "    namespace: internal/limitation/static\n"
        "    scopes:\n"
        "      static: file\n"
        "      dynamic: unsupported\n"
        "  features:\n"
        "    - and:\n"
        "      - section: .data\n"
        "      - not:\n"
        "        - match: decoy\n"));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    const auto gate = papa::capabilities::limitation_gate_rules(*rs);
    CHECK(gate_contains(gate, "lim-not"));
    CHECK(gate_contains(gate, "decoy"));
}

TEST_CASE("limitation gate: verdict agrees with the full pass through a negation") {
    auto build = [] {
        std::vector<std::unique_ptr<papa::rules::Rule>> rules;
        rules.push_back(parse_rule(section_rule("decoy", "misc/decoy", ".text")));
        rules.push_back(parse_rule(section_rule("noise", "host-interaction/file", ".rsrc")));
        rules.push_back(parse_rule(
            "rule:\n"
            "  meta:\n"
            "    name: lim-not\n"
            "    namespace: internal/limitation/static\n"
            "    scopes:\n"
            "      static: file\n"
            "      dynamic: unsupported\n"
            "  features:\n"
            "    - and:\n"
            "      - section: .data\n"
            "      - not:\n"
            "        - match: decoy\n"));
        auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
        REQUIRE(rs);
        return std::move(*rs);
    };

    const auto section = [](std::string_view n) -> papa::features::FeaturePtr {
        return std::make_shared<const papa::features::Section>(std::string(n));
    };

    struct Case {
        const char*                             label;
        std::vector<papa::features::FeaturePtr> feats;
        bool                                    expect_limited;
    };
    const std::vector<Case> cases = {
        // .data present and decoy absent, so the negation holds and it fires
        {".data only",          {section(".data")},                  true},
        // decoy matches, so the negation fails and it must not fire. This is
        // the case that breaks if a negated reference is left out of the gate
        {".data and .text",     {section(".data"), section(".text")}, false},
        {".text only",          {section(".text")},                  false},
        {"nothing",             {},                                  false},
    };

    for (const auto& c : cases) {
        CAPTURE(c.label);
        const auto rs = build();
        FakeFileExtractor extractor(c.feats);
        auto gate_caps = papa::capabilities::find_limitation_capabilities(rs, extractor);
        REQUIRE(gate_caps);
        auto full_caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(full_caps);
        const bool via_gate = papa::capabilities::has_static_limitation(rs, *gate_caps);
        const bool via_full = papa::capabilities::has_static_limitation(rs, *full_caps);
        CHECK(via_gate == via_full);
        CHECK(via_gate == c.expect_limited);
    }
}

TEST_CASE("limitation gate: a limitation rule with no match reference still fires") {
    auto build = [] {
        std::vector<std::unique_ptr<papa::rules::Rule>> rules;
        rules.push_back(parse_rule(section_rule("noise", "host-interaction/file", ".text")));
        rules.push_back(parse_rule(section_rule("lim-direct", "internal/limitation/static", ".packed")));
        auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
        REQUIRE(rs);
        return std::move(*rs);
    };
    const auto section = [](std::string_view n) -> papa::features::FeaturePtr {
        return std::make_shared<const papa::features::Section>(std::string(n));
    };

    for (const bool packed : {true, false}) {
        CAPTURE(packed);
        const auto rs = build();
        std::vector<papa::features::FeaturePtr> feats{section(".text")};
        if (packed) { feats.push_back(section(".packed")); }
        FakeFileExtractor extractor(feats);

        auto gate_caps = papa::capabilities::find_limitation_capabilities(rs, extractor);
        REQUIRE(gate_caps);
        auto full_caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(full_caps);
        CHECK(papa::capabilities::has_static_limitation(rs, *gate_caps) ==
              papa::capabilities::has_static_limitation(rs, *full_caps));
        CHECK(papa::capabilities::has_static_limitation(rs, *gate_caps) == packed);
    }
}
