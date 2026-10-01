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
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "fixture_paths.h"
#include "test_support.h"

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");

}  // namespace

TEST_CASE("capabilities: find_file_capabilities matches a section feature on notepad") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());
    papa::features::extractors::PefileFeatureExtractor extractor(*img);

    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: has-text-section\n"
        "    scope: file\n"
        "  features:\n"
        "    - section: .text\n"
    });

    auto file_caps = papa::capabilities::find_file_capabilities(rs, extractor);
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
        const auto rs = papa_tests::ruleset({
            "rule:\n"
            "  meta:\n"
            "    name: r1\n"
            "    scope: file\n"
            "  features:\n"
            "    - section: .text\n"
        });
        auto caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(caps);
        CHECK_FALSE(papa::capabilities::has_static_limitation(rs, *caps));
    }

    SUBCASE("rule under internal/limitation/static triggers limitation") {
        const auto rs = papa_tests::ruleset({
            "rule:\n"
            "  meta:\n"
            "    name: limit-rule\n"
            "    namespace: internal/limitation/static/dotnet\n"
            "    scope: file\n"
            "  features:\n"
            "    - section: .text\n"
        });
        auto caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(caps);
        CHECK(papa::capabilities::has_static_limitation(rs, *caps));
    }

    SUBCASE("similar but distinct namespace prefix does not trigger") {
        const auto rs = papa_tests::ruleset({
            "rule:\n"
            "  meta:\n"
            "    name: not-limit\n"
            "    namespace: internal/limitation/staticy-thing\n"
            "    scope: file\n"
            "  features:\n"
            "    - section: .text\n"
        });
        auto caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(caps);
        CHECK_FALSE(papa::capabilities::has_static_limitation(rs, *caps));
    }
}

TEST_CASE("capabilities: find_static_capabilities runs end-to-end on notepad") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());

    auto backend = papa::features::extractors::papa_native::PapaNativeBackend::build(
        *img, papa_tests::shared_flirt_sigs());
    REQUIRE(backend);
    papa::features::extractors::papa_native::PapaNativeStaticExtractor extractor(
        std::move(*backend));

    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: has-mov\n"
        "    scope: function\n"
        "  features:\n"
        "    - mnemonic: mov\n",
        "rule:\n"
        "  meta:\n"
        "    name: has-text\n"
        "    scope: file\n"
        "  features:\n"
        "    - section: .text\n"
    });

    auto caps = papa::capabilities::static_::find_static_capabilities(rs, extractor);
    REQUIRE(caps);
    CHECK(caps->all_matches.count("has-text") == 1);
    CHECK(caps->all_matches.count("has-mov")  == 1);
    CHECK(caps->feature_count > 0U);
}

namespace {

[[nodiscard]] bool gate_contains(const std::vector<const papa::rules::Rule*>& gate,
                                 std::string_view name) {
    for (const auto* r : gate) { if (r->name() == name) { return true; } }
    return false;
}

// A file-scope rule keyed on a single section name, in the given namespace
[[nodiscard]] std::string section_rule(std::string_view name, std::string_view ns,
                                       std::string_view section) {
    return papa_tests::rule_yaml(name, "file", {"section: " + std::string(section)}, ns);
}

// A file-scope rule that fires when the referenced rule or namespace matched
[[nodiscard]] std::string match_rule(std::string_view name, std::string_view ns,
                                     std::string_view ref) {
    return papa_tests::rule_yaml(name, "file", {"match: " + std::string(ref)}, ns);
}

}  // namespace

TEST_CASE("limitation gate: closure follows a reference by rule name") {
    const auto rs = papa_tests::ruleset({
        section_rule("packer-sig", "anti-analysis/packer/upx", ".upx0"),
        match_rule("lim", "internal/limitation/static", "packer-sig"),
        section_rule("unrelated", "host-interaction/file", ".text")
    });

    const auto gate = papa::capabilities::limitation_gate_rules(rs);
    CHECK(gate_contains(gate, "lim"));
    CHECK(gate_contains(gate, "packer-sig"));
    CHECK_FALSE(gate_contains(gate, "unrelated"));
}

TEST_CASE("limitation gate: closure expands a namespace reference to every rule beneath it") {
    // This is how every real limitation rule is written, so getting it wrong
    // would silently stop packed samples from being detected
    const auto rs = papa_tests::ruleset({
        section_rule("upx", "anti-analysis/packer/upx", ".upx0"),
        section_rule("aspack", "anti-analysis/packer/aspack", ".aspack"),
        section_rule("deep", "anti-analysis/packer/x/y/z", ".deep"),
        section_rule("sibling", "anti-analysis/obfuscation", ".obf"),
        match_rule("lim", "internal/limitation/static", "anti-analysis/packer")
    });

    const auto gate = papa::capabilities::limitation_gate_rules(rs);
    CHECK(gate_contains(gate, "upx"));
    CHECK(gate_contains(gate, "aspack"));
    CHECK(gate_contains(gate, "deep"));      // nested below the referenced prefix
    CHECK_FALSE(gate_contains(gate, "sibling"));  // shares a parent, not the prefix
}

TEST_CASE("limitation gate: closure is transitive") {
    const auto rs = papa_tests::ruleset({
        section_rule("leaf", "a/leaf", ".leaf"),
        match_rule("mid", "a/mid", "leaf"),
        match_rule("lim", "internal/limitation/static", "mid")
    });

    const auto gate = papa::capabilities::limitation_gate_rules(rs);
    CHECK(gate_contains(gate, "lim"));
    CHECK(gate_contains(gate, "mid"));
    CHECK(gate_contains(gate, "leaf"));
}

TEST_CASE("limitation gate: closure keeps topological order") {
    const auto rs = papa_tests::ruleset({
        match_rule("lim", "internal/limitation/static", "mid"),
        match_rule("mid", "a/mid", "leaf"),
        section_rule("leaf", "a/leaf", ".leaf")
    });

    const auto gate = papa::capabilities::limitation_gate_rules(rs);
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
    const auto rs = papa_tests::ruleset({
        section_rule("a", "host-interaction/file", ".text"),
        section_rule("b", "anti-analysis/packer/upx", ".upx0")
    });
    CHECK(papa::capabilities::limitation_gate_rules(rs).empty());
}

TEST_CASE("limitation gate: a near-miss namespace is not treated as a limitation") {
    const auto rs = papa_tests::ruleset({
        section_rule("x", "internal/limitation/static_other", ".text")
    });
    CHECK(papa::capabilities::limitation_gate_rules(rs).empty());
}

TEST_CASE("limitation gate: verdict always agrees with the full file-scope pass") {
    // The gate exists only to answer has_static_limitation
    auto build = [] {
        return papa_tests::ruleset({
            section_rule("upx", "anti-analysis/packer/upx", ".upx0"),
            section_rule("noise1", "host-interaction/file", ".text"),
            section_rule("noise2", "communication/http", ".data"),
            match_rule("lim", "internal/limitation/static", "anti-analysis/packer")
        });
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
        papa_tests::FakeExtractor extractor(c.feats);

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
    const auto rs = papa_tests::ruleset({
        section_rule("decoy", "misc/decoy", ".text"),
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
        "        - match: decoy\n"
    });

    const auto gate = papa::capabilities::limitation_gate_rules(rs);
    CHECK(gate_contains(gate, "lim-not"));
    CHECK(gate_contains(gate, "decoy"));
}

TEST_CASE("limitation gate: verdict agrees with the full pass through a negation") {
    auto build = [] {
        return papa_tests::ruleset({
            section_rule("decoy", "misc/decoy", ".text"),
            section_rule("noise", "host-interaction/file", ".rsrc"),
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
            "        - match: decoy\n"
        });
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
        papa_tests::FakeExtractor extractor(c.feats);
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
        return papa_tests::ruleset({
            section_rule("noise", "host-interaction/file", ".text"),
            section_rule("lim-direct", "internal/limitation/static", ".packed")
        });
    };
    const auto section = [](std::string_view n) -> papa::features::FeaturePtr {
        return std::make_shared<const papa::features::Section>(std::string(n));
    };

    for (const bool packed : {true, false}) {
        CAPTURE(packed);
        const auto rs = build();
        // Built whole rather than by push_back, which trips a GCC 13 -O2 array-bounds
        // false positive
        const std::vector<papa::features::FeaturePtr> feats =
            packed ? std::vector<papa::features::FeaturePtr>{section(".text"), section(".packed")}
                   : std::vector<papa::features::FeaturePtr>{section(".text")};
        papa_tests::FakeExtractor extractor(feats);

        auto gate_caps = papa::capabilities::find_limitation_capabilities(rs, extractor);
        REQUIRE(gate_caps);
        auto full_caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(full_caps);
        CHECK(papa::capabilities::has_static_limitation(rs, *gate_caps) ==
              papa::capabilities::has_static_limitation(rs, *full_caps));
        CHECK(papa::capabilities::has_static_limitation(rs, *gate_caps) == packed);
    }
}
