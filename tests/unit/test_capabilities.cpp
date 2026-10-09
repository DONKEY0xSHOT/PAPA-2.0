#include <ostream>

#include "doctest.h"

#include "papa/capabilities/common.h"
#include "papa/capabilities/static_.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/file.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/features/extractors/global_.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/extractor.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/pefile.h"
#include "papa/features/extractors/pefile_extractor.h"
#include "papa/loader.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"
#include "papa/render/json.h"
#include "papa/render/result_document.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "pe_builder.h"
#include "test_support.h"

TEST_CASE("capabilities: find_file_capabilities runs file rules over a PE through PefileFeatureExtractor") {
    papa_tests::PeBuilder b;
    b.code    = {0x33, 0xC0, 0xC3};
    b.imports = {{"kernel32.dll", {"CreateFileW"}}};
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    const papa::features::extractors::PefileFeatureExtractor extractor(*img);

    // The extractor hands over the image's base, file and global features unchanged
    CHECK(extractor.get_base_address() == papa_tests::va(img->image_base()));
    CHECK(papa_tests::describe(extractor.extract_file_features()) ==
          papa_tests::describe(papa::features::extractors::pefile::extract_file_features(*img)));
    CHECK(papa_tests::describe(extractor.extract_global_features()) ==
          papa_tests::describe(papa::features::extractors::extract_global_features(*img)));

    const auto rs = papa_tests::ruleset({
        papa_tests::rule_yaml("has-text-section", "file", {"section: .text"}),
        papa_tests::rule_yaml("has-data-section", "file", {"section: .data"}),
    });
    auto file_caps = papa::capabilities::find_file_capabilities(rs, extractor);
    REQUIRE(file_caps);
    REQUIRE(file_caps->matches.size() == 1);
    REQUIRE(file_caps->matches.count("has-text-section") == 1);
    const auto& hits = file_caps->matches.at("has-text-section");
    REQUIRE(hits.size() == 1);
    CHECK(hits[0].first == papa_tests::va(img->image_base()));

    // The distinct file and global features, plus the match the rule injected
    papa::features::FeatureSet distinct;
    distinct.add_all(extractor.extract_file_features());
    distinct.add_all(extractor.extract_global_features());
    CHECK(file_caps->feature_count == distinct.size() + 1U);
}

TEST_CASE("capabilities: has_static_limitation fires at or below internal/limitation/static only") {
    struct Row {
        std::string_view ns;
        bool             limited;
    };
    const std::array<Row, 4> rows{{
        {"host-interaction/file", false},
        {"internal/limitation/static", true},
        {"internal/limitation/static/dotnet", true},
        {"internal/limitation/staticy-thing", false},
    }};
    for (const Row& row : rows) {
        CAPTURE(row.ns);
        const auto rs = papa_tests::ruleset(
            {papa_tests::rule_yaml("r", "file", {"section: .text"}, row.ns)});
        const papa_tests::FakeExtractor extractor(
            {papa_tests::feat<papa::features::Section>(".text")});
        const auto caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(caps);
        REQUIRE(caps->matches.count("r") == 1);
        CHECK(papa::capabilities::has_static_limitation(rs, *caps) == row.limited);
    }
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

// A limitation rule that fires on .data unless the decoy rule matched
constexpr std::string_view kLimitationUnlessDecoy =
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
    "        - match: decoy\n";

// The RuleSet of the rules parsed from yamls, which must parse and link
[[nodiscard]] papa::rules::RuleSet ruleset_of(const std::vector<std::string>& yamls) {
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    for (const std::string& yaml : yamls) { rules.push_back(papa_tests::rule(yaml)); }
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    return std::move(*rs);
}

[[nodiscard]] papa::features::FeaturePtr section(std::string_view n) {
    return std::make_shared<const papa::features::Section>(std::string(n));
}

}  // namespace

TEST_CASE("limitation gate: the closure holds the limitation rules and every rule they reach, by name, namespace or negation") {
    struct Row {
        std::string_view              label;
        std::vector<std::string>      rules;
        std::vector<std::string_view> in_gate;
        std::vector<std::string_view> not_in_gate;
    };
    const std::vector<Row> rows{
        {"a reference by rule name",
         {section_rule("packer-sig", "anti-analysis/packer/upx", ".upx0"),
          match_rule("lim", "internal/limitation/static", "packer-sig"),
          section_rule("unrelated", "host-interaction/file", ".text")},
         {"lim", "packer-sig"}, {"unrelated"}},
        // This is how every real limitation rule is written, so getting it wrong would
        // silently stop packed samples from being detected
        {"a namespace reference expands to every rule beneath it, however deep",
         {section_rule("upx", "anti-analysis/packer/upx", ".upx0"),
          section_rule("aspack", "anti-analysis/packer/aspack", ".aspack"),
          section_rule("deep", "anti-analysis/packer/x/y/z", ".deep"),
          section_rule("sibling", "anti-analysis/obfuscation", ".obf"),
          match_rule("lim", "internal/limitation/static", "anti-analysis/packer")},
         {"lim", "upx", "aspack", "deep"}, {"sibling"}},
        {"the closure is transitive",
         {section_rule("leaf", "a/leaf", ".leaf"), match_rule("mid", "a/mid", "leaf"),
          match_rule("lim", "internal/limitation/static", "mid")},
         {"lim", "mid", "leaf"}, {}},
        {"a corpus with no limitation rule produces an empty gate",
         {section_rule("a", "host-interaction/file", ".text"),
          section_rule("b", "anti-analysis/packer/upx", ".upx0")},
         {}, {"a", "b"}},
        {"a near-miss namespace is not a limitation",
         {section_rule("x", "internal/limitation/static_other", ".text")}, {}, {"x"}},
        // Monotonicity does not hold through a negation
        {"a reference under not: is still in the closure",
         {section_rule("decoy", "misc/decoy", ".text"), std::string(kLimitationUnlessDecoy)},
         {"lim-not", "decoy"}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto rs   = ruleset_of(row.rules);
        const auto gate = papa::capabilities::limitation_gate_rules(rs);
        CHECK(gate.size() == row.in_gate.size());
        for (const std::string_view name : row.in_gate) {
            CAPTURE(name);
            CHECK(gate_contains(gate, name));
        }
        for (const std::string_view name : row.not_in_gate) {
            CAPTURE(name);
            CHECK_FALSE(gate_contains(gate, name));
        }
    }
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

TEST_CASE("limitation gate: the verdict always agrees with the full file-scope pass") {
    // The gate exists only to answer has_static_limitation
    using Corpus = papa::rules::RuleSet (*)();
    const Corpus packer = [] {
        return ruleset_of({section_rule("upx", "anti-analysis/packer/upx", ".upx0"),
                           section_rule("noise1", "host-interaction/file", ".text"),
                           section_rule("noise2", "communication/http", ".data"),
                           match_rule("lim", "internal/limitation/static", "anti-analysis/packer")});
    };
    const Corpus negation = [] {
        return ruleset_of({section_rule("decoy", "misc/decoy", ".text"),
                           section_rule("noise", "host-interaction/file", ".rsrc"),
                           std::string(kLimitationUnlessDecoy)});
    };
    const Corpus direct = [] {
        return ruleset_of({section_rule("noise", "host-interaction/file", ".text"),
                           section_rule("lim-direct", "internal/limitation/static", ".packed")});
    };
    struct Row {
        std::string_view                        label;
        Corpus                                  corpus;
        std::vector<papa::features::FeaturePtr> feats;
        bool                                    limited;
    };
    const std::vector<Row> rows{
        {"a packed sample", packer, {section(".upx0"), section(".text")}, true},
        {"a clean sample", packer, {section(".text"), section(".data")}, false},
        {"no features at all", packer, {}, false},
        {"only unrelated matches", packer, {section(".data")}, false},
        // .data present and decoy absent, so the negation holds and it fires
        {".data only, through a negation", negation, {section(".data")}, true},
        // decoy matches, so the negation fails and it must not fire. This is the case
        // that breaks if a negated reference is left out of the gate
        {".data and .text, through a negation", negation, {section(".data"), section(".text")},
         false},
        {".text only, through a negation", negation, {section(".text")}, false},
        {"nothing, through a negation", negation, {}, false},
        {"a limitation rule with no match reference fires", direct,
         {section(".text"), section(".packed")}, true},
        {"a limitation rule with no match reference stays quiet", direct, {section(".text")},
         false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto rs = row.corpus();
        const papa_tests::FakeExtractor extractor(row.feats);
        const auto gate_caps = papa::capabilities::find_limitation_capabilities(rs, extractor);
        REQUIRE(gate_caps);
        const auto full_caps = papa::capabilities::find_file_capabilities(rs, extractor);
        REQUIRE(full_caps);
        const bool via_gate = papa::capabilities::has_static_limitation(rs, *gate_caps);
        CHECK(via_gate == papa::capabilities::has_static_limitation(rs, *full_caps));
        CHECK(via_gate == row.limited);
    }
}

TEST_CASE("capabilities: one, four and automatic worker threads give byte-identical reports") {
    namespace pn = papa::features::extractors::papa_native;
    // Four function shapes, repeated so the image has work for four workers at once
    const std::vector<std::vector<std::uint8_t>> shapes{
        {0x33, 0xC0, 0xC3},                                            // xor eax, eax | ret
        {0xB8, 0x03, 0x00, 0x00, 0x00, 0xFF, 0xC8, 0x75, 0xFC, 0xC3},  // L: dec eax | jnz L
        {0x48, 0x33, 0xCA, 0xC3},                                      // xor rcx, rdx | ret
        {0xB8, 0x78, 0x56, 0x34, 0x12, 0xC3},                          // mov eax, 0x12345678
    };
    papa_tests::PeBuilder b;
    b.x64 = true;
    for (std::size_t i = 0; i < 160; ++i) { b.add_function(shapes[i % shapes.size()]); }
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    const pn::flirt::FlirtSignatureSet no_sigs;
    auto backend = pn::PapaNativeBackend::build(*img, no_sigs);
    REQUIRE(backend.has_value());
    const pn::PapaNativeStaticExtractor extractor(std::move(*backend));
    REQUIRE(extractor.get_functions().size() == 160U);

    // A rule at every scope, joined by match references within and across scopes
    const auto rs = papa_tests::ruleset({
        papa_tests::rule_yaml("nzxor", "instruction", {"characteristic: nzxor"}),
        papa_tests::rule_yaml("tight-loop", "basic block", {"characteristic: tight loop"}),
        papa_tests::rule_yaml("magic", "function", {"number: 0x12345678"}, "test/magic"),
        papa_tests::rule_yaml("loop-or-xor", "function",
                              {"or:\n      - match: nzxor\n      - match: tight-loop"}),
        papa_tests::rule_yaml("file-magic", "file", {"match: test/magic"}),
        papa_tests::rule_yaml("has-text", "file", {"section: .text"}),
    });
    const auto report = [&](unsigned threads) {
        const auto caps =
            papa::capabilities::static_::find_static_capabilities(rs, extractor, threads);
        REQUIRE(caps.has_value());
        auto meta = papa::collect_metadata("sample.exe", {"sample.exe"}, {}, *img, *caps);
        meta.timestamp = "2026-01-01T00:00:00Z";
        return papa::render::json::render_to_string(
            papa::render::build_document(std::move(meta), rs, caps->all_matches), false);
    };

    const std::string serial = report(1U);
    for (const std::string_view name :
         {"nzxor", "tight-loop", "magic", "loop-or-xor", "file-magic", "has-text"}) {
        CAPTURE(name);
        CHECK(serial.find("\"" + std::string(name) + "\":{") != std::string::npos);
    }
    CHECK(report(4U) == serial);
    CHECK(report(0U) == serial);
}

namespace {

// A fake extractor with empty functions, the one at index throw_at failing to extract
class ThrowingExtractor final : public papa_tests::FakeExtractor {
public:
    ThrowingExtractor(std::size_t functions, std::size_t throw_at)
        : FakeExtractor({}, std::vector<std::vector<papa::features::FeaturePtr>>(functions)),
          throw_at_(papa_tests::va(kFirstFunction + 0x10U * throw_at)) {}

    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_function_features(const papa::features::extractors::FunctionHandle& fh) const override {
        if (fh.addr == throw_at_) { throw std::runtime_error("function 57 failed"); }
        return FakeExtractor::extract_function_features(fh);
    }

private:
    papa::features::Address throw_at_;
};

}  // namespace

TEST_CASE("capabilities: an exception in one function reaches the caller with any worker count") {
    const auto rs =
        papa_tests::ruleset({papa_tests::rule_yaml("any-api", "function", {"api: a"})});
    const ThrowingExtractor extractor(128U, 57U);
    for (const unsigned threads : {1U, 4U, 0U}) {
        CAPTURE(threads);
        CHECK_THROWS_WITH_AS(
            (void)papa::capabilities::static_::find_static_capabilities(rs, extractor, threads),
            "function 57 failed", std::runtime_error);
    }
}
