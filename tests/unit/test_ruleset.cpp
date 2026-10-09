#include <ostream>

#include "doctest.h"

#include "papa/rules/ruleset.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/rules/parser.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"

#include "test_support.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using papa::ErrorKind;
using papa::engine::FeatureStatement;
using papa::engine::Subscope;
using papa::features::Address;
using papa::features::AbsoluteVirtualAddress;
using papa::features::Api;
using papa::features::FeaturePtr;
using papa::features::FeatureSet;
using papa::features::FeatureTag;
using papa::features::MatchedRule;
using papa::rules::Rule;
using papa::rules::RuleSet;
using papa::rules::Scope;

namespace {

// Verify a topo order: every dependency of B precedes B
[[nodiscard]] bool precedes(std::span<const Rule* const> topo,
                            std::string_view a,
                            std::string_view b) noexcept {
    auto pos_a = std::find_if(topo.begin(), topo.end(),
                              [&](const Rule* r) { return r->name() == a; });
    auto pos_b = std::find_if(topo.begin(), topo.end(),
                              [&](const Rule* r) { return r->name() == b; });
    if (pos_a == topo.end() || pos_b == topo.end()) { return false; }
    return std::distance(topo.begin(), pos_a) < std::distance(topo.begin(), pos_b);
}

}  // namespace

TEST_CASE("ruleset: from_rules with one rule yields find()-able RuleSet") {
    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: solo\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: foo\n"
    });
    CHECK(rs.size() == 1);
    REQUIRE(rs.find("solo") != nullptr);
    CHECK(rs.find("solo")->name() == "solo");
    CHECK(rs.find("absent") == nullptr);
}

TEST_CASE("ruleset: rules_by_scope groups rules by their static scope") {
    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: f-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: a\n",
        "rule:\n"
        "  meta:\n"
        "    name: file-rule\n"
        "    scope: file\n"
        "  features:\n"
        "    - import: kernel32.X\n"
    });

    auto fn_rules   = rs.rules_by_scope(Scope::kFunction);
    auto file_rules = rs.rules_by_scope(Scope::kFile);
    auto bb_rules   = rs.rules_by_scope(Scope::kBasicBlock);

    REQUIRE(fn_rules.size() == 1);
    CHECK(fn_rules[0]->name() == "f-rule");
    REQUIRE(file_rules.size() == 1);
    CHECK(file_rules[0]->name() == "file-rule");
    CHECK(bb_rules.empty());
}

TEST_CASE("ruleset: from_rules drops a rule with an unresolved match, orders the rest after what they match, and rejects duplicate names and cycles") {
    const auto yaml = [](std::string_view name, std::string_view feature,
                         std::string_view ns = {}) {
        return papa_tests::rule_yaml(name, "function", {std::string(feature)}, ns);
    };
    // A pair of rules where the first comes before the second in topological order
    using Order = std::pair<std::string_view, std::string_view>;
    struct Row {
        std::string_view              label;
        std::vector<std::string>      rules;
        std::optional<ErrorKind>      error;
        std::size_t                   size;
        std::vector<std::string_view> absent;
        std::vector<Order>            before;
    };
    const std::vector<Row> rows{
        {"duplicate rule names are rejected", {yaml("dup", "api: a"), yaml("dup", "api: b")},
         ErrorKind::kInvalidRule, 0, {}, {}},
        // Real capa corpora always contain a few rules whose match: targets were skipped
        // earlier in the load (irregular YAML, COM lookups, etc.)
        {"a rule with an unresolved match reference is dropped, not failed",
         {yaml("needs-other", "match: not-a-real-rule")}, std::nullopt, 0, {"needs-other"}, {}},
        {"a known match reference is accepted and ordered",
         {yaml("depends-on-a", "match: rule-a"), yaml("rule-a", "api: foo")}, std::nullopt, 2, {},
         {{"rule-a", "depends-on-a"}}},
        {"a namespace match reference resolves to every namespace member",
         {yaml("depends-on-ns", "match: anti-analysis/vm"),
          yaml("vm-probe-1", "api: kernel32.IsDebuggerPresent", "anti-analysis/vm"),
          yaml("vm-probe-2", "api: kernel32.GetTickCount", "anti-analysis/vm")},
         std::nullopt, 3, {}, {{"vm-probe-1", "depends-on-ns"}, {"vm-probe-2", "depends-on-ns"}}},
        {"a match cycle is rejected", {yaml("a", "match: b"), yaml("b", "match: a")},
         ErrorKind::kCycle, 0, {}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        std::vector<std::unique_ptr<Rule>> rules;
        for (const std::string& y : row.rules) { rules.push_back(papa_tests::rule(y)); }
        const auto rs = RuleSet::from_rules(std::move(rules));
        CHECK(rs.has_value() == !row.error.has_value());
        if (!rs) {
            if (row.error.has_value()) { CHECK(rs.error().kind == *row.error); }
            continue;
        }
        CHECK(rs->size() == row.size);
        for (const std::string_view name : row.absent) { CHECK(rs->find(name) == nullptr); }
        const auto topo = rs->rules_by_scope(Scope::kFunction);
        for (const auto& [first, then] : row.before) {
            CAPTURE(first);
            CHECK(precedes(topo, first, then));
        }
    }
}

TEST_CASE("ruleset: subscope is extracted into a synthetic lib rule") {
    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: parent-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - basic block:\n"
        "      - and:\n"
        "        - characteristic: tight loop\n"
    });

    // Two rules: the parent and the synthetic
    CHECK(rs.size() == 2);
    const Rule* parent = rs.find("parent-rule");
    REQUIRE(parent != nullptr);

    // The parent's statement no longer contains a Subscope
    // It refers to the synthetic via a MatchedRule feature
    const auto* fs_node = dynamic_cast<const FeatureStatement*>(&parent->statement());
    REQUIRE(fs_node != nullptr);
    REQUIRE(fs_node->feature() != nullptr);
    REQUIRE(fs_node->feature()->tag() == FeatureTag::kMatchedRule);

    // The synthetic rule has the parent's name as a prefix and is at basic-block scope
    const auto* mr = static_cast<const MatchedRule*>(fs_node->feature().get());
    const std::string& syn_name = mr->rule_name();
    CHECK(syn_name.rfind("parent-rule/", 0) == 0);
    const Rule* syn = rs.find(syn_name);
    REQUIRE(syn != nullptr);
    CHECK(syn->scope() == Scope::kBasicBlock);
    CHECK(syn->is_lib());
    CHECK(syn->meta().is_subscope_rule);
    REQUIRE(syn->meta().parent.has_value());
    CHECK(*syn->meta().parent == "parent-rule");
}

TEST_CASE("ruleset: deeply nested subscopes spawn a chain of synthetic rules") {
    // function -> basic block -> instruction
    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: deep\n"
        "    scope: function\n"
        "  features:\n"
        "    - basic block:\n"
        "      - instruction:\n"
        "        - api: kernel32.X\n"
    });
    CHECK(rs.size() == 3);

    // Find the BB-scope synthetic
    const Rule* bb_syn = nullptr;
    for (const auto& r : rs.all_rules()) {
        if (r->scope() == Scope::kBasicBlock && r->is_lib()) {
            bb_syn = r.get();
            break;
        }
    }
    REQUIRE(bb_syn != nullptr);

    // Find the instruction-scope synthetic
    const Rule* insn_syn = nullptr;
    for (const auto& r : rs.all_rules()) {
        if (r->scope() == Scope::kInstruction && r->is_lib()) {
            insn_syn = r.get();
            break;
        }
    }
    REQUIRE(insn_syn != nullptr);
}

TEST_CASE("ruleset: match runs every rule at the requested scope") {
    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: hits-foo\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: foo\n",
        "rule:\n"
        "  meta:\n"
        "    name: hits-bar\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: bar\n"
    });

    FeatureSet fs;
    fs.add(std::make_shared<const Api>(std::string("foo")),
           Address{AbsoluteVirtualAddress{0x1000}});

    auto [_fs, matches] = rs.match(Scope::kFunction, std::move(fs),
                                    Address{AbsoluteVirtualAddress{0x1000}});
    CHECK(matches.count("hits-foo") == 1);
    CHECK(matches.count("hits-bar") == 0);
}

TEST_CASE("ruleset: match sees a same-scope match reference under an or") {
    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: rule-a\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: foo\n",
        "rule:\n"
        "  meta:\n"
        "    name: rule-b\n"
        "    scope: function\n"
        "  features:\n"
        "    - or:\n"
        "      - match: rule-a\n"
        "      - api: bar\n"
    });

    // rule-a's match is injected mid-cycle, after the index picked candidates from foo alone
    FeatureSet fs;
    fs.add(std::make_shared<const Api>(std::string("foo")),
           Address{AbsoluteVirtualAddress{0x1000}});

    auto [_fs, matches] = rs.match(Scope::kFunction, std::move(fs),
                                    Address{AbsoluteVirtualAddress{0x1000}});
    CHECK(matches.count("rule-a") == 1);
    CHECK(matches.count("rule-b") == 1);
}

TEST_CASE("ruleset: from_directory loads the .yml and .yaml rules of a tree, skipping a hidden folder, other files and a rule that fails to parse") {
    using papa_tests::rule_yaml;
    using papa_tests::write_file;
    const papa_tests::TempDir dir;
    const auto&               root = dir.path();
    write_file(root / "a.yml", rule_yaml("a", "function", {"api: a"}));
    write_file(root / "b.yaml", rule_yaml("b", "function", {"api: b"}));
    write_file(root / "sub" / "c.yml", rule_yaml("c", "function", {"api: c"}));
    write_file(root / "x.txt", rule_yaml("x", "function", {"api: x"}));
    write_file(root / ".github" / "d.yml", rule_yaml("d", "function", {"api: d"}));
    write_file(root / "bad.yml", "rule:\n  meta: [unclosed\n");

    struct Row {
        std::string_view      label;
        std::filesystem::path path;
        std::string_view      detail;
    };
    const std::vector<Row> rows{
        {"a missing path", root / "missing", "rules path does not exist"},
        {"a file path", root / "a.yml", "rules path is not a directory"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto rs = RuleSet::from_directory(row.path);
        REQUIRE_FALSE(rs.has_value());
        CHECK(rs.error().kind == ErrorKind::kIoError);
        CHECK(rs.error().detail.find(row.detail) != std::string::npos);
    }

    const papa_tests::StreamCapture warnings(std::cerr);
    const auto                      rs = RuleSet::from_directory(root);
    REQUIRE(rs.has_value());
    std::vector<std::string> names;
    for (const auto& r : rs->all_rules()) { names.push_back(r->name()); }
    std::sort(names.begin(), names.end());
    CHECK(names == std::vector<std::string>{"a", "b", "c"});
    CHECK(warnings.text().find("warning: skipping rule") != std::string::npos);
    CHECK(warnings.text().find("bad.yml") != std::string::npos);
    CHECK(warnings.text().find("flow collections are not supported") != std::string::npos);
}
