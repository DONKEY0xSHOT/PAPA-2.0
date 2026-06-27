// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the PAPA authors

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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
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
using papa::rules::RuleParser;
using papa::rules::RuleSet;
using papa::rules::Scope;

namespace {

// Build a Rule from a tiny YAML literal so each test reads as a real rule
[[nodiscard]] std::unique_ptr<Rule> make_rule(std::string_view yaml) {
    auto r = RuleParser::parse(yaml, "test.yml");
    REQUIRE(r);
    return std::move(*r);
}

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
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: solo\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: foo\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    CHECK(rs->size() == 1);
    REQUIRE(rs->find("solo") != nullptr);
    CHECK(rs->find("solo")->name() == "solo");
    CHECK(rs->find("absent") == nullptr);
}

TEST_CASE("ruleset: rules_by_scope groups rules by their static scope") {
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: f-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: a\n"));
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: file-rule\n"
        "    scope: file\n"
        "  features:\n"
        "    - import: kernel32.X\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    auto fn_rules   = rs->rules_by_scope(Scope::kFunction);
    auto file_rules = rs->rules_by_scope(Scope::kFile);
    auto bb_rules   = rs->rules_by_scope(Scope::kBasicBlock);

    REQUIRE(fn_rules.size() == 1);
    CHECK(fn_rules[0]->name() == "f-rule");
    REQUIRE(file_rules.size() == 1);
    CHECK(file_rules[0]->name() == "file-rule");
    CHECK(bb_rules.empty());
}

TEST_CASE("ruleset: duplicate rule names are rejected") {
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: dup\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: a\n"));
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: dup\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: b\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE_FALSE(rs);
    CHECK(rs.error().kind == ErrorKind::kInvalidRule);
}

TEST_CASE("ruleset: rule with unresolved match reference is dropped, not failed") {
    // Real CAPA corpora always contain a few rules whose match: targets were
    // skipped earlier in the load (irregular YAML, COM lookups, etc.)
    // The corpus must still load and the dependent rule must simply be absent
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: needs-other\n"
        "    scope: function\n"
        "  features:\n"
        "    - match: not-a-real-rule\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    CHECK(rs->find("needs-other") == nullptr);
    CHECK(rs->size() == 0U);
}

TEST_CASE("ruleset: known match reference is accepted and ordered") {
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: depends-on-a\n"
        "    scope: function\n"
        "  features:\n"
        "    - match: rule-a\n"));
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: rule-a\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: foo\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    auto topo = rs->rules_by_scope(Scope::kFunction);
    CHECK(precedes(topo, "rule-a", "depends-on-a"));
}

TEST_CASE("ruleset: namespace match reference resolves to every namespace member") {
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: depends-on-ns\n"
        "    scope: function\n"
        "  features:\n"
        "    - match: anti-analysis/vm\n"));
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: vm-probe-1\n"
        "    namespace: anti-analysis/vm\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: kernel32.IsDebuggerPresent\n"));
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: vm-probe-2\n"
        "    namespace: anti-analysis/vm\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: kernel32.GetTickCount\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    auto topo = rs->rules_by_scope(Scope::kFunction);
    CHECK(precedes(topo, "vm-probe-1", "depends-on-ns"));
    CHECK(precedes(topo, "vm-probe-2", "depends-on-ns"));
}

TEST_CASE("ruleset: match cycle is rejected") {
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: a\n"
        "    scope: function\n"
        "  features:\n"
        "    - match: b\n"));
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: b\n"
        "    scope: function\n"
        "  features:\n"
        "    - match: a\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE_FALSE(rs);
    CHECK(rs.error().kind == ErrorKind::kCycle);
}

TEST_CASE("ruleset: subscope is extracted into a synthetic lib rule") {
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: parent-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - basic block:\n"
        "      - and:\n"
        "        - characteristic: tight loop\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    // Two rules: the parent and the synthetic
    CHECK(rs->size() == 2);
    const Rule* parent = rs->find("parent-rule");
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
    const Rule* syn = rs->find(syn_name);
    REQUIRE(syn != nullptr);
    CHECK(syn->scope() == Scope::kBasicBlock);
    CHECK(syn->is_lib());
    CHECK(syn->meta().is_subscope_rule);
    REQUIRE(syn->meta().parent.has_value());
    CHECK(*syn->meta().parent == "parent-rule");
}

TEST_CASE("ruleset: deeply nested subscopes spawn a chain of synthetic rules") {
    // function -> basic block -> instruction
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: deep\n"
        "    scope: function\n"
        "  features:\n"
        "    - basic block:\n"
        "      - instruction:\n"
        "        - api: kernel32.X\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    CHECK(rs->size() == 3);

    // Find the BB-scope synthetic
    const Rule* bb_syn = nullptr;
    for (const auto& r : rs->all_rules()) {
        if (r->scope() == Scope::kBasicBlock && r->is_lib()) {
            bb_syn = r.get();
            break;
        }
    }
    REQUIRE(bb_syn != nullptr);

    // Find the instruction-scope synthetic
    const Rule* insn_syn = nullptr;
    for (const auto& r : rs->all_rules()) {
        if (r->scope() == Scope::kInstruction && r->is_lib()) {
            insn_syn = r.get();
            break;
        }
    }
    REQUIRE(insn_syn != nullptr);
}

TEST_CASE("ruleset: match runs every rule at the requested scope") {
    std::vector<std::unique_ptr<Rule>> rules;
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: hits-foo\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: foo\n"));
    rules.push_back(make_rule(
        "rule:\n"
        "  meta:\n"
        "    name: hits-bar\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: bar\n"));

    auto rs = RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    FeatureSet fs;
    fs.add(std::make_shared<const Api>(std::string("foo")),
           Address{AbsoluteVirtualAddress{0x1000}});

    auto [_fs, matches] = rs->match(Scope::kFunction, std::move(fs),
                                    Address{AbsoluteVirtualAddress{0x1000}});
    CHECK(matches.count("hits-foo") == 1);
    CHECK(matches.count("hits-bar") == 0);
}
