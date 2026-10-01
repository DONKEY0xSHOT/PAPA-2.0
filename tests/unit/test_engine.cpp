#include <ostream>

#include "doctest.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"

#include "test_support.h"

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace papa;
using namespace papa::engine;
using namespace papa::features;

using papa_tests::feat;
using papa_tests::feature_set;
using papa_tests::leaf;
using papa_tests::va;

namespace {

std::unique_ptr<Statement> api_leaf(std::string name) {
    return leaf(feat<Api>(std::move(name)));
}

}  // namespace

TEST_SUITE("engine.statements") {

TEST_CASE("And: empty children succeed vacuously") {
    And s{{}};
    auto r = s.evaluate(FeatureSet{}, /*sc=*/true);
    CHECK(r.success);
    CHECK(r.children.empty());
}

TEST_CASE("And: all-true children succeed") {
    auto fs = feature_set({
        {feat<Api>(std::string("a")), va(0x1)},
        {feat<Api>(std::string("b")), va(0x2)},
    });

    std::vector<std::unique_ptr<Statement>> kids;
    kids.push_back(api_leaf("a"));
    kids.push_back(api_leaf("b"));
    And s{std::move(kids)};
    auto r = s.evaluate(fs, /*sc=*/false);
    CHECK(r.success);
    CHECK(r.children.size() == 2);
    CHECK(r.locations.size() == 2);
}

TEST_CASE("And: any-false fails and short-circuits") {
    auto fs = feature_set({
        {feat<Api>(std::string("a")), va(0x1)},
    });

    std::vector<std::unique_ptr<Statement>> kids;
    kids.push_back(api_leaf("a"));
    kids.push_back(api_leaf("missing"));
    kids.push_back(api_leaf("also-missing"));
    And s{std::move(kids)};

    auto r_sc = s.evaluate(fs, /*sc=*/true);
    CHECK_FALSE(r_sc.success);
    // With short-circuit, evaluation stops as soon as a false child is seen
    CHECK(r_sc.children.size() == 2);

    auto r_full = s.evaluate(fs, /*sc=*/false);
    CHECK_FALSE(r_full.success);
    CHECK(r_full.children.size() == 3);
}

TEST_CASE("Or: first-true short-circuits") {
    auto fs = feature_set({
        {feat<Api>(std::string("hit")), va(0x1)},
    });

    std::vector<std::unique_ptr<Statement>> kids;
    kids.push_back(api_leaf("miss"));
    kids.push_back(api_leaf("hit"));
    kids.push_back(api_leaf("third"));
    Or s{std::move(kids)};

    auto r = s.evaluate(fs, /*sc=*/true);
    CHECK(r.success);
    CHECK(r.children.size() == 2);  // stopped after first true
}

TEST_CASE("Or: all-false fails with full child list") {
    std::vector<std::unique_ptr<Statement>> kids;
    kids.push_back(api_leaf("a"));
    kids.push_back(api_leaf("b"));
    Or s{std::move(kids)};

    auto r = s.evaluate(FeatureSet{}, /*sc=*/true);
    CHECK_FALSE(r.success);
    CHECK(r.children.size() == 2);
}

TEST_CASE("Not negates its single child") {
    auto fs = feature_set({
        {feat<Api>(std::string("x")), va(0x1)},
    });

    Not present{api_leaf("x")};
    CHECK_FALSE(present.evaluate(fs, false).success);

    Not absent{api_leaf("nope")};
    CHECK(absent.evaluate(fs, false).success);
}

TEST_CASE("Some: count == 0 is the optional idiom and is always true") {
    // Even with no children, count==0 must succeed
    Some empty_opt{0, {}};
    CHECK(empty_opt.evaluate(FeatureSet{}, false).success);

    // With some false children, still true
    std::vector<std::unique_ptr<Statement>> kids;
    kids.push_back(api_leaf("a"));
    kids.push_back(api_leaf("b"));
    Some opt{0, std::move(kids)};
    CHECK(opt.evaluate(FeatureSet{}, false).success);
}

TEST_CASE("Some: count == 2 requires at least two true children") {
    auto fs = feature_set({
        {feat<Api>(std::string("a")), va(0x1)},
        {feat<Api>(std::string("b")), va(0x2)},
        {feat<Api>(std::string("c")), va(0x3)},
    });

    // Exactly two matches of three must succeed
    std::vector<std::unique_ptr<Statement>> kids;
    kids.push_back(api_leaf("a"));
    kids.push_back(api_leaf("b"));
    kids.push_back(api_leaf("miss"));
    Some s{2, std::move(kids)};
    CHECK(s.evaluate(fs, false).success);

    // One match of three fails
    std::vector<std::unique_ptr<Statement>> kids2;
    kids2.push_back(api_leaf("a"));
    kids2.push_back(api_leaf("miss"));
    kids2.push_back(api_leaf("miss"));
    Some s2{2, std::move(kids2)};
    CHECK_FALSE(s2.evaluate(fs, false).success);
}

TEST_CASE("Range: min == 0 absent feature is vacuously true with empty locations") {
    // Critical CAPA edge case, a zero minimum count holds when the feature is absent
    auto fp = feat<Api>(std::string("never-seen"));
    Range r{fp, /*min=*/0, /*max=*/0xFFFF};

    auto result = r.evaluate(FeatureSet{}, false);
    CHECK(result.success);
    CHECK(result.locations.empty());
}

TEST_CASE("Range: min == 0 with cnt > 0 checks the upper bound") {
    auto fp = feat<Api>(std::string("x"));
    auto fs = feature_set({
        {feat<Api>(std::string("x")), va(0x1)},
        {feat<Api>(std::string("x")), va(0x2)},
    });

    Range in_range{fp, 0, 2};
    CHECK(in_range.evaluate(fs, false).success);

    Range over_max{fp, 0, 1};
    CHECK_FALSE(over_max.evaluate(fs, false).success);
}

TEST_CASE("Range: min > 0 with insufficient count fails") {
    auto fp = feat<Api>(std::string("x"));
    auto fs = feature_set({
        {feat<Api>(std::string("x")), va(0x1)},
    });

    Range need_two{fp, 2, 10};
    CHECK_FALSE(need_two.evaluate(fs, false).success);

    Range need_one{fp, 1, 10};
    auto ok = need_one.evaluate(fs, false);
    CHECK(ok.success);
    CHECK(ok.locations.size() == 1);
}

TEST_CASE("Subscope evaluation throws PapaInvariantError") {
    auto inner = api_leaf("x");
    Subscope s{rules::Scope::kBasicBlock, std::move(inner)};
    // void() discards the nodiscard return
    // The throw is what we care about
    CHECK_THROWS_AS(void(s.evaluate(FeatureSet{}, false)), PapaInvariantError);
}

TEST_CASE("FeatureStatement delegates to the wrapped feature") {
    auto fs = feature_set({
        {feat<Api>(std::string("hi")), va(0x1)},
    });

    FeatureStatement f{feat<Api>(std::string("hi"))};
    CHECK(f.evaluate(fs, false).success);

    FeatureStatement g{feat<Api>(std::string("bye"))};
    CHECK_FALSE(g.evaluate(fs, false).success);
}

TEST_CASE("Null children in Not / FeatureStatement constructors reject") {
    CHECK_THROWS_AS(Not{nullptr}, PapaInvariantError);
    CHECK_THROWS_AS(FeatureStatement{nullptr}, PapaInvariantError);
    CHECK_THROWS_AS((Range{nullptr, 0, 1}), PapaInvariantError);
}

TEST_CASE("Each statement reports its kind, and Some with count 0 is optional") {
    const And              and_st{{}};
    const Or               or_st{{}};
    const Not              not_st{api_leaf("a")};
    const Some             some_st{2, {}};
    const Some             optional_st{0, {}};
    const Range            range_st{feat<Api>(std::string("a")), 1, 2};
    const Subscope         subscope_st{rules::Scope::kBasicBlock, api_leaf("a")};
    const FeatureStatement feature_st{feat<Api>(std::string("a"))};

    CHECK(and_st.kind() == StatementKind::kAnd);
    CHECK(or_st.kind() == StatementKind::kOr);
    CHECK(not_st.kind() == StatementKind::kNot);
    CHECK(some_st.kind() == StatementKind::kSome);
    CHECK(optional_st.kind() == StatementKind::kOptional);
    CHECK(range_st.kind() == StatementKind::kRange);
    CHECK(subscope_st.kind() == StatementKind::kSubscope);
    CHECK(feature_st.kind() == StatementKind::kFeature);

    // The names are output, so they stay pinned alongside the kinds
    CHECK(some_st.name() == "some");
    CHECK(optional_st.name() == "optional");
}

}  // TEST_SUITE engine.statements

TEST_SUITE("engine.match") {

TEST_CASE("index_rule_matches adds the rule name and each namespace level") {
    auto fs = FeatureSet{};
    auto inner = std::make_unique<FeatureStatement>(
        feat<Api>(std::string("anything")));
    const auto r = papa_tests::make_rule(
        "my-rule",
        std::string("foo/bar/baz"),
        rules::Scope::kFile,
        std::move(inner));

    const std::array<Address, 2> addrs{va(0x100), va(0x200)};
    index_rule_matches(fs, *r, addrs);

    // One entry per distinct name: "my-rule" + 3 namespace levels
    CHECK(fs.size() == 4);

    auto probe_name = std::make_shared<const MatchedRule>(std::string("my-rule"));
    auto it_name = fs.find(probe_name);
    REQUIRE(it_name != fs.end());
    CHECK(it_name->second.size() == 2);

    auto probe_ns_leaf = std::make_shared<const MatchedRule>(std::string("foo/bar/baz"));
    auto it_leaf = fs.find(probe_ns_leaf);
    REQUIRE(it_leaf != fs.end());
    CHECK(it_leaf->second.size() == 2);

    auto probe_ns_mid = std::make_shared<const MatchedRule>(std::string("foo/bar"));
    REQUIRE(fs.find(probe_ns_mid) != fs.end());

    auto probe_ns_root = std::make_shared<const MatchedRule>(std::string("foo"));
    REQUIRE(fs.find(probe_ns_root) != fs.end());
}

TEST_CASE("Rule without namespace only injects the rule name") {
    FeatureSet fs;
    auto inner = std::make_unique<FeatureStatement>(
        feat<Api>(std::string("x")));
    const auto r = papa_tests::make_rule(
        "no-namespace",
        std::nullopt,
        rules::Scope::kFile,
        std::move(inner));

    const std::array<Address, 1> addrs{va(0x100)};
    index_rule_matches(fs, *r, addrs);
    CHECK(fs.size() == 1);
}

TEST_CASE("match walks topologically ordered rules and publishes MatchedRule features") {
    // Build a feature set and two rules, where rule-2 depends on rule-1 via match
    FeatureSet fs0;
    fs0.add(feat<Api>(std::string("CreateFile")), va(0x1000));

    // Rule 1: matches "api: CreateFile"
    auto rule1 = papa_tests::make_rule(
        "matches-createfile",
        std::nullopt,
        rules::Scope::kFile,
        std::make_unique<FeatureStatement>(feat<Api>(std::string("CreateFile"))));

    // Rule 2: matches only if Rule 1 has matched
    // Uses "match: matches-createfile"
    auto rule2 = papa_tests::make_rule(
        "depends-on-rule1",
        std::nullopt,
        rules::Scope::kFile,
        std::make_unique<FeatureStatement>(
            feat<MatchedRule>(std::string("matches-createfile"))));

    const std::array<const rules::Rule*, 2> topo{rule1.get(), rule2.get()};

    auto [fs_out, matches] = match(topo, std::move(fs0), va(0x0));

    CHECK(matches.size() == 2);
    CHECK(matches.count("matches-createfile") == 1);
    CHECK(matches.count("depends-on-rule1")   == 1);

    // MatchedRule must have been injected so the later rule could resolve
    auto probe = std::make_shared<const MatchedRule>(std::string("matches-createfile"));
    CHECK(fs_out.find(probe) != fs_out.end());
}

TEST_CASE("match stops early on rules that cannot succeed") {
    auto rule = papa_tests::make_rule(
        "never-matches",
        std::nullopt,
        rules::Scope::kFile,
        std::make_unique<FeatureStatement>(feat<Api>(std::string("absent"))));

    const std::array<const rules::Rule*, 1> topo{rule.get()};
    auto [fs_out, matches] = match(topo, FeatureSet{}, va(0x0));

    CHECK(matches.empty());
    CHECK(fs_out.empty());
}

}  // TEST_SUITE engine.match
