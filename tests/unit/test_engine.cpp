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
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
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

FeaturePtr api(std::string name) {
    return feat<Api>(std::move(name));
}

// A count(f) from min to max, shared so a table row can hold it
std::shared_ptr<const Statement> range(FeaturePtr f, std::size_t min, std::size_t max) {
    return std::make_shared<const Range>(std::move(f), min, max);
}

}  // namespace

TEST_SUITE("engine.statements") {

TEST_CASE("Each statement evaluates its children and the probe pass agrees with the full evaluation") {
    const auto fs_of = [](std::initializer_list<std::pair<std::string, std::uint64_t>> apis) {
        FeatureSet out;
        for (const auto& [name, at] : apis) { out.add(api(name), va(at)); }
        return out;
    };
    const FeatureSet none;
    const FeatureSet a_b   = fs_of({{"a", 0x1}, {"b", 0x2}});
    const FeatureSet a     = fs_of({{"a", 0x1}});
    const FeatureSet a_b_c = fs_of({{"a", 0x1}, {"b", 0x2}, {"c", 0x3}});
    const FeatureSet x     = fs_of({{"x", 0x1}});
    const FeatureSet x_x   = fs_of({{"x", 0x1}, {"x", 0x2}});
    const FeatureSet hit   = fs_of({{"hit", 0x1}});
    const FeatureSet hi    = fs_of({{"hi", 0x1}});
    FeatureSet seven_x3;
    for (const std::uint64_t at : {0x2000U, 0x2004U, 0x2008U}) { seven_x3.add(feat<Number>(7), va(at)); }
    constexpr std::size_t kNoMax = std::numeric_limits<std::size_t>::max();
    const auto seven  = feat<Number>(7);
    const auto absent = feat<Number>(99);

    struct Row {
        std::string_view                 label;
        std::shared_ptr<const Statement> stmt;
        const FeatureSet*                fs;
        bool                             sc;
        bool                             success;
        std::optional<std::size_t>       children;
        std::optional<std::size_t>       locations;
    };
    const std::vector<Row> rows{
        {"an empty and succeeds vacuously", papa_tests::all(), &none, true, true, 0, {}},
        {"an and of true children succeeds at every location", papa_tests::all(api("a"), api("b")),
         &a_b, false, true, 2, 2},
        // With short-circuit, evaluation stops as soon as a false child is seen
        {"a false child fails an and, which short-circuits after it",
         papa_tests::all(api("a"), api("missing"), api("also-missing")), &a, true, false, 2, {}},
        {"without short-circuit an and evaluates every child",
         papa_tests::all(api("a"), api("missing"), api("also-missing")), &a, false, false, 3, {}},
        {"an or short-circuits after its first true child",
         papa_tests::any(api("miss"), api("hit"), api("third")), &hit, true, true, 2, {}},
        {"an or of false children fails with the full child list", papa_tests::any(api("a"), api("b")),
         &none, true, false, 2, {}},
        {"not of a present feature fails", papa_tests::negate(api("x")), &x, false, false, {}, {}},
        {"not of an absent feature succeeds", papa_tests::negate(api("nope")), &x, false, true, {}, {}},
        // count == 0 is the optional idiom, true even with no children or false ones
        {"an empty optional succeeds", papa_tests::opt(), &none, false, true, {}, {}},
        {"an optional of false children succeeds", papa_tests::opt(api("a"), api("b")), &none, false,
         true, {}, {}},
        {"2 or more with two of three true succeeds",
         papa_tests::at_least(2, api("a"), api("b"), api("miss")), &a_b_c, false, true, {}, {}},
        {"2 or more with one of three true fails",
         papa_tests::at_least(2, api("a"), api("miss"), api("miss")), &a_b_c, false, false, {}, {}},
        // The critical capa edge case: a zero minimum holds when the feature is absent
        {"count of at least 0 holds with the feature absent and no locations",
         range(api("never-seen"), 0, 0xFFFF), &none, false, true, {}, 0},
        {"count of 0 to 2 holds with two", range(api("x"), 0, 2), &x_x, false, true, {}, {}},
        {"count of 0 to 1 fails with two", range(api("x"), 0, 1), &x_x, false, false, {}, {}},
        {"count of at least 2 fails with one", range(api("x"), 2, 10), &x, false, false, {}, {}},
        {"count of at least 1 holds with one at its location", range(api("x"), 1, 10), &x, false,
         true, {}, 1},
        {"a feature statement holds when its feature is present", papa_tests::leaf(api("hi")), &hi,
         false, true, {}, {}},
        {"a feature statement fails when its feature is absent", papa_tests::leaf(api("bye")), &hi,
         false, false, {}, {}},
        // Each bound against a feature present 3 times and one that is absent
        {"count(7) of 0 to 0 fails with three", range(seven, 0, 0), &seven_x3, true, false, {}, {}},
        {"count(7) of 0 to 2 fails with three", range(seven, 0, 2), &seven_x3, true, false, {}, {}},
        {"count(7) of 0 to 3 holds with three", range(seven, 0, 3), &seven_x3, true, true, {}, {}},
        {"count(7) of 1 to 3 holds with three", range(seven, 1, 3), &seven_x3, true, true, {}, {}},
        {"count(7) of 3 to 3 holds with three", range(seven, 3, 3), &seven_x3, true, true, {}, {}},
        {"count(7) of 4 to 10 fails with three", range(seven, 4, 10), &seven_x3, true, false, {}, {}},
        {"count(7) of 0 or more holds with three", range(seven, 0, kNoMax), &seven_x3, true, true, {},
         {}},
        {"count(99) of 0 to 0 holds with none", range(absent, 0, 0), &seven_x3, true, true, {}, {}},
        {"count(99) of 0 to 2 holds with none", range(absent, 0, 2), &seven_x3, true, true, {}, {}},
        {"count(99) of 0 to 3 holds with none", range(absent, 0, 3), &seven_x3, true, true, {}, {}},
        {"count(99) of 1 to 3 fails with none", range(absent, 1, 3), &seven_x3, true, false, {}, {}},
        {"count(99) of 3 to 3 fails with none", range(absent, 3, 3), &seven_x3, true, false, {}, {}},
        {"count(99) of 4 to 10 fails with none", range(absent, 4, 10), &seven_x3, true, false, {}, {}},
        {"count(99) of 0 or more holds with none", range(absent, 0, kNoMax), &seven_x3, true, true,
         {}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const Result r = row.stmt->evaluate(*row.fs, row.sc);
        CHECK(r.success == row.success);
        CHECK(row.stmt->evaluate_quick(*row.fs) == r.success);
        if (row.children.has_value()) { CHECK(r.children.size() == *row.children); }
        if (row.locations.has_value()) { CHECK(r.locations.size() == *row.locations); }
    }
}

TEST_CASE("Evaluating a subscope or building a statement around a null child throws PapaInvariantError") {
    struct Row {
        std::string_view      label;
        std::function<void()> build;
    };
    const std::vector<Row> rows{
        // void() discards the nodiscard return, since the throw is what matters
        {"a subscope reached evaluate",
         [] {
             const Subscope s{rules::Scope::kBasicBlock, api_leaf("x")};
             void(s.evaluate(FeatureSet{}, false));
         }},
        {"not around a null child", [] { const Not n{nullptr}; }},
        {"a feature statement around a null feature", [] { const FeatureStatement f{nullptr}; }},
        {"a range around a null feature", [] { const Range r{nullptr, 0, 1}; }},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK_THROWS_AS(row.build(), PapaInvariantError);
    }
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

TEST_CASE("index_rule_matches adds the rule name and each namespace level at every match address") {
    struct Entry {
        std::string_view name;
        std::size_t      locations;
    };
    struct Row {
        std::string_view           label;
        std::string_view           name;
        std::optional<std::string> ns;
        std::vector<Address>       addresses;
        std::vector<Entry>         entries;
    };
    const std::vector<Row> rows{
        // One entry per distinct name: the rule and its 3 namespace levels
        {"a rule with a three-level namespace", "my-rule", std::string("foo/bar/baz"),
         {va(0x100), va(0x200)},
         {{"my-rule", 2}, {"foo/bar/baz", 2}, {"foo/bar", 2}, {"foo", 2}}},
        {"a rule without a namespace only injects its name", "no-namespace", std::nullopt,
         {va(0x100)}, {{"no-namespace", 1}}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        FeatureSet fs;
        const auto r = papa_tests::make_rule(std::string(row.name), row.ns, rules::Scope::kFile,
                                             std::make_unique<FeatureStatement>(api("anything")));
        index_rule_matches(fs, *r, row.addresses);
        CHECK(fs.size() == row.entries.size());
        for (const Entry& want : row.entries) {
            CAPTURE(want.name);
            const auto it = fs.find(feat<MatchedRule>(std::string(want.name)));
            CHECK(it != fs.end());
            if (it != fs.end()) { CHECK(it->second.size() == want.locations); }
        }
    }
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
