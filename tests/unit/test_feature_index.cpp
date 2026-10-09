#include <ostream>

#include "doctest.h"

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/features/basic_block.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/features/insn.h"
#include "papa/rules/feature_index.h"
#include "papa/rules/rule.h"

#include "test_support.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace papa;
using features::FeaturePtr;
using StatementPtr = std::unique_ptr<engine::Statement>;
using papa_tests::all;
using papa_tests::any;
using papa_tests::at_least;
using papa_tests::count;
using papa_tests::feature_set;
using papa_tests::negate;
using papa_tests::opt;
using papa_tests::va;

// Fourteen features, few enough to enumerate every subset, covering every scored family
struct Universe {
    FeaturePtr api_a   = std::make_shared<const features::Api>("A");
    FeaturePtr api_b   = std::make_shared<const features::Api>("B");
    FeaturePtr api_c   = std::make_shared<const features::Api>("C");
    FeaturePtr mov     = std::make_shared<const features::Mnemonic>("mov");
    FeaturePtr loop    = std::make_shared<const features::Characteristic>("loop");
    FeaturePtr num_5   = std::make_shared<const features::Number>(
        features::Number::Value{std::uint64_t{5}});
    FeaturePtr num_big = std::make_shared<const features::Number>(
        features::Number::Value{std::uint64_t{0x12345678}});
    FeaturePtr num_neg = std::make_shared<const features::Number>(
        features::Number::Value{std::int64_t{-1}});
    FeaturePtr opnum   = std::make_shared<const features::OperandNumber>(
        std::size_t{1}, features::OperandNumber::Value{std::uint64_t{0x10}});
    FeaturePtr off_10  = std::make_shared<const features::Offset>(std::int64_t{0x10});
    FeaturePtr foo     = std::make_shared<const features::String>("foo");
    FeaturePtr exp     = std::make_shared<const features::Export>("Exp");
    FeaturePtr bb      = std::make_shared<const features::BasicBlock>();
    FeaturePtr pe      = std::make_shared<const features::Format>("pe");

    [[nodiscard]] std::vector<FeaturePtr> all() const {
        return {api_a, api_b, api_c, mov, loop, num_5, num_big,
                num_neg, opnum, off_10, foo, exp, bb, pe};
    }
};

[[nodiscard]] std::vector<rules::Rule> sample_rules(const Universe& u) {
    std::vector<rules::Rule> out;
    const auto add = [&out](std::string name, StatementPtr st) {
        rules::RuleMeta meta;
        meta.name = std::move(name);
        out.emplace_back(std::move(meta), std::move(st), std::string{});
    };
    const auto regex  = [] { return std::make_shared<const features::Regex>("/fo+/"); };
    const auto os_any = [] { return std::make_shared<const features::Os>("any"); };
    const auto arch   = [] { return std::make_shared<const features::Arch>("amd64"); };
    const auto substring = [] { return std::make_shared<const features::Substring>("oo"); };
    const auto bytes = [] {
        return std::make_shared<const features::Bytes>(papa_tests::byte_vec({0x90, 0x90}));
    };
    const auto matched = [] { return std::make_shared<const features::MatchedRule>("x"); };
    const auto dbl = [] {
        return std::make_shared<const features::Number>(features::Number::Value{1.5});
    };
    const auto neg_big = [] {
        return std::make_shared<const features::Number>(
            features::Number::Value{std::int64_t{-0x10000}});
    };
    add("and-api-mnemonic", all(u.api_a, u.mov));
    add("or-apis",          any(u.api_a, u.api_b));
    add("and-optional",     all(u.loop, opt(u.api_c)));
    add("and-not",          all(negate(u.api_a), u.mov));
    add("count-zero-min",   all(count(u.api_b, 0), u.num_5));
    add("count-positive",   count(u.api_c, 2));
    add("and-regex-number", all(regex(), u.num_5));
    add("or-regex-api",     any(regex(), u.api_a));
    add("some-two",         at_least(2, u.api_a, u.api_b, u.api_c));
    add("nested",           all(any(u.api_b, u.num_big), u.off_10));
    add("or-not",           any(negate(u.api_a), u.api_b));
    add("not-root",         negate(u.api_a));
    add("and-os-not",       all(os_any(), negate(u.api_a)));
    add("and-or-min",       all(any(u.api_a, u.mov), u.loop));
    add("and-or-tie",       all(any(u.api_a, u.api_b), u.api_c));
    add("and-neg-export",   all(u.num_neg, u.exp));
    add("and-negbig-api",   all(neg_big(), u.api_c));
    add("and-double-mov",   all(dbl(), u.mov));
    add("and-string-api",   all(u.foo, u.api_a));
    add("and-opnum-bb",     all(u.opnum, u.bb));
    add("and-format-bb",    all(u.pe, u.bb));
    add("format-only",      all(u.pe));
    add("or-arch-api",      any(arch(), u.api_b));
    add("and-scan-export",  all(bytes(), substring(), u.exp));
    add("and-match-mov",    all(matched(), u.mov));
    return out;
}

[[nodiscard]] bool selects(const std::vector<const rules::Rule*>& selected,
                           std::string_view                       name) {
    return std::any_of(selected.begin(), selected.end(),
                       [name](const rules::Rule* r) { return r->name() == name; });
}

}  // namespace

TEST_CASE("feature_index: select keeps every rule whose probe succeeds, in order") {
    const Universe u;
    const auto     all_rules = sample_rules(u);
    std::vector<const rules::Rule*> order;
    for (const auto& r : all_rules) { order.push_back(&r); }
    rules::RuleFeatureIndex index;
    index.build(order);

    const auto universe = u.all();
    std::vector<const rules::Rule*> selected;
    for (std::size_t mask = 0; mask < (std::size_t{1} << universe.size()); ++mask) {
        features::FeatureSet fs;
        for (std::size_t bit = 0; bit < universe.size(); ++bit) {
            if ((mask & (std::size_t{1} << bit)) == 0U) { continue; }
            // Two sites so count(min 2) can succeed
            fs.add(universe[bit], va(0x1000));
            fs.add(universe[bit], va(0x2000));
        }
        index.select(fs, selected);
        CAPTURE(mask);
        // The rules sit in one array, so ascending pointers mean selection kept the build order
        CHECK(std::is_sorted(selected.begin(), selected.end()));
        std::string dropped;
        for (const rules::Rule* r : order) {
            if (r->statement().evaluate_quick(fs) && !selects(selected, r->name())) {
                dropped.append(r->name()).append(" ");
            }
        }
        CHECK(dropped.empty());
    }
}

TEST_CASE("feature_index: prunes by each rule's most selective required feature") {
    const Universe u;
    const auto     all_rules = sample_rules(u);
    std::vector<const rules::Rule*> order;
    for (const auto& r : all_rules) { order.push_back(&r); }
    rules::RuleFeatureIndex index;
    index.build(order);
    std::vector<const rules::Rule*> selected;

    index.select(feature_set({{u.mov, va(0x1000)}}), selected);
    CHECK_FALSE(selects(selected, "and-api-mnemonic"));   // api A is required too
    CHECK_FALSE(selects(selected, "or-apis"));            // neither api is present

    index.select(feature_set({{u.api_b, va(0x1000)}}), selected);
    CHECK(selects(selected, "or-apis"));

    index.select(feature_set({{u.loop, va(0x1000)}}), selected);
    CHECK(selects(selected, "and-optional"));   // an optional block requires nothing

    index.select(feature_set({{u.api_c, va(0x1000)}}), selected);
    CHECK_FALSE(selects(selected, "and-optional"));   // indexed on loop, not the optional api

    index.select(feature_set({{u.api_a, va(0x1000)}}), selected);
    CHECK_FALSE(selects(selected, "and-or-min"));   // or scores its weakest branch, so loop wins
    CHECK_FALSE(selects(selected, "and-or-tie"));   // equal scores prefer fewer features, so C
    CHECK_FALSE(selects(selected, "and-string-api"));   // a string, at 9, outscores the api

    index.select(feature_set({{u.num_neg, va(0x1000)}}), selected);
    CHECK_FALSE(selects(selected, "and-neg-export"));   // a small negative number scores 3

    index.select(feature_set({{u.exp, va(0x1000)}}), selected);
    CHECK(selects(selected, "and-neg-export"));         // so the export, at 7, is chosen
    CHECK(selects(selected, "and-scan-export"));        // scanning leaves are never chosen

    index.select(feature_set({{u.api_c, va(0x1000)}}), selected);
    CHECK(selects(selected, "and-negbig-api"));         // a large negative number scores 7

    index.select(feature_set({{u.mov, va(0x1000)}}), selected);
    CHECK_FALSE(selects(selected, "and-double-mov"));   // a double scores 7, above mov
    CHECK(selects(selected, "and-match-mov"));          // match: is never chosen

    index.select(feature_set({{u.bb, va(0x1000)}}), selected);
    CHECK_FALSE(selects(selected, "and-opnum-bb"));     // an operand number outscores a block
    CHECK(selects(selected, "and-format-bb"));          // a block outscores the format

    index.select(feature_set({{u.pe, va(0x1000)}}), selected);
    CHECK(selects(selected, "format-only"));            // a lone format is still indexed
    CHECK_FALSE(selects(selected, "and-format-bb"));

    const features::FeatureSet empty;
    index.select(empty, selected);
    // Only the five always-run rules survive an empty set, so the other 20 are indexed
    CHECK(selected.size() == 5U);
    CHECK(selects(selected, "or-regex-api"));   // a scanning branch keeps the rule always-run
    CHECK(selects(selected, "or-not"));         // so does a branch that requires nothing
    CHECK(selects(selected, "not-root"));
    CHECK(selects(selected, "and-os-not"));     // os is a wildcard, so it is never indexed
    CHECK(selects(selected, "or-arch-api"));    // arch is never indexed either
}
