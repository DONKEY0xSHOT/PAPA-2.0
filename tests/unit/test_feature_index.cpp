#include <ostream>

#include "doctest.h"

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/rules/feature_index.h"
#include "papa/rules/rule.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace papa;
using features::FeaturePtr;
using StatementPtr = std::unique_ptr<engine::Statement>;

constexpr std::size_t kMany = std::numeric_limits<std::size_t>::max();

[[nodiscard]] StatementPtr node(StatementPtr st) { return st; }

[[nodiscard]] StatementPtr node(const FeaturePtr& f) {
    return std::make_unique<engine::FeatureStatement>(f);
}

template <typename... Kids>
[[nodiscard]] std::vector<StatementPtr> kids(Kids&&... k) {
    std::vector<StatementPtr> out;
    (out.push_back(node(std::forward<Kids>(k))), ...);
    return out;
}

// Builders named after the rule keywords so each sample rule reads like its YAML
// Not all_of and any_of, since ADL would hand three-argument calls to the std algorithms
template <typename... Kids>
[[nodiscard]] StatementPtr all(Kids&&... k) {
    return std::make_unique<engine::And>(kids(std::forward<Kids>(k)...));
}

template <typename... Kids>
[[nodiscard]] StatementPtr any(Kids&&... k) {
    return std::make_unique<engine::Or>(kids(std::forward<Kids>(k)...));
}

template <typename... Kids>
[[nodiscard]] StatementPtr at_least(std::size_t n, Kids&&... k) {
    return std::make_unique<engine::Some>(n, kids(std::forward<Kids>(k)...));
}

template <typename... Kids>
[[nodiscard]] StatementPtr opt(Kids&&... k) {
    return at_least(0, std::forward<Kids>(k)...);
}

template <typename Kid>
[[nodiscard]] StatementPtr negate(Kid&& k) {
    return std::make_unique<engine::Not>(node(std::forward<Kid>(k)));
}

[[nodiscard]] StatementPtr count(const FeaturePtr& f, std::size_t min) {
    return std::make_unique<engine::Range>(f, min, kMany);
}

[[nodiscard]] features::Address at(std::uint64_t va) {
    return features::Address{features::AbsoluteVirtualAddress{va}};
}

// Ten features small enough to enumerate every subset
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
    FeaturePtr off_10  = std::make_shared<const features::Offset>(std::int64_t{0x10});
    FeaturePtr foo     = std::make_shared<const features::String>("foo");
    FeaturePtr windows = std::make_shared<const features::Os>("windows");

    [[nodiscard]] std::vector<FeaturePtr> all() const {
        return {api_a, api_b, api_c, mov, loop, num_5, num_big, off_10, foo, windows};
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
    return out;
}

[[nodiscard]] bool selects(const std::vector<const rules::Rule*>& selected,
                           std::string_view                       name) {
    return std::any_of(selected.begin(), selected.end(),
                       [name](const rules::Rule* r) { return r->name() == name; });
}

[[nodiscard]] features::FeatureSet only(const FeaturePtr& f) {
    features::FeatureSet fs;
    fs.add(f, at(0x1000));
    return fs;
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
            fs.add(universe[bit], at(0x1000));
            fs.add(universe[bit], at(0x2000));
        }
        index.select(fs, selected);
        CAPTURE(mask);
        // The rules sit in one array, so ascending pointers mean selection kept the build order
        CHECK(std::is_sorted(selected.begin(), selected.end()));
        for (const rules::Rule* r : order) {
            if (r->statement().evaluate_quick(fs)) { CHECK(selects(selected, r->name())); }
        }
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

    index.select(only(u.mov), selected);
    CHECK_FALSE(selects(selected, "and-api-mnemonic"));   // api A is required too
    CHECK_FALSE(selects(selected, "or-apis"));            // neither api is present

    index.select(only(u.api_b), selected);
    CHECK(selects(selected, "or-apis"));

    index.select(only(u.loop), selected);
    CHECK(selects(selected, "and-optional"));   // an optional block requires nothing

    index.select(only(u.api_c), selected);
    CHECK_FALSE(selects(selected, "and-optional"));   // indexed on loop, not the optional api

    index.select(only(u.api_a), selected);
    CHECK_FALSE(selects(selected, "and-or-min"));   // or scores its weakest branch, so loop wins
    CHECK_FALSE(selects(selected, "and-or-tie"));   // equal scores prefer fewer features, so C

    const features::FeatureSet empty;
    index.select(empty, selected);
    // Only the four always-run rules survive an empty set, so the other 11 are indexed
    CHECK(selected.size() == 4U);
    CHECK(selects(selected, "or-regex-api"));   // a scanning branch keeps the rule always-run
    CHECK(selects(selected, "or-not"));         // so does a branch that requires nothing
    CHECK(selects(selected, "not-root"));
    CHECK(selects(selected, "and-os-not"));     // os is a wildcard, so it is never indexed
}
