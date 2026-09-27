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

[[nodiscard]] StatementPtr leaf(FeaturePtr f) {
    return std::make_unique<engine::FeatureStatement>(std::move(f));
}

template <typename... Kids>
[[nodiscard]] std::vector<StatementPtr> kids(Kids... k) {
    std::vector<StatementPtr> out;
    (out.push_back(std::move(k)), ...);
    return out;
}

[[nodiscard]] features::Address at(std::uint64_t va) {
    return features::Address{features::AbsoluteVirtualAddress{va}};
}

// Nine features small enough to enumerate every subset
struct Universe {
    FeaturePtr api_a   = std::make_shared<const features::Api>("A");
    FeaturePtr api_b   = std::make_shared<const features::Api>("B");
    FeaturePtr api_c   = std::make_shared<const features::Api>("C");
    FeaturePtr mov     = std::make_shared<const features::Mnemonic>("mov");
    FeaturePtr loop    = std::make_shared<const features::Characteristic>("loop");
    FeaturePtr num_5   = std::make_shared<const features::Number>(features::Number::Value{std::uint64_t{5}});
    FeaturePtr num_big = std::make_shared<const features::Number>(features::Number::Value{std::uint64_t{0x12345678}});
    FeaturePtr off_10  = std::make_shared<const features::Offset>(std::int64_t{0x10});
    FeaturePtr foo     = std::make_shared<const features::String>("foo");

    [[nodiscard]] std::vector<FeaturePtr> all() const {
        return {api_a, api_b, api_c, mov, loop, num_5, num_big, off_10, foo};
    }
};

[[nodiscard]] std::vector<rules::Rule> sample_rules(const Universe& u) {
    std::vector<rules::Rule> out;
    const auto add = [&out](std::string name, StatementPtr st) {
        rules::RuleMeta meta;
        meta.name = std::move(name);
        out.emplace_back(std::move(meta), std::move(st), std::string{});
    };
    const auto regex = [] { return std::make_shared<const features::Regex>("/fo+/"); };
    add("and-api-mnemonic", std::make_unique<engine::And>(kids(leaf(u.api_a), leaf(u.mov))));
    add("or-apis",          std::make_unique<engine::Or>(kids(leaf(u.api_a), leaf(u.api_b))));
    add("and-optional",     std::make_unique<engine::And>(kids(
                                leaf(u.loop),
                                std::make_unique<engine::Some>(0U, kids(leaf(u.api_c))))));
    add("and-not",          std::make_unique<engine::And>(kids(
                                std::make_unique<engine::Not>(leaf(u.api_a)), leaf(u.mov))));
    add("count-zero-min",   std::make_unique<engine::And>(kids(
                                std::make_unique<engine::Range>(u.api_b, 0U, kMany), leaf(u.num_5))));
    add("count-positive",   std::make_unique<engine::Range>(u.api_c, 2U, kMany));
    add("and-regex-number", std::make_unique<engine::And>(kids(leaf(regex()), leaf(u.num_5))));
    add("or-regex-api",     std::make_unique<engine::Or>(kids(leaf(regex()), leaf(u.api_a))));
    add("some-two",         std::make_unique<engine::Some>(2U, kids(
                                leaf(u.api_a), leaf(u.api_b), leaf(u.api_c))));
    add("nested",           std::make_unique<engine::And>(kids(
                                std::make_unique<engine::Or>(kids(leaf(u.api_b), leaf(u.num_big))),
                                leaf(u.off_10))));
    return out;
}

[[nodiscard]] bool selects(const std::vector<const rules::Rule*>& selected, std::string_view name) {
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
            fs.add(universe[bit], at(0x1000));
            fs.add(universe[bit], at(0x2000));
        }
        index.select(fs, selected);
        CAPTURE(mask);
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

    features::FeatureSet only_mov;
    only_mov.add(u.mov, at(0x1000));
    index.select(only_mov, selected);
    CHECK_FALSE(selects(selected, "and-api-mnemonic"));   // api A is required too
    CHECK_FALSE(selects(selected, "or-apis"));            // neither api is present

    features::FeatureSet only_b;
    only_b.add(u.api_b, at(0x1000));
    index.select(only_b, selected);
    CHECK(selects(selected, "or-apis"));

    features::FeatureSet only_loop;
    only_loop.add(u.loop, at(0x1000));
    index.select(only_loop, selected);
    CHECK(selects(selected, "and-optional"));   // an optional block requires nothing

    const features::FeatureSet empty;
    index.select(empty, selected);
    CHECK(selects(selected, "or-regex-api"));   // a scanning branch keeps the rule always-run
}
