#include <ostream>

#include "doctest.h"

#include "papa/engine.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/rules/optimizer.h"

#include <memory>
#include <utility>
#include <vector>

namespace {

using namespace papa;

[[nodiscard]] std::unique_ptr<engine::Statement> feat(features::FeaturePtr f) {
    return std::make_unique<engine::FeatureStatement>(std::move(f));
}

[[nodiscard]] features::FeatureTag tag_of(const engine::Statement& s) {
    return static_cast<const engine::FeatureStatement&>(s).feature()->tag();
}

}  // namespace

TEST_CASE("optimizer: sorts and/or children cheap-first like capa") {
    std::vector<std::unique_ptr<engine::Statement>> kids;
    kids.push_back(feat(std::make_shared<features::Regex>("/foo/")));      // cost 2
    kids.push_back(feat(std::make_shared<features::Os>("windows")));       // cost 0
    kids.push_back(feat(std::make_shared<features::Api>("CreateFileA")));  // cost 1
    engine::And node(std::move(kids));

    papa::rules::optimize(node);

    const auto children = node.children();
    REQUIRE(children.size() == 3);
    CHECK(tag_of(*children[0]) == features::FeatureTag::kOs);
    CHECK(tag_of(*children[1]) == features::FeatureTag::kApi);
    CHECK(tag_of(*children[2]) == features::FeatureTag::kRegex);
}

TEST_CASE("optimizer: stable among equal-cost children and recurses through not") {
    std::vector<std::unique_ptr<engine::Statement>> inner;
    inner.push_back(feat(std::make_shared<features::Regex>("/z/")));        // cost 2
    inner.push_back(feat(std::make_shared<features::Api>("A")));            // cost 1
    inner.push_back(feat(std::make_shared<features::Mnemonic>("call")));    // cost 1
    engine::Not node(std::make_unique<engine::And>(std::move(inner)));

    papa::rules::optimize(node);

    const auto inner_children = node.children()[0]->children();
    REQUIRE(inner_children.size() == 3);
    // The two cost-1 features keep their source order, the cost-2 regex sinks.
    CHECK(tag_of(*inner_children[0]) == features::FeatureTag::kApi);
    CHECK(tag_of(*inner_children[1]) == features::FeatureTag::kMnemonic);
    CHECK(tag_of(*inner_children[2]) == features::FeatureTag::kRegex);
}
