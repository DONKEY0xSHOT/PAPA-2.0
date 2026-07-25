#include "papa/rules/optimizer.h"

#include "papa/engine.h"
#include "papa/features/feature.h"

#include <algorithm>
#include <memory>
#include <string_view>

namespace papa::rules {

namespace {

// Relative evaluation cost of a leaf feature, mirroring capa's get_node_cost.
// os/arch/format are the most selective and cheapest, scanning features
// (substring/regex/bytes) the most expensive, everything else a hash lookup
[[nodiscard]] int feature_cost(const features::Feature& f) noexcept {
    switch (f.tag()) {
        case features::FeatureTag::kOs:
        case features::FeatureTag::kArch:
        case features::FeatureTag::kFormat:
            return 0;
        case features::FeatureTag::kSubstring:
        case features::FeatureTag::kRegex:
        case features::FeatureTag::kBytes:
            return 2;
        default:
            return 1;
    }
}

// Worst-case evaluation cost of a statement subtree, mirroring capa's
// get_node_cost: a compound node costs one plus the sum of its children
[[nodiscard]] int node_cost(const engine::Statement& s) {
    const std::string_view name = s.name();
    if (name == "feature") {
        return feature_cost(*static_cast<const engine::FeatureStatement&>(s).feature());
    }
    if (name == "count") {
        // Range carries a single feature rather than a child statement
        return 1 + feature_cost(*static_cast<const engine::Range&>(s).feature());
    }
    int total = 1;
    for (const auto& child : s.children()) {
        if (child) { total += node_cost(*child); }
    }
    return total;
}

}  // namespace

void optimize(engine::Statement& statement) {
    const std::string_view name = statement.name();
    if (name == "and" || name == "or" || name == "some" || name == "optional") {
        // Stable sort keeps capa's behavior of preserving source order among
        // equal-cost children. capa does not recurse past this node
        auto children = statement.children_for_rewrite();
        std::stable_sort(children.begin(), children.end(),
                         [](const std::unique_ptr<engine::Statement>& a,
                            const std::unique_ptr<engine::Statement>& b) {
                             return node_cost(*a) < node_cost(*b);
                         });
    } else if (name == "not") {
        // A not only follows through to its single child, like capa
        const auto children = statement.children_for_rewrite();
        if (!children.empty() && children[0]) { optimize(*children[0]); }
    }
}

}  // namespace papa::rules
