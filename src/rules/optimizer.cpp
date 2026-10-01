#include "papa/rules/optimizer.h"

#include "papa/engine.h"
#include "papa/features/feature.h"

#include <algorithm>
#include <memory>

namespace papa::rules {

namespace {

using engine::StatementKind;

// Relative evaluation cost of a leaf feature, mirroring capa's get_node_cost, with
// os and arch cheapest and the scanning features most expensive
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
        case features::FeatureTag::kString:
        case features::FeatureTag::kNumber:
        case features::FeatureTag::kOffset:
        case features::FeatureTag::kMnemonic:
        case features::FeatureTag::kApi:
        case features::FeatureTag::kImport:
        case features::FeatureTag::kExport:
        case features::FeatureTag::kSection:
        case features::FeatureTag::kFunctionName:
        case features::FeatureTag::kClass:
        case features::FeatureTag::kNamespace:
        case features::FeatureTag::kProperty:
        case features::FeatureTag::kCharacteristic:
        case features::FeatureTag::kMatchedRule:
        case features::FeatureTag::kOperandNumber:
        case features::FeatureTag::kOperandOffset:
        case features::FeatureTag::kBasicBlock:
            break;
    }
    return 1;
}

// Worst-case evaluation cost of a statement subtree, mirroring capa's
// get_node_cost: a compound node costs one plus the sum of its children
[[nodiscard]] int node_cost(const engine::Statement& s) {
    switch (s.kind()) {
        case StatementKind::kFeature:
            return feature_cost(*static_cast<const engine::FeatureStatement&>(s).feature());
        case StatementKind::kRange:
            // Range carries a single feature rather than a child statement
            return 1 + feature_cost(*static_cast<const engine::Range&>(s).feature());
        case StatementKind::kAnd:
        case StatementKind::kOr:
        case StatementKind::kNot:
        case StatementKind::kSome:
        case StatementKind::kOptional:
        case StatementKind::kSubscope:
            break;
    }
    int total = 1;
    for (const auto& child : s.children()) {
        if (child) { total += node_cost(*child); }
    }
    return total;
}

}  // namespace

void optimize(engine::Statement& statement) {
    switch (statement.kind()) {
        case StatementKind::kAnd:
        case StatementKind::kOr:
        case StatementKind::kSome:
        case StatementKind::kOptional: {
            // Stable sort keeps capa's behavior of preserving source order among
            // equal-cost children. capa does not recurse past this node
            auto children = statement.children_for_rewrite();
            std::stable_sort(children.begin(), children.end(),
                             [](const std::unique_ptr<engine::Statement>& a,
                                const std::unique_ptr<engine::Statement>& b) {
                                 return node_cost(*a) < node_cost(*b);
                             });
            return;
        }
        case StatementKind::kNot: {
            // A not only follows through to its single child, like capa
            const auto children = statement.children_for_rewrite();
            if (!children.empty() && children[0]) { optimize(*children[0]); }
            return;
        }
        case StatementKind::kRange:
        case StatementKind::kSubscope:
        case StatementKind::kFeature:
            return;
    }
}

}  // namespace papa::rules
