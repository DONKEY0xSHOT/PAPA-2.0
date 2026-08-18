#pragma once

#include "papa/features/feature.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

namespace papa::rules {

class Rule;

/// Narrows a scope's rule list to the ones a feature set could possibly match
class RuleFeatureIndex {
public:
    /// Index a scope's topologically-ordered rules
    void build(std::span<const Rule* const> rules);

    /// Fill out with the rules worth evaluating against fs, in the order given
    /// to build, so the caller's topological guarantees still hold
    void select(const features::FeatureSet& fs, std::vector<const Rule*>& out) const;

    [[nodiscard]] std::size_t rule_count() const noexcept { return order_.size(); }
    [[nodiscard]] std::size_t indexed_count() const noexcept { return indexed_count_; }

private:
    using FeatureToRules = std::unordered_map<features::FeaturePtr,
                                              std::vector<std::uint32_t>,
                                              features::FeatureHashKey,
                                              features::FeatureEqKey>;

    std::vector<const Rule*>   order_;
    std::vector<std::uint8_t>  always_run_;
    FeatureToRules             by_feature_;
    std::size_t                indexed_count_{0};
};

}  // namespace papa::rules
