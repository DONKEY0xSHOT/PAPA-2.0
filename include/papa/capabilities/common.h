#pragma once

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/rules/ruleset.h"

#include <cstddef>
#include <vector>

namespace papa::capabilities {

// Result of running rules at file scope. features carries the FeatureSet after
// MatchedRule injections, so find_static_capabilities can reuse it
struct FileCapabilities {
    features::FeatureSet  features;
    engine::MatchResults  matches;
    std::size_t           feature_count{0};
};

// Run the file-scope match cycle. cached_file_features lets a caller that already
// extracted them hand them over instead of paying for a second whole-file carve
[[nodiscard]] Expected<FileCapabilities>
find_file_capabilities(
    const ::papa::rules::RuleSet&                                     rules,
    const ::papa::features::extractors::StaticFeatureExtractor&       extractor,
    const std::vector<::papa::features::extractors::FeatureWithAddress>*
        cached_file_features = nullptr);

// The file-scope rules that can decide whether a static-limitation rule matches,
// in topological order. Exposed for testing
[[nodiscard]] std::vector<const ::papa::rules::Rule*>
limitation_gate_rules(const ::papa::rules::RuleSet& rules);

// Run only the limitation gate rather than the whole file-scope corpus
[[nodiscard]] Expected<FileCapabilities>
find_limitation_capabilities(
    const ::papa::rules::RuleSet&                                     rules,
    const ::papa::features::extractors::StaticFeatureExtractor&       extractor,
    const std::vector<::papa::features::extractors::FeatureWithAddress>*
        cached_file_features = nullptr);

// True when any rule under namespace "internal/limitation/static" matched
[[nodiscard]] bool
has_static_limitation(const ::papa::rules::RuleSet& rules,
                      const FileCapabilities&       file_caps) noexcept;

}  // namespace papa::capabilities
