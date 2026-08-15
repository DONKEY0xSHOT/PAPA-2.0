#pragma once

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/rules/ruleset.h"

#include <cstddef>
#include <vector>

namespace papa::capabilities {

// Result of running rules at file scope
// features carries the FeatureSet after MatchedRule injections, suitable for
// reuse by find_static_capabilities so the engine does not re-extract them
struct FileCapabilities {
    features::FeatureSet  features;
    engine::MatchResults  matches;
    std::size_t           feature_count{0};
};

// Run the file-scope match cycle
// extractor must yield non-empty file features for any meaningful result
// Both PefileFeatureExtractor and PapaNativeStaticExtractor satisfy this contract
//
// cached_file_features lets a caller that already extracted the file features
// hand them over instead of paying for a second whole-file carve. Both
// extractors derive them from the same PeImage through the same function, so
// the cached vector is interchangeable with a fresh extraction
[[nodiscard]] Expected<FileCapabilities>
find_file_capabilities(
    const ::papa::rules::RuleSet&                                     rules,
    const ::papa::features::extractors::StaticFeatureExtractor&       extractor,
    const std::vector<::papa::features::extractors::FeatureWithAddress>*
        cached_file_features = nullptr);

// True when any rule under namespace "internal/limitation/static" matched
// CAPA shortcut: when this returns true the caller drops to a pefile-only
// rendering path because deeper analysis would be misleading
[[nodiscard]] bool
has_static_limitation(const ::papa::rules::RuleSet& rules,
                      const FileCapabilities&       file_caps) noexcept;

}  // namespace papa::capabilities
