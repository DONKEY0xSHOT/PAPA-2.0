#pragma once

#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/papa_native/cfg.h"

#include <optional>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::basic_block {

using FeatureWithAddress = std::pair<features::FeaturePtr, features::Address>;

// Detect a tight self-loop: any successor equals the basic block's own VA
[[nodiscard]] std::optional<FeatureWithAddress>
extract_tight_loop(const BasicBlock& bb);

// Detect "stack string" pattern: consecutive immediate stores to a stack
// register whose bytes form a printable ASCII run of length >= kMinStackStringLen
// is_64bit determines which registers count as the stack pointer or frame pointer
[[nodiscard]] std::optional<FeatureWithAddress>
extract_stack_string(const BasicBlock& bb, bool is_64bit);

// Aggregate all basic-block-scope features for one block
[[nodiscard]] std::vector<FeatureWithAddress>
extract_basic_block_features(const BasicBlock& bb, bool is_64bit);

}  // namespace papa::features::extractors::papa_native::basic_block
