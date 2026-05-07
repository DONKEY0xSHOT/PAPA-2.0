#pragma once

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/rules/ruleset.h"

#include <cstddef>
#include <vector>

namespace papa::capabilities::static_ {

// Per-instruction result: post-injection feature set plus the rule matches
struct InstructionCapabilities {
    features::FeatureSet  features;
    engine::MatchResults  matches;
};

// Per-basic-block result, accumulating the contained instruction matches too
struct BasicBlockCapabilities {
    features::FeatureSet  features;
    engine::MatchResults  matches;
    engine::MatchResults  insn_matches;
};

// Per-function aggregate over all contained BBs and instructions
struct CodeCapabilities {
    engine::MatchResults  function_matches;
    engine::MatchResults  bb_matches;
    engine::MatchResults  insn_matches;
    std::size_t           feature_count{0};
};

// Final image-level aggregate
// per_function_feature_counts is populated as the orchestrator walks each
// function so collect_metadata never has to re-extract just to count
struct StaticCapabilities {
    engine::MatchResults                    all_matches;
    std::size_t                             feature_count{0};
    std::vector<features::Address>          library_functions;
    std::vector<std::size_t>                per_function_feature_counts;
};

[[nodiscard]] InstructionCapabilities
find_instruction_capabilities(
    const ::papa::rules::RuleSet&                              rules,
    const ::papa::features::extractors::StaticFeatureExtractor& extractor,
    const ::papa::features::extractors::FunctionHandle&        fh,
    const ::papa::features::extractors::BBHandle&              bbh,
    const ::papa::features::extractors::InsnHandle&            ih);

[[nodiscard]] BasicBlockCapabilities
find_basic_block_capabilities(
    const ::papa::rules::RuleSet&                              rules,
    const ::papa::features::extractors::StaticFeatureExtractor& extractor,
    const ::papa::features::extractors::FunctionHandle&        fh,
    const ::papa::features::extractors::BBHandle&              bbh);

[[nodiscard]] CodeCapabilities
find_code_capabilities(
    const ::papa::rules::RuleSet&                              rules,
    const ::papa::features::extractors::StaticFeatureExtractor& extractor,
    const ::papa::features::extractors::FunctionHandle&        fh);

// Top-level entry: walk every function and roll matches up to file scope
[[nodiscard]] Expected<StaticCapabilities>
find_static_capabilities(
    const ::papa::rules::RuleSet&                              rules,
    const ::papa::features::extractors::StaticFeatureExtractor& extractor);

}  // namespace papa::capabilities::static_
