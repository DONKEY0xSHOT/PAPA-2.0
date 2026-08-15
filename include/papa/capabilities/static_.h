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

// One recovered function's entry address and the number of features extracted
// from it. Mirrors capa's feature_counts.functions entries so the report JSON
// stays schema-compatible and downstream tooling can see which functions the
// extractor actually analyzed
struct FunctionFeatureCount {
    features::Address  address;
    std::size_t        count{0};
};

// Final image-level aggregate
// per_function_feature_counts is populated as the orchestrator walks each
// function so collect_metadata never has to re-extract just to count
struct StaticCapabilities {
    engine::MatchResults                    all_matches;
    std::size_t                             feature_count{0};
    std::vector<features::Address>          library_functions;
    std::vector<FunctionFeatureCount>       per_function_feature_counts;
    // Split of this stage for the --timing report, so the parallel per-function
    // work can be told apart from the serial file-scope tail
    double                                  parallel_seconds{0.0};
    double                                  reduce_seconds{0.0};
    double                                  file_scope_seconds{0.0};
    unsigned                                workers{1};
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
// Per-function analysis is independent, so it runs across threads. threads=0
// picks one worker per hardware thread and threads=1 forces the serial path.
// The reduction always runs afterwards in recovered-function order, so the
// result does not depend on the worker count
// cached_file_features skips a second whole-file carve when the caller already
// extracted them for the limitation pre-pass
[[nodiscard]] Expected<StaticCapabilities>
find_static_capabilities(
    const ::papa::rules::RuleSet&                              rules,
    const ::papa::features::extractors::StaticFeatureExtractor& extractor,
    unsigned                                                   threads = 0U,
    const std::vector<::papa::features::extractors::FeatureWithAddress>*
        cached_file_features = nullptr);

}  // namespace papa::capabilities::static_
