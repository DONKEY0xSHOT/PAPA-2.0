#include "papa/capabilities/static_.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"
#include "papa/rules/scope.h"

#include <cstddef>
#include <utility>
#include <vector>

namespace papa::capabilities::static_ {

namespace {

namespace base = ::papa::features::extractors;

// Append every entry of src into dst, overwriting any conflicting per-rule
// match list. Same-rule entries from different scopes never conflict because
// CAPA encodes scope into the address space, but we still append rather than
// replace so cross-scope match merging is associative
void merge_into(::papa::engine::MatchResults& dst,
                ::papa::engine::MatchResults  src) {
    for (auto& [rule_name, addr_pairs] : src) {
        auto& slot = dst[rule_name];
        slot.reserve(slot.size() + addr_pairs.size());
        for (auto& p : addr_pairs) {
            slot.push_back(std::move(p));
        }
    }
}

// Append every (feature, address) pair from src into the target FeatureSet
// add() handles structural deduplication so the resulting sets remain valid
void absorb_into(features::FeatureSet&             dst,
                 std::vector<base::FeatureWithAddress> src) {
    for (auto& [feat, addr] : src) {
        dst.add(std::move(feat), addr);
    }
}

// Globals (Os, Arch, Format) are constant for the whole image
// Extracting them once and copying the cheap shared_ptr handles into every
// scope's FeatureSet avoids reallocating Os/Arch/Format objects per insn
void absorb_globals(features::FeatureSet& dst,
                    const std::vector<base::FeatureWithAddress>& globals) {
    for (const auto& [feat, addr] : globals) {
        dst.add(feat, addr);
    }
}

// Walk every match in matches and inject MatchedRule features for every rule
// at every recorded address. This is what propagates child-scope matches into
// the next-outer scope's feature set, allowing a function rule to depend on
// an instruction-scope match without re-running the inner extractor
void inject_match_features(features::FeatureSet&                fs,
                           const ::papa::rules::RuleSet&        rules,
                           const ::papa::engine::MatchResults&  matches) {
    for (const auto& [rule_name, addr_pairs] : matches) {
        const ::papa::rules::Rule* rule = rules.find(rule_name);
        if (rule == nullptr) { continue; }
        std::vector<features::Address> addrs;
        addrs.reserve(addr_pairs.size());
        for (const auto& p : addr_pairs) { addrs.push_back(p.first); }
        ::papa::engine::index_rule_matches(fs, *rule, addrs);
    }
}

}  // namespace

/// Internal find_* overloads that take pre-extracted globals. The public
/// wrappers below extract globals once and forward
namespace {

InstructionCapabilities
find_instruction_capabilities_inner(
    const ::papa::rules::RuleSet&                  rules,
    const base::StaticFeatureExtractor&            extractor,
    const base::FunctionHandle&                    fh,
    const base::BBHandle&                          bbh,
    const base::InsnHandle&                        ih,
    const std::vector<base::FeatureWithAddress>&   globals) {
    features::FeatureSet fs;
    absorb_into(fs, extractor.extract_insn_features(fh, bbh, ih));
    absorb_globals(fs, globals);

    auto [merged_fs, matches] =
        rules.match(::papa::rules::Scope::kInstruction, std::move(fs), ih.addr);
    return InstructionCapabilities{ std::move(merged_fs), std::move(matches) };
}

BasicBlockCapabilities
find_basic_block_capabilities_inner(
    const ::papa::rules::RuleSet&                  rules,
    const base::StaticFeatureExtractor&            extractor,
    const base::FunctionHandle&                    fh,
    const base::BBHandle&                          bbh,
    const std::vector<base::FeatureWithAddress>&   globals) {
    features::FeatureSet bb_fs;
    ::papa::engine::MatchResults insn_matches_acc;

    for (const auto& ih : extractor.get_instructions(fh, bbh)) {
        auto insn_caps = find_instruction_capabilities_inner(
            rules, extractor, fh, bbh, ih, globals);
        for (const auto& [feat, addrs] : insn_caps.features) {
            for (const auto& a : addrs) { bb_fs.add(feat, a); }
        }
        merge_into(insn_matches_acc, std::move(insn_caps.matches));
    }

    absorb_into(bb_fs, extractor.extract_basic_block_features(fh, bbh));
    absorb_globals(bb_fs, globals);

    auto [merged_fs, bb_matches] =
        rules.match(::papa::rules::Scope::kBasicBlock, std::move(bb_fs), bbh.addr);
    return BasicBlockCapabilities{
        std::move(merged_fs),
        std::move(bb_matches),
        std::move(insn_matches_acc),
    };
}

CodeCapabilities
find_code_capabilities_inner(
    const ::papa::rules::RuleSet&                  rules,
    const base::StaticFeatureExtractor&            extractor,
    const base::FunctionHandle&                    fh,
    const std::vector<base::FeatureWithAddress>&   globals) {
    features::FeatureSet fn_fs;
    ::papa::engine::MatchResults bb_matches_acc;
    ::papa::engine::MatchResults insn_matches_acc;

    for (const auto& bbh : extractor.get_basic_blocks(fh)) {
        auto bb_caps = find_basic_block_capabilities_inner(
            rules, extractor, fh, bbh, globals);
        for (const auto& [feat, addrs] : bb_caps.features) {
            for (const auto& a : addrs) { fn_fs.add(feat, a); }
        }
        merge_into(bb_matches_acc,   std::move(bb_caps.matches));
        merge_into(insn_matches_acc, std::move(bb_caps.insn_matches));
    }

    absorb_into(fn_fs, extractor.extract_function_features(fh));
    absorb_globals(fn_fs, globals);

    auto [merged_fs, fn_matches] =
        rules.match(::papa::rules::Scope::kFunction, std::move(fn_fs), fh.addr);

    return CodeCapabilities{
        std::move(fn_matches),
        std::move(bb_matches_acc),
        std::move(insn_matches_acc),
        merged_fs.size(),
    };
}

}  // namespace

InstructionCapabilities
find_instruction_capabilities(
    const ::papa::rules::RuleSet&        rules,
    const base::StaticFeatureExtractor&  extractor,
    const base::FunctionHandle&          fh,
    const base::BBHandle&                bbh,
    const base::InsnHandle&              ih) {
    return find_instruction_capabilities_inner(
        rules, extractor, fh, bbh, ih, extractor.extract_global_features());
}

BasicBlockCapabilities
find_basic_block_capabilities(
    const ::papa::rules::RuleSet&        rules,
    const base::StaticFeatureExtractor&  extractor,
    const base::FunctionHandle&          fh,
    const base::BBHandle&                bbh) {
    return find_basic_block_capabilities_inner(
        rules, extractor, fh, bbh, extractor.extract_global_features());
}

CodeCapabilities
find_code_capabilities(
    const ::papa::rules::RuleSet&        rules,
    const base::StaticFeatureExtractor&  extractor,
    const base::FunctionHandle&          fh) {
    return find_code_capabilities_inner(
        rules, extractor, fh, extractor.extract_global_features());
}

::papa::Expected<StaticCapabilities>
find_static_capabilities(
    const ::papa::rules::RuleSet&        rules,
    const base::StaticFeatureExtractor&  extractor) {
    StaticCapabilities caps;
    ::papa::engine::MatchResults all_fn_matches;
    ::papa::engine::MatchResults all_bb_matches;
    ::papa::engine::MatchResults all_insn_matches;

    // Extract globals once: Os, Arch, Format are constant for the whole image
    // and re-extracting them per-instruction was the dominant allocation cost
    const auto globals = extractor.extract_global_features();

    const auto fhs = extractor.get_functions();
    caps.per_function_feature_counts.reserve(fhs.size());
    for (const auto& fh : fhs) {
        // Library functions are skipped entirely
        // Their matches would inflate the corpus-wide hit count without
        // representing real capabilities authored by the binary's developers
        if (extractor.is_library_function(fh.addr)) {
            caps.library_functions.push_back(fh.addr);
            caps.per_function_feature_counts.push_back({fh.addr, 0U});
            continue;
        }
        auto code_caps = find_code_capabilities_inner(rules, extractor, fh, globals);
        caps.per_function_feature_counts.push_back({fh.addr, code_caps.feature_count});
        merge_into(all_fn_matches,   std::move(code_caps.function_matches));
        merge_into(all_bb_matches,   std::move(code_caps.bb_matches));
        merge_into(all_insn_matches, std::move(code_caps.insn_matches));
    }

    // Build the file-scope feature set from extractor-provided features plus
    // injected MatchedRule features for every match seen below file scope
    features::FeatureSet file_fs;
    absorb_into(file_fs, extractor.extract_file_features());
    absorb_into(file_fs, extractor.extract_global_features());
    inject_match_features(file_fs, rules, all_fn_matches);
    inject_match_features(file_fs, rules, all_bb_matches);
    inject_match_features(file_fs, rules, all_insn_matches);

    const features::Address base = extractor.get_base_address();
    auto [merged_file_fs, file_matches] =
        rules.match(::papa::rules::Scope::kFile, std::move(file_fs), base);

    caps.feature_count = merged_file_fs.size();
    merge_into(caps.all_matches, std::move(file_matches));
    merge_into(caps.all_matches, std::move(all_fn_matches));
    merge_into(caps.all_matches, std::move(all_bb_matches));
    merge_into(caps.all_matches, std::move(all_insn_matches));

    return caps;
}

}  // namespace papa::capabilities::static_
