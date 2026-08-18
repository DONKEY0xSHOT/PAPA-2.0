#include "papa/capabilities/static_.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"
#include "papa/rules/scope.h"

#include <atomic>
#include <cstddef>
#include <exception>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace papa::capabilities::static_ {

namespace {

namespace base = ::papa::features::extractors;

// One recovered function's analysis output, held until the ordered reduction
struct FunctionSlot {
    CodeCapabilities  caps;
    bool              library{false};
};

// Smallest number of functions worth handing to one worker
inline constexpr std::size_t kMinFunctionsPerWorker = 24U;

// Clamp a requested worker count to something sensible for the work on hand.
// A requested count of zero means decide automatically
[[nodiscard]] unsigned resolve_worker_count(unsigned requested, std::size_t work) noexcept {
    if (requested == 1U || work <= kMinFunctionsPerWorker) { return 1U; }

    unsigned want = requested;
    if (want == 0U) {
        want = std::thread::hardware_concurrency();
        if (want == 0U) { want = 1U; }
    }

    // Never spawn more workers than there is work to keep them busy
    const auto by_work = static_cast<unsigned>(work / kMinFunctionsPerWorker);
    if (by_work < want) { want = by_work; }
    return want == 0U ? 1U : want;
}

// Run body(i) for every i in [0, n) across workers threads, claiming indices from a
// shared counter so an expensive function cannot stall a whole stripe
template <typename Body>
[[nodiscard]] std::exception_ptr
run_indexed(std::size_t n, unsigned workers, Body&& body) {
    std::atomic<std::size_t> next{0};
    std::exception_ptr       first_error;
    std::mutex               error_mutex;

    const auto worker = [&]() noexcept {
        try {
            // Claiming one index at a time keeps a slow function from stalling a whole
            // stripe
            for (;;) {
                const std::size_t i = next.fetch_add(1U, std::memory_order_relaxed);
                if (i >= n) { break; }
                body(i);
            }
        } catch (...) {
            const std::lock_guard<std::mutex> lock(error_mutex);
            if (!first_error) { first_error = std::current_exception(); }
        }
    };

    if (workers <= 1U) {
        worker();
        return first_error;
    }

    std::vector<std::thread> pool;
    pool.reserve(workers - 1U);
    for (unsigned w = 1U; w < workers; ++w) { pool.emplace_back(worker); }
    worker();
    for (auto& t : pool) { t.join(); }
    return first_error;
}

// Append every entry of src into dst. Same-rule entries from different scopes never
// conflict, because CAPA encodes scope into the address space
void merge_into(::papa::engine::MatchResults& dst,
                ::papa::engine::MatchResults  src) {
    for (auto& [rule_name, addr_pairs] : src) {
        auto& slot = dst[rule_name];
        // No reserve here on purpose
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
void absorb_globals(features::FeatureSet& dst,
                    const std::vector<base::FeatureWithAddress>& globals) {
    for (const auto& [feat, addr] : globals) {
        dst.add(feat, addr);
    }
}

// Walk every match in matches and inject MatchedRule features for every rule at every
// recorded address
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
    const ::papa::rules::RuleSet&                       rules,
    const base::StaticFeatureExtractor&                 extractor,
    unsigned                                            threads,
    const std::vector<base::FeatureWithAddress>*        cached_file_features) {
    StaticCapabilities caps;
    ::papa::engine::MatchResults all_fn_matches;
    ::papa::engine::MatchResults all_bb_matches;
    ::papa::engine::MatchResults all_insn_matches;

    // Extract globals once: Os, Arch, Format are constant for the whole image
    // and re-extracting them per-instruction was the dominant allocation cost
    const auto globals = extractor.extract_global_features();

    const auto        fhs = extractor.get_functions();
    const std::size_t n   = fhs.size();
    caps.per_function_feature_counts.reserve(n);

    // One slot per recovered function, filled in place so no worker ever needs to see
    // another's output
    std::vector<FunctionSlot> slots(n);

    const auto analyze_one = [&](std::size_t i) {
        // Library functions are skipped entirely
        if (extractor.is_library_function(fhs[i].addr)) {
            slots[i].library = true;
            return;
        }
        slots[i].caps = find_code_capabilities_inner(rules, extractor, fhs[i], globals);
    };

    const unsigned workers = resolve_worker_count(threads, n);
    if (auto err = run_indexed(n, workers, analyze_one)) {
        std::rethrow_exception(err);
    }
    // Reduce in recovered-function order so the output never depends on which
    // worker finished first
    for (std::size_t i = 0; i < n; ++i) {
        if (slots[i].library) {
            caps.library_functions.push_back(fhs[i].addr);
            caps.per_function_feature_counts.push_back({fhs[i].addr, 0U});
            continue;
        }
        auto& code_caps = slots[i].caps;
        caps.per_function_feature_counts.push_back({fhs[i].addr, code_caps.feature_count});
        merge_into(all_fn_matches,   std::move(code_caps.function_matches));
        merge_into(all_bb_matches,   std::move(code_caps.bb_matches));
        merge_into(all_insn_matches, std::move(code_caps.insn_matches));
    }

    // Build the file-scope feature set from extractor-provided features plus
    // injected MatchedRule features for every match seen below file scope
    features::FeatureSet file_fs;
    if (cached_file_features != nullptr) {
        // Shares the immutable feature objects rather than carving the file a
        // second time. The pre-pass derived them from the same image
        for (const auto& [feat, addr] : *cached_file_features) {
            file_fs.add(feat, addr);
        }
    } else {
        absorb_into(file_fs, extractor.extract_file_features());
    }
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
