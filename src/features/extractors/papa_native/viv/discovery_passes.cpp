#include "papa/features/extractors/papa_native/viv/discovery_passes.h"

#include <algorithm>
#include <unordered_set>

namespace papa::features::extractors::papa_native::viv {

void run_entrypoints(Discovery& disc, std::span<const std::uint64_t> entries) {
    for (const std::uint64_t va : entries) {
        disc.make_function(va);
    }
}

void run_relocations(Discovery& disc, std::span<const std::uint64_t> reloc_sites) {
    for (const std::uint64_t site : reloc_sites) {
        disc.make_pointer(site, /*follow=*/true);
    }
}

void run_emucode(Discovery& disc, const CandidateSource& collect_candidates) {
    // A tried set persists across fixpoint passes so a candidate that failed once
    // is never re-emulated, matching emucode.py
    std::unordered_set<std::uint64_t> tried;
    while (true) {
        std::vector<std::uint64_t> docode;
        for (const std::uint64_t va : collect_candidates()) {
            if (!tried.insert(va).second) {
                continue;
            }
            // analyze_pointer is kOp exactly when va is undefined and looks like
            // code, emucode's undefined-and-looksgood gate over one candidate
            if (disc.analyze_pointer(va) == LocType::kOp) {
                docode.push_back(va);
            }
        }
        if (docode.empty()) {
            break;
        }
        std::sort(docode.begin(), docode.end());
        for (const std::uint64_t va : docode) {
            // An earlier make_function this pass may have covered a later target,
            // so re-check the getLocation gate before each make the way emucode
            // does
            if (!disc.locations().get_location(va).has_value()) {
                disc.make_function(va);
            }
        }
    }
}

void run_funcentries(Discovery& disc, const CandidateSource& collect_prologues) {
    // Making a function shrinks the undefined gaps the next scan sees, so iterate
    // until a pass finds no new prologue. A prologue candidate is already
    // validated, so an undefined one becomes a function directly. A bounded pass
    // count guards against a candidate that make_function cannot cover
    constexpr int kMaxPasses = 8;
    for (int pass = 0; pass < kMaxPasses; ++pass) {
        bool added = false;
        for (const std::uint64_t va : collect_prologues()) {
            if (!disc.locations().get_location(va).has_value()) {
                disc.make_function(va);
                added = true;
            }
        }
        if (!added) {
            break;
        }
    }
}

void run_calling(Discovery& disc, const CallTargetSource& discover_targets) {
    // Emulate each function once across the passes. A function newly made this
    // pass is emulated on the next, so the discovery reaches a fixpoint
    std::unordered_set<std::uint64_t> emulated;
    constexpr int                     kMaxPasses = 6;
    for (int pass = 0; pass < kMaxPasses; ++pass) {
        bool added = false;
        // Snapshot the entry list because make_function appends to it
        const std::vector<std::uint64_t> snapshot = disc.function_entries();
        for (const std::uint64_t fva : snapshot) {
            if (!emulated.insert(fva).second) {
                continue;
            }
            for (const std::uint64_t target : discover_targets(fva)) {
                if (!disc.locations().get_location(target).has_value()) {
                    disc.make_function(target);
                    added = true;
                }
            }
        }
        if (!added) {
            break;
        }
    }
}

}  // namespace papa::features::extractors::papa_native::viv
