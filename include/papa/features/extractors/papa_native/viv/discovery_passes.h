#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <vector>

#include "papa/features/extractors/papa_native/viv/discovery.h"

namespace papa::features::extractors::papa_native::viv {

/// Make every listed code entry a function, a port of vivisect's
/// processEntryPoints over the PE entry, exports, TLS callbacks, and .pdata
/// begins. This is the first pass, so its functions exist before any pointer or
/// emulation pass runs
void run_entrypoints(Discovery& disc, std::span<const std::uint64_t> entries);

/// Define a pointer at every relocation site and follow it, a port of vivisect's
/// relocations pass. Running after entrypoints and before the emulation pass is
/// what turns a reloc-stored code pointer into its own function while a dispatcher
/// still shares the block, the pass timing that decides shared-block attribution
void run_relocations(Discovery& disc, std::span<const std::uint64_t> reloc_sites);

/// Recomputes the current set of undefined pointer targets to try as code. In
/// production this is the reloc and data-scan pointers plus the amd64 lea targets
/// of the recovered code, recomputed as new functions appear
using CandidateSource = std::function<std::vector<std::uint64_t>()>;

/// Emulate every undefined pointer target and make a function of each one that
/// behaves like code, iterating to a fixpoint because a newly made function can
/// expose fresh targets. A port of vivisect's emucode pass. Runs after
/// entrypoints and relocations, so a target another pass already claimed is left
/// alone and only genuinely undefined code becomes a new function
void run_emucode(Discovery& disc, const CandidateSource& collect_candidates);

/// Make a function of each undefined prologue-gap candidate, iterating to a
/// fixpoint because making one function shrinks the undefined gaps the next scan
/// sees. A port of vivisect's funcentries pass, the last-resort scan of code no
/// pointer or emulation pass reached
void run_funcentries(Discovery& disc, const CandidateSource& collect_prologues);

/// The executable indirect-call targets a function's emulation resolves
using CallTargetSource =
    std::function<std::vector<std::uint64_t>(std::uint64_t fva)>;

/// Emulate each function and make a function of every runtime-resolved indirect
/// call target, iterating to a fixpoint because a newly made function has its own
/// indirect calls. A port of vivisect's i386.calling / amd64.emulation fmods.
/// Each function is emulated at most once
void run_calling(Discovery& disc, const CallTargetSource& discover_targets);

}  // namespace papa::features::extractors::papa_native::viv
