#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/jump_tables.h"
#include "papa/features/extractors/papa_native/viv/br_flags.h"

namespace papa::features::extractors::papa_native::viv {

/// Maximum nested call descent. A DoS bound on the native recursion of add_entry_point
/// over a crafted deep call chain (CLAUDE.md 7.7)
inline constexpr std::size_t kMaxDescentDepth = 512;

/// A control-flow edge in vivisect's envi getBranches model: an optional target
/// (absent for an unresolved indirect branch) and its BR_* flags
struct CfBranch {
    std::optional<std::uint64_t> target;
    std::uint16_t                flags{0};
};

/// A faithful port of vivisect's envi/codeflow.py CodeFlowContext
class CodeFlowContext {
public:
    /// True when an address already holds a code location, the decode-once gate
    using IsDefined = std::function<bool(std::uint64_t)>;
    /// Called for each newly decoded instruction with its branches, in vivisect
    /// getBranches order (fall-through first, target last)
    using OnOpcode =
        std::function<void(std::uint64_t va, const DecodedInsn& op,
                           std::span<const CfBranch> branches)>;
    /// Called once a function's code flow is complete, to run its fmods
    using OnFunction = std::function<void(std::uint64_t va)>;
    /// True when a call instruction does not return, so the fall-through after it is
    /// suppressed
    using NoReturnCall = std::function<bool(const DecodedInsn& call_op)>;
    /// Called for each resolved jump-table case so the driver can record the code
    /// cross-reference codeblocks splits on. Ports vivisect's _cb_branchtable
    using OnBranchTable =
        std::function<void(std::uint64_t from_va, std::uint64_t case_va)>;

    CodeFlowContext(InsnReader read, std::function<bool(std::uint64_t)> is_exec,
                    IsDefined is_defined, OnOpcode on_opcode,
                    OnFunction on_function, JumpTableResolver resolve_jt = {},
                    NoReturnCall is_no_return_call = {},
                    OnBranchTable on_branch_table = {});

    /// Make va a function (guarding duplicates), flow its code, then fire the
    /// on_function callback unless it is being held by the deferral machinery
    void add_entry_point(std::uint64_t va);

    /// Decode and follow control flow from va. Ports addCodeFlow
    void add_code_flow(std::uint64_t va);

private:
    // Report va as a completed function and release any function whose only remaining
    // reason to wait was va
    void report_function(std::uint64_t va);

    // True when va is a function currently being flowed, so a branch to it must
    // not descend or flow across it. Ports the `va in self._cf_blocks` test
    [[nodiscard]] bool on_active_path(std::uint64_t va) const;

    InsnReader                         read_;
    std::function<bool(std::uint64_t)> is_exec_;
    IsDefined                          is_defined_;
    OnOpcode                           on_opcode_;
    OnFunction                         on_function_;
    JumpTableResolver                  resolve_jt_;
    NoReturnCall                       is_no_return_call_;
    OnBranchTable                      on_branch_table_;
    // Suppressed (from, to) code edges, the fall-through after a no-return call.
    // Ports _cf_noflow (envi addNoFlow)
    std::set<std::pair<std::uint64_t, std::uint64_t>> noflow_;
    std::unordered_set<std::uint64_t>  functions_;  // addEntryPoint dedup guard
    std::unordered_set<std::uint64_t>  reported_;   // on_function has fired
    std::vector<std::uint64_t>         cf_blocks_;  // active call path
    // A function that jumped into an in-analysis ancestor waits on the set of ancestors
    // it jumped into, with an inverse index. Ports _cf_delayed and _cf_delaying
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> waits_on_;
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> awaited_by_;
    std::unordered_set<std::uint64_t> report_held_;  // report stashed until a wait clears
    std::vector<std::uint64_t> blocked_recursion_;   // deferred recursion targets, _cf_blocked
};

}  // namespace papa::features::extractors::papa_native::viv
