#include "papa/features/extractors/papa_native/viv/cf_context.h"

#include <algorithm>
#include <unordered_map>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::viv {

namespace {

// The control-flow edges of one instruction, in vivisect's envi getBranches
// order (i386 disasm.py:594-661): the fall-through first when the instruction
// can fall through, then the branch target last. A conditional branch also
// tags its fall-through BR_COND. The order matters because the worklist consumes
// branches from the end, so a call's target is descended before its
// fall-through is ever queued
[[nodiscard]] std::vector<CfBranch> get_branches(const DecodedInsn& op) {
    std::vector<CfBranch> ret;
    if (op.is_return) {
        return ret;
    }
    const std::uint16_t flags =
        op.is_conditional ? kBrCond : static_cast<std::uint16_t>(0);
    if (op.is_fallthrough) {
        ret.push_back(CfBranch{op.va + op.length,
                               static_cast<std::uint16_t>(flags | kBrFall)});
    }
    if (op.is_call && op.branch_target.has_value()) {
        ret.push_back(CfBranch{op.branch_target,
                               static_cast<std::uint16_t>(flags | kBrProc)});
    } else if (op.is_jump && op.branch_target.has_value()) {
        ret.push_back(CfBranch{op.branch_target, flags});
    } else if (op.is_jump && !op.branch_target.has_value()) {
        ret.push_back(CfBranch{std::nullopt,
                               static_cast<std::uint16_t>(flags | kBrDeref)});
    }
    return ret;
}

// True when op is the kind of indirect jump a switch dispatch uses: an
// unconditional jump with no static target through a register or a scaled-index
// memory operand
[[nodiscard]] bool is_jump_table_candidate(const DecodedInsn& op) {
    return op.is_jump && !op.is_conditional && !op.branch_target.has_value() &&
           op.operand_count > 0 &&
           (op.operands[0].kind == OperandKind::kReg ||
            op.operands[0].kind == OperandKind::kSib);
}

// Append v to an ordered unique list, keeping its first position
void push_unique(std::vector<std::uint64_t>& list, std::uint64_t v) {
    if (std::find(list.begin(), list.end(), v) == list.end()) {
        list.push_back(v);
    }
}

// Erase the first occurrence of v from an ordered list
void erase_value(std::vector<std::uint64_t>& list, std::uint64_t v) {
    const auto it = std::find(list.begin(), list.end(), v);
    if (it != list.end()) {
        list.erase(it);
    }
}

}  // namespace

CodeFlowContext::CodeFlowContext(InsnReader read,
                                 std::function<bool(std::uint64_t)> is_exec,
                                 IsDefined is_defined, OnOpcode on_opcode,
                                 OnFunction on_function,
                                 JumpTableResolver resolve_jt,
                                 NoReturnCall is_no_return_call,
                                 OnBranchTable on_branch_table)
    : read_(std::move(read)),
      is_exec_(std::move(is_exec)),
      is_defined_(std::move(is_defined)),
      on_opcode_(std::move(on_opcode)),
      on_function_(std::move(on_function)),
      resolve_jt_(std::move(resolve_jt)),
      is_no_return_call_(std::move(is_no_return_call)),
      on_branch_table_(std::move(on_branch_table)) {}

bool CodeFlowContext::on_active_path(std::uint64_t va) const {
    return std::find(cf_blocks_.begin(), cf_blocks_.end(), va) != cf_blocks_.end();
}

void CodeFlowContext::report_function(std::uint64_t va) {
    reported_.insert(va);
    if (on_function_) {
        on_function_(va);
    }
    // va is done, so release any function whose only remaining wait was va
    const auto waiters = awaited_by_.find(va);
    if (waiters == awaited_by_.end()) {
        return;
    }
    std::vector<std::uint64_t> freed;
    for (const std::uint64_t waiter : waiters->second) {
        const auto held = waits_on_.find(waiter);
        if (held != waits_on_.end()) {
            held->second.erase(va);
            if (held->second.empty()) {
                freed.push_back(waiter);
            }
        }
    }
    awaited_by_.erase(va);
    // A freed function is reported directly, one level deep, matching vivisect
    for (const std::uint64_t waiter : freed) {
        waits_on_.erase(waiter);
        report_held_.erase(waiter);
        reported_.insert(waiter);
        if (on_function_) {
            on_function_(waiter);
        }
    }
}

void CodeFlowContext::add_entry_point(std::uint64_t va) {
    // A va that is already a function is left alone, so the closure terminates
    if (!functions_.insert(va).second) {
        return;
    }
    add_code_flow(va);
    // Hold the report if va is itself still waiting on an in-analysis ancestor,
    // otherwise report it now
    if (waits_on_.find(va) == waits_on_.end()) {
        report_function(va);
    } else {
        report_held_.insert(va);
    }
}

void CodeFlowContext::add_code_flow(std::uint64_t va) {
    const std::uint64_t startva = va;
    // Record this function on the active call path so a branch that targets it
    // is deferred rather than descended into or flowed across
    cf_blocks_.push_back(startva);
    std::vector<std::uint64_t> recursion_targets;  // deferred this flow, cf_eps

    // Instructions decoded on this flow, for rebuilding the straight-line window
    // a jump-table resolver reads, plus the byte spans of any resolved offset
    // tables so their data is never decoded as code
    std::unordered_map<std::uint64_t, DecodedInsn>      flow_insns;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> jt_data;
    const auto in_jt_data = [&jt_data](std::uint64_t addr) noexcept {
        for (const auto& span : jt_data) {
            if (addr >= span.first && addr < span.second) {
                return true;
            }
        }
        return false;
    };
    const auto window_ending_at =
        [&flow_insns](const DecodedInsn& terminal) -> std::vector<DecodedInsn> {
        // The function's decoded instructions up to the terminal, in ascending
        // address order. The dispatch block's straight-line lead-up is the tail
        // (where a jump-table resolver's backward scans find the index and load),
        // and the earlier body is included so the resolver can also reach a base
        // register set far back at the prologue. Capped for DoS
        constexpr std::size_t            kMaxWindow = 4096;
        std::vector<const DecodedInsn*> before;
        for (const auto& entry : flow_insns) {
            if (entry.first < terminal.va) {
                before.push_back(&entry.second);
            }
        }
        std::sort(before.begin(), before.end(),
                  [](const DecodedInsn* a, const DecodedInsn* b) {
                      return a->va < b->va;
                  });
        if (before.size() > kMaxWindow) {
            before.erase(before.begin(), before.end() - kMaxWindow);
        }
        std::vector<DecodedInsn> out;
        out.reserve(before.size() + 1);
        for (const DecodedInsn* p : before) {
            out.push_back(*p);
        }
        out.push_back(terminal);
        return out;
    };

    std::vector<std::uint64_t>        optodo{va};  // LIFO worklist
    std::unordered_set<std::uint64_t> visited;
    while (!optodo.empty()) {
        const std::uint64_t cur = optodo.back();
        optodo.pop_back();
        if (!visited.insert(cur).second) {
            continue;
        }
        // Decode-once: an address another flow already claimed is not re-decoded
        // and follows no branches, the way _cb_opcode returns no branches for an
        // already-LOC_OP address
        if (is_defined_ && is_defined_(cur)) {
            continue;
        }
        // The bytes of a resolved offset table are data, not instructions
        if (in_jt_data(cur)) {
            continue;
        }
        const auto insn = read_(cur);
        if (!insn) {
            continue;
        }
        const DecodedInsn&    op       = *insn;
        flow_insns.emplace(cur, op);
        std::vector<CfBranch> branches = get_branches(op);
        on_opcode_(cur, op, std::span<const CfBranch>(branches));
        // Consume branches from the end, matching addCodeFlow's branches.pop()
        while (!branches.empty()) {
            const CfBranch br = branches.back();
            branches.pop_back();
            if (!br.target.has_value()) {
                // An indirect branch. When it resolves as a jump table, its
                // cases are explored intra-procedurally (as BR_COND edges),
                // matching envi codeflow's BR_TABLE expansion, and the offset
                // table's own bytes are excluded from decoding
                if (resolve_jt_ && is_jump_table_candidate(op)) {
                    const auto jt = resolve_jt_(window_ending_at(op));
                    if (jt.has_value()) {
                        for (const std::uint64_t case_va : jt->targets) {
                            branches.push_back(CfBranch{case_va, kBrCond});
                            if (on_branch_table_) {
                                on_branch_table_(op.va, case_va);
                            }
                        }
                        if (jt->table_size != 0) {
                            jt_data.emplace_back(jt->table_va,
                                                 jt->table_va + jt->table_size);
                        }
                    }
                }
                continue;
            }
            const std::uint64_t bva = *br.target;
            if (!is_exec_(bva)) {
                continue;
            }
            // A suppressed edge, the fall-through after a no-return call, is not
            // followed (envi _cf_noflow)
            if (!noflow_.empty() && noflow_.count({cur, bva}) != 0) {
                continue;
            }
            if ((br.flags & kBrProc) != 0) {
                const std::uint64_t nextva = cur + op.length;
                if (bva != nextva) {  // avoid a call to the next instruction
                    // Descend into the callee to completion (its flow and its
                    // fmods) before this caller's fall-through is ever queued,
                    // the post-order DFS. A call to a function already on the
                    // active path is a recursion, deferred to the unwind drain.
                    // Past the descent cap the branch is abandoned, bounding the
                    // native recursion over a crafted deep chain (CLAUDE.md 7.7)
                    if (on_active_path(bva)) {
                        push_unique(recursion_targets, bva);
                    } else if (cf_blocks_.size() < kMaxDescentDepth) {
                        add_entry_point(bva);
                    }
                    // A no-return call suppresses this caller's fall-through, so
                    // the phantom block after the call is never decoded, once the
                    // callee has been analyzed above (envi addNoFlow)
                    if (is_no_return_call_ && is_no_return_call_(op)) {
                        noflow_.insert({cur, nextva});
                    }
                }
                continue;  // ascend to a procedure, do not flow across it
            }
            // A jump whose target is a function still being flowed is a
            // tail-branch into an ancestor. Hold this function's report until
            // that ancestor finishes, rather than flowing across it
            if (on_active_path(bva) && op.is_jump && startva != bva) {
                waits_on_[startva].insert(bva);
                awaited_by_[bva].insert(startva);
                continue;
            }
            if (visited.count(bva) == 0) {
                optodo.push_back(bva);
            }
        }
    }
    cf_blocks_.pop_back();

    // Drain this flow's deferred recursion targets. One still on the active path
    // stays blocked at the instance level, one now off the path and not yet a
    // function is entered here
    for (const std::uint64_t fva : recursion_targets) {
        if (on_active_path(fva)) {
            push_unique(blocked_recursion_, fva);
        } else if (reported_.count(fva) == 0) {
            add_entry_point(fva);
        }
    }

    // Drain the instance-level blocked set: enter any function no longer on the
    // active path and not yet reported, keep the rest for a later unwind. Any
    // entry a nested flow adds during this pass is discarded by the reassignment,
    // matching vivisect's rebind of _cf_blocked to a fresh fallback
    const std::vector<std::uint64_t> blocked_snapshot = blocked_recursion_;
    std::vector<std::uint64_t>       still_blocked;
    for (const std::uint64_t fva : blocked_snapshot) {
        if (!on_active_path(fva) && reported_.count(fva) == 0) {
            functions_.erase(fva);
            erase_value(blocked_recursion_, fva);
            add_entry_point(fva);
        } else {
            still_blocked.push_back(fva);
        }
    }
    blocked_recursion_ = std::move(still_blocked);
}

}  // namespace papa::features::extractors::papa_native::viv
