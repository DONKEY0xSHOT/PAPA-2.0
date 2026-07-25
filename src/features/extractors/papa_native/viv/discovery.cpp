#include "papa/features/extractors/papa_native/viv/discovery.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace papa::features::extractors::papa_native::viv {

Discovery::Discovery(InsnReader read, std::function<bool(std::uint64_t)> is_exec,
                     JumpTableResolver resolve_jt,
                     IsProbablyCode is_probably_code, ReadPtr read_ptr,
                     std::uint64_t ptr_size, NoReturnOracle api_no_return)
    : read_(read),  // a copy, cf_ takes the original below
      is_probably_code_(std::move(is_probably_code)),
      read_ptr_(std::move(read_ptr)),
      api_no_return_(std::move(api_no_return)),
      ptr_size_(ptr_size),
      cf_(std::move(read), std::move(is_exec),
          [this](std::uint64_t va) { return is_defined(va); },
          [this](std::uint64_t va, const DecodedInsn& op,
                 std::span<const CfBranch> branches) {
              on_opcode(va, op, branches);
          },
          [this](std::uint64_t va) { on_function(va); }, std::move(resolve_jt),
          [this](const DecodedInsn& op) { return is_no_return_call(op); },
          [this](std::uint64_t from, std::uint64_t to) {
              xrefs_.add_code_xref(from, to, kBrCond);
          }) {}

void Discovery::make_function(std::uint64_t va) {
    cf_.add_entry_point(va);
}

std::optional<LocType> Discovery::analyze_pointer(std::uint64_t va) const {
    // A target already holding any location is left alone, the getLocation gate
    // that keeps a pointer pass from redefining what another pass claimed
    if (locations_.get_location(va).has_value()) {
        return std::nullopt;
    }
    if (is_probably_code_ && is_probably_code_(va)) {
        return LocType::kOp;
    }
    return std::nullopt;
}

void Discovery::follow_pointer(std::uint64_t target) {
    if (analyze_pointer(target) == LocType::kOp) {
        make_function(target);
    }
}

void Discovery::make_pointer(std::uint64_t site, bool follow) {
    // getLocation gate: makePointer does not remake a pointer where a location
    // already sits
    if (locations_.get_location(site).has_value()) {
        return;
    }
    // castPointer reads the stored target. An unreadable site defines nothing
    const std::optional<std::uint64_t> target =
        read_ptr_ ? read_ptr_(site) : std::nullopt;
    if (!target.has_value()) {
        return;
    }
    locations_.add_location(site, ptr_size_, LocType::kPointer);
    if (follow) {
        follow_pointer(*target);
    }
}

bool Discovery::is_defined(std::uint64_t va) const {
    return locations_.get_location(va).has_value();
}

bool Discovery::is_no_fall(std::uint64_t va) const {
    return no_fall_.count(va) != 0;
}

void Discovery::on_opcode(std::uint64_t va, const DecodedInsn& op,
                          std::span<const CfBranch> branches) {
    locations_.add_location(va, op.length, LocType::kOp);
    if (!op.is_fallthrough) {
        no_fall_.insert(va);
    }
    // Record a code cross-reference for every branch that has a target, except
    // the implicit fall-through (vivisect does not store a REF_CODE xref for it)
    for (const CfBranch& branch : branches) {
        if (branch.target.has_value() && (branch.flags & kBrFall) == 0) {
            xrefs_.add_code_xref(va, *branch.target, branch.flags);
        }
    }
}

void Discovery::on_function(std::uint64_t va) {
    // The deferral machinery can report a function more than once, the way
    // vivisect's codeflow may call _cb_function twice. Analyze each function only
    // once, matching vivisect's isFunction guard (base.py _cb_function), so its
    // blocks are not attributed twice
    if (!analyzed_.insert(va).second) {
        return;
    }
    function_entries_.push_back(va);
    analyze_function(
        locations_, xrefs_,
        [this](std::uint64_t at) { return is_no_fall(at); },
        [this](std::uint64_t at) { return read_(at).has_value(); }, va, blocks_);
    // The noret fmod runs after codeblocks (its blocks already reflect the
    // suppression the flow applied). A function whose every leaf ends in a
    // no-return call does not return, so a later caller loses its fall-through.
    // Post-order makes this hold in one pass: the callee is analyzed here, before
    // any caller flows past its call
    if (function_is_noreturn(materialize_function(va),
                             [this](const DecodedInsn& op) {
                                 return is_no_return_call(op);
                             })) {
        no_return_functions_.insert(va);
    }
    // The FLIRT fmod runs last, the way vivisect registers the signature
    // analyzers after codeblocks and noret. It may create library sub-functions
    // this signature names at its local offsets, which is what collapses an
    // enclosing function whose region a helper claims. It re-enters make_function,
    // which is safe here because this function's flow has already unwound
    if (flirt_fmod_) {
        flirt_fmod_(va);
    }
}

bool Discovery::is_no_return_call(const DecodedInsn& op) const {
    if (api_no_return_ && api_no_return_(op)) {
        return true;
    }
    return op.is_call && op.branch_target.has_value() &&
           no_return_functions_.count(*op.branch_target) != 0;
}

std::vector<Function> Discovery::materialize_functions() const {
    std::vector<Function> out;
    out.reserve(function_entries_.size());
    for (const std::uint64_t fva : function_entries_) {
        Function fn = materialize_function(fva);
        // Predecessors are the inverse of the intra-function successor edges
        std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> preds;
        for (const BasicBlock& bb : fn.basic_blocks) {
            for (const std::uint64_t succ : bb.successors) {
                preds[succ].push_back(bb.va);
            }
        }
        for (BasicBlock& bb : fn.basic_blocks) {
            if (const auto it = preds.find(bb.va); it != preds.end()) {
                bb.predecessors = it->second;
            }
        }
        // Callees are the direct call targets in the function's instructions
        for (const BasicBlock& bb : fn.basic_blocks) {
            for (const DecodedInsn& op : bb.instructions) {
                if (op.is_call && op.branch_target.has_value()) {
                    fn.callees.push_back(*op.branch_target);
                }
            }
        }
        std::sort(fn.callees.begin(), fn.callees.end());
        fn.callees.erase(std::unique(fn.callees.begin(), fn.callees.end()),
                         fn.callees.end());
        out.push_back(std::move(fn));
    }
    return out;
}

Function Discovery::materialize_function(std::uint64_t fva) const {
    Function fn;
    fn.va = fva;
    const std::vector<CodeBlock>&     block_list = blocks_.function_blocks(fva);
    std::unordered_set<std::uint64_t> starts;
    for (const CodeBlock& b : block_list) {
        starts.insert(b.va);
    }
    for (const CodeBlock& b : block_list) {
        BasicBlock bb;
        bb.va = b.va;
        // Decode the block's instructions from its recovered byte range
        std::uint64_t       va  = b.va;
        const std::uint64_t end = b.va + b.size;
        while (va < end) {
            auto insn = read_(va);
            if (!insn) {
                break;
            }
            const std::uint64_t length = insn->length;
            bb.instructions.push_back(std::move(*insn));
            if (length == 0) {
                break;
            }
            va += length;
        }
        // Successors are the terminator's non-call edges that land on another
        // block of this function. A suppressed fall-through is not a block start,
        // so a leaf after a no-return call has no successor, exactly what the leaf
        // scan needs
        if (!bb.instructions.empty()) {
            const DecodedInsn& term = bb.instructions.back();
            for (const CodeXref& xref : xrefs_.code_xrefs_from(term.va)) {
                if ((xref.branch_flags & (kBrProc | kBrDeref)) != 0) {
                    continue;
                }
                if (starts.count(xref.to_va) != 0) {
                    bb.successors.push_back(xref.to_va);
                }
            }
            if (term.is_fallthrough) {
                const std::uint64_t fall = term.va + term.length;
                if (starts.count(fall) != 0) {
                    bb.successors.push_back(fall);
                }
            }
        }
        fn.basic_blocks.push_back(std::move(bb));
    }
    return fn;
}

}  // namespace papa::features::extractors::papa_native::viv
