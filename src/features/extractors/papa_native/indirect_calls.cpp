#include "papa/features/extractors/papa_native/indirect_calls.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

namespace papa::features::extractors::papa_native {

namespace {

// True when reg writes destructively to target_reg's enclosing register
// Partial-width writes ("mov al, ...") leave the upper bits of eax intact and
// therefore cannot be treated as definitions for slicing purposes
[[nodiscard]] bool
is_full_write_to_register(ZydisRegister      written,
                          ZydisRegister      target,
                          ZydisMachineMode   mode) noexcept {
    if (written == ZYDIS_REGISTER_NONE || target == ZYDIS_REGISTER_NONE) {
        return false;
    }
    const ZydisRegister written_full = ZydisRegisterGetLargestEnclosing(mode, written);
    const ZydisRegister target_full  = ZydisRegisterGetLargestEnclosing(mode, target);
    if (written_full != target_full) { return false; }

    // Only writes whose width matches or exceeds the target width fully overwrite
    // the enclosing register (on x64, 32-bit writes also zero-extend the upper 32
    // bits, which Zydis reports through GetWidth, not the register class itself)
    const auto written_width = ZydisRegisterGetWidth(mode, written);
    const auto target_width  = ZydisRegisterGetWidth(mode, target);
    return written_width >= target_width;
}

// Classify the writing instruction and extract a constant when one is encoded
// Returns nullopt when the destination of the instruction is not target_reg
[[nodiscard]] std::optional<Definition>
classify_definition(const DecodedInsn& ins,
                    ZydisRegister      target_reg,
                    bool               is_64bit) noexcept {
    if (ins.operand_count == 0) { return std::nullopt; }
    const auto& dst = ins.operands[0];
    const ZydisMachineMode mode =
        is_64bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;

    // Only register destinations qualify as register definitions
    if (dst.kind != OperandKind::kReg) { return std::nullopt; }
    if (!is_full_write_to_register(dst.base_reg, target_reg, mode)) { return std::nullopt; }

    // CAPA accepts mov, lea, pop, and xor as destructive register writes
    // Other instructions also write registers but vivisect's slicer ignores them
    // because their semantics are too implementation-defined for the heuristic
    const bool is_destructive_mnem =
        ins.zyd_mnem == ZYDIS_MNEMONIC_MOV ||
        ins.zyd_mnem == ZYDIS_MNEMONIC_LEA ||
        ins.zyd_mnem == ZYDIS_MNEMONIC_POP ||
        ins.zyd_mnem == ZYDIS_MNEMONIC_XOR;
    if (!is_destructive_mnem) { return std::nullopt; }

    Definition def;
    def.site_va = ins.va;

    if (ins.operand_count >= 2) {
        const auto& src = ins.operands[1];
        switch (src.kind) {
            case OperandKind::kImm:
                // mov reg, imm
                def.value = src.imm;
                break;
            case OperandKind::kImmMem:
                // mov reg, [imm32]   -- the slot address itself is what callers want
                def.value = static_cast<std::uint64_t>(src.disp);
                break;
            case OperandKind::kRipRel:
                // mov reg, [rip+disp]
                def.value = ins.va + ins.length +
                            static_cast<std::uint64_t>(src.disp);
                break;
            default:
                break;
        }
    }
    return def;
}

// Search instructions [0, upto) of one block backward for the first qualifying
// definition of reg
[[nodiscard]] std::optional<Definition>
scan_block_backward(const BasicBlock& bb, std::size_t upto,
                    ZydisRegister reg, bool is_64bit) noexcept {
    for (std::size_t step = upto; step > 0; --step) {
        if (auto def = classify_definition(bb.instructions[step - 1U], reg, is_64bit);
            def.has_value()) {
            return def;
        }
    }
    return std::nullopt;
}

// Locate the block whose entry equals va. basic_blocks is sorted by entry VA,
// so a binary search keeps the predecessor walk cheap on large functions
[[nodiscard]] const BasicBlock* block_at(const Function& fn, std::uint64_t va) noexcept {
    const auto it = std::lower_bound(
        fn.basic_blocks.begin(), fn.basic_blocks.end(), va,
        [](const BasicBlock& bb, std::uint64_t v) noexcept { return bb.va < v; });
    if (it != fn.basic_blocks.end() && it->va == va) { return &*it; }
    return nullptr;
}

// Resolve the definition of reg reaching the entry of start by a bounded
// breadth-first walk over predecessor blocks, returning the nearest reaching
// definition. This approximates the emulation-based resolution capa performs:
// the register is loaded from the IAT once and called later past a guard, so
// the closest backward write is the one an emulator would observe at the call
[[nodiscard]] std::optional<Definition>
define_at_entry(const Function& fn, const BasicBlock& start,
                ZydisRegister reg, bool is_64bit) {
    constexpr std::size_t kMaxBlocks = 64;
    std::vector<std::uint64_t> visited{start.va};
    std::vector<const BasicBlock*> frontier{&start};
    std::size_t examined = 0;
    while (!frontier.empty() && examined < kMaxBlocks) {
        std::vector<const BasicBlock*> next;
        for (const BasicBlock* bb : frontier) {
            for (const auto pred_va : bb->predecessors) {
                if (std::find(visited.begin(), visited.end(), pred_va) != visited.end()) {
                    continue;
                }
                visited.push_back(pred_va);
                const BasicBlock* pred = block_at(fn, pred_va);
                if (pred == nullptr) { continue; }
                examined += 1;
                if (auto def = scan_block_backward(
                        *pred, pred->instructions.size(), reg, is_64bit);
                    def.has_value()) {
                    return def;
                }
                next.push_back(pred);
            }
        }
        frontier = std::move(next);
    }
    return std::nullopt;
}

}  // namespace

std::optional<Definition>
find_definition(const Function&    fn,
                std::uint64_t      call_va,
                ZydisRegister      target_reg,
                bool               is_64bit) noexcept {
    if (target_reg == ZYDIS_REGISTER_NONE) { return std::nullopt; }
    if (fn.basic_blocks.empty())            { return std::nullopt; }

    // Locate the basic block containing call_va
    // CAPA limits the slice to that block to avoid false positives from
    // cross-block aliasing through register pressure or paths not yet visited
    const BasicBlock* host = nullptr;
    std::size_t call_index = 0;
    for (const auto& bb : fn.basic_blocks) {
        for (std::size_t i = 0; i < bb.instructions.size(); ++i) {
            if (bb.instructions[i].va == call_va) {
                host       = &bb;
                call_index = i;
                break;
            }
        }
        if (host != nullptr) { break; }
    }
    if (host == nullptr) { return std::nullopt; }

    // The first qualifying write before the call in the host block wins. Any
    // later writes are stale because the slicer travels in reverse program order
    if (auto def = scan_block_backward(*host, call_index, target_reg, is_64bit);
        def.has_value()) {
        return def;
    }

    // The register is set up in an earlier block, as compilers routinely do for
    // an import loaded once and called past a guard. Search predecessors for the
    // nearest reaching definition
    return define_at_entry(fn, *host, target_reg, is_64bit);
}

}  // namespace papa::features::extractors::papa_native
