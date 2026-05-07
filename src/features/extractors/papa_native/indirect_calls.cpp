#include "papa/features/extractors/papa_native/indirect_calls.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <Zydis/Zydis.h>

#include <cstdint>
#include <optional>

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
    if (call_index == 0) { return std::nullopt; }

    // Walk backward from the instruction immediately before the call
    // The first qualifying definition wins
    // Any later writes are stale by definition because the slicer travels in
    // reverse program order from the call site backward
    for (std::size_t step = call_index; step > 0; --step) {
        const auto& candidate = host->instructions[step - 1U];
        if (auto def = classify_definition(candidate, target_reg, is_64bit);
            def.has_value()) {
            return def;
        }
    }
    return std::nullopt;
}

}  // namespace papa::features::extractors::papa_native
