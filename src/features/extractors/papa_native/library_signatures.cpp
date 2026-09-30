#include "papa/features/extractors/papa_native/library_signatures.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"

namespace papa::features::extractors::papa_native {

bool is_thunk(const Function& fn) noexcept {
    // A thunk is a single basic block that contains exactly one instruction
    // and that instruction is an unconditional jmp or call through memory
    if (fn.basic_blocks.size() != 1) { return false; }
    const auto& bb = fn.basic_blocks.front();
    if (bb.instructions.size() != 1) { return false; }

    const auto& ins = bb.instructions.front();
    const bool is_uncond_branch =
        (ins.is_jump || ins.is_call) && !ins.is_conditional;
    if (!is_uncond_branch) { return false; }
    if (ins.operand_count == 0) { return false; }

    const auto& op0 = ins.operands.front();
    // kImmMem is x86 absolute "[disp32]" and kRipRel is x64 RIP-relative "[rip+disp]",
    // both memory operands whose target is an IAT slot in normal thunks
    return op0.kind == OperandKind::kImmMem || op0.kind == OperandKind::kRipRel;
}

}  // namespace papa::features::extractors::papa_native
