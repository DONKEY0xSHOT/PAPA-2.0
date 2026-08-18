#include "papa/features/extractors/papa_native/library_signatures.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"

#include <cstdint>
#include <span>

namespace papa::features::extractors::papa_native {

LibrarySignatureSet LibrarySignatureSet::make_default() {
    LibrarySignatureSet set;
    set.flirt_ = flirt::FlirtSignatureSet::make_embedded();
    return set;
}

bool LibrarySignatureSet::is_thunk(const Function& fn) noexcept {
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
    // kImmMem is x86 absolute "[disp32]" kRipRel is x64 RIP-relative "[rip+disp]". Both
    // encode a memory operand whose target is an IAT slot in normal thunks
    return op0.kind == OperandKind::kImmMem || op0.kind == OperandKind::kRipRel;
}

bool LibrarySignatureSet::classify_as_library(
    const Function& fn,
    std::span<const std::uint8_t> function_bytes) const noexcept {
    // Thunk check first (O(1) structural), then FLIRT (tree walk). This mirrors
    // CAPA which suppresses thunks and FLIRT-identified library functions
    if (is_thunk(fn)) { return true; }
    return flirt_.classify(function_bytes);
}

}  // namespace papa::features::extractors::papa_native
