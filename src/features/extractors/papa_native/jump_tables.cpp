#include "papa/features/extractors/papa_native/jump_tables.h"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_set>
#include <vector>

namespace papa::features::extractors::papa_native {

namespace {

// A jump table larger than this is treated as a mis-recognition and rejected
constexpr std::uint64_t kMaxJumpTableEntries = 4096;

// Largest enclosing register so eax/ax/al and ecx/rcx compare equal
[[nodiscard]] ZydisRegister enclosing(ZydisRegister r, bool is_64bit) noexcept {
    if (r == ZYDIS_REGISTER_NONE) { return r; }
    const ZydisMachineMode mode =
        is_64bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    return ZydisRegisterGetLargestEnclosing(mode, r);
}

[[nodiscard]] bool is_reg(const DecodedOperand& op) noexcept {
    return op.kind == OperandKind::kReg;
}

}  // namespace

std::optional<JumpTableTargets>
resolve_indexed_jump_table(std::span<const DecodedInsn> window,
                           bool is_64bit,
                           std::uint64_t range_lo,
                           std::uint64_t range_hi,
                           const TableReader& read_u32) {
    if (window.empty()) { return std::nullopt; }

    // The window must terminate at an indirect register jump, the form whose
    // target recursive descent cannot follow on its own
    const DecodedInsn& jmp = window.back();
    if (!jmp.is_jump || jmp.is_conditional || jmp.branch_target.has_value()) {
        return std::nullopt;
    }
    if (jmp.operand_count == 0 || !is_reg(jmp.operands[0])) { return std::nullopt; }
    const ZydisRegister tgt = enclosing(jmp.operands[0].base_reg, is_64bit);
    if (tgt == ZYDIS_REGISTER_NONE) { return std::nullopt; }

    const std::size_t jmp_pos = window.size() - 1;

    // add tgt, base  -- the target is the table entry biased by base
    ZydisRegister base = ZYDIS_REGISTER_NONE;
    std::size_t add_pos = 0;
    bool found_add = false;
    for (std::size_t i = jmp_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_ADD && ins.operand_count >= 2 &&
            is_reg(ins.operands[0]) && is_reg(ins.operands[1]) &&
            enclosing(ins.operands[0].base_reg, is_64bit) == tgt) {
            base = enclosing(ins.operands[1].base_reg, is_64bit);
            add_pos = i;
            found_add = true;
            break;
        }
    }
    if (!found_add || base == ZYDIS_REGISTER_NONE) { return std::nullopt; }

    // mov tgt, [base + index*4 + disp]  -- the load of the 32-bit offset table
    ZydisRegister index = ZYDIS_REGISTER_NONE;
    std::uint8_t scale = 0;
    std::int64_t table_disp = 0;
    std::size_t load_pos = 0;
    bool found_load = false;
    for (std::size_t i = add_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        const bool movish = ins.zyd_mnem == ZYDIS_MNEMONIC_MOV ||
                            ins.zyd_mnem == ZYDIS_MNEMONIC_MOVZX ||
                            ins.zyd_mnem == ZYDIS_MNEMONIC_MOVSXD;
        if (movish && ins.operand_count >= 2 && is_reg(ins.operands[0]) &&
            enclosing(ins.operands[0].base_reg, is_64bit) == tgt &&
            ins.operands[1].kind == OperandKind::kSib &&
            enclosing(ins.operands[1].base_reg, is_64bit) == base &&
            ins.operands[1].index_reg != ZYDIS_REGISTER_NONE &&
            ins.operands[1].scale == 4) {
            index = enclosing(ins.operands[1].index_reg, is_64bit);
            scale = ins.operands[1].scale;
            table_disp = ins.operands[1].disp;
            load_pos = i;
            found_load = true;
            break;
        }
    }
    if (!found_load) { return std::nullopt; }

    // lea base, [rip+disp] (or mov base, imm) resolves the base to a concrete VA.
    // The nearest write to base before the load is the one that reaches it
    std::optional<std::uint64_t> base_va;
    for (std::size_t i = load_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.operand_count == 0 || !is_reg(ins.operands[0]) ||
            enclosing(ins.operands[0].base_reg, is_64bit) != base) {
            continue;
        }
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_LEA && ins.operand_count >= 2 &&
            ins.operands[1].kind == OperandKind::kRipRel) {
            base_va = ins.va + ins.length +
                      static_cast<std::uint64_t>(ins.operands[1].disp);
        } else if (ins.zyd_mnem == ZYDIS_MNEMONIC_MOV && ins.operand_count >= 2 &&
                   ins.operands[1].kind == OperandKind::kImm) {
            base_va = ins.operands[1].imm;
        }
        break;
    }
    if (!base_va.has_value()) { return std::nullopt; }

    // The index may be copied from a 32-bit register that the bound checks, as
    // with "movsxd rax, ecx" feeding a "cmp ecx, N". Track both registers
    std::vector<ZydisRegister> bound_regs{index};
    for (std::size_t i = load_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        const bool copyish = ins.zyd_mnem == ZYDIS_MNEMONIC_MOV ||
                             ins.zyd_mnem == ZYDIS_MNEMONIC_MOVSXD ||
                             ins.zyd_mnem == ZYDIS_MNEMONIC_MOVZX;
        if (copyish && ins.operand_count >= 2 && is_reg(ins.operands[0]) &&
            enclosing(ins.operands[0].base_reg, is_64bit) == index &&
            is_reg(ins.operands[1])) {
            bound_regs.push_back(enclosing(ins.operands[1].base_reg, is_64bit));
            break;
        }
    }

    // cmp bound_reg, N nearest before the dispatch fixes the case count. The
    // guarding branch tells inclusive (ja, 0..N) from exclusive (jae, 0..N-1)
    std::optional<std::uint64_t> count;
    for (std::size_t i = load_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.zyd_mnem != ZYDIS_MNEMONIC_CMP || ins.operand_count < 2 ||
            !is_reg(ins.operands[0]) || ins.operands[1].kind != OperandKind::kImm) {
            continue;
        }
        const ZydisRegister cmp_reg = enclosing(ins.operands[0].base_reg, is_64bit);
        bool bounds_index = false;
        for (const ZydisRegister r : bound_regs) {
            if (r == cmp_reg) { bounds_index = true; break; }
        }
        if (!bounds_index) { continue; }
        const std::uint64_t n = ins.operands[1].imm;
        std::uint64_t entries = n + 1;
        for (std::size_t j = i + 1; j < load_pos && j <= i + 3; ++j) {
            const DecodedInsn& guard = window[j];
            if (!guard.is_jump || !guard.is_conditional) { continue; }
            if (guard.zyd_mnem == ZYDIS_MNEMONIC_JNB ||
                guard.zyd_mnem == ZYDIS_MNEMONIC_JNL) {
                entries = n;
            }
            break;
        }
        count = entries;
        break;
    }
    if (!count.has_value() || *count == 0 || *count > kMaxJumpTableEntries) {
        return std::nullopt;
    }

    const std::uint64_t table_va = *base_va + static_cast<std::uint64_t>(table_disp);

    JumpTableTargets out;
    out.table_va   = table_va;
    out.table_size = *count * scale;
    out.targets.reserve(static_cast<std::size_t>(*count));
    for (std::uint64_t k = 0; k < *count; ++k) {
        const auto entry = read_u32(table_va + k * scale);
        if (!entry.has_value()) { break; }
        const std::uint64_t target = *base_va + static_cast<std::uint64_t>(*entry);
        if (target < range_lo || target >= range_hi) { break; }
        out.targets.push_back(target);
    }
    if (out.targets.empty()) { return std::nullopt; }
    return out;
}

std::optional<JumpTableTargets>
resolve_two_level_indexed_jump_table(std::span<const DecodedInsn> window,
                                     bool is_64bit,
                                     std::uint64_t range_lo,
                                     std::uint64_t range_hi,
                                     const TableReader& read_u32,
                                     const ByteReader& read_u8) {
    if (window.empty()) { return std::nullopt; }

    const DecodedInsn& jmp = window.back();
    if (!jmp.is_jump || jmp.is_conditional || jmp.branch_target.has_value()) {
        return std::nullopt;
    }
    if (jmp.operand_count == 0 || !is_reg(jmp.operands[0])) { return std::nullopt; }
    const ZydisRegister tgt = enclosing(jmp.operands[0].base_reg, is_64bit);
    if (tgt == ZYDIS_REGISTER_NONE) { return std::nullopt; }

    const std::size_t jmp_pos = window.size() - 1;

    // add tgt, base
    ZydisRegister base = ZYDIS_REGISTER_NONE;
    std::size_t   add_pos = 0;
    bool          found_add = false;
    for (std::size_t i = jmp_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_ADD && ins.operand_count >= 2 &&
            is_reg(ins.operands[0]) && is_reg(ins.operands[1]) &&
            enclosing(ins.operands[0].base_reg, is_64bit) == tgt) {
            base = enclosing(ins.operands[1].base_reg, is_64bit);
            add_pos = i;
            found_add = true;
            break;
        }
    }
    if (!found_add || base == ZYDIS_REGISTER_NONE) { return std::nullopt; }

    // mov tgt, [base + index*4 + T1]  -- the dword offset-table load
    ZydisRegister index = ZYDIS_REGISTER_NONE;
    std::int64_t  off_disp = 0;
    std::size_t   load_pos = 0;
    bool          found_load = false;
    for (std::size_t i = add_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        const bool movish = ins.zyd_mnem == ZYDIS_MNEMONIC_MOV ||
                            ins.zyd_mnem == ZYDIS_MNEMONIC_MOVZX ||
                            ins.zyd_mnem == ZYDIS_MNEMONIC_MOVSXD;
        if (movish && ins.operand_count >= 2 && is_reg(ins.operands[0]) &&
            enclosing(ins.operands[0].base_reg, is_64bit) == tgt &&
            ins.operands[1].kind == OperandKind::kSib &&
            enclosing(ins.operands[1].base_reg, is_64bit) == base &&
            ins.operands[1].index_reg != ZYDIS_REGISTER_NONE &&
            ins.operands[1].scale == 4) {
            index    = enclosing(ins.operands[1].index_reg, is_64bit);
            off_disp = ins.operands[1].disp;
            load_pos = i;
            found_load = true;
            break;
        }
    }
    if (!found_load) { return std::nullopt; }

    // movzx index, byte [base + val + T2]  -- the byte index-map remap that makes
    // this a two-level switch. Its absence means the single-level resolver applies
    ZydisRegister val_reg = ZYDIS_REGISTER_NONE;
    std::int64_t  map_disp = 0;
    std::size_t   remap_pos = 0;
    bool          found_remap = false;
    for (std::size_t i = load_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_MOVZX && ins.operand_count >= 2 &&
            is_reg(ins.operands[0]) &&
            enclosing(ins.operands[0].base_reg, is_64bit) == index &&
            ins.operands[1].kind == OperandKind::kSib &&
            enclosing(ins.operands[1].base_reg, is_64bit) == base &&
            ins.operands[1].index_reg != ZYDIS_REGISTER_NONE &&
            ins.operands[1].scale == 1) {
            val_reg   = enclosing(ins.operands[1].index_reg, is_64bit);
            map_disp  = ins.operands[1].disp;
            remap_pos = i;
            found_remap = true;
            break;
        }
    }
    if (!found_remap) { return std::nullopt; }

    // lea base, [rip+disp] (or mov base, imm), often at the prologue
    std::optional<std::uint64_t> base_va;
    for (std::size_t i = load_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.operand_count == 0 || !is_reg(ins.operands[0]) ||
            enclosing(ins.operands[0].base_reg, is_64bit) != base) {
            continue;
        }
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_LEA && ins.operand_count >= 2 &&
            ins.operands[1].kind == OperandKind::kRipRel) {
            base_va = ins.va + ins.length +
                      static_cast<std::uint64_t>(ins.operands[1].disp);
        } else if (ins.zyd_mnem == ZYDIS_MNEMONIC_MOV && ins.operand_count >= 2 &&
                   ins.operands[1].kind == OperandKind::kImm) {
            base_va = ins.operands[1].imm;
        }
        break;
    }
    if (!base_va.has_value()) { return std::nullopt; }

    // cmp val_reg, N nearest before the remap fixes the switch-value count
    std::optional<std::uint64_t> count;
    for (std::size_t i = remap_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.zyd_mnem != ZYDIS_MNEMONIC_CMP || ins.operand_count < 2 ||
            !is_reg(ins.operands[0]) || ins.operands[1].kind != OperandKind::kImm ||
            enclosing(ins.operands[0].base_reg, is_64bit) != val_reg) {
            continue;
        }
        const std::uint64_t n = ins.operands[1].imm;
        std::uint64_t entries = n + 1;
        for (std::size_t j = i + 1; j < remap_pos && j <= i + 3; ++j) {
            const DecodedInsn& guard = window[j];
            if (!guard.is_jump || !guard.is_conditional) { continue; }
            if (guard.zyd_mnem == ZYDIS_MNEMONIC_JNB ||
                guard.zyd_mnem == ZYDIS_MNEMONIC_JNL) {
                entries = n;
            }
            break;
        }
        count = entries;
        break;
    }
    if (!count.has_value() || *count == 0 || *count > kMaxJumpTableEntries) {
        return std::nullopt;
    }

    // For each switch value, remap it through the byte table, then read the dword
    // offset table, and bias by the base. Collect the distinct case targets
    const std::uint64_t map_va = *base_va + static_cast<std::uint64_t>(map_disp);
    const std::uint64_t off_va = *base_va + static_cast<std::uint64_t>(off_disp);
    JumpTableTargets out;
    out.table_va   = off_va;
    out.table_size = 0;  // both tables sit in read-only data, never decoded as code
    std::vector<std::uint64_t> seen;
    // Membership index beside the ordered list. The list still decides the
    // result and its order, so this only removes the linear rescan that made
    // a full-length table quadratic
    std::unordered_set<std::uint64_t> seen_index;
    for (std::uint64_t v = 0; v < *count; ++v) {
        const auto idx = read_u8(map_va + v);
        if (!idx.has_value()) { break; }
        const auto entry = read_u32(off_va + static_cast<std::uint64_t>(*idx) * 4U);
        if (!entry.has_value()) { break; }
        const std::uint64_t target = *base_va + static_cast<std::uint64_t>(*entry);
        if (target < range_lo || target >= range_hi) { continue; }
        const bool already = seen_index.count(target) != 0;
        if (!already) {
            seen_index.insert(target);
            seen.push_back(target);
            out.targets.push_back(target);
        }
    }
    if (out.targets.empty()) { return std::nullopt; }
    return out;
}

std::optional<JumpTableTargets>
resolve_switch_jump_table(std::span<const DecodedInsn> window,
                          bool                         is_64bit,
                          const SwitchEnv&             env) {
    if (window.empty() || !env.base_reg_value || !env.read_entry ||
        !env.is_probably_code) {
        return std::nullopt;
    }

    // The window must end at an indirect register jump (switchcase getSwitchBase
    // requires IF_BRANCH with a register operand)
    const DecodedInsn& jmp = window.back();
    if (!jmp.is_jump || jmp.is_conditional || jmp.branch_target.has_value()) {
        return std::nullopt;
    }
    if (jmp.operand_count == 0 || !is_reg(jmp.operands[0])) { return std::nullopt; }
    const ZydisRegister tgt = enclosing(jmp.operands[0].base_reg, is_64bit);
    if (tgt == ZYDIS_REGISTER_NONE) { return std::nullopt; }

    const std::size_t jmp_pos = window.size() - 1;

    // findOp 'add' reg: the add that biases the jump register by the base
    ZydisRegister base = ZYDIS_REGISTER_NONE;
    std::size_t   add_pos = 0;
    bool          found_add = false;
    for (std::size_t i = jmp_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_ADD && ins.operand_count >= 2 &&
            is_reg(ins.operands[0]) && is_reg(ins.operands[1]) &&
            enclosing(ins.operands[0].base_reg, is_64bit) == tgt) {
            base = enclosing(ins.operands[1].base_reg, is_64bit);
            add_pos = i;
            found_add = true;
            break;
        }
    }
    if (!found_add || base == ZYDIS_REGISTER_NONE) { return std::nullopt; }

    // The base register's value comes from the live emulator (getOperValue), so a
    // path-sensitive base a static lea scan cannot follow resolves. The offset
    // table is image-base-relative, so vivisect requires the base to be the image
    // base (getSwitchBase: regbase must equal imgbase)
    const auto base_val = env.base_reg_value(base);
    if (!base_val.has_value() || *base_val != env.image_base) {
        return std::nullopt;
    }

    // findOp 'mov' reg: the SIB load of the offset-table entry into the jump
    // register (mov tgt, [base + index*4 + disp]). This is the 32-bit
    // image-base-relative offset table, so the index scale and the entry width
    // are both 4, matching read_entry
    std::int64_t  table_disp = 0;
    bool          found_load = false;
    for (std::size_t i = add_pos; i-- > 0;) {
        const DecodedInsn& ins = window[i];
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_MOV && ins.operand_count >= 2 &&
            is_reg(ins.operands[0]) &&
            enclosing(ins.operands[0].base_reg, is_64bit) == tgt &&
            ins.operands[1].kind == OperandKind::kSib &&
            enclosing(ins.operands[1].base_reg, is_64bit) == base &&
            ins.operands[1].index_reg != ZYDIS_REGISTER_NONE &&
            ins.operands[1].scale == 4) {
            table_disp = ins.operands[1].disp;
            found_load = true;
            break;
        }
    }
    if (!found_load) { return std::nullopt; }
    constexpr std::uint64_t kEntryWidth = 4;

    // makeJumpTable / iterJumpTable: walk the offset table sequentially, rebasing
    // each image-base-relative entry, while the target is probable code. Distinct
    // targets are the case bodies (makeJumpTable dedups via tabdone)
    const std::uint64_t table_va = env.image_base +
                                   static_cast<std::uint64_t>(table_disp);
    JumpTableTargets out;
    out.table_va = table_va;
    std::vector<std::uint64_t> seen;
    // Membership index beside the ordered list. The list still decides the
    // result and its order, so this only removes the linear rescan that made
    // a full-length table quadratic
    std::unordered_set<std::uint64_t> seen_index;
    std::uint64_t entries = 0;
    for (; entries < kMaxJumpTableEntries; ++entries) {
        const auto raw = env.read_entry(table_va + entries * kEntryWidth);
        if (!raw.has_value()) { break; }
        std::uint64_t rdest = *raw;
        if (rdest < env.image_base) { rdest += env.image_base; }
        if (!env.is_probably_code(rdest)) { break; }
        const bool already = seen_index.count(rdest) != 0;
        if (!already) {
            seen_index.insert(rdest);
            seen.push_back(rdest);
            out.targets.push_back(rdest);
        }
    }
    if (out.targets.empty()) { return std::nullopt; }
    out.table_size = entries * kEntryWidth;
    return out;
}

std::optional<JumpTableTargets> resolve_memory_indirect_jump_table(
    const DecodedInsn& jmp_insn, std::uint64_t range_lo, std::uint64_t range_hi,
    const TableReader& read_u32) {
    if (!jmp_insn.is_jump || jmp_insn.is_conditional || jmp_insn.operand_count == 0) {
        return std::nullopt;
    }
    const DecodedOperand& op = jmp_insn.operands[0];
    // Only the constant-base indexed form: jmp [index*scale + table]. A base
    // register makes the table address runtime-dependent, and without an index
    // there is no table to walk
    if (op.kind != OperandKind::kSib) { return std::nullopt; }
    if (op.base_reg != ZYDIS_REGISTER_NONE) { return std::nullopt; }
    if (op.index_reg == ZYDIS_REGISTER_NONE) { return std::nullopt; }
    if (op.scale < 4 || op.disp <= 0) { return std::nullopt; }

    const std::uint64_t table_va = static_cast<std::uint64_t>(op.disp);
    JumpTableTargets out;
    out.table_va = table_va;
    // The table holds absolute 32-bit case-target pointers. Read until one falls
    // outside the executable range or the address is unmapped
    for (std::uint64_t k = 0; k < kMaxJumpTableEntries; ++k) {
        const auto entry = read_u32(table_va + k * 4U);
        if (!entry.has_value()) { break; }
        const std::uint64_t target = *entry;
        if (target < range_lo || target >= range_hi) { break; }
        out.targets.push_back(target);
    }
    if (out.targets.empty()) { return std::nullopt; }
    out.table_size = out.targets.size() * 4U;
    return out;
}

}  // namespace papa::features::extractors::papa_native
