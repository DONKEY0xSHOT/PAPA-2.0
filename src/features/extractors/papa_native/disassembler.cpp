#include "papa/features/extractors/papa_native/disassembler.h"

#include "papa/exceptions.h"

#include <algorithm>
#include <cstring>

namespace papa::features::extractors::papa_native {

namespace {

// Stack registers used to suppress is_security_cookie and Number/Offset false positives
constexpr std::array<ZydisRegister, 2> kStackRegs32 {
    ZYDIS_REGISTER_ESP, ZYDIS_REGISTER_EBP,
};
constexpr std::array<ZydisRegister, 2> kStackRegs64 {
    ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_RBP,
};

[[nodiscard]] bool is_ip_register(ZydisRegister r) noexcept {
    return r == ZYDIS_REGISTER_RIP || r == ZYDIS_REGISTER_EIP || r == ZYDIS_REGISTER_IP;
}

}  // namespace

Disassembler::Disassembler(bool is_64bit) : is_64bit_(is_64bit) {
    const ZydisMachineMode mm = is_64bit
        ? ZYDIS_MACHINE_MODE_LONG_64
        : ZYDIS_MACHINE_MODE_LEGACY_32;
    const ZydisStackWidth  sw = is_64bit
        ? ZYDIS_STACK_WIDTH_64
        : ZYDIS_STACK_WIDTH_32;
    const ZyanStatus s = ZydisDecoderInit(&decoder_, mm, sw);
    if (!ZYAN_SUCCESS(s)) {
        // Init never fails for valid enum inputs
        // Treat any failure as a programmer error
        throw PapaInvariantError("ZydisDecoderInit failed");
    }
}

std::span<const ZydisRegister> Disassembler::stack_registers() const noexcept {
    return is_64bit_
        ? std::span<const ZydisRegister>(kStackRegs64.data(), kStackRegs64.size())
        : std::span<const ZydisRegister>(kStackRegs32.data(), kStackRegs32.size());
}

std::string_view Disassembler::mnemonic_to_string(ZydisMnemonic m) noexcept {
    const char* s = ZydisMnemonicGetString(m);
    return s != nullptr ? std::string_view{s} : std::string_view{};
}

OperandKind Disassembler::classify(
    const ZydisDecodedOperand& op, ZydisMachineMode /*mode*/,
    bool has_sib) noexcept {
    switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            return OperandKind::kReg;

        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            return op.imm.is_relative ? OperandKind::kPcRel : OperandKind::kImm;

        case ZYDIS_OPERAND_TYPE_MEMORY: {
            const auto& m = op.mem;
            if (is_ip_register(m.base)) {
                return OperandKind::kRipRel;
            }
            const bool has_base  = (m.base  != ZYDIS_REGISTER_NONE);
            const bool has_index = (m.index != ZYDIS_REGISTER_NONE);
            if (!has_base && !has_index) {
                // A SIB byte with neither base nor index is vivisect's i386SibOper, whose
                // displacement is an offset source. Without one it is i386ImmMemOper, a number
                return has_sib ? OperandKind::kSib : OperandKind::kImmMem;
            }
            if (has_index) {
                return OperandKind::kSib;
            }
            return OperandKind::kRegMem;
        }

        case ZYDIS_OPERAND_TYPE_POINTER:
        case ZYDIS_OPERAND_TYPE_UNUSED:
        default:
            return OperandKind::kUnknown;
    }
}

namespace {

// Translate one Zydis operand into our DecodedOperand
// op.size is in bits and is always converted to bytes here
[[nodiscard]] DecodedOperand translate_operand(
    const ZydisDecodedOperand& op, ZydisMachineMode mode, bool has_sib) noexcept {
    DecodedOperand out;
    out.kind        = Disassembler::classify(op, mode, has_sib);
    out.width_bytes = static_cast<std::size_t>(op.size) / 8U;

    switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            out.base_reg = op.reg.value;
            break;

        case ZYDIS_OPERAND_TYPE_MEMORY:
            out.base_reg     = op.mem.base;
            out.index_reg    = op.mem.index;
            out.scale        = op.mem.scale;
            out.disp         = op.mem.disp.has_displacement ? op.mem.disp.value : 0;
            out.sib_encoded  = has_sib;
            break;

        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            out.is_signed_imm = (op.imm.is_signed != ZYAN_FALSE);
            out.imm           = op.imm.value.u;
            break;

        default:
            break;
    }
    return out;
}

// Instructions that end a block without falling through, beyond the return and
// unconditional-branch cases
[[nodiscard]] bool is_nofall_terminal(const DecodedInsn& d) noexcept {
    switch (d.zyd_mnem) {
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_HLT:
        case ZYDIS_MNEMONIC_UD0:
        case ZYDIS_MNEMONIC_UD1:
        case ZYDIS_MNEMONIC_UD2:
        case ZYDIS_MNEMONIC_INTO:
            return true;
        case ZYDIS_MNEMONIC_INT: {
            // PAPA only analyzes Windows PEs, so the platform is always Windows
            constexpr std::uint64_t kWindowsSyscallGate = 0x2EU;
            return d.operand_count > 0 &&
                   d.operands[0].imm != kWindowsSyscallGate;
        }
        default:
            return false;
    }
}

// Derive high-level control flow from Zydis category/mnemonic
void fill_cf_fields(DecodedInsn& d, const ZydisDecodedInstruction& zi) noexcept {
    switch (zi.meta.category) {
        case ZYDIS_CATEGORY_CALL:
            d.is_call = true;
            break;
        case ZYDIS_CATEGORY_UNCOND_BR:
            d.is_jump = true;
            break;
        case ZYDIS_CATEGORY_COND_BR:
            d.is_jump        = true;
            d.is_conditional = true;
            break;
        case ZYDIS_CATEGORY_RET:
            d.is_return = true;
            break;
        default:
            break;
    }
    // Returns, unconditional jumps, and the trap/debug/halt/invalid classes
    // never fall through
    d.is_fallthrough =
        !(d.is_return || (d.is_jump && !d.is_conditional) || is_nofall_terminal(d));
}

// Resolve absolute branch target when operand[0] is a relative imm
void fill_branch_target(DecodedInsn& d,
                        const ZydisDecodedInstruction& zi,
                        const ZydisDecodedOperand& op0,
                        std::uint64_t va) noexcept {
    if ((!d.is_call && !d.is_jump) || op0.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        return;
    }
    if (!op0.imm.is_relative) {
        // Absolute immediate call or jmp
        // Rare on x86, handled via kImmMem elsewhere
        return;
    }
    ZyanU64 abs = 0;
    const ZyanStatus s = ZydisCalcAbsoluteAddress(&zi, &op0, va, &abs);
    if (ZYAN_SUCCESS(s)) {
        d.branch_target = abs;
    }
}

}  // namespace

Expected<DecodedInsn> Disassembler::decode(
    std::span<const std::byte> bytes, std::uint64_t va) const {
    if (bytes.empty()) {
        return Unexpected{make_error(
            ErrorKind::kDisassemblyFailed, "empty instruction buffer")};
    }

    ZydisDecodedInstruction zi{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> zops{};

    const ZyanStatus s = ZydisDecoderDecodeFull(
        &decoder_,
        bytes.data(),
        bytes.size(),
        &zi,
        zops.data());
    if (!ZYAN_SUCCESS(s)) {
        return Unexpected{make_error(
            ErrorKind::kDisassemblyFailed, "ZydisDecoderDecodeFull failed")};
    }
    if (zi.length == 0 || zi.length > bytes.size()) {
        return Unexpected{make_error(
            ErrorKind::kDisassemblyFailed, "impossible instruction length")};
    }

    DecodedInsn d;
    d.va            = va;
    d.length        = zi.length;
    d.zyd_mnem      = zi.mnemonic;
    d.mnemonic_str  = mnemonic_to_string(zi.mnemonic);
    d.raw_bytes     = bytes.first(zi.length);
    d.has_prefix_fs = (zi.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) != 0;
    d.has_prefix_gs = (zi.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS) != 0;

    const std::size_t visible = std::min<std::size_t>(
        zi.operand_count_visible, constants::kMaxOperandCount);
    d.operand_count = visible;
    const ZydisMachineMode mode = zi.machine_mode;
    // The SIB flag is instruction-level
    const bool has_sib = (zi.attributes & ZYDIS_ATTRIB_HAS_SIB) != 0;
    for (std::size_t i = 0; i < visible; ++i) {
        d.operands[i] = translate_operand(zops[i], mode, has_sib);
    }

    fill_cf_fields(d, zi);
    if (visible > 0) {
        fill_branch_target(d, zi, zops[0], va);
    }
    return d;
}

}  // namespace papa::features::extractors::papa_native
