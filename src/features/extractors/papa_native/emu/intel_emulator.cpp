#include "papa/features/extractors/papa_native/emu/intel_emulator.h"

#include "papa/features/extractors/papa_native/emu/bits.h"

namespace papa::features::extractors::papa_native::emu {

std::optional<std::uint32_t>
reg_index_from_zydis(ZydisRegister reg, bool is_64bit) noexcept {
    if (is_64bit) {
        switch (reg) {
            // 64-bit
            case ZYDIS_REGISTER_RAX: return kRegRax;
            case ZYDIS_REGISTER_RCX: return kRegRcx;
            case ZYDIS_REGISTER_RDX: return kRegRdx;
            case ZYDIS_REGISTER_RBX: return kRegRbx;
            case ZYDIS_REGISTER_RSP: return kRegRsp;
            case ZYDIS_REGISTER_RBP: return kRegRbp;
            case ZYDIS_REGISTER_RSI: return kRegRsi;
            case ZYDIS_REGISTER_RDI: return kRegRdi;
            case ZYDIS_REGISTER_R8:  return kRegR8;
            case ZYDIS_REGISTER_R9:  return kRegR9;
            case ZYDIS_REGISTER_R10: return kRegR10;
            case ZYDIS_REGISTER_R11: return kRegR11;
            case ZYDIS_REGISTER_R12: return kRegR12;
            case ZYDIS_REGISTER_R13: return kRegR13;
            case ZYDIS_REGISTER_R14: return kRegR14;
            case ZYDIS_REGISTER_R15: return kRegR15;
            case ZYDIS_REGISTER_RIP: return kRegRip;
            // 32-bit lanes: writing zero-extends into the parent (RMETA_LOW32)
            case ZYDIS_REGISTER_EAX: return make_meta_reg(0, 32, kRegRax);
            case ZYDIS_REGISTER_ECX: return make_meta_reg(0, 32, kRegRcx);
            case ZYDIS_REGISTER_EDX: return make_meta_reg(0, 32, kRegRdx);
            case ZYDIS_REGISTER_EBX: return make_meta_reg(0, 32, kRegRbx);
            case ZYDIS_REGISTER_ESP: return make_meta_reg(0, 32, kRegRsp);
            case ZYDIS_REGISTER_EBP: return make_meta_reg(0, 32, kRegRbp);
            case ZYDIS_REGISTER_ESI: return make_meta_reg(0, 32, kRegRsi);
            case ZYDIS_REGISTER_EDI: return make_meta_reg(0, 32, kRegRdi);
            case ZYDIS_REGISTER_R8D:  return make_meta_reg(0, 32, kRegR8);
            case ZYDIS_REGISTER_R9D:  return make_meta_reg(0, 32, kRegR9);
            case ZYDIS_REGISTER_R10D: return make_meta_reg(0, 32, kRegR10);
            case ZYDIS_REGISTER_R11D: return make_meta_reg(0, 32, kRegR11);
            case ZYDIS_REGISTER_R12D: return make_meta_reg(0, 32, kRegR12);
            case ZYDIS_REGISTER_R13D: return make_meta_reg(0, 32, kRegR13);
            case ZYDIS_REGISTER_R14D: return make_meta_reg(0, 32, kRegR14);
            case ZYDIS_REGISTER_R15D: return make_meta_reg(0, 32, kRegR15);
            case ZYDIS_REGISTER_EIP:  return make_meta_reg(0, 32, kRegRip);
            // 16-bit lanes
            case ZYDIS_REGISTER_AX: return kRegAx;
            case ZYDIS_REGISTER_CX: return kRegCx;
            case ZYDIS_REGISTER_DX: return kRegDx;
            case ZYDIS_REGISTER_BX: return kRegBx;
            case ZYDIS_REGISTER_SP: return kRegSp;
            case ZYDIS_REGISTER_BP: return kRegBp;
            case ZYDIS_REGISTER_SI: return kRegSi;
            case ZYDIS_REGISTER_DI: return kRegDi;
            case ZYDIS_REGISTER_R8W:  return make_meta_reg(0, 16, kRegR8);
            case ZYDIS_REGISTER_R9W:  return make_meta_reg(0, 16, kRegR9);
            case ZYDIS_REGISTER_R10W: return make_meta_reg(0, 16, kRegR10);
            case ZYDIS_REGISTER_R11W: return make_meta_reg(0, 16, kRegR11);
            case ZYDIS_REGISTER_R12W: return make_meta_reg(0, 16, kRegR12);
            case ZYDIS_REGISTER_R13W: return make_meta_reg(0, 16, kRegR13);
            case ZYDIS_REGISTER_R14W: return make_meta_reg(0, 16, kRegR14);
            case ZYDIS_REGISTER_R15W: return make_meta_reg(0, 16, kRegR15);
            // 8-bit low lanes (spl/bpl/sil/dil exist only with a REX prefix)
            case ZYDIS_REGISTER_AL: return kRegAl;
            case ZYDIS_REGISTER_CL: return kRegCl;
            case ZYDIS_REGISTER_DL: return kRegDl;
            case ZYDIS_REGISTER_BL: return kRegBl;
            case ZYDIS_REGISTER_SPL: return make_meta_reg(0, 8, kRegRsp);
            case ZYDIS_REGISTER_BPL: return make_meta_reg(0, 8, kRegRbp);
            case ZYDIS_REGISTER_SIL: return make_meta_reg(0, 8, kRegRsi);
            case ZYDIS_REGISTER_DIL: return make_meta_reg(0, 8, kRegRdi);
            case ZYDIS_REGISTER_R8B:  return make_meta_reg(0, 8, kRegR8);
            case ZYDIS_REGISTER_R9B:  return make_meta_reg(0, 8, kRegR9);
            case ZYDIS_REGISTER_R10B: return make_meta_reg(0, 8, kRegR10);
            case ZYDIS_REGISTER_R11B: return make_meta_reg(0, 8, kRegR11);
            case ZYDIS_REGISTER_R12B: return make_meta_reg(0, 8, kRegR12);
            case ZYDIS_REGISTER_R13B: return make_meta_reg(0, 8, kRegR13);
            case ZYDIS_REGISTER_R14B: return make_meta_reg(0, 8, kRegR14);
            case ZYDIS_REGISTER_R15B: return make_meta_reg(0, 8, kRegR15);
            // 8-bit high lanes
            case ZYDIS_REGISTER_AH: return kRegAh;
            case ZYDIS_REGISTER_CH: return kRegCh;
            case ZYDIS_REGISTER_DH: return kRegDh;
            case ZYDIS_REGISTER_BH: return kRegBh;
            default:
                return std::nullopt;
        }
    }

    switch (reg) {
        // 32-bit
        case ZYDIS_REGISTER_EAX: return kRegEax;
        case ZYDIS_REGISTER_ECX: return kRegEcx;
        case ZYDIS_REGISTER_EDX: return kRegEdx;
        case ZYDIS_REGISTER_EBX: return kRegEbx;
        case ZYDIS_REGISTER_ESP: return kRegEsp;
        case ZYDIS_REGISTER_EBP: return kRegEbp;
        case ZYDIS_REGISTER_ESI: return kRegEsi;
        case ZYDIS_REGISTER_EDI: return kRegEdi;
        case ZYDIS_REGISTER_EIP: return kRegEip;
        // 16-bit
        case ZYDIS_REGISTER_AX: return kRegAx;
        case ZYDIS_REGISTER_CX: return kRegCx;
        case ZYDIS_REGISTER_DX: return kRegDx;
        case ZYDIS_REGISTER_BX: return kRegBx;
        case ZYDIS_REGISTER_SP: return kRegSp;
        case ZYDIS_REGISTER_BP: return kRegBp;
        case ZYDIS_REGISTER_SI: return kRegSi;
        case ZYDIS_REGISTER_DI: return kRegDi;
        // 8-bit low
        case ZYDIS_REGISTER_AL: return kRegAl;
        case ZYDIS_REGISTER_CL: return kRegCl;
        case ZYDIS_REGISTER_DL: return kRegDl;
        case ZYDIS_REGISTER_BL: return kRegBl;
        // 8-bit high
        case ZYDIS_REGISTER_AH: return kRegAh;
        case ZYDIS_REGISTER_CH: return kRegCh;
        case ZYDIS_REGISTER_DH: return kRegDh;
        case ZYDIS_REGISTER_BH: return kRegBh;
        default:
            return std::nullopt;
    }
}

std::uint64_t IntelEmulator::register_value(ZydisRegister reg) const noexcept {
    const std::optional<std::uint32_t> idx = reg_index_from_zydis(reg, is_64bit_);
    if (!idx.has_value()) {
        return 0U;
    }
    return regs_.get_register(*idx);
}

std::uint64_t
IntelEmulator::get_oper_addr(const DecodedInsn& insn, std::size_t idx) const {
    const DecodedOperand& op = insn.operands[idx];
    std::uint64_t addr = 0;
    switch (op.kind) {
        case OperandKind::kRegMem:
            addr = static_cast<std::uint64_t>(register_value(op.base_reg)) +
                   static_cast<std::uint64_t>(op.disp);
            break;
        case OperandKind::kImmMem:
            addr = op.imm;
            break;
        case OperandKind::kSib: {
            std::uint64_t base = 0;
            if (op.base_reg != ZYDIS_REGISTER_NONE) {
                base += register_value(op.base_reg);
            }
            if (op.index_reg != ZYDIS_REGISTER_NONE) {
                base += static_cast<std::uint64_t>(register_value(op.index_reg)) *
                        op.scale;
            }
            addr = base + static_cast<std::uint64_t>(op.disp);
            break;
        }
        case OperandKind::kRipRel:
            addr = insn.va + insn.length + static_cast<std::uint64_t>(op.disp);
            break;
        default:
            return 0U;
    }
    return addr & addr_mask();
}

std::uint64_t
IntelEmulator::get_oper_value(const DecodedInsn& insn, std::size_t idx) const {
    const DecodedOperand& op = insn.operands[idx];
    switch (op.kind) {
        case OperandKind::kReg:
            return register_value(op.base_reg);
        case OperandKind::kImm:
            return op.imm;
        case OperandKind::kPcRel:
            if (insn.branch_target.has_value()) {
                return *insn.branch_target;
            }
            // i386PcRelOper.getOperValue = va + size + imm
            return (insn.va + insn.length + op.imm) & addr_mask();
        case OperandKind::kRegMem:
        case OperandKind::kImmMem:
        case OperandKind::kSib:
        case OperandKind::kRipRel:
            return mem_.read_value(get_oper_addr(insn, idx), op.width_bytes);
        default:
            return 0U;
    }
}

void IntelEmulator::set_oper_value(const DecodedInsn& insn, std::size_t idx,
                                   std::uint64_t value) {
    const DecodedOperand& op = insn.operands[idx];
    switch (op.kind) {
        case OperandKind::kReg: {
            const std::optional<std::uint32_t> ridx =
                reg_index_from_zydis(op.base_reg, is_64bit_);
            if (ridx.has_value()) {
                regs_.set_register(*ridx, value);
            }
            break;
        }
        case OperandKind::kRegMem:
        case OperandKind::kImmMem:
        case OperandKind::kSib:
        case OperandKind::kRipRel:
            mem_.write_value(get_oper_addr(insn, idx), value, op.width_bytes);
            break;
        default:
            // Immediate / pc-relative operands cannot be written
            break;
    }
}

namespace {
// XMM register index (0..15) for an SSE register operand, else nullopt
[[nodiscard]] std::optional<std::uint32_t> xmm_index(ZydisRegister reg) noexcept {
    if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM15) {
        return static_cast<std::uint32_t>(reg - ZYDIS_REGISTER_XMM0);
    }
    return std::nullopt;
}
}  // namespace

Xmm IntelEmulator::read_simd_oper(const DecodedInsn& insn, std::size_t idx,
                                  std::size_t width) const {
    const DecodedOperand& op = insn.operands[idx];
    Xmm out{};
    if (op.kind == OperandKind::kReg) {
        if (const auto xi = xmm_index(op.base_reg); xi.has_value()) {
            return regs_.get_xmm(*xi);
        }
        // General-purpose register source (the movd/movq reg form)
        const std::uint64_t v = register_value(op.base_reg);
        for (std::size_t i = 0; i < width && i < out.size(); ++i) {
            out[i] = static_cast<std::uint8_t>((v >> (8U * i)) & 0xFFU);
        }
        return out;
    }
    const std::vector<std::uint8_t> bytes =
        mem_.read_bytes(get_oper_addr(insn, idx), width);
    for (std::size_t i = 0; i < bytes.size() && i < out.size(); ++i) {
        out[i] = bytes[i];
    }
    return out;
}

void IntelEmulator::write_simd_oper(const DecodedInsn& insn, std::size_t idx,
                                    const Xmm& value, std::size_t width) {
    const DecodedOperand& op = insn.operands[idx];
    if (op.kind == OperandKind::kReg) {
        if (const auto xi = xmm_index(op.base_reg); xi.has_value()) {
            // XMM destination: low `width` bytes set, the upper bytes cleared
            Xmm v{};
            for (std::size_t i = 0; i < width && i < v.size(); ++i) {
                v[i] = value[i];
            }
            regs_.set_xmm(*xi, v);
            return;
        }
        // General-purpose register destination (the movd/movq reg form)
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < width && i < 8U; ++i) {
            v |= static_cast<std::uint64_t>(value[i]) << (8U * i);
        }
        if (const auto ri = reg_index_from_zydis(op.base_reg, is_64bit_);
            ri.has_value()) {
            regs_.set_register(*ri, v);
        }
        return;
    }
    std::vector<std::uint8_t> bytes(width);
    for (std::size_t i = 0; i < width && i < value.size(); ++i) {
        bytes[i] = value[i];
    }
    mem_.write(get_oper_addr(insn, idx), bytes);
}

void IntelEmulator::do_push(std::uint64_t value, std::size_t size) {
    std::uint64_t esp = regs_.get_register(kRegEsp);
    esp -= size;
    mem_.write_value(esp, value, size);
    regs_.set_register(kRegEsp, esp);
}

std::uint64_t IntelEmulator::do_pop(std::size_t size) {
    const std::uint64_t esp = regs_.get_register(kRegEsp);
    const std::uint64_t value = mem_.read_value(esp, size);
    regs_.set_register(kRegEsp, esp + size);
    return value;
}

std::uint64_t IntelEmulator::int_sub_base(std::uint64_t src, std::uint64_t dst,
                                          std::size_t ssize, std::size_t dsize) {
    const std::uint64_t usrc = bits::unsigned_(src, ssize);
    const std::uint64_t udst = bits::unsigned_(dst, dsize);
    const std::int64_t ssrc = bits::signed_(src, ssize);
    const std::int64_t sdst = bits::signed_(dst, dsize);

    const std::int64_t ures =
        static_cast<std::int64_t>(udst) - static_cast<std::int64_t>(usrc);
    const std::int64_t sres = sdst - ssrc;

    regs_.set_flag(kEflagsOf, bits::is_signed_overflow(sres, dsize));
    regs_.set_flag(kEflagsAf, bits::is_aux_carry_sub(usrc, udst));
    regs_.set_flag(kEflagsCf, bits::is_unsigned_carry(ures, dsize));
    regs_.set_flag(kEflagsSf, bits::is_signed(static_cast<std::uint64_t>(ures), dsize));
    regs_.set_flag(kEflagsZf, sres == 0);
    regs_.set_flag(kEflagsPf, bits::is_parity_byte(static_cast<std::uint64_t>(ures)));

    return static_cast<std::uint64_t>(ures);
}

std::uint64_t IntelEmulator::integer_subtraction(const DecodedInsn& insn) {
    const std::uint64_t dst = get_oper_value(insn, 0);
    std::uint64_t src = get_oper_value(insn, 1);
    const std::size_t dsize = insn.operands[0].width_bytes;
    std::size_t ssize = insn.operands[1].width_bytes;
    if (dsize != ssize) {
        src = bits::sign_extend(src, ssize, dsize);
        ssize = dsize;
    }
    return int_sub_base(src, dst, ssize, dsize);
}

std::uint64_t IntelEmulator::logical_and(const DecodedInsn& insn) {
    std::uint64_t dst = get_oper_value(insn, 0);
    std::uint64_t src = get_oper_value(insn, 1);
    const std::size_t dsize = insn.operands[0].width_bytes;
    std::size_t ssize = insn.operands[1].width_bytes;
    if (dsize != ssize) {
        src = bits::sign_extend(src, ssize, dsize);
        ssize = dsize;
    }
    dst = bits::unsigned_(dst, dsize);
    src = bits::unsigned_(src, ssize);
    const std::uint64_t res = src & dst;

    regs_.set_flag(kEflagsAf, false);
    regs_.set_flag(kEflagsOf, false);
    regs_.set_flag(kEflagsCf, false);
    regs_.set_flag(kEflagsSf, bits::is_signed(res, dsize));
    regs_.set_flag(kEflagsZf, res == 0);
    regs_.set_flag(kEflagsPf, bits::is_parity_byte(res));
    return res;
}

namespace {

[[nodiscard]] bool is_deref_kind(OperandKind kind) noexcept {
    return kind == OperandKind::kRegMem || kind == OperandKind::kImmMem ||
           kind == OperandKind::kSib || kind == OperandKind::kRipRel;
}

// The accumulator or data register lane for a given operand size, al/ax/eax/rax for
// base rax and dl/dx/edx/rdx for base rdx
[[nodiscard]] std::uint32_t gp_lane(std::uint32_t base, std::size_t size,
                                    bool is_64bit) noexcept {
    if (size == 1) {
        return make_meta_reg(0, 8, base);
    }
    if (size == 2) {
        return make_meta_reg(0, 16, base);
    }
    if (size == 4 && is_64bit) {
        return make_meta_reg(0, 32, base);
    }
    return base;
}

// High 64 bits of the unsigned 64x64 product, via 32-bit halves (portable, no
// intrinsics, no undefined >>64)
[[nodiscard]] std::uint64_t umul_hi(std::uint64_t a, std::uint64_t b) noexcept {
    const std::uint64_t a_lo = a & 0xFFFFFFFFULL;
    const std::uint64_t a_hi = a >> 32;
    const std::uint64_t b_lo = b & 0xFFFFFFFFULL;
    const std::uint64_t b_hi = b >> 32;
    const std::uint64_t ll = a_lo * b_lo;
    const std::uint64_t lh = a_lo * b_hi;
    const std::uint64_t hl = a_hi * b_lo;
    const std::uint64_t hh = a_hi * b_hi;
    const std::uint64_t cross =
        (ll >> 32) + (lh & 0xFFFFFFFFULL) + (hl & 0xFFFFFFFFULL);
    return hh + (lh >> 32) + (hl >> 32) + (cross >> 32);
}

// High 64 bits of the signed 64x64 product, derived from the unsigned high
[[nodiscard]] std::uint64_t smul_hi(std::uint64_t a, std::uint64_t b) noexcept {
    std::uint64_t hi = umul_hi(a, b);
    if ((a >> 63) != 0) {
        hi -= b;
    }
    if ((b >> 63) != 0) {
        hi -= a;
    }
    return hi;
}

// Unsigned 128/64 long division. Never traps (unlike the hardware DIV or the _udiv128
// intrinsic)
struct Div128 {
    std::uint64_t quot;
    std::uint64_t rem;
};
[[nodiscard]] Div128 udiv128(std::uint64_t hi, std::uint64_t lo,
                             std::uint64_t d) noexcept {
    std::uint64_t rem = 0;
    std::uint64_t quot = 0;
    for (int i = 127; i >= 0; --i) {
        const std::uint64_t bit =
            (i >= 64) ? ((hi >> (i - 64)) & 1ULL) : ((lo >> i) & 1ULL);
        const std::uint64_t rem_top = rem >> 63;
        rem = (rem << 1) | bit;
        quot <<= 1;
        // rem_top catches the 65-bit overflow: a set top bit means the true
        // remainder already exceeds the 64-bit divisor
        if (rem_top != 0 || rem >= d) {
            rem -= d;
            quot |= 1ULL;
        }
    }
    return Div128{quot, rem};
}

}  // namespace

std::vector<Branch> IntelEmulator::get_branches(const DecodedInsn& insn) const {
    std::vector<Branch> ret;
    if (insn.zyd_mnem == ZYDIS_MNEMONIC_HLT) {
        return ret;
    }

    std::uint32_t flags = 0;
    bool addb = false;

    // A conditional branch makes even the fall-through conditional
    if (insn.is_jump && insn.is_conditional) {
        flags |= kBrCond;
        addb = true;
    }

    // Fall-through edge (unless the instruction never falls through)
    if (insn.is_fallthrough) {
        ret.push_back(Branch{insn.va + insn.length, flags | kBrFall});
    }

    if (insn.operand_count == 0) {
        return ret;
    }

    if (insn.is_call) {
        flags |= kBrProc;
        addb = true;
    } else if (insn.is_jump && !insn.is_conditional) {
        const DecodedOperand& op0 = insn.operands[0];
        if (op0.kind == OperandKind::kSib && op0.scale == 4) {
            // Jump table: read consecutive pointers from the table base and
            // yield each valid one, stopping at the first invalid entry
            std::uint64_t base = static_cast<std::uint64_t>(op0.disp);
            if (op0.base_reg != ZYDIS_REGISTER_NONE) {
                base += register_value(op0.base_reg);
            }
            base &= addr_mask();
            std::uint64_t dest = mem_.read_value(base, op0.width_bytes);
            // Bounded by kMaxJumpTableEntries, since a crafted image can make
            // every entry read as a valid pointer forever
            std::size_t walked = 0;
            while (mem_.is_valid_pointer(dest) && walked < kMaxJumpTableEntries) {
                ret.push_back(Branch{dest, kBrCond});
                base += op0.width_bytes;
                dest = mem_.read_value(base, op0.width_bytes);
                ++walked;
            }
        } else {
            addb = true;
        }
    }

    if (addb) {
        const DecodedOperand& op0 = insn.operands[0];
        std::uint64_t tova = 0;
        if (is_deref_kind(op0.kind)) {
            flags |= kBrDeref;
            tova = get_oper_addr(insn, 0);
        } else {
            tova = get_oper_value(insn, 0);
        }
        ret.push_back(Branch{tova, flags});
    }
    return ret;
}

bool IntelEmulator::condition_met(ZydisMnemonic mnem) const noexcept {
    const bool cf = regs_.get_flag(kEflagsCf);
    const bool zf = regs_.get_flag(kEflagsZf);
    const bool sf = regs_.get_flag(kEflagsSf);
    const bool of = regs_.get_flag(kEflagsOf);
    const bool pf = regs_.get_flag(kEflagsPf);
    switch (mnem) {
        case ZYDIS_MNEMONIC_JB:    return cf;                  // cond_b
        case ZYDIS_MNEMONIC_JNB:   return !cf;                 // cond_ae
        case ZYDIS_MNEMONIC_JBE:   return cf || zf;            // cond_be
        case ZYDIS_MNEMONIC_JNBE:  return !cf && !zf;          // cond_a
        case ZYDIS_MNEMONIC_JZ:    return zf;                  // cond_e
        case ZYDIS_MNEMONIC_JNZ:   return !zf;                 // cond_ne
        case ZYDIS_MNEMONIC_JL:    return sf != of;            // cond_l
        case ZYDIS_MNEMONIC_JNL:   return sf == of;            // cond_ge
        case ZYDIS_MNEMONIC_JLE:   return (sf != of) || zf;    // cond_le
        case ZYDIS_MNEMONIC_JNLE:  return !zf && (sf == of);   // cond_g
        case ZYDIS_MNEMONIC_JO:    return of;                  // cond_o
        case ZYDIS_MNEMONIC_JNO:   return !of;                 // cond_no
        case ZYDIS_MNEMONIC_JS:    return sf;                  // cond_s
        case ZYDIS_MNEMONIC_JNS:   return !sf;                 // cond_ns
        case ZYDIS_MNEMONIC_JP:    return pf;                  // cond_p
        case ZYDIS_MNEMONIC_JNP:   return !pf;                 // cond_np
        case ZYDIS_MNEMONIC_JCXZ:  return regs_.get_register(kRegCx) == 0;
        case ZYDIS_MNEMONIC_JECXZ: return regs_.get_register(kRegEcx) == 0;
        // SETcc share the same condition algebra as the matching Jcc
        case ZYDIS_MNEMONIC_SETB:   return cf;
        case ZYDIS_MNEMONIC_SETNB:  return !cf;
        case ZYDIS_MNEMONIC_SETBE:  return cf || zf;
        case ZYDIS_MNEMONIC_SETNBE: return !cf && !zf;
        case ZYDIS_MNEMONIC_SETZ:   return zf;
        case ZYDIS_MNEMONIC_SETNZ:  return !zf;
        case ZYDIS_MNEMONIC_SETL:   return sf != of;
        case ZYDIS_MNEMONIC_SETNL:  return sf == of;
        case ZYDIS_MNEMONIC_SETLE:  return (sf != of) || zf;
        case ZYDIS_MNEMONIC_SETNLE: return !zf && (sf == of);
        case ZYDIS_MNEMONIC_SETO:   return of;
        case ZYDIS_MNEMONIC_SETNO:  return !of;
        case ZYDIS_MNEMONIC_SETS:   return sf;
        case ZYDIS_MNEMONIC_SETNS:  return !sf;
        case ZYDIS_MNEMONIC_SETP:   return pf;
        case ZYDIS_MNEMONIC_SETNP:  return !pf;
        // CMOVcc share the same condition algebra as the matching Jcc
        case ZYDIS_MNEMONIC_CMOVB:   return cf;
        case ZYDIS_MNEMONIC_CMOVNB:  return !cf;
        case ZYDIS_MNEMONIC_CMOVBE:  return cf || zf;
        case ZYDIS_MNEMONIC_CMOVNBE: return !cf && !zf;
        case ZYDIS_MNEMONIC_CMOVZ:   return zf;
        case ZYDIS_MNEMONIC_CMOVNZ:  return !zf;
        case ZYDIS_MNEMONIC_CMOVL:   return sf != of;
        case ZYDIS_MNEMONIC_CMOVNL:  return sf == of;
        case ZYDIS_MNEMONIC_CMOVLE:  return (sf != of) || zf;
        case ZYDIS_MNEMONIC_CMOVNLE: return !zf && (sf == of);
        case ZYDIS_MNEMONIC_CMOVO:   return of;
        case ZYDIS_MNEMONIC_CMOVNO:  return !of;
        case ZYDIS_MNEMONIC_CMOVS:   return sf;
        case ZYDIS_MNEMONIC_CMOVNS:  return !sf;
        case ZYDIS_MNEMONIC_CMOVP:   return pf;
        case ZYDIS_MNEMONIC_CMOVNP:  return !pf;
        default:                   return false;
    }
}

ExecResult IntelEmulator::execute_opcode(const DecodedInsn& insn) {
    set_program_counter(insn.va);
    ExecResult result = ExecResult::kContinue;
    std::optional<std::uint64_t> next_pc;

    // dst size for the common two-operand and one-operand arithmetic shapes
    const std::size_t dsize =
        insn.operand_count > 0 ? insn.operands[0].width_bytes : 4;

    // add / adc core (emu.py i_add). carry_in folds CF for adc
    const auto op_add = [&](bool carry_in) {
        const std::uint64_t dst = get_oper_value(insn, 0);
        std::uint64_t src = get_oper_value(insn, 1);
        std::size_t ssize = insn.operands[1].width_bytes;
        if (dsize > ssize) {
            src = bits::sign_extend(src, ssize, dsize);
            ssize = dsize;
        }
        const std::uint64_t udst = bits::unsigned_(dst, dsize);
        const std::uint64_t usrc = bits::unsigned_(src, ssize);
        const std::int64_t sdst = bits::signed_(dst, dsize);
        const std::int64_t ssrc = bits::signed_(src, ssize);
        const std::uint64_t cf =
            carry_in && regs_.get_flag(kEflagsCf) ? 1ULL : 0ULL;
        const std::uint64_t ures = udst + usrc + cf;
        const std::int64_t sres = sdst + ssrc + static_cast<std::int64_t>(cf);

        regs_.set_flag(kEflagsCf,
                       bits::is_unsigned_carry(static_cast<std::int64_t>(ures), dsize));
        regs_.set_flag(kEflagsPf, bits::is_parity_byte(ures));
        regs_.set_flag(kEflagsAf, bits::is_aux_carry(src, dst));
        regs_.set_flag(kEflagsZf, ures == 0);
        regs_.set_flag(kEflagsSf, bits::is_signed(ures, dsize));
        regs_.set_flag(kEflagsOf, bits::is_signed_overflow(sres, dsize));
        set_oper_value(insn, 0, ures);
    };

    switch (insn.zyd_mnem) {
        case ZYDIS_MNEMONIC_MOV:
        case ZYDIS_MNEMONIC_MOVZX:
            set_oper_value(insn, 0, get_oper_value(insn, 1));
            break;

        case ZYDIS_MNEMONIC_MOVSX:
        case ZYDIS_MNEMONIC_MOVSXD: {
            const std::size_t ssize = insn.operands[1].width_bytes;
            const std::uint64_t v =
                bits::sign_extend(get_oper_value(insn, 1), ssize, dsize);
            set_oper_value(insn, 0, v);
            break;
        }

        case ZYDIS_MNEMONIC_LEA:
            set_oper_value(insn, 0, get_oper_addr(insn, 1));
            break;

        case ZYDIS_MNEMONIC_PUSH: {
            const std::size_t psize = dsize == 2 ? 2 : ptr_size();
            std::uint64_t v = get_oper_value(insn, 0);
            if (insn.operands[0].kind == OperandKind::kImm && dsize < psize) {
                v = bits::sign_extend(v, dsize, psize);
            }
            do_push(v, psize);
            break;
        }

        case ZYDIS_MNEMONIC_POP: {
            const std::size_t psize = dsize == 2 ? 2 : ptr_size();
            set_oper_value(insn, 0, do_pop(psize));
            break;
        }

        case ZYDIS_MNEMONIC_ADD:
            op_add(false);
            break;
        case ZYDIS_MNEMONIC_ADC:
            op_add(true);
            break;

        case ZYDIS_MNEMONIC_SUB:
            set_oper_value(insn, 0,
                           bits::unsigned_(integer_subtraction(insn), dsize));
            break;

        case ZYDIS_MNEMONIC_SBB: {
            const std::uint64_t dst = get_oper_value(insn, 0);
            std::uint64_t src = get_oper_value(insn, 1);
            std::size_t ssize = insn.operands[1].width_bytes;
            if (dsize != ssize) {
                src = bits::sign_extend(src, ssize, dsize);
                ssize = dsize;
            }
            src += regs_.get_flag(kEflagsCf) ? 1ULL : 0ULL;
            set_oper_value(insn, 0, int_sub_base(src, dst, ssize, dsize));
            break;
        }

        case ZYDIS_MNEMONIC_CMP:
            (void)integer_subtraction(insn);
            break;

        case ZYDIS_MNEMONIC_INC: {
            const std::int64_t sval =
                bits::signed_(get_oper_value(insn, 0), dsize) + 1;
            set_oper_value(insn, 0, static_cast<std::uint64_t>(sval));
            regs_.set_flag(kEflagsOf, bits::is_signed_overflow(sval, dsize));
            regs_.set_flag(kEflagsSf,
                           bits::is_signed(static_cast<std::uint64_t>(sval), dsize));
            regs_.set_flag(kEflagsZf, sval == 0);
            regs_.set_flag(kEflagsAf,
                           (static_cast<std::uint64_t>(sval) & 0xFULL) == 0);
            regs_.set_flag(kEflagsPf,
                           bits::is_parity_byte(static_cast<std::uint64_t>(sval)));
            break;
        }

        case ZYDIS_MNEMONIC_DEC: {
            const std::uint64_t v = get_oper_value(insn, 0);
            const std::uint64_t uval = bits::unsigned_(v, dsize);
            const std::int64_t res = static_cast<std::int64_t>(v) - 1;
            set_oper_value(insn, 0, static_cast<std::uint64_t>(res));
            regs_.set_flag(kEflagsOf, false);
            regs_.set_flag(kEflagsSf,
                           bits::is_signed(static_cast<std::uint64_t>(res), dsize));
            regs_.set_flag(kEflagsZf, res == 0);
            regs_.set_flag(kEflagsAf, bits::is_aux_carry_sub(1, uval));
            regs_.set_flag(kEflagsPf,
                           bits::is_parity_byte(static_cast<std::uint64_t>(res)));
            break;
        }

        case ZYDIS_MNEMONIC_NEG: {
            const std::uint64_t val = get_oper_value(insn, 0);
            const std::int64_t res = 0 - static_cast<std::int64_t>(val);
            set_oper_value(insn, 0, static_cast<std::uint64_t>(res));
            regs_.set_flag(kEflagsCf, val != 0);
            regs_.set_flag(kEflagsZf, res == 0);
            regs_.set_flag(kEflagsSf,
                           bits::is_signed(static_cast<std::uint64_t>(res), dsize));
            regs_.set_flag(kEflagsAf,
                           bits::is_aux_carry(val, static_cast<std::uint64_t>(res)));
            regs_.set_flag(kEflagsPf,
                           bits::is_parity_byte(static_cast<std::uint64_t>(res)));
            break;
        }

        case ZYDIS_MNEMONIC_AND:
            set_oper_value(insn, 0, logical_and(insn));
            break;

        case ZYDIS_MNEMONIC_TEST:
            (void)logical_and(insn);
            break;

        case ZYDIS_MNEMONIC_OR: {
            const std::uint64_t dst = get_oper_value(insn, 0);
            std::uint64_t src = get_oper_value(insn, 1);
            std::size_t ssize = insn.operands[1].width_bytes;
            if (dsize != ssize) {
                src = bits::sign_extend(src, ssize, dsize);
                ssize = dsize;
            }
            const std::uint64_t res = dst | src;
            set_oper_value(insn, 0, res);
            regs_.set_flag(kEflagsOf, false);
            regs_.set_flag(kEflagsCf, false);
            regs_.set_flag(kEflagsSf, bits::is_signed(res, dsize));
            regs_.set_flag(kEflagsZf, res == 0);
            regs_.set_flag(kEflagsPf, bits::is_parity_byte(res));
            break;
        }

        case ZYDIS_MNEMONIC_XOR: {
            const std::uint64_t dst = get_oper_value(insn, 0);
            const std::uint64_t src = get_oper_value(insn, 1);
            const std::uint64_t res = src ^ dst;
            set_oper_value(insn, 0, res);
            regs_.set_flag(kEflagsCf, false);
            regs_.set_flag(kEflagsOf, false);
            regs_.set_flag(kEflagsSf, bits::is_signed(res, dsize));
            regs_.set_flag(kEflagsZf, res == 0);
            regs_.set_flag(kEflagsPf, bits::is_parity_byte(res));
            regs_.set_flag(kEflagsAf, false);
            break;
        }

        case ZYDIS_MNEMONIC_NOT: {
            const std::uint64_t val =
                get_oper_value(insn, 0) ^ bits::u_max(dsize);
            set_oper_value(insn, 0, val);
            break;
        }

        case ZYDIS_MNEMONIC_CALL:
            // i_call: push the return address, then jump. The WorkspaceEmulator
            // intercepts IF_CALL (func_only) before this matters for discovery
            do_push(insn.va + insn.length, ptr_size());
            next_pc = get_oper_value(insn, 0);
            break;

        case ZYDIS_MNEMONIC_JMP:
            next_pc = get_oper_value(insn, 0);
            break;

        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
            if (condition_met(insn.zyd_mnem)) {
                next_pc = get_oper_value(insn, 0);
            }
            break;

        case ZYDIS_MNEMONIC_RET: {
            const std::uint64_t ret = do_pop(ptr_size());
            if (insn.operand_count > 0) {
                const std::uint64_t esp = regs_.get_register(kRegEsp);
                regs_.set_register(kRegEsp, esp + get_oper_value(insn, 0));
            }
            next_pc = ret;
            break;
        }

        case ZYDIS_MNEMONIC_LEAVE: {
            // i_leave: ESP = EBP, then EBP = pop()
            regs_.set_register(kRegEsp, regs_.get_register(kRegEbp));
            regs_.set_register(kRegEbp, do_pop(ptr_size()));
            break;
        }

        case ZYDIS_MNEMONIC_SHL: {
            const std::uint64_t dst = get_oper_value(insn, 0);
            const std::uint64_t src =
                get_oper_value(insn, 1) & (dsize == 8 ? 0x3FULL : 0x1FULL);
            if (src == 0) {
                break;
            }
            const std::uint64_t shifted = dst << src;
            // The carry is the last bit shifted out, read from dst so a 64-bit
            // shift never needs an undefined >>64 of `shifted`
            const std::uint64_t cf = (dst >> (8U * dsize - src)) & 1ULL;
            const std::uint64_t res = bits::unsigned_(shifted, dsize);
            regs_.set_flag(kEflagsCf, cf != 0);
            regs_.set_flag(kEflagsSf, bits::is_signed(res, dsize));
            regs_.set_flag(kEflagsZf, res == 0);
            regs_.set_flag(kEflagsPf, bits::is_parity_byte(res));
            if (src == 1) {
                regs_.set_flag(kEflagsOf,
                               (bits::msb(res, dsize) ? 1ULL : 0ULL) != cf);
            } else {
                regs_.set_flag(kEflagsOf, false);
            }
            regs_.set_flag(kEflagsAf, false);
            set_oper_value(insn, 0, res);
            break;
        }

        case ZYDIS_MNEMONIC_SHR: {
            const std::uint64_t dst = get_oper_value(insn, 0);
            const std::uint64_t src =
                get_oper_value(insn, 1) & (dsize == 8 ? 0x3FULL : 0x1FULL);
            if (src == 0) {
                break;
            }
            const std::uint64_t res = bits::unsigned_(dst >> src, dsize);
            const std::uint64_t cf = (dst >> (src - 1)) & 1ULL;
            regs_.set_flag(kEflagsCf, cf != 0);
            regs_.set_flag(kEflagsSf, bits::is_signed(res, dsize));
            regs_.set_flag(kEflagsZf, res == 0);
            regs_.set_flag(kEflagsPf, bits::is_parity_byte(res));
            regs_.set_flag(kEflagsOf, src == 1 && bits::msb(dst, dsize));
            set_oper_value(insn, 0, res);
            break;
        }

        case ZYDIS_MNEMONIC_SAR: {
            const std::uint64_t dst = get_oper_value(insn, 0);
            const std::uint64_t src =
                get_oper_value(insn, 1) & (dsize == 8 ? 0x3FULL : 0x1FULL);
            if (src == 0) {
                break;
            }
            std::uint64_t res = dst >> src;
            if (bits::msb(dst, dsize)) {
                const std::uint64_t x = 8U * dsize - src;
                res |= (bits::u_max(dsize) >> x) << x;
            }
            res = bits::unsigned_(res, dsize);
            const std::uint64_t cf = (dst >> (src - 1)) & 1ULL;
            regs_.set_flag(kEflagsCf, cf != 0);
            regs_.set_flag(kEflagsSf, bits::is_signed(res, dsize));
            regs_.set_flag(kEflagsZf, res == 0);
            regs_.set_flag(kEflagsPf, bits::is_parity_byte(res));
            regs_.set_flag(kEflagsOf, false);
            regs_.set_flag(kEflagsAf, false);
            set_oper_value(insn, 0, res);
            break;
        }

        case ZYDIS_MNEMONIC_MUL: {
            const std::uint64_t val = get_oper_value(insn, 0);
            const std::uint64_t a =
                regs_.get_register(gp_lane(kRegEax, dsize, is_64bit_));
            if (dsize == 8) {
                // 64-bit mul: the product spans rdx:rax (envi Amd64Emulator)
                const std::uint64_t lo = a * val;
                const std::uint64_t hi = umul_hi(a, val);
                regs_.set_register(kRegRax, lo);
                regs_.set_register(kRegRdx, hi);
                regs_.set_flag(kEflagsCf, hi != 0);
                regs_.set_flag(kEflagsOf, hi != 0);
                break;
            }
            const std::uint64_t res = a * val;
            if (dsize == 1) {
                regs_.set_register(kRegAx, res);
            } else {
                regs_.set_register(gp_lane(kRegEax, dsize, is_64bit_),
                                   res & bits::u_max(dsize));
                regs_.set_register(gp_lane(kRegEdx, dsize, is_64bit_),
                                   (res >> (8U * dsize)) & bits::u_max(dsize));
            }
            const bool of = (res >> (8U * dsize)) != 0;
            regs_.set_flag(kEflagsCf, of);
            regs_.set_flag(kEflagsOf, of);
            break;
        }

        case ZYDIS_MNEMONIC_IMUL: {
            std::uint64_t res = 0;
            if (insn.operand_count == 1 && dsize == 8) {
                // 64-bit one-operand imul: signed product spans rdx:rax
                const std::uint64_t aval = regs_.get_register(kRegRax);
                const std::uint64_t bval = get_oper_value(insn, 0);
                const std::uint64_t lo = aval * bval;
                const std::uint64_t hi = smul_hi(aval, bval);
                regs_.set_register(kRegRax, lo);
                regs_.set_register(kRegRdx, hi);
                // CF/OF clear iff the full product sign-extends from rax alone
                const bool fits = ((lo >> 63) == 0 && hi == 0) ||
                                  ((lo >> 63) != 0 && hi == 0xFFFFFFFFFFFFFFFFULL);
                regs_.set_flag(kEflagsCf, !fits);
                regs_.set_flag(kEflagsOf, !fits);
                res = lo;
            } else if (insn.operand_count == 1) {
                const std::int64_t a = bits::signed_(
                    regs_.get_register(gp_lane(kRegEax, dsize, is_64bit_)), dsize);
                const std::int64_t mult =
                    bits::signed_(get_oper_value(insn, 0), dsize);
                const std::int64_t sres = a * mult;
                res = static_cast<std::uint64_t>(sres);
                if (dsize == 1) {
                    regs_.set_register(kRegAx, res);
                } else {
                    regs_.set_register(gp_lane(kRegEax, dsize, is_64bit_),
                                       res & bits::u_max(dsize));
                    regs_.set_register(gp_lane(kRegEdx, dsize, is_64bit_),
                                       (res >> (8U * dsize)) & bits::u_max(dsize));
                }
                const bool of = bits::is_unsigned_carry(sres, dsize);
                regs_.set_flag(kEflagsCf, of);
                regs_.set_flag(kEflagsOf, of);
            } else {
                // Two- and three-operand forms multiply the last two operands
                const std::size_t lhs = insn.operand_count == 3 ? 1 : 0;
                std::uint64_t a = get_oper_value(insn, lhs);
                std::uint64_t b = get_oper_value(insn, lhs + 1);
                const std::size_t bsize = insn.operands[lhs + 1].width_bytes;
                if (dsize > bsize) {
                    b = bits::sign_extend(b, bsize, dsize);
                }
                res = a * b;
                const bool of = res > bits::u_max(dsize);
                regs_.set_flag(kEflagsCf, of);
                regs_.set_flag(kEflagsOf, of);
                set_oper_value(insn, 0, res);
            }
            regs_.set_flag(kEflagsPf, bits::is_parity_byte(res));
            regs_.set_flag(kEflagsSf, false);
            break;
        }

        case ZYDIS_MNEMONIC_DIV: {
            const std::uint64_t val = get_oper_value(insn, 0);
            if (val == 0) {
                result = ExecResult::kDivideByZero;
                break;
            }
            if (dsize == 1) {
                const std::uint64_t ax = regs_.get_register(kRegAx);
                regs_.set_register(kRegEax, ((ax / val) << 8) + (ax % val));
            } else if (dsize == 2) {
                const std::uint64_t tot =
                    (regs_.get_register(kRegDx) << 16) + regs_.get_register(kRegAx);
                regs_.set_register(kRegAx, tot / val);
                regs_.set_register(kRegDx, tot % val);
            } else if (dsize == 4) {
                const std::uint64_t tot =
                    (regs_.get_register(gp_lane(kRegEdx, 4, is_64bit_)) << 32) +
                    regs_.get_register(gp_lane(kRegEax, 4, is_64bit_));
                regs_.set_register(gp_lane(kRegEax, 4, is_64bit_), tot / val);
                regs_.set_register(gp_lane(kRegEdx, 4, is_64bit_), tot % val);
            } else {
                // 64-bit div: rdx:rax / val via 128-bit long division
                const Div128 dr = udiv128(regs_.get_register(kRegRdx),
                                          regs_.get_register(kRegRax), val);
                regs_.set_register(kRegRax, dr.quot);
                regs_.set_register(kRegRdx, dr.rem);
            }
            break;
        }

        case ZYDIS_MNEMONIC_IDIV: {
            const std::uint64_t uval = get_oper_value(insn, 0);
            if (uval == 0) {
                result = ExecResult::kDivideByZero;
                break;
            }
            if (dsize == 1) {
                const std::int64_t val = bits::signed_(regs_.get_register(kRegAx), 2);
                const std::int64_t d = bits::signed_(uval, 1);
                std::int64_t q = (val < 0 ? -val : val) / (d < 0 ? -d : d);
                std::int64_t r = (val < 0 ? -val : val) % (d < 0 ? -d : d);
                if ((val < 0) != (d < 0)) {
                    q = -q;
                    r = -r;
                }
                regs_.set_register(
                    kRegAx, ((static_cast<std::uint64_t>(r) & 0xFF) << 8) |
                                (static_cast<std::uint64_t>(q) & 0xFF));
            } else if (dsize == 2) {
                const std::int64_t val = bits::signed_(
                    (static_cast<std::uint64_t>(regs_.get_register(kRegDx)) << 16) |
                        regs_.get_register(kRegAx),
                    4);
                const std::int64_t d = bits::signed_(uval, 2);
                std::int64_t q = (val < 0 ? -val : val) / (d < 0 ? -d : d);
                std::int64_t r = (val < 0 ? -val : val) % (d < 0 ? -d : d);
                if ((val < 0) != (d < 0)) {
                    q = -q;
                    r = -r;
                }
                regs_.set_register(kRegAx, static_cast<std::uint64_t>(q));
                regs_.set_register(kRegDx, static_cast<std::uint64_t>(r));
            } else if (dsize == 4) {
                const std::int64_t val = bits::signed_(
                    (regs_.get_register(gp_lane(kRegEdx, 4, is_64bit_)) << 32) |
                        regs_.get_register(gp_lane(kRegEax, 4, is_64bit_)),
                    8);
                const std::int64_t d = bits::signed_(uval, 4);
                std::int64_t q = (val < 0 ? -val : val) / (d < 0 ? -d : d);
                std::int64_t r = (val < 0 ? -val : val) % (d < 0 ? -d : d);
                if ((val < 0) != (d < 0)) {
                    q = -q;
                    r = -r;
                }
                regs_.set_register(gp_lane(kRegEax, 4, is_64bit_),
                                   static_cast<std::uint64_t>(q));
                regs_.set_register(gp_lane(kRegEdx, 4, is_64bit_),
                                   static_cast<std::uint64_t>(r));
            } else {
                // 64-bit idiv: signed rdx:rax / val via 128-bit division
                std::uint64_t hi = regs_.get_register(kRegRdx);
                std::uint64_t lo = regs_.get_register(kRegRax);
                const bool dividend_neg = (hi >> 63) != 0;
                if (dividend_neg) {
                    lo = ~lo + 1ULL;
                    hi = ~hi + (lo == 0 ? 1ULL : 0ULL);
                }
                const bool divisor_neg = (uval >> 63) != 0;
                const std::uint64_t ud = divisor_neg ? (~uval + 1ULL) : uval;
                Div128 dr = udiv128(hi, lo, ud);
                if (dividend_neg != divisor_neg) {
                    dr.quot = ~dr.quot + 1ULL;
                }
                if (dividend_neg) {
                    dr.rem = ~dr.rem + 1ULL;
                }
                regs_.set_register(kRegRax, dr.quot);
                regs_.set_register(kRegRdx, dr.rem);
            }
            break;
        }

        case ZYDIS_MNEMONIC_CDQ:
            // Sign-extend eax into edx (i_cwd)
            regs_.set_register(kRegEdx,
                               bits::is_signed(regs_.get_register(kRegEax), 4)
                                   ? 0xFFFFFFFFULL
                                   : 0ULL);
            break;

        case ZYDIS_MNEMONIC_CWD:
            // Sign-extend ax into dx
            regs_.set_register(kRegDx,
                               bits::is_signed(regs_.get_register(kRegAx), 2)
                                   ? 0xFFFFULL
                                   : 0ULL);
            break;

        case ZYDIS_MNEMONIC_CBW:
            // Sign-extend al into ax (i_cbw)
            regs_.set_register(
                kRegAx, bits::sign_extend(regs_.get_register(kRegAl), 1, 2));
            break;

        case ZYDIS_MNEMONIC_CWDE:
            // Sign-extend ax into eax (zero-extends into rax in 64-bit mode)
            regs_.set_register(
                gp_lane(kRegEax, 4, is_64bit_),
                bits::sign_extend(regs_.get_register(kRegAx), 2, 4));
            break;

        case ZYDIS_MNEMONIC_CDQE:
            // amd64: sign-extend eax into rax
            regs_.set_register(
                kRegRax,
                bits::sign_extend(
                    regs_.get_register(make_meta_reg(0, 32, kRegRax)), 4, 8));
            break;

        case ZYDIS_MNEMONIC_CQO:
            // amd64: sign-extend rax into rdx
            regs_.set_register(kRegRdx,
                               bits::is_signed(regs_.get_register(kRegRax), 8)
                                   ? 0xFFFFFFFFFFFFFFFFULL
                                   : 0ULL);
            break;

        case ZYDIS_MNEMONIC_SETB:
        case ZYDIS_MNEMONIC_SETNB:
        case ZYDIS_MNEMONIC_SETBE:
        case ZYDIS_MNEMONIC_SETNBE:
        case ZYDIS_MNEMONIC_SETZ:
        case ZYDIS_MNEMONIC_SETNZ:
        case ZYDIS_MNEMONIC_SETL:
        case ZYDIS_MNEMONIC_SETNL:
        case ZYDIS_MNEMONIC_SETLE:
        case ZYDIS_MNEMONIC_SETNLE:
        case ZYDIS_MNEMONIC_SETO:
        case ZYDIS_MNEMONIC_SETNO:
        case ZYDIS_MNEMONIC_SETS:
        case ZYDIS_MNEMONIC_SETNS:
        case ZYDIS_MNEMONIC_SETP:
        case ZYDIS_MNEMONIC_SETNP:
            set_oper_value(insn, 0, condition_met(insn.zyd_mnem) ? 1ULL : 0ULL);
            break;

        case ZYDIS_MNEMONIC_NOP:
            break;

        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_INT3:
            result = ExecResult::kBreakpoint;
            break;

        case ZYDIS_MNEMONIC_UD0:
        case ZYDIS_MNEMONIC_UD1:
        case ZYDIS_MNEMONIC_UD2:
            result = ExecResult::kBadOpcode;
            break;

        case ZYDIS_MNEMONIC_IN:
        case ZYDIS_MNEMONIC_OUT:
            result = ExecResult::kOutInstruction;
            break;

        // SSE and AVX moves as faithful byte copies through the XMM file, so a function using
        // SSE emulates to its ret instead of bailing on an unmodeled opcode
        case ZYDIS_MNEMONIC_MOVUPS:
        case ZYDIS_MNEMONIC_MOVUPD:
        case ZYDIS_MNEMONIC_MOVAPS:
        case ZYDIS_MNEMONIC_MOVAPD:
        case ZYDIS_MNEMONIC_MOVDQU:
        case ZYDIS_MNEMONIC_MOVDQA:
        case ZYDIS_MNEMONIC_LDDQU:
            write_simd_oper(insn, 0, read_simd_oper(insn, 1, 16), 16);
            break;
        case ZYDIS_MNEMONIC_MOVQ:
            write_simd_oper(insn, 0, read_simd_oper(insn, 1, 8), 8);
            break;
        case ZYDIS_MNEMONIC_MOVD:
        case ZYDIS_MNEMONIC_MOVSS:
            write_simd_oper(insn, 0, read_simd_oper(insn, 1, 4), 4);
            break;
        case ZYDIS_MNEMONIC_MOVSD:
            // The SSE scalar-double move shares this mnemonic with the MOVS string op.
            // The SSE form has an XMM operand
            if (xmm_index(insn.operands[0].base_reg).has_value() ||
                xmm_index(insn.operands[1].base_reg).has_value()) {
                write_simd_oper(insn, 0, read_simd_oper(insn, 1, 8), 8);
            } else {
                result = ExecResult::kUnsupported;
            }
            break;

        case ZYDIS_MNEMONIC_XORPS:
        case ZYDIS_MNEMONIC_XORPD:
        case ZYDIS_MNEMONIC_PXOR: {
            const Xmm a = read_simd_oper(insn, 0, 16);
            const Xmm b = read_simd_oper(insn, 1, 16);
            Xmm r{};
            for (std::size_t i = 0; i < r.size(); ++i) {
                r[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
            }
            write_simd_oper(insn, 0, r, 16);
            break;
        }

        case ZYDIS_MNEMONIC_PSRLDQ: {
            const Xmm v = read_simd_oper(insn, 0, 16);
            const std::uint64_t n =
                std::min<std::uint64_t>(get_oper_value(insn, 1), v.size());
            Xmm r{};
            for (std::size_t i = 0; i + n < v.size(); ++i) {
                r[i] = v[i + n];
            }
            write_simd_oper(insn, 0, r, 16);
            break;
        }
        case ZYDIS_MNEMONIC_PSLLDQ: {
            const Xmm v = read_simd_oper(insn, 0, 16);
            const std::uint64_t n =
                std::min<std::uint64_t>(get_oper_value(insn, 1), v.size());
            Xmm r{};
            for (std::size_t i = n; i < v.size(); ++i) {
                r[i] = v[i - n];
            }
            write_simd_oper(insn, 0, r, 16);
            break;
        }

        case ZYDIS_MNEMONIC_CMOVB:
        case ZYDIS_MNEMONIC_CMOVNB:
        case ZYDIS_MNEMONIC_CMOVBE:
        case ZYDIS_MNEMONIC_CMOVNBE:
        case ZYDIS_MNEMONIC_CMOVZ:
        case ZYDIS_MNEMONIC_CMOVNZ:
        case ZYDIS_MNEMONIC_CMOVL:
        case ZYDIS_MNEMONIC_CMOVNL:
        case ZYDIS_MNEMONIC_CMOVLE:
        case ZYDIS_MNEMONIC_CMOVNLE:
        case ZYDIS_MNEMONIC_CMOVO:
        case ZYDIS_MNEMONIC_CMOVNO:
        case ZYDIS_MNEMONIC_CMOVS:
        case ZYDIS_MNEMONIC_CMOVNS:
        case ZYDIS_MNEMONIC_CMOVP:
        case ZYDIS_MNEMONIC_CMOVNP:
            // Conditional move: write the source only when the flags condition
            // holds (emu.py i_cmov uses the same cond_* algebra as Jcc)
            if (condition_met(insn.zyd_mnem)) {
                set_oper_value(insn, 0, get_oper_value(insn, 1));
            }
            break;

        case ZYDIS_MNEMONIC_BT:
        case ZYDIS_MNEMONIC_BTS:
        case ZYDIS_MNEMONIC_BTR:
        case ZYDIS_MNEMONIC_BTC: {
            // Bit test: CF is the addressed bit, and bts, btr and btc also change it. The index
            // is reduced modulo the operand width
            const std::uint64_t dst = get_oper_value(insn, 0);
            const std::uint64_t bitidx = get_oper_value(insn, 1) % (8ULL * dsize);
            const std::uint64_t mask = 1ULL << bitidx;
            regs_.set_flag(kEflagsCf, (dst & mask) != 0);
            if (insn.zyd_mnem == ZYDIS_MNEMONIC_BTS) {
                set_oper_value(insn, 0, dst | mask);
            } else if (insn.zyd_mnem == ZYDIS_MNEMONIC_BTR) {
                set_oper_value(insn, 0, dst & ~mask);
            } else if (insn.zyd_mnem == ZYDIS_MNEMONIC_BTC) {
                set_oper_value(insn, 0, dst ^ mask);
            }
            break;
        }

        case ZYDIS_MNEMONIC_ROL: {
            const std::uint64_t dst = bits::unsigned_(get_oper_value(insn, 0), dsize);
            const std::uint64_t bitw = 8ULL * dsize;
            const std::uint64_t cnt =
                (get_oper_value(insn, 1) & (dsize == 8 ? 0x3FULL : 0x1FULL)) % bitw;
            if (cnt == 0) { break; }
            const std::uint64_t res =
                bits::unsigned_((dst << cnt) | (dst >> (bitw - cnt)), dsize);
            set_oper_value(insn, 0, res);
            regs_.set_flag(kEflagsCf, (res & 1ULL) != 0);
            break;
        }
        case ZYDIS_MNEMONIC_ROR: {
            const std::uint64_t dst = bits::unsigned_(get_oper_value(insn, 0), dsize);
            const std::uint64_t bitw = 8ULL * dsize;
            const std::uint64_t cnt =
                (get_oper_value(insn, 1) & (dsize == 8 ? 0x3FULL : 0x1FULL)) % bitw;
            if (cnt == 0) { break; }
            const std::uint64_t res =
                bits::unsigned_((dst >> cnt) | (dst << (bitw - cnt)), dsize);
            set_oper_value(insn, 0, res);
            regs_.set_flag(kEflagsCf, (res >> (bitw - 1)) != 0);
            break;
        }

        case ZYDIS_MNEMONIC_XCHG: {
            const std::uint64_t a = get_oper_value(insn, 0);
            const std::uint64_t b = get_oper_value(insn, 1);
            set_oper_value(insn, 0, b);
            set_oper_value(insn, 1, a);
            break;
        }
        case ZYDIS_MNEMONIC_XADD: {
            const std::uint64_t dst = get_oper_value(insn, 0);
            const std::uint64_t src = get_oper_value(insn, 1);
            const std::uint64_t sum = bits::unsigned_(dst + src, dsize);
            set_oper_value(insn, 1, dst);
            set_oper_value(insn, 0, sum);
            regs_.set_flag(kEflagsZf, sum == 0);
            regs_.set_flag(kEflagsCf,
                           bits::is_unsigned_carry(
                               static_cast<std::int64_t>(dst + src), dsize));
            regs_.set_flag(kEflagsSf, bits::is_signed(sum, dsize));
            regs_.set_flag(kEflagsPf, bits::is_parity_byte(sum));
            break;
        }
        case ZYDIS_MNEMONIC_CMPXCHG: {
            // Compare the accumulator with dst. Equal: dst = src, ZF set. Else
            // the accumulator takes dst, ZF clear (emu.py i_cmpxchg)
            const std::uint32_t acc = gp_lane(kRegEax, dsize, is_64bit_);
            const std::uint64_t dst = get_oper_value(insn, 0);
            if (bits::unsigned_(regs_.get_register(acc), dsize) ==
                bits::unsigned_(dst, dsize)) {
                regs_.set_flag(kEflagsZf, true);
                set_oper_value(insn, 0, get_oper_value(insn, 1));
            } else {
                regs_.set_flag(kEflagsZf, false);
                regs_.set_register(acc, dst);
            }
            break;
        }

        default:
            result = ExecResult::kUnsupported;
            break;
    }

    if (result == ExecResult::kContinue) {
        set_program_counter(next_pc.value_or(insn.va + insn.length));
    }
    return result;
}

}  // namespace papa::features::extractors::papa_native::emu
