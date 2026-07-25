#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <cstdint>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// Data / arithmetic / logic instruction handlers, ported from
// envi/archs/i386/emu.py. Flags are checked against vivisect's exact formulas,
// including its quirks (add derives ZF from the unmasked sum), so emulation is
// bit-identical and discovery follows the same paths

namespace {

pn::DecodedOperand reg_oper(ZydisRegister r, std::size_t width) {
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kReg;
    op.base_reg = r;
    op.width_bytes = width;
    return op;
}

pn::DecodedOperand imm_oper(std::uint64_t v, std::size_t width) {
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kImm;
    op.imm = v;
    op.width_bytes = width;
    return op;
}

pn::DecodedInsn insn2(ZydisMnemonic m, pn::DecodedOperand a, pn::DecodedOperand b) {
    pn::DecodedInsn insn;
    insn.va = 0x1000;
    insn.length = 2;
    insn.zyd_mnem = m;
    insn.operands[0] = a;
    insn.operands[1] = b;
    insn.operand_count = 2;
    return insn;
}

pn::DecodedInsn insn1(ZydisMnemonic m, pn::DecodedOperand a) {
    pn::DecodedInsn insn;
    insn.va = 0x1000;
    insn.length = 2;
    insn.zyd_mnem = m;
    insn.operands[0] = a;
    insn.operand_count = 1;
    return insn;
}

pn::DecodedInsn insn0(ZydisMnemonic m) {
    pn::DecodedInsn insn;
    insn.va = 0x1000;
    insn.length = 2;
    insn.zyd_mnem = m;
    insn.operand_count = 0;
    return insn;
}

}  // namespace

TEST_CASE("emu cmov: cmovz copies when ZF is set and skips otherwise") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEcx, 0x1111U);
    e.regs().set_register(emu::kRegEdx, 0x2222U);
    e.regs().set_flag(emu::kEflagsZf, true);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_CMOVZ, reg_oper(ZYDIS_REGISTER_ECX, 4),
                           reg_oper(ZYDIS_REGISTER_EDX, 4)));
    CHECK(e.regs().get_register(emu::kRegEcx) == 0x2222U);

    e.regs().set_register(emu::kRegEcx, 0x1111U);
    e.regs().set_flag(emu::kEflagsZf, false);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_CMOVZ, reg_oper(ZYDIS_REGISTER_ECX, 4),
                           reg_oper(ZYDIS_REGISTER_EDX, 4)));
    CHECK(e.regs().get_register(emu::kRegEcx) == 0x1111U);
}

TEST_CASE("emu bt: bt sets CF to the addressed bit") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x8U);  // bit 3 set
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_BT, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(3, 1)));
    CHECK(e.regs().get_flag(emu::kEflagsCf));
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_BT, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(2, 1)));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsCf));
}

TEST_CASE("emu bts: bts sets the addressed bit and reports the old value in CF") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x0U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_BTS, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(5, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0x20U);  // bit 5 now set
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsCf));        // was clear
}

TEST_CASE("emu sse: movups copies a full XMM register") {
    emu::IntelEmulator e;
    emu::Xmm v{};
    for (std::size_t i = 0; i < v.size(); ++i) {
        v[i] = static_cast<std::uint8_t>(i + 1);
    }
    e.regs().set_xmm(1, v);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_MOVUPS,
                           reg_oper(ZYDIS_REGISTER_XMM0, 16),
                           reg_oper(ZYDIS_REGISTER_XMM1, 16)));
    CHECK(e.regs().get_xmm(0) == v);
}

TEST_CASE("emu sse: movq moves 8 bytes and zero-extends the XMM destination") {
    emu::IntelEmulator e;
    emu::Xmm src{};
    for (auto& b : src) { b = 0xFF; }
    e.regs().set_xmm(2, src);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_MOVQ,
                           reg_oper(ZYDIS_REGISTER_XMM0, 16),
                           reg_oper(ZYDIS_REGISTER_XMM2, 16)));
    emu::Xmm expect{};
    for (std::size_t i = 0; i < 8; ++i) { expect[i] = 0xFF; }
    CHECK(e.regs().get_xmm(0) == expect);
}

TEST_CASE("emu sse: pxor of a register with itself clears it") {
    emu::IntelEmulator e;
    emu::Xmm v{};
    for (auto& b : v) { b = 0xAB; }
    e.regs().set_xmm(3, v);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_PXOR,
                           reg_oper(ZYDIS_REGISTER_XMM3, 16),
                           reg_oper(ZYDIS_REGISTER_XMM3, 16)));
    CHECK(e.regs().get_xmm(3) == emu::Xmm{});
}

TEST_CASE("emu arith: mov reg, reg copies the value") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEcx, 0xABCD1234U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_MOV, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xABCD1234ULL);
}

// --- amd64 arithmetic: 64-bit shift counts mask to 0x3f (not 0x1f), the
// sign-extension ops cdqe/cqo, and 64-bit mul/div produce the rdx:rax pair via
// 128-bit arithmetic (envi/archs/amd64 EMU NOTES + Amd64Emulator i_div/i_idiv)

TEST_CASE("emu arith amd64: shl rax masks the shift count to 0x3f") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRax, 1ULL);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SHL, reg_oper(ZYDIS_REGISTER_RAX, 8),
                           imm_oper(40, 1)));
    CHECK(e.regs().get_register(emu::kRegRax) == (1ULL << 40));
}

TEST_CASE("emu arith amd64: shr rax masks the shift count to 0x3f") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRax, 0xFF00000000000000ULL);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SHR, reg_oper(ZYDIS_REGISTER_RAX, 8),
                           imm_oper(40, 1)));
    CHECK(e.regs().get_register(emu::kRegRax) == 0x0000000000FF0000ULL);
}

TEST_CASE("emu arith amd64: cdqe sign-extends eax into rax") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRax, 0x80000000ULL);
    e.execute_opcode(insn0(ZYDIS_MNEMONIC_CDQE));
    CHECK(e.regs().get_register(emu::kRegRax) == 0xFFFFFFFF80000000ULL);
}

TEST_CASE("emu arith amd64: cqo sign-extends rax into rdx") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRax, 0x8000000000000000ULL);
    e.execute_opcode(insn0(ZYDIS_MNEMONIC_CQO));
    CHECK(e.regs().get_register(emu::kRegRdx) == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("emu arith amd64: mul r64 produces the rdx:rax product") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRax, 0x100000000ULL);  // 2^32
    e.regs().set_register(emu::kRegRcx, 0x100000000ULL);  // 2^32
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_MUL, reg_oper(ZYDIS_REGISTER_RCX, 8)));
    CHECK(e.regs().get_register(emu::kRegRdx) == 1ULL);   // 2^64 -> high = 1
    CHECK(e.regs().get_register(emu::kRegRax) == 0ULL);
}

TEST_CASE("emu arith amd64: div r64 divides rdx:rax by the operand") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRdx, 1ULL);   // dividend = (1<<64) + 0
    e.regs().set_register(emu::kRegRax, 0ULL);
    e.regs().set_register(emu::kRegRcx, 2ULL);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_DIV, reg_oper(ZYDIS_REGISTER_RCX, 8)));
    CHECK(e.regs().get_register(emu::kRegRax) == 0x8000000000000000ULL);  // 2^63
    CHECK(e.regs().get_register(emu::kRegRdx) == 0ULL);                    // remainder
}

TEST_CASE("emu arith amd64: idiv r64 handles a negative dividend") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    // dividend = -100 (128-bit sign-extended), divisor = 7 -> quot -14, rem -2
    e.regs().set_register(emu::kRegRax, static_cast<std::uint64_t>(-100));
    e.regs().set_register(emu::kRegRdx, 0xFFFFFFFFFFFFFFFFULL);  // sign-extension
    e.regs().set_register(emu::kRegRcx, 7ULL);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_IDIV, reg_oper(ZYDIS_REGISTER_RCX, 8)));
    CHECK(static_cast<std::int64_t>(e.regs().get_register(emu::kRegRax)) == -14);
    CHECK(static_cast<std::int64_t>(e.regs().get_register(emu::kRegRdx)) == -2);
}

TEST_CASE("emu arith: mov reg, imm loads the immediate") {
    emu::IntelEmulator e;
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_MOV, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(0x42U, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0x42ULL);
}

TEST_CASE("emu arith: movzx zero-extends a byte source") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEcx, 0x000001FFU);  // cl = 0xff
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_MOVZX, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_CL, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xFFULL);
}

TEST_CASE("emu arith: movsx sign-extends a byte source") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEcx, 0x00000080U);  // cl = 0x80
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_MOVSX, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_CL, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xFFFFFF80ULL);
}

TEST_CASE("emu arith: lea loads the effective address, not memory") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x1000U);
    pn::DecodedOperand mem;
    mem.kind = pn::OperandKind::kRegMem;
    mem.base_reg = ZYDIS_REGISTER_EAX;
    mem.disp = 0x8;
    mem.width_bytes = 4;
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_LEA, reg_oper(ZYDIS_REGISTER_EDX, 4), mem));
    CHECK(e.regs().get_register(emu::kRegEdx) == 0x1008ULL);
}

TEST_CASE("emu arith: add sets result and arithmetic flags") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 5U);
    e.regs().set_register(emu::kRegEcx, 3U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_ADD, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 8ULL);
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsCf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsZf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsSf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsOf));
}

TEST_CASE("emu arith: add that carries out wraps and keeps ZF clear (vivisect quirk)") {
    // vivisect derives ZF from the unmasked sum, so 0xffffffff+1 leaves ZF=0
    // even though the stored result is 0. Reproduced for bit-identical paths
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0xFFFFFFFFU);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_ADD, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(1U, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0ULL);
    CHECK(e.regs().get_flag(emu::kEflagsCf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsZf));
}

TEST_CASE("emu arith: sub computes the difference and flags") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 10U);
    e.regs().set_register(emu::kRegEcx, 3U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SUB, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 7ULL);
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsCf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsZf));
}

TEST_CASE("emu arith: sub of equal operands sets ZF") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 5U);
    e.regs().set_register(emu::kRegEcx, 5U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SUB, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0ULL);
    CHECK(e.regs().get_flag(emu::kEflagsZf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsCf));
}

TEST_CASE("emu arith: sub that borrows sets CF and SF") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0U);
    e.regs().set_register(emu::kRegEcx, 1U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SUB, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xFFFFFFFFULL);
    CHECK(e.regs().get_flag(emu::kEflagsCf));
    CHECK(e.regs().get_flag(emu::kEflagsSf));
}

TEST_CASE("emu arith: cmp sets flags without storing") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 5U);
    e.regs().set_register(emu::kRegEcx, 5U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_CMP, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 5ULL);  // unchanged
    CHECK(e.regs().get_flag(emu::kEflagsZf));
}

TEST_CASE("emu arith: inc sets overflow at the signed boundary, leaves CF") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsCf, true);
    e.regs().set_register(emu::kRegEax, 0x7FFFFFFFU);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_INC, reg_oper(ZYDIS_REGISTER_EAX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0x80000000ULL);
    CHECK(e.regs().get_flag(emu::kEflagsOf));
    CHECK(e.regs().get_flag(emu::kEflagsSf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsZf));
    CHECK(e.regs().get_flag(emu::kEflagsCf));  // inc does not touch CF
}

TEST_CASE("emu arith: dec to zero sets ZF") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 1U);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_DEC, reg_oper(ZYDIS_REGISTER_EAX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0ULL);
    CHECK(e.regs().get_flag(emu::kEflagsZf));
}

TEST_CASE("emu arith: neg negates and sets CF when nonzero") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 1U);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_NEG, reg_oper(ZYDIS_REGISTER_EAX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xFFFFFFFFULL);
    CHECK(e.regs().get_flag(emu::kEflagsCf));
    CHECK(e.regs().get_flag(emu::kEflagsSf));
}

TEST_CASE("emu arith: neg of zero clears CF and sets ZF") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0U);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_NEG, reg_oper(ZYDIS_REGISTER_EAX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0ULL);
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsCf));
    CHECK(e.regs().get_flag(emu::kEflagsZf));
}

TEST_CASE("emu arith: and masks and clears CF and OF") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0xFFU);
    e.regs().set_register(emu::kRegEcx, 0x0FU);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_AND, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0x0FULL);
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsCf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsOf));
    CHECK(e.regs().get_flag(emu::kEflagsPf));  // 0x0F = 4 bits, even
}

TEST_CASE("emu arith: or combines bits") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0xF0U);
    e.regs().set_register(emu::kRegEcx, 0x0FU);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_OR, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xFFULL);
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsZf));
}

TEST_CASE("emu arith: xor of a register with itself zeroes it and sets ZF") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x1234U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_XOR, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_EAX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0ULL);
    CHECK(e.regs().get_flag(emu::kEflagsZf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsCf));
    CHECK_FALSE(e.regs().get_flag(emu::kEflagsOf));
}

TEST_CASE("emu arith: not flips all bits without touching flags") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x00000000U);
    e.regs().set_flag(emu::kEflagsZf, true);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_NOT, reg_oper(ZYDIS_REGISTER_EAX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xFFFFFFFFULL);
    CHECK(e.regs().get_flag(emu::kEflagsZf));  // unchanged
}

TEST_CASE("emu arith: test sets ZF when the and is zero, without storing") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0U);
    e.regs().set_register(emu::kRegEcx, 0xFFU);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_TEST, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0ULL);  // unchanged
    CHECK(e.regs().get_flag(emu::kEflagsZf));
}

TEST_CASE("emu arith: adc adds the carry flag in") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 1U);
    e.regs().set_register(emu::kRegEcx, 1U);
    e.regs().set_flag(emu::kEflagsCf, true);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_ADC, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 3ULL);
}

TEST_CASE("emu arith: sbb subtracts the carry flag in") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 5U);
    e.regs().set_register(emu::kRegEcx, 1U);
    e.regs().set_flag(emu::kEflagsCf, true);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SBB, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 3ULL);
}

TEST_CASE("emu arith: push then pop round-trips through the stack") {
    emu::IntelEmulator e;
    e.memory().init_stack();
    const std::uint32_t sp0 = static_cast<std::uint32_t>(emu::kStackBase) + 0x100U;
    e.regs().set_register(emu::kRegEsp, sp0);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_PUSH, imm_oper(0x11223344U, 4)));
    CHECK(e.regs().get_register(emu::kRegEsp) == sp0 - 4U);
    CHECK(e.memory().read_value(sp0 - 4U, 4) == 0x11223344ULL);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_POP, reg_oper(ZYDIS_REGISTER_EDX, 4)));
    CHECK(e.regs().get_register(emu::kRegEdx) == 0x11223344ULL);
    CHECK(e.regs().get_register(emu::kRegEsp) == sp0);
}

TEST_CASE("emu arith: mul produces the product in edx:eax") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 4U);
    e.regs().set_register(emu::kRegEcx, 3U);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_MUL, reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 12ULL);
    CHECK(e.regs().get_register(emu::kRegEdx) == 0ULL);
}

TEST_CASE("emu arith: mul sets CF and OF when the high half is nonzero") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x10000U);
    e.regs().set_register(emu::kRegEcx, 0x10000U);  // 2^16 * 2^16 = 2^32
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_MUL, reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0ULL);
    CHECK(e.regs().get_register(emu::kRegEdx) == 1ULL);
    CHECK(e.regs().get_flag(emu::kEflagsCf));
    CHECK(e.regs().get_flag(emu::kEflagsOf));
}

TEST_CASE("emu arith: imul two-operand multiplies into the destination") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 4U);
    e.regs().set_register(emu::kRegEcx, 3U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_IMUL, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 12ULL);
}

TEST_CASE("emu arith: div computes quotient in eax and remainder in edx") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEdx, 0U);
    e.regs().set_register(emu::kRegEax, 13U);
    e.regs().set_register(emu::kRegEcx, 3U);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_DIV, reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == 4ULL);  // 13 / 3
    CHECK(e.regs().get_register(emu::kRegEdx) == 1ULL);  // 13 % 3
}

TEST_CASE("emu arith: div by zero reports a divide-by-zero result") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 12U);
    e.regs().set_register(emu::kRegEcx, 0U);
    const emu::ExecResult r =
        e.execute_opcode(insn1(ZYDIS_MNEMONIC_DIV, reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(r == emu::ExecResult::kDivideByZero);
}

TEST_CASE("emu arith: idiv handles signed division") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEdx, 0xFFFFFFFFU);  // sign-extension of -13
    e.regs().set_register(emu::kRegEax, static_cast<std::uint32_t>(-13));
    e.regs().set_register(emu::kRegEcx, 3U);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_IDIV, reg_oper(ZYDIS_REGISTER_ECX, 4)));
    CHECK(e.regs().get_register(emu::kRegEax) == static_cast<std::uint32_t>(-4));
}

TEST_CASE("emu arith: cdq sign-extends eax into edx") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x80000000U);  // negative
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_CDQ, reg_oper(ZYDIS_REGISTER_EDX, 4)));
    CHECK(e.regs().get_register(emu::kRegEdx) == 0xFFFFFFFFULL);
}

TEST_CASE("emu arith: cdq clears edx for a non-negative eax") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x00000001U);
    e.regs().set_register(emu::kRegEdx, 0xDEADBEEFU);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_CDQ, reg_oper(ZYDIS_REGISTER_EDX, 4)));
    CHECK(e.regs().get_register(emu::kRegEdx) == 0ULL);
}

TEST_CASE("emu arith: setz writes 1 when ZF is set, 0 otherwise") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0xFFFFFF00U);
    e.regs().set_flag(emu::kEflagsZf, true);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_SETZ, reg_oper(ZYDIS_REGISTER_AL, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xFFFFFF01ULL);

    e.regs().set_flag(emu::kEflagsZf, false);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_SETZ, reg_oper(ZYDIS_REGISTER_AL, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xFFFFFF00ULL);
}

TEST_CASE("emu arith: setnz is the inverse of setz") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsZf, false);
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_SETNZ, reg_oper(ZYDIS_REGISTER_CL, 1)));
    CHECK(e.regs().get_register(emu::kRegCl) == 1ULL);
}

TEST_CASE("emu arith: setl follows the signed less-than condition") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsSf, true);
    e.regs().set_flag(emu::kEflagsOf, false);  // SF != OF -> less than
    e.execute_opcode(insn1(ZYDIS_MNEMONIC_SETL, reg_oper(ZYDIS_REGISTER_DL, 1)));
    CHECK(e.regs().get_register(emu::kRegDl) == 1ULL);
}

TEST_CASE("emu arith: execute_opcode advances the program counter by length") {
    emu::IntelEmulator e;
    pn::DecodedInsn insn = insn2(ZYDIS_MNEMONIC_MOV, reg_oper(ZYDIS_REGISTER_EAX, 4),
                                 imm_oper(0U, 4));
    insn.va = 0x401000;
    insn.length = 5;
    e.execute_opcode(insn);
    CHECK(e.program_counter() == 0x401005ULL);
}

TEST_CASE("emu arith: an unmodeled mnemonic reports unsupported") {
    emu::IntelEmulator e;
    const emu::ExecResult r =
        e.execute_opcode(insn1(ZYDIS_MNEMONIC_RDRAND, reg_oper(ZYDIS_REGISTER_EAX, 4)));
    CHECK(r == emu::ExecResult::kUnsupported);
}
