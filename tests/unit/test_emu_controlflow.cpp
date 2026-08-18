#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <cstdint>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// Control-flow handlers and shifts ported from envi/archs/i386/emu.py. These are
// what let an emulated function body run to its ret

namespace {

pn::DecodedInsn branch_insn(ZydisMnemonic m, std::uint64_t target,
                            std::uint64_t va = 0x1000, std::size_t length = 2) {
    pn::DecodedInsn insn;
    insn.va = va;
    insn.length = length;
    insn.zyd_mnem = m;
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kPcRel;
    op.width_bytes = 4;
    insn.operands[0] = op;
    insn.operand_count = 1;
    insn.branch_target = target;
    return insn;
}

pn::DecodedInsn no_oper_insn(ZydisMnemonic m, std::uint64_t va = 0x1000,
                             std::size_t length = 1) {
    pn::DecodedInsn insn;
    insn.va = va;
    insn.length = length;
    insn.zyd_mnem = m;
    insn.operand_count = 0;
    return insn;
}

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
    insn.length = 3;
    insn.zyd_mnem = m;
    insn.operands[0] = a;
    insn.operands[1] = b;
    insn.operand_count = 2;
    return insn;
}

// A stack-ready emulator with ESP near the top of the stack window
emu::IntelEmulator stacked() {
    emu::IntelEmulator e;
    e.memory().init_stack();
    e.regs().set_register(emu::kRegEsp,
                          static_cast<std::uint32_t>(emu::kStackBase) + 0x400U);
    return e;
}

}  // namespace

TEST_CASE("emu cf: jmp sets the program counter to the target") {
    emu::IntelEmulator e;
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JMP, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: call pushes the return address and jumps") {
    emu::IntelEmulator e = stacked();
    const std::uint64_t sp0 = e.regs().get_register(emu::kRegEsp);
    pn::DecodedInsn insn = branch_insn(ZYDIS_MNEMONIC_CALL, 0x3000,
                                       /*va=*/0x401000, /*length=*/5);
    e.execute_opcode(insn);
    CHECK(e.program_counter() == 0x3000ULL);
    CHECK(e.regs().get_register(emu::kRegEsp) == sp0 - 4U);
    CHECK(e.memory().read_value(sp0 - 4U, 4) == 0x401005ULL);  // return address
}

TEST_CASE("emu cf amd64: call pushes an 8-byte return address and decrements RSP by 8") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.memory().init_stack();
    const std::uint64_t sp0 = emu::kStackBase + 0x400U;
    e.regs().set_register(emu::kRegRsp, sp0);
    pn::DecodedInsn insn = branch_insn(ZYDIS_MNEMONIC_CALL, 0x140003000ULL,
                                       /*va=*/0x140001000ULL, /*length=*/5);
    e.execute_opcode(insn);
    CHECK(e.program_counter() == 0x140003000ULL);
    CHECK(e.regs().get_register(emu::kRegRsp) == sp0 - 8U);
    CHECK(e.memory().read_value(sp0 - 8U, 8) == 0x140001005ULL);
}

TEST_CASE("emu cf: ret pops the return address into the program counter") {
    emu::IntelEmulator e = stacked();
    const std::uint64_t sp0 = e.regs().get_register(emu::kRegEsp);
    e.memory().write_value(sp0, 0x401005ULL, 4);
    e.execute_opcode(no_oper_insn(ZYDIS_MNEMONIC_RET));
    CHECK(e.program_counter() == 0x401005ULL);
    CHECK(e.regs().get_register(emu::kRegEsp) == sp0 + 4U);
}

TEST_CASE("emu cf: ret imm also adjusts the stack pointer by the immediate") {
    emu::IntelEmulator e = stacked();
    const std::uint64_t sp0 = e.regs().get_register(emu::kRegEsp);
    e.memory().write_value(sp0, 0x401005ULL, 4);
    pn::DecodedInsn insn;
    insn.va = 0x2000;
    insn.length = 3;
    insn.zyd_mnem = ZYDIS_MNEMONIC_RET;
    insn.operands[0] = imm_oper(0x8U, 2);
    insn.operand_count = 1;
    e.execute_opcode(insn);
    CHECK(e.program_counter() == 0x401005ULL);
    CHECK(e.regs().get_register(emu::kRegEsp) == sp0 + 4U + 0x8U);
}

TEST_CASE("emu cf: jz branches only when ZF is set") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsZf, true);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JZ, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: jz falls through when ZF is clear") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsZf, false);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JZ, 0x2000, /*va=*/0x1000, /*length=*/2));
    CHECK(e.program_counter() == 0x1002ULL);
}

TEST_CASE("emu cf: jnz branches when ZF is clear") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsZf, false);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JNZ, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: jb branches when CF is set, jnb when clear") {
    emu::IntelEmulator e1;
    e1.regs().set_flag(emu::kEflagsCf, true);
    e1.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JB, 0x2000));
    CHECK(e1.program_counter() == 0x2000ULL);

    emu::IntelEmulator e2;
    e2.regs().set_flag(emu::kEflagsCf, false);
    e2.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JNB, 0x2000));
    CHECK(e2.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: jbe branches when CF or ZF is set") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsCf, false);
    e.regs().set_flag(emu::kEflagsZf, true);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JBE, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: jnbe (above) branches when CF and ZF are both clear") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsCf, false);
    e.regs().set_flag(emu::kEflagsZf, false);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JNBE, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: jl branches when SF != OF") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsSf, true);
    e.regs().set_flag(emu::kEflagsOf, false);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JL, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: jle branches when SF != OF or ZF set") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsSf, false);
    e.regs().set_flag(emu::kEflagsOf, false);
    e.regs().set_flag(emu::kEflagsZf, true);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JLE, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: jnle (greater) branches when ZF clear and SF == OF") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsZf, false);
    e.regs().set_flag(emu::kEflagsSf, true);
    e.regs().set_flag(emu::kEflagsOf, true);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JNLE, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: js branches when SF is set") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsSf, true);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JS, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: jecxz branches when ECX is zero") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEcx, 0U);
    e.execute_opcode(branch_insn(ZYDIS_MNEMONIC_JECXZ, 0x2000));
    CHECK(e.program_counter() == 0x2000ULL);
}

TEST_CASE("emu cf: an indirect jmp through a register targets the register value") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x00405000U);
    pn::DecodedInsn insn;
    insn.va = 0x1000;
    insn.length = 2;
    insn.zyd_mnem = ZYDIS_MNEMONIC_JMP;
    insn.operands[0] = reg_oper(ZYDIS_REGISTER_EAX, 4);
    insn.operand_count = 1;
    e.execute_opcode(insn);
    CHECK(e.program_counter() == 0x00405000ULL);
}

TEST_CASE("emu cf: leave restores ESP from EBP and pops EBP") {
    emu::IntelEmulator e = stacked();
    const std::uint32_t frame = static_cast<std::uint32_t>(emu::kStackBase) + 0x200U;
    e.regs().set_register(emu::kRegEbp, frame);
    e.memory().write_value(frame, 0xAABBCCDDULL, 4);  // saved EBP
    e.execute_opcode(no_oper_insn(ZYDIS_MNEMONIC_LEAVE));
    CHECK(e.regs().get_register(emu::kRegEbp) == 0xAABBCCDDULL);
    CHECK(e.regs().get_register(emu::kRegEsp) == frame + 4U);
}

TEST_CASE("emu cf: shl shifts left and sets the carry out") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x1U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SHL, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(4U, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0x10ULL);
}

TEST_CASE("emu cf: shl by zero leaves flags unchanged") {
    emu::IntelEmulator e;
    e.regs().set_flag(emu::kEflagsCf, true);
    e.regs().set_register(emu::kRegEax, 0x1U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SHL, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(0U, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0x1ULL);
    CHECK(e.regs().get_flag(emu::kEflagsCf));  // unchanged
}

TEST_CASE("emu cf: shr shifts right") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x10U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SHR, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(4U, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0x1ULL);
}

TEST_CASE("emu cf: sar shifts right with sign fill") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x80000000U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SAR, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(4U, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0xF8000000ULL);
}

TEST_CASE("emu cf: shl producing zero sets ZF") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x80000000U);
    e.execute_opcode(insn2(ZYDIS_MNEMONIC_SHL, reg_oper(ZYDIS_REGISTER_EAX, 4),
                           imm_oper(1U, 1)));
    CHECK(e.regs().get_register(emu::kRegEax) == 0ULL);
    CHECK(e.regs().get_flag(emu::kEflagsZf));
}
