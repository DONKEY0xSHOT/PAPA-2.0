#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <array>
#include <cstdint>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// The operand-access layer bridges Zydis-decoded operands to register and memory
// state. Synthetic instructions drive the tests, so no real PE is needed

namespace {

// Build a one-operand instruction with the given va/length
pn::DecodedInsn make_insn(pn::DecodedOperand op, std::uint64_t va = 0x1000,
                          std::size_t length = 2) {
    pn::DecodedInsn insn;
    insn.va = va;
    insn.length = length;
    insn.operands[0] = op;
    insn.operand_count = 1;
    return insn;
}

pn::DecodedOperand reg_oper(ZydisRegister r, std::size_t width) {
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kReg;
    op.base_reg = r;
    op.width_bytes = width;
    return op;
}

}  // namespace

TEST_CASE("emu operands: get_oper_value reads a 32-bit register") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0xDEADBEEFU);
    const pn::DecodedInsn insn = make_insn(reg_oper(ZYDIS_REGISTER_EAX, 4));
    CHECK(e.get_oper_value(insn, 0) == 0xDEADBEEFULL);
}

TEST_CASE("emu operands: get_oper_value reads a sub-register lane") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x11223344U);
    CHECK(e.get_oper_value(make_insn(reg_oper(ZYDIS_REGISTER_AL, 1)), 0) == 0x44ULL);
    CHECK(e.get_oper_value(make_insn(reg_oper(ZYDIS_REGISTER_AH, 1)), 0) == 0x33ULL);
    CHECK(e.get_oper_value(make_insn(reg_oper(ZYDIS_REGISTER_AX, 2)), 0) == 0x3344ULL);
}

TEST_CASE("emu operands: get_oper_value returns an immediate") {
    emu::IntelEmulator e;
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kImm;
    op.imm = 0x12345678U;
    op.width_bytes = 4;
    CHECK(e.get_oper_value(make_insn(op), 0) == 0x12345678ULL);
}

TEST_CASE("emu operands: get_oper_value on a pc-relative operand is the absolute target") {
    // vivisect i386PcRelOper.getOperValue = op.va + op.size + imm. papa already
    // resolves that into DecodedInsn.branch_target via Zydis
    emu::IntelEmulator e;
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kPcRel;
    op.width_bytes = 4;
    pn::DecodedInsn insn = make_insn(op, /*va=*/0x401000, /*length=*/5);
    insn.branch_target = 0x401200U;
    CHECK(e.get_oper_value(insn, 0) == 0x401200ULL);
}

TEST_CASE("emu operands: get_oper_addr of [reg + disp]") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x2000U);
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kRegMem;
    op.base_reg = ZYDIS_REGISTER_EAX;
    op.disp = 0x10;
    op.width_bytes = 4;
    CHECK(e.get_oper_addr(make_insn(op), 0) == 0x2010ULL);
}

TEST_CASE("emu operands: get_oper_addr of [reg - disp] handles a negative displacement") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEbp, 0x3000U);
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kRegMem;
    op.base_reg = ZYDIS_REGISTER_EBP;
    op.disp = -0x8;
    op.width_bytes = 4;
    CHECK(e.get_oper_addr(make_insn(op), 0) == 0x2FF8ULL);
}

TEST_CASE("emu operands: get_oper_value of [reg + disp] reads memory") {
    emu::IntelEmulator e;
    static constexpr std::array<std::uint8_t, 4> data = {0xEF, 0xBE, 0xAD, 0xDE};
    e.memory().add_map(0x2000, emu::kMemRead, data);
    e.regs().set_register(emu::kRegEax, 0x2000U);
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kRegMem;
    op.base_reg = ZYDIS_REGISTER_EAX;
    op.disp = 0;
    op.width_bytes = 4;
    CHECK(e.get_oper_value(make_insn(op), 0) == 0xDEADBEEFULL);
}

TEST_CASE("emu operands: get_oper_addr of a SIB [base + index*scale + disp]") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x1000U);  // base
    e.regs().set_register(emu::kRegEcx, 0x4U);     // index
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kSib;
    op.base_reg = ZYDIS_REGISTER_EAX;
    op.index_reg = ZYDIS_REGISTER_ECX;
    op.scale = 4;
    op.disp = 0x10;
    op.width_bytes = 4;
    // 0x1000 + 4*4 + 0x10 = 0x1020
    CHECK(e.get_oper_addr(make_insn(op), 0) == 0x1020ULL);
}

TEST_CASE("emu operands: get_oper_addr of an absolute [imm]") {
    emu::IntelEmulator e;
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kImmMem;
    op.imm = 0x00401000U;
    op.width_bytes = 4;
    CHECK(e.get_oper_addr(make_insn(op), 0) == 0x00401000ULL);
}

TEST_CASE("emu operands: set_oper_value writes a register") {
    emu::IntelEmulator e;
    e.set_oper_value(make_insn(reg_oper(ZYDIS_REGISTER_EDX, 4)), 0, 0xCAFEBABEULL);
    CHECK(e.regs().get_register(emu::kRegEdx) == 0xCAFEBABEULL);
}

TEST_CASE("emu operands: set_oper_value on a sub-register splices the lane") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEbx, 0x11223344U);
    e.set_oper_value(make_insn(reg_oper(ZYDIS_REGISTER_BL, 1)), 0, 0xFFULL);
    CHECK(e.regs().get_register(emu::kRegEbx) == 0x112233FFULL);
}

TEST_CASE("emu operands: set_oper_value writes memory at [reg + disp]") {
    emu::IntelEmulator e;
    e.memory().init_stack();
    e.regs().set_register(emu::kRegEsp, static_cast<std::uint32_t>(emu::kStackBase));
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kRegMem;
    op.base_reg = ZYDIS_REGISTER_ESP;
    op.disp = 0x20;
    op.width_bytes = 4;
    e.set_oper_value(make_insn(op), 0, 0x12345678ULL);
    CHECK(e.memory().read_value(emu::kStackBase + 0x20, 4) == 0x12345678ULL);
}

TEST_CASE("emu operands: get_oper_addr masks the computed address to 32 bits") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0xFFFFFFF0U);
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kRegMem;
    op.base_reg = ZYDIS_REGISTER_EAX;
    op.disp = 0x20;  // 0xFFFFFFF0 + 0x20 = 0x1'00000010 -> wraps to 0x10
    op.width_bytes = 4;
    CHECK(e.get_oper_addr(make_insn(op), 0) == 0x10ULL);
}

// amd64 addressing: rip is 64-bit and addresses are not truncated, so near branches
// and implicit rsp use rip and addresses span the full 64-bit space

TEST_CASE("emu operands amd64: the program counter holds a full 64-bit RIP") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.set_program_counter(0x0000000140001234ULL);
    CHECK(e.program_counter() == 0x0000000140001234ULL);
}

TEST_CASE("emu operands amd64: a RIP-relative address is not truncated to 32 bits") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kRipRel;
    op.disp = 0x200;
    op.width_bytes = 8;
    // va + length + disp = 0x140001000 + 7 + 0x200 = 0x140001207
    const pn::DecodedInsn insn = make_insn(op, /*va=*/0x140001000ULL, /*length=*/7);
    CHECK(e.get_oper_addr(insn, 0) == 0x140001207ULL);
}

TEST_CASE("emu operands amd64: an absolute [imm] address keeps its high bits") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kImmMem;
    op.imm = 0x0000000140005000ULL;
    op.width_bytes = 8;
    CHECK(e.get_oper_addr(make_insn(op), 0) == 0x140005000ULL);
}

TEST_CASE("emu operands amd64: get_oper_value reads a 64-bit register (rax)") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRax, 0x1122334455667788ULL);
    CHECK(e.get_oper_value(make_insn(reg_oper(ZYDIS_REGISTER_RAX, 8)), 0)
          == 0x1122334455667788ULL);
}

TEST_CASE("emu operands amd64: get_oper_value reads an extended register (r8)") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegR8, 0xAABBCCDDEEFF0011ULL);
    CHECK(e.get_oper_value(make_insn(reg_oper(ZYDIS_REGISTER_R8, 8)), 0)
          == 0xAABBCCDDEEFF0011ULL);
}

TEST_CASE("emu operands amd64: writing the eax operand zero-extends rax") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRax, 0x1122334455667788ULL);
    e.set_oper_value(make_insn(reg_oper(ZYDIS_REGISTER_EAX, 4)), 0, 0xDEADBEEFULL);
    CHECK(e.regs().get_register(emu::kRegRax) == 0x00000000DEADBEEFULL);
}

TEST_CASE("emu operands amd64: a base register in [rax + disp] resolves 64-bit") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.regs().set_register(emu::kRegRax, 0x140002000ULL);
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kRegMem;
    op.base_reg = ZYDIS_REGISTER_RAX;
    op.disp = 0x10;
    op.width_bytes = 8;
    CHECK(e.get_oper_addr(make_insn(op), 0) == 0x140002010ULL);
}
