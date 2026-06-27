#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <array>
#include <cstdint>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// get_branches enumerates an instruction's control-flow successors, resolving
// indirect targets from live emulator state. A faithful port of
// envi/archs/i386/disasm.py getBranches(emu=self), including the SIB scale-4
// pointer-table walk that recovers switch cases. Branch flags mirror envi BR_*.

namespace {

pn::DecodedInsn normal_insn(std::uint64_t va = 0x1000, std::size_t length = 2) {
    pn::DecodedInsn insn;
    insn.va = va;
    insn.length = length;
    insn.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    insn.is_fallthrough = true;
    insn.operand_count = 2;
    return insn;
}

pn::DecodedInsn jcc_insn(std::uint64_t target, std::uint64_t va = 0x1000,
                         std::size_t length = 2) {
    pn::DecodedInsn insn;
    insn.va = va;
    insn.length = length;
    insn.zyd_mnem = ZYDIS_MNEMONIC_JZ;
    insn.is_jump = true;
    insn.is_conditional = true;
    insn.is_fallthrough = true;
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kPcRel;
    op.width_bytes = 4;
    insn.operands[0] = op;
    insn.operand_count = 1;
    insn.branch_target = target;
    return insn;
}

bool has_target(const std::vector<emu::Branch>& bs, std::uint64_t va) {
    for (const emu::Branch& b : bs) {
        if (b.va == va) {
            return true;
        }
    }
    return false;
}

}  // namespace

TEST_CASE("emu branches: a normal instruction has a single fall-through edge") {
    emu::IntelEmulator e;
    const std::vector<emu::Branch> bs = e.get_branches(normal_insn(0x1000, 2));
    REQUIRE(bs.size() == 1);
    CHECK(bs[0].va == 0x1002ULL);
    CHECK((bs[0].flags & emu::kBrFall) != 0);
}

TEST_CASE("emu branches: an unconditional direct jmp has one target and no fall-through") {
    emu::IntelEmulator e;
    pn::DecodedInsn insn;
    insn.va = 0x1000;
    insn.length = 2;
    insn.zyd_mnem = ZYDIS_MNEMONIC_JMP;
    insn.is_jump = true;
    insn.is_fallthrough = false;
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kPcRel;
    op.width_bytes = 4;
    insn.operands[0] = op;
    insn.operand_count = 1;
    insn.branch_target = 0x2000;
    const std::vector<emu::Branch> bs = e.get_branches(insn);
    REQUIRE(bs.size() == 1);
    CHECK(bs[0].va == 0x2000ULL);
}

TEST_CASE("emu branches: a conditional jump has both a fall-through and a target") {
    emu::IntelEmulator e;
    const std::vector<emu::Branch> bs = e.get_branches(jcc_insn(0x2000, 0x1000, 2));
    REQUIRE(bs.size() == 2);
    CHECK(has_target(bs, 0x1002));  // fall-through
    CHECK(has_target(bs, 0x2000));  // taken target
}

TEST_CASE("emu branches: an indirect jmp through a register resolves the register value") {
    emu::IntelEmulator e;
    e.regs().set_register(emu::kRegEax, 0x00404000U);
    pn::DecodedInsn insn;
    insn.va = 0x1000;
    insn.length = 2;
    insn.zyd_mnem = ZYDIS_MNEMONIC_JMP;
    insn.is_jump = true;
    insn.is_fallthrough = false;
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kReg;
    op.base_reg = ZYDIS_REGISTER_EAX;
    op.width_bytes = 4;
    insn.operands[0] = op;
    insn.operand_count = 1;
    const std::vector<emu::Branch> bs = e.get_branches(insn);
    REQUIRE(bs.size() == 1);
    CHECK(bs[0].va == 0x00404000ULL);
}

TEST_CASE("emu branches: a return has no branches") {
    emu::IntelEmulator e;
    pn::DecodedInsn insn;
    insn.va = 0x1000;
    insn.length = 1;
    insn.zyd_mnem = ZYDIS_MNEMONIC_RET;
    insn.is_return = true;
    insn.is_fallthrough = false;
    insn.operand_count = 0;
    CHECK(e.get_branches(insn).empty());
}

TEST_CASE("emu branches: a SIB scale-4 jump table walks the pointer array") {
    // jmp [idx*4 + table]: get_branches reads consecutive pointers from the
    // table base and yields each valid one, stopping at the first invalid entry.
    emu::IntelEmulator e;
    // A code region the table entries point into.
    static constexpr std::array<std::uint8_t, 0x40> code{};
    e.memory().add_map(0x401000, emu::kMemRead | emu::kMemExec, code);
    // The table: three valid targets then a zero (invalid) terminator.
    static const std::array<std::uint8_t, 16> table = {
        0x00, 0x10, 0x40, 0x00,  // 0x00401000
        0x10, 0x10, 0x40, 0x00,  // 0x00401010
        0x20, 0x10, 0x40, 0x00,  // 0x00401020
        0x00, 0x00, 0x00, 0x00,  // 0 -> invalid, stop
    };
    e.memory().add_map(0x405000, emu::kMemRead, table);

    pn::DecodedInsn insn;
    insn.va = 0x1000;
    insn.length = 7;
    insn.zyd_mnem = ZYDIS_MNEMONIC_JMP;
    insn.is_jump = true;
    insn.is_fallthrough = false;
    pn::DecodedOperand op;
    op.kind = pn::OperandKind::kSib;
    op.base_reg = ZYDIS_REGISTER_NONE;
    op.index_reg = ZYDIS_REGISTER_EAX;
    op.scale = 4;
    op.disp = 0x405000;  // table base
    op.width_bytes = 4;
    insn.operands[0] = op;
    insn.operand_count = 1;

    const std::vector<emu::Branch> bs = e.get_branches(insn);
    REQUIRE(bs.size() == 3);
    CHECK(has_target(bs, 0x401000));
    CHECK(has_target(bs, 0x401010));
    CHECK(has_target(bs, 0x401020));
}
