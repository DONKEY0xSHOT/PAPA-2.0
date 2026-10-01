#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// get_branches enumerates an instruction's control-flow successors, resolving
// indirect targets from live emulator state. Branch flags mirror envi BR_*

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

TEST_CASE("emu branches: get_branches yields each successor edge with its envi flags") {
    pn::DecodedInsn jmp = normal_insn(0x1000, 2);
    jmp.zyd_mnem = ZYDIS_MNEMONIC_JMP;
    jmp.is_jump = true;
    jmp.is_fallthrough = false;
    jmp.operand_count = 1;

    pn::DecodedInsn jmp_direct = jmp;
    jmp_direct.operands[0].kind = pn::OperandKind::kPcRel;
    jmp_direct.operands[0].width_bytes = 4;
    jmp_direct.branch_target = 0x2000;

    pn::DecodedInsn jmp_eax = jmp;
    jmp_eax.operands[0].kind = pn::OperandKind::kReg;
    jmp_eax.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    jmp_eax.operands[0].width_bytes = 4;

    pn::DecodedInsn ret = normal_insn(0x1000, 1);
    ret.zyd_mnem = ZYDIS_MNEMONIC_RET;
    ret.is_return = true;
    ret.is_fallthrough = false;
    ret.operand_count = 0;

    struct Row {
        std::string_view         label;
        pn::DecodedInsn          ins;
        std::vector<emu::Branch> edges;
    };
    const std::vector<Row> rows{
        {"a normal instruction has a single fall-through edge", normal_insn(0x1000, 2),
         {{0x1002, emu::kBrFall}}},
        {"an unconditional direct jmp has one target and no fall-through", jmp_direct,
         {{0x2000, 0}}},
        {"a conditional jump has a conditional fall-through and a conditional target",
         jcc_insn(0x2000, 0x1000, 2),
         {{0x1002, emu::kBrCond | emu::kBrFall}, {0x2000, emu::kBrCond}}},
        {"an indirect jmp through a register resolves the register value", jmp_eax,
         {{0x00404000, 0}}},
        {"a return has no branches", ret, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::IntelEmulator e;
        e.regs().set_register(emu::kRegEax, 0x00404000U);
        const std::vector<emu::Branch> bs = e.get_branches(row.ins);
        CHECK(bs.size() == row.edges.size());
        for (std::size_t i = 0; i < bs.size() && i < row.edges.size(); ++i) {
            CAPTURE(i);
            CHECK(bs[i].va == row.edges[i].va);
            CHECK(bs[i].flags == row.edges[i].flags);
        }
    }
}

TEST_CASE("emu branches: a SIB scale-4 jump table walks the pointer array") {
    // jmp [idx*4 + table]: get_branches reads consecutive pointers from the
    // table base and yields each valid one, stopping at the first invalid entry
    emu::IntelEmulator e;
    // A code region the table entries point into
    static constexpr std::array<std::uint8_t, 0x40> code{};
    e.memory().add_map(0x401000, emu::kMemRead | emu::kMemExec, code);
    // The table: three valid targets then a zero (invalid) terminator
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

TEST_CASE("emu branches: a jump table walk off the end of its map is bounded") {
    // The crafted-image case
    emu::IntelEmulator e;
    static constexpr std::array<std::uint8_t, 0x40> code{};
    e.memory().add_map(0x401000, emu::kMemRead | emu::kMemExec, code);

    // The section an attacker positions over the taint constant
    static constexpr std::array<std::uint8_t, 0x1000> bait{};
    e.memory().add_map(0x61616000, emu::kMemRead, bait);
    REQUIRE(e.memory().is_valid_pointer(0x61616161));

    // A two-entry table. Reads past it land unmapped and never stop being valid
    static constexpr std::array<std::uint8_t, 8> table = {
        0x00, 0x10, 0x40, 0x00,  // 0x00401000
        0x10, 0x10, 0x40, 0x00,  // 0x00401010
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
    op.disp = 0x405000;
    op.width_bytes = 4;
    insn.operands[0] = op;
    insn.operand_count = 1;

    const std::vector<emu::Branch> bs = e.get_branches(insn);
    CHECK(bs.size() == emu::kMaxJumpTableEntries);
    CHECK(has_target(bs, 0x401000));
    CHECK(has_target(bs, 0x61616161));
}
