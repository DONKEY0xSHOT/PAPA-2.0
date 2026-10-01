#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include "test_support.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// Control-flow handlers ported from envi/archs/i386/emu.py. These are what let an
// emulated function body run to its ret

using papa_tests::imm;
using papa_tests::insn;
using papa_tests::reg;

using emu::kEflagsCf;
using emu::kEflagsOf;
using emu::kEflagsSf;
using emu::kEflagsZf;

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

// A jmp through eax
pn::DecodedInsn jmp_eax() {
    return insn(ZYDIS_MNEMONIC_JMP, reg(ZYDIS_REGISTER_EAX, 4));
}

// A ret that also releases n bytes of arguments
pn::DecodedInsn ret_imm(std::uint64_t n) {
    pn::DecodedInsn out = insn(ZYDIS_MNEMONIC_RET, imm(n, 2));
    out.va = 0x2000;
    out.length = 3;
    return out;
}

}  // namespace

TEST_CASE("emu cf: each jump goes to its target when its condition holds and falls through otherwise") {
    // The flags not named in eflags are clear
    struct State {
        std::uint32_t eflags = 0;
        std::uint64_t ecx    = 1;
        std::uint64_t eax    = 0;
    };
    struct Row {
        std::string_view     label;
        pn::DecodedInsn      ins;
        State                taken;
        std::optional<State> not_taken;
        std::uint64_t        target;
    };
    const std::vector<Row> rows{
        {"jz on ZF", branch_insn(ZYDIS_MNEMONIC_JZ, 0x2000), {.eflags = kEflagsZf}, State{},
         0x2000},
        {"jnz on clear ZF", branch_insn(ZYDIS_MNEMONIC_JNZ, 0x2000), {}, State{.eflags = kEflagsZf},
         0x2000},
        {"jb on CF", branch_insn(ZYDIS_MNEMONIC_JB, 0x2000), {.eflags = kEflagsCf}, State{},
         0x2000},
        {"jnb on clear CF", branch_insn(ZYDIS_MNEMONIC_JNB, 0x2000), {}, State{.eflags = kEflagsCf},
         0x2000},
        {"jbe on CF or ZF", branch_insn(ZYDIS_MNEMONIC_JBE, 0x2000), {.eflags = kEflagsZf}, State{},
         0x2000},
        {"jnbe (above) on CF and ZF both clear", branch_insn(ZYDIS_MNEMONIC_JNBE, 0x2000), {},
         State{.eflags = kEflagsCf}, 0x2000},
        {"jl on SF != OF", branch_insn(ZYDIS_MNEMONIC_JL, 0x2000), {.eflags = kEflagsSf},
         State{.eflags = kEflagsSf | kEflagsOf}, 0x2000},
        {"jle on SF != OF or ZF", branch_insn(ZYDIS_MNEMONIC_JLE, 0x2000), {.eflags = kEflagsZf},
         State{}, 0x2000},
        {"jnle (greater) on clear ZF and SF == OF", branch_insn(ZYDIS_MNEMONIC_JNLE, 0x2000),
         {.eflags = kEflagsSf | kEflagsOf}, State{.eflags = kEflagsSf}, 0x2000},
        {"js on SF", branch_insn(ZYDIS_MNEMONIC_JS, 0x2000), {.eflags = kEflagsSf}, State{},
         0x2000},
        {"jecxz on a zero ECX", branch_insn(ZYDIS_MNEMONIC_JECXZ, 0x2000), {.ecx = 0}, State{},
         0x2000},
        {"a direct jmp always goes to its target", branch_insn(ZYDIS_MNEMONIC_JMP, 0x2000), {},
         std::nullopt, 0x2000},
        {"an indirect jmp through a register goes to the register value", jmp_eax(),
         {.eax = 0x00405000U}, std::nullopt, 0x00405000U},
    };
    const auto run = [](const pn::DecodedInsn& ins, const State& s) {
        emu::IntelEmulator e;
        for (const std::uint32_t f : {kEflagsCf, kEflagsZf, kEflagsSf, kEflagsOf}) {
            e.regs().set_flag(f, (s.eflags & f) != 0);
        }
        e.regs().set_register(emu::kRegEcx, s.ecx);
        e.regs().set_register(emu::kRegEax, s.eax);
        e.execute_opcode(ins);
        return e.program_counter();
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(run(row.ins, row.taken) == row.target);
        if (row.not_taken.has_value()) {
            CHECK(run(row.ins, *row.not_taken) == row.ins.va + row.ins.length);
        }
    }
}

TEST_CASE("emu cf: call, ret and leave move the stack pointer, the stack and the pc") {
    constexpr std::uint64_t kSp    = emu::kStackBase + 0x400U;
    constexpr std::uint64_t kFrame = emu::kStackBase + 0x200U;
    struct Reg {
        std::uint32_t id;
        std::uint64_t value;
    };
    struct Slot {
        std::uint64_t at;
        std::size_t   width;
        std::uint64_t value;
    };
    struct Row {
        std::string_view  label;
        bool              is_64bit;
        pn::DecodedInsn   ins;
        std::vector<Reg>  regs_in;
        std::vector<Slot> stack_in;
        std::uint64_t     pc;
        std::vector<Reg>  regs_out;
        std::vector<Slot> stack_out;
    };
    const std::vector<Row> rows{
        {"call pushes the return address and jumps", false,
         branch_insn(ZYDIS_MNEMONIC_CALL, 0x3000, /*va=*/0x401000, /*length=*/5),
         {{emu::kRegEsp, kSp}}, {}, 0x3000, {{emu::kRegEsp, kSp - 4U}}, {{kSp - 4U, 4, 0x401005}}},
        {"amd64 call pushes an 8-byte return address and decrements RSP by 8", true,
         branch_insn(ZYDIS_MNEMONIC_CALL, 0x140003000ULL, /*va=*/0x140001000ULL, /*length=*/5),
         {{emu::kRegRsp, kSp}}, {}, 0x140003000ULL, {{emu::kRegRsp, kSp - 8U}},
         {{kSp - 8U, 8, 0x140001005ULL}}},
        {"ret pops the return address into the program counter", false,
         insn(ZYDIS_MNEMONIC_RET), {{emu::kRegEsp, kSp}}, {{kSp, 4, 0x401005}}, 0x401005,
         {{emu::kRegEsp, kSp + 4U}}, {}},
        {"ret imm also adjusts the stack pointer by the immediate", false, ret_imm(0x8U),
         {{emu::kRegEsp, kSp}}, {{kSp, 4, 0x401005}}, 0x401005, {{emu::kRegEsp, kSp + 4U + 0x8U}},
         {}},
        {"leave restores ESP from EBP and pops EBP", false, insn(ZYDIS_MNEMONIC_LEAVE),
         {{emu::kRegEsp, kSp}, {emu::kRegEbp, kFrame}}, {{kFrame, 4, 0xAABBCCDDU}}, 0x1002,
         {{emu::kRegEbp, 0xAABBCCDDU}, {emu::kRegEsp, kFrame + 4U}}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::IntelEmulator e(row.is_64bit);
        e.memory().init_stack();
        for (const Reg& r : row.regs_in) { e.regs().set_register(r.id, r.value); }
        for (const Slot& s : row.stack_in) { e.memory().write_value(s.at, s.value, s.width); }
        e.execute_opcode(row.ins);
        CHECK(e.program_counter() == row.pc);
        for (const Reg& want : row.regs_out) {
            CAPTURE(want.id);
            CHECK(e.regs().get_register(want.id) == want.value);
        }
        for (const Slot& want : row.stack_out) {
            CAPTURE(want.at);
            CHECK(e.memory().read_value(want.at, want.width) == want.value);
        }
    }
}
