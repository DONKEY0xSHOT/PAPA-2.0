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
using emu::kEflagsPf;
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
        {"jecxz on a zero ECX", branch_insn(ZYDIS_MNEMONIC_JECXZ, 0x2000), {.ecx = 0}, State{},
         0x2000},
        {"jcxz on a zero CX even when the upper half of ECX is set",
         branch_insn(ZYDIS_MNEMONIC_JCXZ, 0x2000), {.ecx = 0x10000}, State{}, 0x2000},
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

TEST_CASE("emu cc: each jcc, setcc and cmovcc follows its condition on every flag state that decides it") {
    struct Row {
        std::string_view           label;
        ZydisMnemonic              jcc;
        ZydisMnemonic              setcc;
        ZydisMnemonic              cmovcc;
        std::vector<std::uint32_t> holds;
        std::vector<std::uint32_t> fails;
    };
    constexpr std::uint32_t kNone = 0;
    const std::vector<Row> rows{
        {"b", ZYDIS_MNEMONIC_JB, ZYDIS_MNEMONIC_SETB, ZYDIS_MNEMONIC_CMOVB,
         {kEflagsCf}, {kNone, kEflagsZf}},
        {"nb", ZYDIS_MNEMONIC_JNB, ZYDIS_MNEMONIC_SETNB, ZYDIS_MNEMONIC_CMOVNB,
         {kNone, kEflagsZf}, {kEflagsCf}},
        {"be", ZYDIS_MNEMONIC_JBE, ZYDIS_MNEMONIC_SETBE, ZYDIS_MNEMONIC_CMOVBE,
         {kEflagsCf, kEflagsZf}, {kNone}},
        {"nbe", ZYDIS_MNEMONIC_JNBE, ZYDIS_MNEMONIC_SETNBE, ZYDIS_MNEMONIC_CMOVNBE,
         {kNone}, {kEflagsCf, kEflagsZf}},
        {"z", ZYDIS_MNEMONIC_JZ, ZYDIS_MNEMONIC_SETZ, ZYDIS_MNEMONIC_CMOVZ,
         {kEflagsZf}, {kNone}},
        {"nz", ZYDIS_MNEMONIC_JNZ, ZYDIS_MNEMONIC_SETNZ, ZYDIS_MNEMONIC_CMOVNZ,
         {kNone}, {kEflagsZf}},
        {"l", ZYDIS_MNEMONIC_JL, ZYDIS_MNEMONIC_SETL, ZYDIS_MNEMONIC_CMOVL,
         {kEflagsSf, kEflagsOf}, {kNone, kEflagsSf | kEflagsOf}},
        {"nl", ZYDIS_MNEMONIC_JNL, ZYDIS_MNEMONIC_SETNL, ZYDIS_MNEMONIC_CMOVNL,
         {kNone, kEflagsSf | kEflagsOf}, {kEflagsSf, kEflagsOf}},
        {"le", ZYDIS_MNEMONIC_JLE, ZYDIS_MNEMONIC_SETLE, ZYDIS_MNEMONIC_CMOVLE,
         {kEflagsZf, kEflagsSf, kEflagsOf}, {kNone, kEflagsSf | kEflagsOf}},
        {"nle", ZYDIS_MNEMONIC_JNLE, ZYDIS_MNEMONIC_SETNLE, ZYDIS_MNEMONIC_CMOVNLE,
         {kNone, kEflagsSf | kEflagsOf},
         {kEflagsZf, kEflagsSf, kEflagsZf | kEflagsSf | kEflagsOf}},
        {"o", ZYDIS_MNEMONIC_JO, ZYDIS_MNEMONIC_SETO, ZYDIS_MNEMONIC_CMOVO,
         {kEflagsOf}, {kNone}},
        {"no", ZYDIS_MNEMONIC_JNO, ZYDIS_MNEMONIC_SETNO, ZYDIS_MNEMONIC_CMOVNO,
         {kNone}, {kEflagsOf}},
        {"s", ZYDIS_MNEMONIC_JS, ZYDIS_MNEMONIC_SETS, ZYDIS_MNEMONIC_CMOVS,
         {kEflagsSf}, {kNone}},
        {"ns", ZYDIS_MNEMONIC_JNS, ZYDIS_MNEMONIC_SETNS, ZYDIS_MNEMONIC_CMOVNS,
         {kNone}, {kEflagsSf}},
        {"p", ZYDIS_MNEMONIC_JP, ZYDIS_MNEMONIC_SETP, ZYDIS_MNEMONIC_CMOVP,
         {kEflagsPf}, {kNone}},
        {"np", ZYDIS_MNEMONIC_JNP, ZYDIS_MNEMONIC_SETNP, ZYDIS_MNEMONIC_CMOVNP,
         {kNone}, {kEflagsPf}},
    };
    // The program counter and ECX after ins runs with exactly the eflags bits set
    struct After {
        std::uint64_t pc;
        std::uint64_t ecx;
    };
    const auto run = [](const pn::DecodedInsn& ins, std::uint32_t eflags) {
        emu::IntelEmulator e;
        for (const std::uint32_t f : {kEflagsCf, kEflagsZf, kEflagsSf, kEflagsOf, kEflagsPf}) {
            e.regs().set_flag(f, (eflags & f) != 0);
        }
        e.regs().set_register(emu::kRegEcx, 0xAABBCC55U);
        e.regs().set_register(emu::kRegEdx, 0x2222U);
        e.execute_opcode(ins);
        return After{e.program_counter(), e.regs().get_register(emu::kRegEcx)};
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const pn::DecodedInsn jcc   = branch_insn(row.jcc, 0x2000);
        const pn::DecodedInsn setcc = insn(row.setcc, reg(ZYDIS_REGISTER_CL, 1));
        const pn::DecodedInsn cmovcc =
            insn(row.cmovcc, reg(ZYDIS_REGISTER_ECX, 4), reg(ZYDIS_REGISTER_EDX, 4));
        for (const bool holds : {true, false}) {
            for (const std::uint32_t eflags : holds ? row.holds : row.fails) {
                CAPTURE(holds);
                CAPTURE(eflags);
                CHECK(run(jcc, eflags).pc == (holds ? 0x2000U : jcc.va + jcc.length));
                CHECK(run(setcc, eflags).ecx == (holds ? 0xAABBCC01U : 0xAABBCC00U));
                CHECK(run(cmovcc, eflags).ecx == (holds ? 0x2222U : 0xAABBCC55U));
            }
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
