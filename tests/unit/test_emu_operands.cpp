#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include "test_support.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// The operand-access layer bridges Zydis-decoded operands to register and memory
// state. Synthetic instructions drive the tests, so no real PE is needed

using papa_tests::imm;
using papa_tests::mem;
using papa_tests::reg;

namespace {

constexpr bool k32 = false;
constexpr bool k64 = true;

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

// An operand of the given kind with the fields a test sets afterwards left empty
pn::DecodedOperand operand(pn::OperandKind kind, std::size_t width) {
    pn::DecodedOperand op;
    op.kind = kind;
    op.width_bytes = width;
    return op;
}

pn::DecodedOperand sib(ZydisRegister base, ZydisRegister index, std::uint8_t scale,
                       std::int64_t disp, std::size_t width) {
    pn::DecodedOperand op = operand(pn::OperandKind::kSib, width);
    op.base_reg = base;
    op.index_reg = index;
    op.scale = scale;
    op.disp = disp;
    return op;
}

pn::DecodedOperand imm_mem(std::uint64_t address, std::size_t width) {
    pn::DecodedOperand op = operand(pn::OperandKind::kImmMem, width);
    op.imm = address;
    return op;
}

pn::DecodedOperand rip_rel(std::int64_t disp, std::size_t width) {
    pn::DecodedOperand op = operand(pn::OperandKind::kRipRel, width);
    op.disp = disp;
    return op;
}

// A pc-relative branch operand at va whose resolved target is target
pn::DecodedInsn pc_rel(std::uint64_t va, std::size_t length, std::uint64_t target) {
    pn::DecodedInsn insn = make_insn(operand(pn::OperandKind::kPcRel, 4), va, length);
    insn.branch_target = target;
    return insn;
}

struct Reg {
    std::uint32_t id;
    std::uint64_t value;
};

// The bytes mapped readable at kDataVa in every emulator these tables use
constexpr std::uint64_t kDataVa = 0x2000;
constexpr std::array<std::uint8_t, 4> kData = {0xEF, 0xBE, 0xAD, 0xDE};

// An emulator with kData mapped at kDataVa, the stack ready and the registers set
emu::IntelEmulator fixture(bool is_64bit, const std::vector<Reg>& regs) {
    emu::IntelEmulator e(is_64bit);
    e.memory().add_map(kDataVa, emu::kMemRead, kData);
    e.memory().init_stack();
    for (const Reg& r : regs) { e.regs().set_register(r.id, r.value); }
    return e;
}

// Where a write lands: a register, or width bytes of memory
struct Where {
    bool          memory;
    std::uint64_t at;
    std::size_t   width;
};

Where in_reg(std::uint32_t id) { return {false, id, 0}; }
Where in_mem(std::uint64_t at, std::size_t width) { return {true, at, width}; }

// An operand read: the registers set beforehand, the instruction, and the value
// get_oper_value or the address get_oper_addr yields for operand 0
struct ReadRow {
    std::string_view label;
    bool             is_64bit;
    std::vector<Reg> regs;
    pn::DecodedInsn  ins;
    std::uint64_t    expected;
};

}  // namespace

TEST_CASE("emu operands: reg_index_from_zydis maps each register family to its register or lane") {
    struct Row {
        std::string_view             label;
        bool                         is_64bit;
        ZydisRegister                reg;
        std::optional<std::uint32_t> expected;
    };
    const std::vector<Row> rows{
        {"amd64 rax", k64, ZYDIS_REGISTER_RAX, emu::kRegRax},
        {"amd64 r15", k64, ZYDIS_REGISTER_R15, emu::kRegR15},
        {"amd64 rip", k64, ZYDIS_REGISTER_RIP, emu::kRegRip},
        {"amd64 eax is the low 32 bits of rax", k64, ZYDIS_REGISTER_EAX,
         emu::make_meta_reg(0, 32, emu::kRegRax)},
        {"amd64 r9d is the low 32 bits of r9", k64, ZYDIS_REGISTER_R9D,
         emu::make_meta_reg(0, 32, emu::kRegR9)},
        {"amd64 eip is the low 32 bits of rip", k64, ZYDIS_REGISTER_EIP,
         emu::make_meta_reg(0, 32, emu::kRegRip)},
        {"amd64 ax", k64, ZYDIS_REGISTER_AX, emu::kRegAx},
        {"amd64 r10w is the low 16 bits of r10", k64, ZYDIS_REGISTER_R10W,
         emu::make_meta_reg(0, 16, emu::kRegR10)},
        {"amd64 al", k64, ZYDIS_REGISTER_AL, emu::kRegAl},
        {"amd64 spl is the low byte of rsp", k64, ZYDIS_REGISTER_SPL,
         emu::make_meta_reg(0, 8, emu::kRegRsp)},
        {"amd64 r11b is the low byte of r11", k64, ZYDIS_REGISTER_R11B,
         emu::make_meta_reg(0, 8, emu::kRegR11)},
        {"amd64 ah", k64, ZYDIS_REGISTER_AH, emu::kRegAh},
        {"amd64 has no general register for xmm0", k64, ZYDIS_REGISTER_XMM0, std::nullopt},
        {"i386 eax", k32, ZYDIS_REGISTER_EAX, emu::kRegEax},
        {"i386 eip", k32, ZYDIS_REGISTER_EIP, emu::kRegEip},
        {"i386 si", k32, ZYDIS_REGISTER_SI, emu::kRegSi},
        {"i386 bl", k32, ZYDIS_REGISTER_BL, emu::kRegBl},
        {"i386 bh", k32, ZYDIS_REGISTER_BH, emu::kRegBh},
        {"i386 has no rax", k32, ZYDIS_REGISTER_RAX, std::nullopt},
        {"i386 has no r8d", k32, ZYDIS_REGISTER_R8D, std::nullopt},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(emu::reg_index_from_zydis(row.reg, row.is_64bit) == row.expected);
    }
}

TEST_CASE("emu operands: get_oper_value reads registers, lanes, immediates, branch targets and memory") {
    // vivisect i386PcRelOper.getOperValue = op.va + op.size + imm. papa already
    // resolves that into DecodedInsn.branch_target via Zydis
    const std::vector<ReadRow> rows{
        {"a 32-bit register", k32, {{emu::kRegEax, 0xDEADBEEFU}},
         make_insn(reg(ZYDIS_REGISTER_EAX, 4)), 0xDEADBEEFULL},
        {"the AL lane", k32, {{emu::kRegEax, 0x11223344U}}, make_insn(reg(ZYDIS_REGISTER_AL, 1)),
         0x44ULL},
        {"the AH lane", k32, {{emu::kRegEax, 0x11223344U}}, make_insn(reg(ZYDIS_REGISTER_AH, 1)),
         0x33ULL},
        {"the AX lane", k32, {{emu::kRegEax, 0x11223344U}}, make_insn(reg(ZYDIS_REGISTER_AX, 2)),
         0x3344ULL},
        {"an immediate", k32, {}, make_insn(imm(0x12345678U, 4)), 0x12345678ULL},
        {"a pc-relative operand is the absolute target", k32, {},
         pc_rel(/*va=*/0x401000, /*length=*/5, /*target=*/0x401200U), 0x401200ULL},
        {"[reg + disp] reads memory", k32, {{emu::kRegEax, kDataVa}},
         make_insn(mem(ZYDIS_REGISTER_EAX, 0, 4)), 0xDEADBEEFULL},
        {"amd64 a 64-bit register (rax)", k64, {{emu::kRegRax, 0x1122334455667788ULL}},
         make_insn(reg(ZYDIS_REGISTER_RAX, 8)), 0x1122334455667788ULL},
        {"amd64 an extended register (r8)", k64, {{emu::kRegR8, 0xAABBCCDDEEFF0011ULL}},
         make_insn(reg(ZYDIS_REGISTER_R8, 8)), 0xAABBCCDDEEFF0011ULL},
    };
    for (const ReadRow& row : rows) {
        CAPTURE(row.label);
        emu::IntelEmulator e = fixture(row.is_64bit, row.regs);
        CHECK(e.get_oper_value(row.ins, 0) == row.expected);
    }
}

TEST_CASE("emu operands: get_oper_addr resolves each addressing form, masked to 32 bits only on i386") {
    const std::vector<ReadRow> rows{
        {"[reg + disp]", k32, {{emu::kRegEax, 0x2000U}},
         make_insn(mem(ZYDIS_REGISTER_EAX, 0x10, 4)), 0x2010ULL},
        {"[reg - disp] handles a negative displacement", k32, {{emu::kRegEbp, 0x3000U}},
         make_insn(mem(ZYDIS_REGISTER_EBP, -0x8, 4)), 0x2FF8ULL},
        {"a SIB [base + index*scale + disp]", k32, {{emu::kRegEax, 0x1000U}, {emu::kRegEcx, 0x4U}},
         make_insn(sib(ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_ECX, 4, 0x10, 4)), 0x1020ULL},
        {"an absolute [imm]", k32, {}, make_insn(imm_mem(0x00401000U, 4)), 0x00401000ULL},
        {"the computed address masks to 32 bits", k32, {{emu::kRegEax, 0xFFFFFFF0U}},
         make_insn(mem(ZYDIS_REGISTER_EAX, 0x20, 4)), 0x10ULL},
        // va + length + disp = 0x140001000 + 7 + 0x200
        {"amd64 a RIP-relative address is not truncated to 32 bits", k64, {},
         make_insn(rip_rel(0x200, 8), /*va=*/0x140001000ULL, /*length=*/7), 0x140001207ULL},
        {"amd64 an absolute [imm] address keeps its high bits", k64, {},
         make_insn(imm_mem(0x0000000140005000ULL, 8)), 0x140005000ULL},
        {"amd64 a base register in [rax + disp] resolves 64-bit", k64,
         {{emu::kRegRax, 0x140002000ULL}}, make_insn(mem(ZYDIS_REGISTER_RAX, 0x10, 8)),
         0x140002010ULL},
    };
    for (const ReadRow& row : rows) {
        CAPTURE(row.label);
        emu::IntelEmulator e = fixture(row.is_64bit, row.regs);
        CHECK(e.get_oper_addr(row.ins, 0) == row.expected);
    }
}

TEST_CASE("emu operands: set_oper_value writes registers, lanes and memory") {
    struct Row {
        std::string_view   label;
        bool               is_64bit;
        std::vector<Reg>   regs;
        pn::DecodedOperand op;
        std::uint64_t      value;
        Where              where;
        std::uint64_t      expected;
    };
    const std::vector<Row> rows{
        {"a register", k32, {}, reg(ZYDIS_REGISTER_EDX, 4), 0xCAFEBABEULL,
         in_reg(emu::kRegEdx), 0xCAFEBABEULL},
        {"a sub-register splices the lane", k32, {{emu::kRegEbx, 0x11223344U}},
         reg(ZYDIS_REGISTER_BL, 1), 0xFFULL, in_reg(emu::kRegEbx), 0x112233FFULL},
        {"memory at [reg + disp]", k32, {{emu::kRegEsp, emu::kStackBase}},
         mem(ZYDIS_REGISTER_ESP, 0x20, 4), 0x12345678ULL, in_mem(emu::kStackBase + 0x20, 4),
         0x12345678ULL},
        {"amd64 writing the eax operand zero-extends rax", k64,
         {{emu::kRegRax, 0x1122334455667788ULL}}, reg(ZYDIS_REGISTER_EAX, 4), 0xDEADBEEFULL,
         in_reg(emu::kRegRax), 0x00000000DEADBEEFULL},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::IntelEmulator e = fixture(row.is_64bit, row.regs);
        e.set_oper_value(make_insn(row.op), 0, row.value);
        if (row.where.memory) {
            CHECK(e.memory().read_value(row.where.at, row.where.width) == row.expected);
        } else {
            CHECK(e.regs().get_register(static_cast<std::uint32_t>(row.where.at)) == row.expected);
        }
    }
}

TEST_CASE("emu operands amd64: the program counter holds a full 64-bit RIP") {
    emu::IntelEmulator e(/*is_64bit=*/true);
    e.set_program_counter(0x0000000140001234ULL);
    CHECK(e.program_counter() == 0x0000000140001234ULL);
}
