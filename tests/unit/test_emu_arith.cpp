#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include "test_support.h"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// Data, arithmetic, logic and shift handlers ported from envi/archs/i386/emu.py. Flags
// are checked against vivisect's exact formulas, including its quirks

using papa_tests::imm;
using papa_tests::insn;
using papa_tests::mem;
using papa_tests::reg;

using emu::kEflagsCf;
using emu::kEflagsOf;
using emu::kEflagsPf;
using emu::kEflagsSf;
using emu::kEflagsZf;
using emu::kRegEax;
using emu::kRegEcx;
using emu::kRegEdx;
using emu::kRegRax;
using emu::kRegRcx;
using emu::kRegRdx;

namespace {

constexpr bool k32 = false;
constexpr bool k64 = true;

// A register and the value it holds
struct Reg {
    std::uint32_t id;
    std::uint64_t value;
};

// An EFLAGS bit and whether it is set
struct Flag {
    std::uint32_t mask;
    bool          set;
};

// The instruction ins placed at va with the given length
pn::DecodedInsn at(pn::DecodedInsn ins, std::uint64_t va, std::size_t length) {
    ins.va     = va;
    ins.length = length;
    return ins;
}

// An XMM value whose first n bytes are b and the rest zero
emu::Xmm xmm_fill(std::uint8_t b, std::size_t n = 16) {
    emu::Xmm v{};
    for (std::size_t i = 0; i < n; ++i) { v[i] = b; }
    return v;
}

}  // namespace

TEST_CASE("emu arith: each data, arithmetic, logic and shift handler leaves vivisect's registers and flags") {
    struct Row {
        std::string_view  label;
        bool              is_64bit;
        pn::DecodedInsn   ins;
        std::vector<Reg>  regs_in;
        std::vector<Flag> flags_in;
        std::vector<Reg>  regs_out;
        std::vector<Flag> flags_out;
    };
    const std::vector<Row> rows{
        {"mov reg, reg copies the value", k32,
         insn(ZYDIS_MNEMONIC_MOV, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEcx, 0xABCD1234U}}, {}, {{kRegEax, 0xABCD1234U}}, {}},
        {"mov reg, imm loads the immediate", k32,
         insn(ZYDIS_MNEMONIC_MOV, reg(ZYDIS_REGISTER_EAX, 4), imm(0x42U, 4)),
         {}, {}, {{kRegEax, 0x42U}}, {}},
        {"movzx zero-extends a byte source", k32,
         insn(ZYDIS_MNEMONIC_MOVZX, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_CL, 1)),
         {{kRegEcx, 0x000001FFU}}, {}, {{kRegEax, 0xFFU}}, {}},
        {"movsx sign-extends a byte source", k32,
         insn(ZYDIS_MNEMONIC_MOVSX, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_CL, 1)),
         {{kRegEcx, 0x00000080U}}, {}, {{kRegEax, 0xFFFFFF80U}}, {}},
        {"lea loads the effective address, not memory", k32,
         insn(ZYDIS_MNEMONIC_LEA, reg(ZYDIS_REGISTER_EDX, 4), mem(ZYDIS_REGISTER_EAX, 0x8, 4)),
         {{kRegEax, 0x1000U}}, {}, {{kRegEdx, 0x1008U}}, {}},

        {"cdq sign-extends a negative eax into edx", k32,
         insn(ZYDIS_MNEMONIC_CDQ, reg(ZYDIS_REGISTER_EDX, 4)),
         {{kRegEax, 0x80000000U}}, {}, {{kRegEdx, 0xFFFFFFFFU}}, {}},
        {"cdq clears edx for a non-negative eax", k32,
         insn(ZYDIS_MNEMONIC_CDQ, reg(ZYDIS_REGISTER_EDX, 4)),
         {{kRegEax, 0x00000001U}, {kRegEdx, 0xDEADBEEFU}}, {}, {{kRegEdx, 0U}}, {}},
        {"amd64 cdqe sign-extends eax into rax", k64, insn(ZYDIS_MNEMONIC_CDQE),
         {{kRegRax, 0x80000000ULL}}, {}, {{kRegRax, 0xFFFFFFFF80000000ULL}}, {}},
        {"amd64 cqo sign-extends rax into rdx", k64, insn(ZYDIS_MNEMONIC_CQO),
         {{kRegRax, 0x8000000000000000ULL}}, {}, {{kRegRdx, 0xFFFFFFFFFFFFFFFFULL}}, {}},
        {"cwd sign-extends a negative ax into dx", k32, insn(ZYDIS_MNEMONIC_CWD),
         {{kRegEax, 0x00008000U}, {kRegEdx, 0x12340000U}}, {}, {{kRegEdx, 0x1234FFFFU}}, {}},
        {"cwd clears dx for a non-negative ax", k32, insn(ZYDIS_MNEMONIC_CWD),
         {{kRegEax, 0xFFFF7FFFU}, {kRegEdx, 0x1234FFFFU}}, {}, {{kRegEdx, 0x12340000U}}, {}},
        {"cbw sign-extends al into ax", k32, insn(ZYDIS_MNEMONIC_CBW),
         {{kRegEax, 0x12345680U}}, {}, {{kRegEax, 0x1234FF80U}}, {}},
        {"cwde sign-extends ax into eax", k32, insn(ZYDIS_MNEMONIC_CWDE),
         {{kRegEax, 0x12348000U}}, {}, {{kRegEax, 0xFFFF8000U}}, {}},
        {"amd64 cwde zero-extends its eax result into rax", k64, insn(ZYDIS_MNEMONIC_CWDE),
         {{kRegRax, 0xAAAAAAAA00008000ULL}}, {}, {{kRegRax, 0x00000000FFFF8000ULL}}, {}},

        {"add sets the result and the arithmetic flags", k32,
         insn(ZYDIS_MNEMONIC_ADD, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 5U}, {kRegEcx, 3U}}, {}, {{kRegEax, 8U}},
         {{kEflagsCf, false}, {kEflagsZf, false}, {kEflagsSf, false}, {kEflagsOf, false}}},
        // vivisect derives ZF from the unmasked sum, so 0xffffffff+1 leaves ZF=0 even
        // though the stored result is 0. Reproduced for bit-identical paths
        {"add that carries out wraps and keeps ZF clear (vivisect quirk)", k32,
         insn(ZYDIS_MNEMONIC_ADD, reg(ZYDIS_REGISTER_EAX, 4), imm(1U, 4)),
         {{kRegEax, 0xFFFFFFFFU}}, {}, {{kRegEax, 0U}}, {{kEflagsCf, true}, {kEflagsZf, false}}},
        {"sub computes the difference and flags", k32,
         insn(ZYDIS_MNEMONIC_SUB, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 10U}, {kRegEcx, 3U}}, {}, {{kRegEax, 7U}},
         {{kEflagsCf, false}, {kEflagsZf, false}}},
        {"sub of equal operands sets ZF", k32,
         insn(ZYDIS_MNEMONIC_SUB, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 5U}, {kRegEcx, 5U}}, {}, {{kRegEax, 0U}},
         {{kEflagsZf, true}, {kEflagsCf, false}}},
        {"sub that borrows sets CF and SF", k32,
         insn(ZYDIS_MNEMONIC_SUB, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 0U}, {kRegEcx, 1U}}, {}, {{kRegEax, 0xFFFFFFFFU}},
         {{kEflagsCf, true}, {kEflagsSf, true}}},
        {"cmp sets flags without storing", k32,
         insn(ZYDIS_MNEMONIC_CMP, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 5U}, {kRegEcx, 5U}}, {}, {{kRegEax, 5U}}, {{kEflagsZf, true}}},
        {"inc sets overflow at the signed boundary and leaves CF", k32,
         insn(ZYDIS_MNEMONIC_INC, reg(ZYDIS_REGISTER_EAX, 4)),
         {{kRegEax, 0x7FFFFFFFU}}, {{kEflagsCf, true}}, {{kRegEax, 0x80000000U}},
         {{kEflagsOf, true}, {kEflagsSf, true}, {kEflagsZf, false}, {kEflagsCf, true}}},
        {"dec to zero sets ZF", k32, insn(ZYDIS_MNEMONIC_DEC, reg(ZYDIS_REGISTER_EAX, 4)),
         {{kRegEax, 1U}}, {}, {{kRegEax, 0U}}, {{kEflagsZf, true}}},
        {"neg negates and sets CF when nonzero", k32,
         insn(ZYDIS_MNEMONIC_NEG, reg(ZYDIS_REGISTER_EAX, 4)),
         {{kRegEax, 1U}}, {}, {{kRegEax, 0xFFFFFFFFU}}, {{kEflagsCf, true}, {kEflagsSf, true}}},
        {"neg of zero clears CF and sets ZF", k32,
         insn(ZYDIS_MNEMONIC_NEG, reg(ZYDIS_REGISTER_EAX, 4)),
         {{kRegEax, 0U}}, {{kEflagsCf, true}}, {{kRegEax, 0U}},
         {{kEflagsCf, false}, {kEflagsZf, true}}},

        {"and masks and clears CF and OF", k32,
         insn(ZYDIS_MNEMONIC_AND, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 0xFFU}, {kRegEcx, 0x0FU}}, {{kEflagsCf, true}, {kEflagsOf, true}},
         {{kRegEax, 0x0FU}}, {{kEflagsCf, false}, {kEflagsOf, false}, {kEflagsPf, true}}},
        {"or combines bits", k32,
         insn(ZYDIS_MNEMONIC_OR, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 0xF0U}, {kRegEcx, 0x0FU}}, {}, {{kRegEax, 0xFFU}}, {{kEflagsZf, false}}},
        {"xor of a register with itself zeroes it and sets ZF", k32,
         insn(ZYDIS_MNEMONIC_XOR, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_EAX, 4)),
         {{kRegEax, 0x1234U}}, {}, {{kRegEax, 0U}},
         {{kEflagsZf, true}, {kEflagsCf, false}, {kEflagsOf, false}}},
        {"not flips all bits without touching flags", k32,
         insn(ZYDIS_MNEMONIC_NOT, reg(ZYDIS_REGISTER_EAX, 4)),
         {{kRegEax, 0U}}, {{kEflagsZf, true}}, {{kRegEax, 0xFFFFFFFFU}}, {{kEflagsZf, true}}},
        {"test sets ZF when the and is zero, without storing", k32,
         insn(ZYDIS_MNEMONIC_TEST, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 0U}, {kRegEcx, 0xFFU}}, {}, {{kRegEax, 0U}}, {{kEflagsZf, true}}},
        {"adc adds the carry flag in", k32,
         insn(ZYDIS_MNEMONIC_ADC, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 1U}, {kRegEcx, 1U}}, {{kEflagsCf, true}}, {{kRegEax, 3U}}, {}},
        {"sbb subtracts the carry flag in", k32,
         insn(ZYDIS_MNEMONIC_SBB, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 5U}, {kRegEcx, 1U}}, {{kEflagsCf, true}}, {{kRegEax, 3U}}, {}},

        {"mul produces the product in edx:eax", k32,
         insn(ZYDIS_MNEMONIC_MUL, reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 4U}, {kRegEcx, 3U}}, {}, {{kRegEax, 12U}, {kRegEdx, 0U}}, {}},
        {"mul sets CF and OF when the high half is nonzero", k32,
         insn(ZYDIS_MNEMONIC_MUL, reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 0x10000U}, {kRegEcx, 0x10000U}}, {}, {{kRegEax, 0U}, {kRegEdx, 1U}},
         {{kEflagsCf, true}, {kEflagsOf, true}}},
        {"imul two-operand multiplies into the destination", k32,
         insn(ZYDIS_MNEMONIC_IMUL, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 4U}, {kRegEcx, 3U}}, {}, {{kRegEax, 12U}}, {}},
        {"imul three-operand sign-extends the immediate and flags a product past the width", k32,
         insn(ZYDIS_MNEMONIC_IMUL, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4),
              imm(0xFEU, 1)),
         {{kRegEcx, 3U}}, {}, {{kRegEax, 0xFFFFFFFAU}, {kRegEcx, 3U}},
         {{kEflagsCf, true}, {kEflagsOf, true}}},
        // vivisect tests the signed product with is_unsigned_carry, so any negative one carries
        {"imul one-operand writes edx:eax and flags a negative product (vivisect quirk)", k32,
         insn(ZYDIS_MNEMONIC_IMUL, reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 0xFFFFFFFEU}, {kRegEcx, 3U}}, {},
         {{kRegEax, 0xFFFFFFFAU}, {kRegEdx, 0xFFFFFFFFU}},
         {{kEflagsCf, true}, {kEflagsOf, true}, {kEflagsPf, true}, {kEflagsSf, false}}},
        {"imul one-operand clears CF and OF for a product that fits", k32,
         insn(ZYDIS_MNEMONIC_IMUL, reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 3U}, {kRegEcx, 4U}, {kRegEdx, 0xDEADBEEFU}}, {{kEflagsCf, true}},
         {{kRegEax, 12U}, {kRegEdx, 0U}}, {{kEflagsCf, false}, {kEflagsOf, false}}},
        {"imul of a byte writes the whole product into ax", k32,
         insn(ZYDIS_MNEMONIC_IMUL, reg(ZYDIS_REGISTER_CL, 1)),
         {{kRegEax, 0x123400FEU}, {kRegEcx, 3U}}, {}, {{kRegEax, 0x1234FFFAU}},
         {{kEflagsCf, true}}},
        {"amd64 imul r64 writes the signed rdx:rax product", k64,
         insn(ZYDIS_MNEMONIC_IMUL, reg(ZYDIS_REGISTER_RCX, 8)),
         {{kRegRax, static_cast<std::uint64_t>(-3)}, {kRegRcx, 5U}}, {{kEflagsCf, true}},
         {{kRegRax, static_cast<std::uint64_t>(-15)}, {kRegRdx, 0xFFFFFFFFFFFFFFFFULL}},
         {{kEflagsCf, false}, {kEflagsOf, false}}},
        {"amd64 imul r64 flags a product past 64 bits", k64,
         insn(ZYDIS_MNEMONIC_IMUL, reg(ZYDIS_REGISTER_RCX, 8)),
         {{kRegRax, 0x4000000000000000ULL}, {kRegRcx, 4U}}, {}, {{kRegRax, 0U}, {kRegRdx, 1U}},
         {{kEflagsCf, true}, {kEflagsOf, true}}},
        {"div computes quotient in eax and remainder in edx", k32,
         insn(ZYDIS_MNEMONIC_DIV, reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEdx, 0U}, {kRegEax, 13U}, {kRegEcx, 3U}}, {}, {{kRegEax, 4U}, {kRegEdx, 1U}}, {}},
        {"idiv handles signed division", k32,
         insn(ZYDIS_MNEMONIC_IDIV, reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEdx, 0xFFFFFFFFU}, {kRegEax, static_cast<std::uint32_t>(-13)}, {kRegEcx, 3U}}, {},
         {{kRegEax, static_cast<std::uint32_t>(-4)}}, {}},
        {"div of a byte writes (quotient << 8) + remainder over all of eax (vivisect quirk)", k32,
         insn(ZYDIS_MNEMONIC_DIV, reg(ZYDIS_REGISTER_CL, 1)),
         {{kRegEax, 0xAAAA000DU}, {kRegEcx, 3U}}, {}, {{kRegEax, 0x401U}}, {}},
        {"div of a word divides dx:ax and keeps the upper halves", k32,
         insn(ZYDIS_MNEMONIC_DIV, reg(ZYDIS_REGISTER_CX, 2)),
         {{kRegEdx, 0xBBBB0001U}, {kRegEax, 0xAAAA0000U}, {kRegEcx, 3U}}, {},
         {{kRegEax, 0xAAAA5555U}, {kRegEdx, 0xBBBB0001U}}, {}},
        {"idiv of a byte packs the remainder into ah and the quotient into al", k32,
         insn(ZYDIS_MNEMONIC_IDIV, reg(ZYDIS_REGISTER_CL, 1)),
         {{kRegEax, 0x1234FFF9U}, {kRegEcx, 2U}}, {}, {{kRegEax, 0x1234FFFDU}}, {}},
        {"idiv of a word divides the signed dx:ax", k32,
         insn(ZYDIS_MNEMONIC_IDIV, reg(ZYDIS_REGISTER_CX, 2)),
         {{kRegEdx, 0x0000FFFFU}, {kRegEax, 0x0000FF9CU}, {kRegEcx, 7U}}, {},
         {{kRegEax, 0x0000FFF2U}, {kRegEdx, 0x0000FFFEU}}, {}},
        {"amd64 mul r64 produces the rdx:rax product", k64,
         insn(ZYDIS_MNEMONIC_MUL, reg(ZYDIS_REGISTER_RCX, 8)),
         {{kRegRax, 0x100000000ULL}, {kRegRcx, 0x100000000ULL}}, {},
         {{kRegRdx, 1U}, {kRegRax, 0U}}, {}},
        {"amd64 div r64 divides rdx:rax by the operand", k64,
         insn(ZYDIS_MNEMONIC_DIV, reg(ZYDIS_REGISTER_RCX, 8)),
         {{kRegRdx, 1U}, {kRegRax, 0U}, {kRegRcx, 2U}}, {},
         {{kRegRax, 0x8000000000000000ULL}, {kRegRdx, 0U}}, {}},
        // -100 sign-extended to 128 bits, divided by 7, is quotient -14 remainder -2
        {"amd64 idiv r64 handles a negative dividend", k64,
         insn(ZYDIS_MNEMONIC_IDIV, reg(ZYDIS_REGISTER_RCX, 8)),
         {{kRegRax, static_cast<std::uint64_t>(-100)}, {kRegRdx, 0xFFFFFFFFFFFFFFFFULL},
          {kRegRcx, 7U}},
         {},
         {{kRegRax, static_cast<std::uint64_t>(-14)}, {kRegRdx, static_cast<std::uint64_t>(-2)}},
         {}},

        {"setz writes 1 into AL when ZF is set", k32,
         insn(ZYDIS_MNEMONIC_SETZ, reg(ZYDIS_REGISTER_AL, 1)),
         {{kRegEax, 0xFFFFFF00U}}, {{kEflagsZf, true}}, {{kRegEax, 0xFFFFFF01U}}, {}},
        {"setz writes 0 into AL when ZF is clear", k32,
         insn(ZYDIS_MNEMONIC_SETZ, reg(ZYDIS_REGISTER_AL, 1)),
         {{kRegEax, 0xFFFFFF01U}}, {{kEflagsZf, false}}, {{kRegEax, 0xFFFFFF00U}}, {}},
        {"bt sets CF from a set addressed bit", k32,
         insn(ZYDIS_MNEMONIC_BT, reg(ZYDIS_REGISTER_EAX, 4), imm(3, 1)),
         {{kRegEax, 0x8U}}, {}, {}, {{kEflagsCf, true}}},
        {"bt clears CF from a clear addressed bit", k32,
         insn(ZYDIS_MNEMONIC_BT, reg(ZYDIS_REGISTER_EAX, 4), imm(2, 1)),
         {{kRegEax, 0x8U}}, {{kEflagsCf, true}}, {}, {{kEflagsCf, false}}},
        {"bts sets the addressed bit and reports the old value in CF", k32,
         insn(ZYDIS_MNEMONIC_BTS, reg(ZYDIS_REGISTER_EAX, 4), imm(5, 1)),
         {{kRegEax, 0U}}, {{kEflagsCf, true}}, {{kRegEax, 0x20U}}, {{kEflagsCf, false}}},
        {"btr clears the addressed bit and reports the old value in CF", k32,
         insn(ZYDIS_MNEMONIC_BTR, reg(ZYDIS_REGISTER_EAX, 4), imm(5, 1)),
         {{kRegEax, 0x28U}}, {}, {{kRegEax, 0x08U}}, {{kEflagsCf, true}}},
        {"btc flips a set addressed bit", k32,
         insn(ZYDIS_MNEMONIC_BTC, reg(ZYDIS_REGISTER_EAX, 4), imm(3, 1)),
         {{kRegEax, 0x08U}}, {}, {{kRegEax, 0U}}, {{kEflagsCf, true}}},
        {"btc takes the bit index modulo the operand width", k32,
         insn(ZYDIS_MNEMONIC_BTC, reg(ZYDIS_REGISTER_EAX, 4), imm(33, 1)),
         {{kRegEax, 0U}}, {{kEflagsCf, true}}, {{kRegEax, 0x2U}}, {{kEflagsCf, false}}},

        {"xchg swaps its operands", k32,
         insn(ZYDIS_MNEMONIC_XCHG, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 1U}, {kRegEcx, 2U}}, {}, {{kRegEax, 2U}, {kRegEcx, 1U}}, {}},
        {"xadd stores the sum and hands the old destination to the source", k32,
         insn(ZYDIS_MNEMONIC_XADD, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 5U}, {kRegEcx, 3U}}, {}, {{kRegEax, 8U}, {kRegEcx, 5U}},
         {{kEflagsZf, false}, {kEflagsCf, false}, {kEflagsSf, false}}},
        {"xadd that wraps to zero sets ZF and CF", k32,
         insn(ZYDIS_MNEMONIC_XADD, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 0xFFFFFFFFU}, {kRegEcx, 1U}}, {}, {{kRegEax, 0U}, {kRegEcx, 0xFFFFFFFFU}},
         {{kEflagsZf, true}, {kEflagsCf, true}, {kEflagsPf, true}}},
        {"cmpxchg stores the source when the accumulator equals the destination", k32,
         insn(ZYDIS_MNEMONIC_CMPXCHG, reg(ZYDIS_REGISTER_ECX, 4), reg(ZYDIS_REGISTER_EDX, 4)),
         {{kRegEax, 7U}, {kRegEcx, 7U}, {kRegEdx, 9U}}, {}, {{kRegEcx, 9U}, {kRegEax, 7U}},
         {{kEflagsZf, true}}},
        {"cmpxchg loads the destination into the accumulator when they differ", k32,
         insn(ZYDIS_MNEMONIC_CMPXCHG, reg(ZYDIS_REGISTER_ECX, 4), reg(ZYDIS_REGISTER_EDX, 4)),
         {{kRegEax, 7U}, {kRegEcx, 8U}, {kRegEdx, 9U}}, {{kEflagsZf, true}},
         {{kRegEcx, 8U}, {kRegEax, 8U}}, {{kEflagsZf, false}}},

        {"shl shifts left and sets the carry out", k32,
         insn(ZYDIS_MNEMONIC_SHL, reg(ZYDIS_REGISTER_EAX, 4), imm(4U, 1)),
         {{kRegEax, 0x10000001U}}, {}, {{kRegEax, 0x10U}}, {{kEflagsCf, true}}},
        {"shl by zero leaves flags unchanged", k32,
         insn(ZYDIS_MNEMONIC_SHL, reg(ZYDIS_REGISTER_EAX, 4), imm(0U, 1)),
         {{kRegEax, 0x1U}}, {{kEflagsCf, true}}, {{kRegEax, 0x1U}}, {{kEflagsCf, true}}},
        {"shl producing zero sets ZF", k32,
         insn(ZYDIS_MNEMONIC_SHL, reg(ZYDIS_REGISTER_EAX, 4), imm(1U, 1)),
         {{kRegEax, 0x80000000U}}, {}, {{kRegEax, 0U}}, {{kEflagsZf, true}}},
        {"shr shifts right", k32, insn(ZYDIS_MNEMONIC_SHR, reg(ZYDIS_REGISTER_EAX, 4), imm(4U, 1)),
         {{kRegEax, 0x10U}}, {}, {{kRegEax, 0x1U}}, {}},
        {"sar shifts right with sign fill", k32,
         insn(ZYDIS_MNEMONIC_SAR, reg(ZYDIS_REGISTER_EAX, 4), imm(4U, 1)),
         {{kRegEax, 0x80000000U}}, {}, {{kRegEax, 0xF8000000U}}, {}},
        {"amd64 shl rax masks the shift count to 0x3f", k64,
         insn(ZYDIS_MNEMONIC_SHL, reg(ZYDIS_REGISTER_RAX, 8), imm(40, 1)),
         {{kRegRax, 1U}}, {}, {{kRegRax, 1ULL << 40}}, {}},
        {"amd64 shr rax masks the shift count to 0x3f", k64,
         insn(ZYDIS_MNEMONIC_SHR, reg(ZYDIS_REGISTER_RAX, 8), imm(40, 1)),
         {{kRegRax, 0xFF00000000000000ULL}}, {}, {{kRegRax, 0x0000000000FF0000ULL}}, {}},
        {"rol rotates the top bit around into bit 0 and CF", k32,
         insn(ZYDIS_MNEMONIC_ROL, reg(ZYDIS_REGISTER_EAX, 4), imm(1U, 1)),
         {{kRegEax, 0x80000001U}}, {}, {{kRegEax, 0x00000003U}}, {{kEflagsCf, true}}},
        {"rol of a byte rotates within the byte", k32,
         insn(ZYDIS_MNEMONIC_ROL, reg(ZYDIS_REGISTER_AL, 1), imm(4U, 1)),
         {{kRegEax, 0xAABBCC81U}}, {{kEflagsCf, true}}, {{kRegEax, 0xAABBCC18U}},
         {{kEflagsCf, false}}},
        {"rol by zero leaves the value and flags unchanged", k32,
         insn(ZYDIS_MNEMONIC_ROL, reg(ZYDIS_REGISTER_EAX, 4), imm(0U, 1)),
         {{kRegEax, 0x2U}}, {{kEflagsCf, true}}, {{kRegEax, 0x2U}}, {{kEflagsCf, true}}},
        {"ror rotates bit 0 around into the top bit and CF", k32,
         insn(ZYDIS_MNEMONIC_ROR, reg(ZYDIS_REGISTER_EAX, 4), imm(1U, 1)),
         {{kRegEax, 0x00000003U}}, {}, {{kRegEax, 0x80000001U}}, {{kEflagsCf, true}}},
        {"amd64 ror rax keeps a count past 31", k64,
         insn(ZYDIS_MNEMONIC_ROR, reg(ZYDIS_REGISTER_RAX, 8), imm(36U, 1)),
         {{kRegRax, 0x000000F000000000ULL}}, {{kEflagsCf, true}}, {{kRegRax, 0xFULL}},
         {{kEflagsCf, false}}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::IntelEmulator e(row.is_64bit);
        for (const Reg& r : row.regs_in) { e.regs().set_register(r.id, r.value); }
        for (const Flag& f : row.flags_in) { e.regs().set_flag(f.mask, f.set); }
        e.execute_opcode(row.ins);
        for (const Reg& want : row.regs_out) {
            CAPTURE(want.id);
            CHECK(e.regs().get_register(want.id) == want.value);
        }
        for (const Flag& want : row.flags_out) {
            CAPTURE(want.mask);
            CHECK(e.regs().get_flag(want.mask) == want.set);
        }
    }
}

TEST_CASE("emu sse: each simd move, xor and byte shift writes its bytes, zero-extending a narrow move") {
    struct XmmValue {
        std::uint32_t id;
        emu::Xmm      value;
    };
    struct Row {
        std::string_view      label;
        std::vector<XmmValue> xmm_in;
        std::vector<Reg>      regs_in;
        pn::DecodedInsn       ins;
        std::vector<XmmValue> xmm_out;
        std::vector<Reg>      regs_out;
    };
    emu::Xmm counting{};
    for (std::size_t i = 0; i < counting.size(); ++i) {
        counting[i] = static_cast<std::uint8_t>(i + 1);
    }
    // counting moved n bytes down for a positive n or up for a negative one, zero filled
    const auto shifted = [&counting](int n) {
        emu::Xmm out{};
        for (int i = 0; i < 16; ++i) {
            const int from = i + n;
            if (from >= 0 && from < 16) {
                out[static_cast<std::size_t>(i)] = counting[static_cast<std::size_t>(from)];
            }
        }
        return out;
    };
    const std::vector<Row> rows{
        {"movups copies a full XMM register", {{1, counting}}, {},
         insn(ZYDIS_MNEMONIC_MOVUPS, reg(ZYDIS_REGISTER_XMM0, 16), reg(ZYDIS_REGISTER_XMM1, 16)),
         {{0, counting}}, {}},
        {"movq moves 8 bytes and zero-extends the XMM destination", {{2, xmm_fill(0xFF)}}, {},
         insn(ZYDIS_MNEMONIC_MOVQ, reg(ZYDIS_REGISTER_XMM0, 16), reg(ZYDIS_REGISTER_XMM2, 16)),
         {{0, xmm_fill(0xFF, 8)}}, {}},
        {"movss moves 4 bytes and zero-extends the XMM destination", {{2, xmm_fill(0xFF)}}, {},
         insn(ZYDIS_MNEMONIC_MOVSS, reg(ZYDIS_REGISTER_XMM0, 16), reg(ZYDIS_REGISTER_XMM2, 16)),
         {{0, xmm_fill(0xFF, 4)}}, {}},
        {"movsd with an XMM operand moves 8 bytes", {{3, xmm_fill(0xAB)}}, {},
         insn(ZYDIS_MNEMONIC_MOVSD, reg(ZYDIS_REGISTER_XMM0, 16), reg(ZYDIS_REGISTER_XMM3, 16)),
         {{0, xmm_fill(0xAB, 8)}}, {}},
        {"movd from a general register loads its 4 bytes", {}, {{kRegEax, 0x11223344U}},
         insn(ZYDIS_MNEMONIC_MOVD, reg(ZYDIS_REGISTER_XMM0, 16), reg(ZYDIS_REGISTER_EAX, 4)),
         {{0, emu::Xmm{0x44, 0x33, 0x22, 0x11}}}, {}},
        {"movd to a general register stores the low 4 bytes", {{1, counting}}, {},
         insn(ZYDIS_MNEMONIC_MOVD, reg(ZYDIS_REGISTER_EAX, 4), reg(ZYDIS_REGISTER_XMM1, 16)),
         {}, {{kRegEax, 0x04030201U}}},
        {"pxor of a register with itself clears it", {{3, xmm_fill(0xAB)}}, {},
         insn(ZYDIS_MNEMONIC_PXOR, reg(ZYDIS_REGISTER_XMM3, 16), reg(ZYDIS_REGISTER_XMM3, 16)),
         {{3, emu::Xmm{}}}, {}},
        {"psrldq shifts the bytes down", {{0, counting}}, {},
         insn(ZYDIS_MNEMONIC_PSRLDQ, reg(ZYDIS_REGISTER_XMM0, 16), imm(4U, 1)),
         {{0, shifted(4)}}, {}},
        {"pslldq shifts the bytes up", {{0, counting}}, {},
         insn(ZYDIS_MNEMONIC_PSLLDQ, reg(ZYDIS_REGISTER_XMM0, 16), imm(4U, 1)),
         {{0, shifted(-4)}}, {}},
        {"psrldq by 16 or more clears the register", {{0, counting}}, {},
         insn(ZYDIS_MNEMONIC_PSRLDQ, reg(ZYDIS_REGISTER_XMM0, 16), imm(20U, 1)),
         {{0, emu::Xmm{}}}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::IntelEmulator e;
        // A stale destination shows that the move replaced all 16 bytes
        for (const XmmValue& out : row.xmm_out) { e.regs().set_xmm(out.id, xmm_fill(0xEE)); }
        for (const XmmValue& in : row.xmm_in) { e.regs().set_xmm(in.id, in.value); }
        for (const Reg& r : row.regs_in) { e.regs().set_register(r.id, r.value); }
        CHECK(e.execute_opcode(row.ins) == emu::ExecResult::kContinue);
        for (const XmmValue& want : row.xmm_out) {
            CAPTURE(want.id);
            CHECK(e.regs().get_xmm(want.id) == want.value);
        }
        for (const Reg& want : row.regs_out) {
            CAPTURE(want.id);
            CHECK(e.regs().get_register(want.id) == want.value);
        }
    }
}

TEST_CASE("emu exec: execute_opcode reports its result and advances the pc only on success") {
    struct Row {
        std::string_view label;
        pn::DecodedInsn  ins;
        std::vector<Reg> regs_in;
        emu::ExecResult  result;
        std::uint64_t    pc;
    };
    const std::vector<Row> rows{
        {"a handled instruction advances the program counter by its length",
         at(insn(ZYDIS_MNEMONIC_MOV, reg(ZYDIS_REGISTER_EAX, 4), imm(0U, 4)), 0x401000, 5), {},
         emu::ExecResult::kContinue, 0x401005},
        {"div by zero reports a divide-by-zero result",
         insn(ZYDIS_MNEMONIC_DIV, reg(ZYDIS_REGISTER_ECX, 4)),
         {{kRegEax, 12U}, {kRegEcx, 0U}}, emu::ExecResult::kDivideByZero, 0x1000},
        {"an unmodeled mnemonic reports unsupported",
         insn(ZYDIS_MNEMONIC_RDRAND, reg(ZYDIS_REGISTER_EAX, 4)), {},
         emu::ExecResult::kUnsupported, 0x1000},
        {"movsd with no XMM operand is the string move, which is unmodeled",
         insn(ZYDIS_MNEMONIC_MOVSD, mem(ZYDIS_REGISTER_EDI, 0, 4), mem(ZYDIS_REGISTER_ESI, 0, 4)),
         {}, emu::ExecResult::kUnsupported, 0x1000},
        {"int3 reports a breakpoint", insn(ZYDIS_MNEMONIC_INT3), {},
         emu::ExecResult::kBreakpoint, 0x1000},
        {"int reports a breakpoint", insn(ZYDIS_MNEMONIC_INT, imm(0x2EU, 1)), {},
         emu::ExecResult::kBreakpoint, 0x1000},
        {"int1 reports a breakpoint", insn(ZYDIS_MNEMONIC_INT1), {},
         emu::ExecResult::kBreakpoint, 0x1000},
        {"ud0 reports a bad opcode", insn(ZYDIS_MNEMONIC_UD0), {}, emu::ExecResult::kBadOpcode,
         0x1000},
        {"ud1 reports a bad opcode", insn(ZYDIS_MNEMONIC_UD1), {}, emu::ExecResult::kBadOpcode,
         0x1000},
        {"ud2 reports a bad opcode", insn(ZYDIS_MNEMONIC_UD2), {}, emu::ExecResult::kBadOpcode,
         0x1000},
        {"in reports a port instruction",
         insn(ZYDIS_MNEMONIC_IN, reg(ZYDIS_REGISTER_AL, 1), reg(ZYDIS_REGISTER_DX, 2)), {},
         emu::ExecResult::kOutInstruction, 0x1000},
        {"out reports a port instruction",
         insn(ZYDIS_MNEMONIC_OUT, reg(ZYDIS_REGISTER_DX, 2), reg(ZYDIS_REGISTER_AL, 1)), {},
         emu::ExecResult::kOutInstruction, 0x1000},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::IntelEmulator e;
        for (const Reg& r : row.regs_in) { e.regs().set_register(r.id, r.value); }
        CHECK(e.execute_opcode(row.ins) == row.result);
        CHECK(e.program_counter() == row.pc);
    }
}

TEST_CASE("emu arith: push then pop round-trips through the stack") {
    emu::IntelEmulator e;
    e.memory().init_stack();
    const std::uint32_t sp0 = static_cast<std::uint32_t>(emu::kStackBase) + 0x100U;
    e.regs().set_register(emu::kRegEsp, sp0);
    e.execute_opcode(insn(ZYDIS_MNEMONIC_PUSH, imm(0x11223344U, 4)));
    CHECK(e.regs().get_register(emu::kRegEsp) == sp0 - 4U);
    CHECK(e.memory().read_value(sp0 - 4U, 4) == 0x11223344ULL);
    e.execute_opcode(insn(ZYDIS_MNEMONIC_POP, reg(ZYDIS_REGISTER_EDX, 4)));
    CHECK(e.regs().get_register(emu::kRegEdx) == 0x11223344ULL);
    CHECK(e.regs().get_register(emu::kRegEsp) == sp0);
}
