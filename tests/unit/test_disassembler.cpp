// MSVC: <ostream> must precede doctest so std::string pretty-printing compiles
#include <ostream>

#include "doctest.h"

#include "papa/constants.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>
#include "test_support.h"

using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::Disassembler;
using papa::features::extractors::papa_native::OperandKind;

namespace {

constexpr bool k32 = false;
constexpr bool k64 = true;

}  // namespace

TEST_CASE("decode rejects an empty, invalid or truncated encoding as a disassembly failure") {
    struct Row {
        std::string_view       label;
        std::vector<std::byte> bytes;
    };
    const std::vector<Row> rows{
        {"an empty buffer", {}},
        // 0x06 is invalid in long mode (legacy PUSH ES)
        {"a garbage byte stream", papa_tests::byte_vec({0x06})},
        // E8 needs 4 more bytes and only 3 follow, so the decoder must not over-read
        {"a call cut short at the buffer end", papa_tests::byte_vec({0xE8, 0x00, 0x00, 0x00})},
    };
    const Disassembler d(true);
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = d.decode(row.bytes, 0x1000);
        CHECK_FALSE(r.has_value());
        if (!r.has_value()) { CHECK(r.error().kind == papa::ErrorKind::kDisassemblyFailed); }
    }
}

TEST_CASE("decode classifies each operand form the way vivisect's operand classes split them") {
    // Only the fields an operand spec names are checked
    struct OperandSpec {
        std::optional<OperandKind>   kind;
        std::optional<ZydisRegister> base;
        std::optional<ZydisRegister> index;
        std::optional<std::uint8_t>  scale;
        std::optional<std::int64_t>  disp;
        std::optional<std::uint64_t> imm;
        std::optional<bool>          sib;
    };
    struct Row {
        std::string_view                label;
        bool                            x64;
        std::vector<std::byte>          bytes;
        std::optional<std::size_t>      count;
        std::vector<OperandSpec>        operands;
        std::optional<std::string_view> mnemonic;
        std::optional<bool>             fs;
        std::optional<bool>             gs;
    };
    using papa_tests::byte_vec;
    const std::vector<Row> rows{
        // r12 as a base forces a SIB byte, which vivisect splits into i386SibOper. The
        // operand stays base+disp memory, not an absolute immediate-memory operand
        {"lea rcx, [r12 + 0xB8] is flagged SIB-encoded", k64,
         byte_vec({0x49, 0x8D, 0x8C, 0x24, 0xB8, 0x00, 0x00, 0x00}), 2,
         {{}, {.kind = OperandKind::kRegMem, .sib = true}}, {}, {}, {}},
        // rbx needs no SIB byte
        {"lea rcx, [rbx + 0x10] is not flagged SIB-encoded", k64,
         byte_vec({0x48, 0x8D, 0x4B, 0x10}), 2, {{}, {.sib = false}}, {}, {}, {}},
        {"kReg on mov eax, ebx", k64, byte_vec({0x89, 0xD8}), 2,
         {{.kind = OperandKind::kReg}, {.kind = OperandKind::kReg}}, "mov", {}, {}},
        {"kImm on mov eax, 0x1234", k64, byte_vec({0xB8, 0x34, 0x12, 0x00, 0x00}), 2,
         {{.kind = OperandKind::kReg}, {.kind = OperandKind::kImm, .imm = 0x1234U}}, {}, {}, {}},
        {"kPcRel on a near call", k64, byte_vec({0xE8, 0x00, 0x00, 0x00, 0x00}), 1,
         {{.kind = OperandKind::kPcRel}}, {}, {}, {}},
        {"kRipRel on an x64 RIP-relative load", k64,
         byte_vec({0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00}), 2,
         {{.kind = OperandKind::kReg}, {.kind = OperandKind::kRipRel, .disp = 0}}, {}, {}, {}},
        {"kImmMem on a 32-bit absolute memory access", k32,
         byte_vec({0xA1, 0x78, 0x56, 0x34, 0x12}), 2,
         {{.kind = OperandKind::kReg},
          {.kind = OperandKind::kImmMem, .disp = static_cast<std::int64_t>(0x12345678)}},
         {}, {}, {}},
        {"kRegMem on [rbx+8]", k64, byte_vec({0x8B, 0x43, 0x08}), 2,
         {{}, {.kind = OperandKind::kRegMem, .base = ZYDIS_REGISTER_RBX,
               .index = ZYDIS_REGISTER_NONE, .disp = 8}},
         {}, {}, {}},
        {"kSib on [rbx+rcx*4+0x10]", k64, byte_vec({0x8B, 0x44, 0x8B, 0x10}), 2,
         {{}, {.kind = OperandKind::kSib, .base = ZYDIS_REGISTER_RBX,
               .index = ZYDIS_REGISTER_RCX, .scale = std::uint8_t{4}, .disp = 0x10}},
         {}, {}, {}},
        // On x64 a non-RIP absolute address must be SIB-encoded (mod=00, rm=100, base=101)
        {"kSib on an x64 SIB-encoded absolute address", k64,
         byte_vec({0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00}), 2,
         {{}, {.kind = OperandKind::kSib, .base = ZYDIS_REGISTER_NONE,
               .index = ZYDIS_REGISTER_NONE, .disp = 0x30}},
         {}, {}, {}},
        // mov rax, gs:[0x30], the TEB self-pointer read
        {"kSib on a gs segment-relative SIB access", k64,
         byte_vec({0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00}), 2,
         {{}, {.kind = OperandKind::kSib, .disp = 0x30}}, {}, {}, true},
        {"the fs segment prefix on mov rax, fs:[0x30]", k64,
         byte_vec({0x64, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00}), {}, {}, {}, true,
         false},
        {"the gs segment prefix on the x64 PEB read mov rax, gs:[0x60]", k64,
         byte_vec({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}), {}, {}, {}, false,
         true},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const Disassembler d(row.x64);
        const auto r = d.decode(row.bytes, 0x1000);
        REQUIRE(r.has_value());
        if (row.count.has_value()) { CHECK(r->operand_count == *row.count); }
        if (row.mnemonic.has_value()) { CHECK(r->mnemonic_str == *row.mnemonic); }
        if (row.fs.has_value()) { CHECK(r->has_prefix_fs == *row.fs); }
        if (row.gs.has_value()) { CHECK(r->has_prefix_gs == *row.gs); }
        for (std::size_t i = 0; i < row.operands.size(); ++i) {
            CAPTURE(i);
            const auto& got  = r->operands[i];
            const auto& want = row.operands[i];
            if (want.kind.has_value()) { CHECK(got.kind == *want.kind); }
            if (want.base.has_value()) { CHECK(got.base_reg == *want.base); }
            if (want.index.has_value()) { CHECK(got.index_reg == *want.index); }
            if (want.scale.has_value()) { CHECK(got.scale == *want.scale); }
            if (want.disp.has_value()) { CHECK(got.disp == *want.disp); }
            if (want.imm.has_value()) { CHECK(got.imm == *want.imm); }
            if (want.sib.has_value()) { CHECK(got.sib_encoded == *want.sib); }
        }
    }
}

TEST_CASE("decode flags how each instruction leaves its block, as envi's iflags do") {
    // vivisect's envi iflag_lookup marks several non-branch classes IF_NOFALL, so papa
    // must stop a block on them or recovery walks an int3 pad into the next function
    struct Flow {
        bool call = false;
        bool jump = false;
        bool cond = false;
        bool ret  = false;
        bool fall = false;
    };
    struct Row {
        std::string_view             label;
        bool                         x64;
        std::vector<std::byte>       bytes;
        Flow                         flow;
        std::optional<std::uint64_t> target;
    };
    using papa_tests::byte_vec;
    const std::vector<Row> rows{
        {"mov eax, ebx falls through", k64, byte_vec({0x89, 0xD8}), {.fall = true}, {}},
        // call +0 targets the next instruction, and a call falls through for the CFG
        {"a near call", k64, byte_vec({0xE8, 0x00, 0x00, 0x00, 0x00}),
         {.call = true, .fall = true}, 0x1005U},
        {"ret returns and does not fall through", k64, byte_vec({0xC3}), {.ret = true}, {}},
        {"jz +2 is a conditional jump", k64, byte_vec({0x74, 0x02}),
         {.jump = true, .cond = true, .fall = true}, 0x1004U},
        {"jmp +5 does not fall through", k64, byte_vec({0xEB, 0x05}), {.jump = true}, 0x1007U},
        {"int3 does not fall through", k64, byte_vec({0xCC}), {}, {}},
        {"hlt does not fall through", k64, byte_vec({0xF4}), {}, {}},
        {"ud2 does not fall through", k64, byte_vec({0x0F, 0x0B}), {}, {}},
        // into is only valid in 32-bit mode
        {"into does not fall through", k32, byte_vec({0xCE}), {}, {}},
        {"iret returns and does not fall through", k32, byte_vec({0xCF}), {.ret = true}, {}},
        // int 0x29 is RtlFailFast, which does not return
        {"int 0x29 fastfail does not fall through", k64, byte_vec({0xCD, 0x29}), {}, {}},
        // vivisect treats the Windows syscall interrupt as a returning call
        {"int 0x2e (the syscall gate) falls through", k64, byte_vec({0xCD, 0x2E}),
         {.fall = true}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const Disassembler d(row.x64);
        const auto r = d.decode(row.bytes, 0x1000);
        REQUIRE(r.has_value());
        CHECK(r->is_call == row.flow.call);
        CHECK(r->is_jump == row.flow.jump);
        CHECK(r->is_conditional == row.flow.cond);
        CHECK(r->is_return == row.flow.ret);
        CHECK(r->is_fallthrough == row.flow.fall);
        CHECK(r->branch_target == row.target);
    }
}

TEST_CASE("decode sweeps known encodings exactly and arbitrary bytes safely on both bitnesses") {
    struct Stream {
        bool                                   x64;
        std::vector<std::vector<std::uint8_t>> insns;
    };
    const std::array<Stream, 2> streams{{
        {true,
         {
             {0x48, 0x83, 0xEC, 0x28},                                // sub rsp, 0x28
             {0x33, 0xC0},                                            // xor eax, eax
             {0xFF, 0x15, 0x10, 0x00, 0x00, 0x00},                    // call [rip+0x10]
             {0x48, 0x8D, 0x4B, 0x10},                                // lea rcx, [rbx+0x10]
             {0x49, 0x8D, 0x8C, 0x24, 0xB8, 0x00, 0x00, 0x00},        // lea rcx, [r12+0xB8]
             {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00},  // mov rax, gs:[0x60]
             {0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8},                    // movabs rax, imm64
             {0xF3, 0x0F, 0x1E, 0xFA},                                // endbr64
             {0xE8, 0x00, 0x00, 0x00, 0x00},                          // call $+5
             {0x66, 0x0F, 0xEF, 0xC0},                                // pxor xmm0, xmm0
             {0xC3},                                                  // ret
         }},
        {false,
         {
             {0x55},                                       // push ebp
             {0x8B, 0xEC},                                 // mov ebp, esp
             {0x64, 0xA1, 0x30, 0x00, 0x00, 0x00},         // mov eax, fs:[0x30]
             {0xFF, 0x15, 0x00, 0x20, 0x40, 0x00},         // call [0x402000]
             {0x8D, 0x04, 0x85, 0x00, 0x10, 0x40, 0x00},   // lea eax, [eax*4+0x401000]
             {0x6A, 0x10},                                 // push 0x10
             {0x0F, 0x84, 0x00, 0x00, 0x00, 0x00},         // jz $+6
             {0xC2, 0x08, 0x00},                           // ret 8
         }},
    }};
    for (const Stream& s : streams) {
        CAPTURE(s.x64);
        const Disassembler dis(s.x64);

        // Back to back, the encodings decode one by one at their own lengths
        std::vector<std::byte> code;
        for (const auto& encoding : s.insns) {
            for (const std::uint8_t b : encoding) { code.push_back(std::byte{b}); }
        }
        std::span<const std::byte> cursor = code;
        std::uint64_t              va     = 0x1000;
        for (const auto& encoding : s.insns) {
            const auto ins = dis.decode(cursor, va);
            REQUIRE(ins.has_value());
            CHECK(ins->va == va);
            CHECK(ins->length == encoding.size());
            cursor = cursor.subspan(ins->length);
            va += ins->length;
        }
        CHECK(cursor.empty());

        // Over 4 KiB of LCG bytes every decode stays within the bytes left and the x86
        // length limit, and every rejection is a disassembly failure
        std::vector<std::byte> noise(0x1000);
        std::uint64_t          x = 0x9E3779B97F4A7C15ULL;
        for (std::byte& b : noise) {
            x = x * 6364136223846793005ULL + 1442695040888963407ULL;
            b = std::byte{static_cast<std::uint8_t>(x >> 56U)};
        }
        std::size_t decoded = 0;
        std::size_t rejected = 0;
        std::size_t bad_length = 0;
        std::size_t bad_error  = 0;
        for (std::span<const std::byte> rest = noise; !rest.empty();) {
            const auto  ins  = dis.decode(rest, 0x1000 + (noise.size() - rest.size()));
            std::size_t step = 1;
            if (ins.has_value()) {
                ++decoded;
                if (ins->length < 1U ||
                    ins->length > std::min(rest.size(), papa::constants::kMaxInsnBytes)) {
                    ++bad_length;
                } else {
                    step = ins->length;
                }
            } else {
                ++rejected;
                bad_error += ins.error().kind == papa::ErrorKind::kDisassemblyFailed ? 0U : 1U;
            }
            rest = rest.subspan(step);
        }
        CHECK(bad_length == 0U);
        CHECK(bad_error == 0U);
        // The stream reaches both outcomes, or the checks above would prove nothing
        CHECK(decoded != 0U);
        CHECK(rejected != 0U);
    }
}
