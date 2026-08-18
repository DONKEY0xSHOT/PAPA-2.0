// MSVC: <ostream> must precede doctest so std::string pretty-printing compiles
#include <ostream>

#include "doctest.h"

#include "papa/constants.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>
#include "fixture_paths.h"

using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::Disassembler;
using papa::features::extractors::papa_native::OperandKind;

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");

// Small helper to turn a list of byte-integers into std::array<std::byte, N>
template <typename... B>
constexpr auto make_bytes(B... bs) {
    return std::array<std::byte, sizeof...(B)>{ std::byte{static_cast<std::uint8_t>(bs)}... };
}

}  // namespace

TEST_CASE("decode rejects an empty buffer") {
    Disassembler d(true);
    const auto r = d.decode({}, 0x1000);
    CHECK_FALSE(r.has_value());
    CHECK(r.error().kind == papa::ErrorKind::kDisassemblyFailed);
}

TEST_CASE("decode rejects a garbage byte stream") {
    Disassembler d(true);
    // 0x06 is invalid in long mode (legacy PUSH ES)
    const auto bytes = make_bytes(0x06);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    CHECK_FALSE(r.has_value());
    CHECK(r.error().kind == papa::ErrorKind::kDisassemblyFailed);
}

TEST_CASE("decode flags a SIB-encoded base+disp memory operand") {
    Disassembler d(true);
    // 49 8D 8C 24 B8 00 00 00 : lea rcx, [r12 + 0xB8]
    // r12 as a base forces a SIB byte, which vivisect splits into i386SibOper
    const auto bytes = make_bytes(0x49, 0x8D, 0x8C, 0x24, 0xB8, 0x00, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    REQUIRE(r->operand_count == 2);
    // base+disp memory is not an absolute immediate-memory operand
    CHECK(r->operands[1].kind != OperandKind::kImmMem);
    // but it was SIB-encoded, so the flag distinguishes it from a plain [reg+disp]
    CHECK(r->operands[1].sib_encoded);
}

TEST_CASE("decode does not flag a non-SIB base+disp memory operand") {
    Disassembler d(true);
    // 48 8D 4B 10 : lea rcx, [rbx + 0x10]  (rbx needs no SIB byte)
    const auto bytes = make_bytes(0x48, 0x8D, 0x4B, 0x10);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    REQUIRE(r->operand_count == 2);
    CHECK_FALSE(r->operands[1].sib_encoded);
}

TEST_CASE("decode classifies kReg on mov eax, ebx") {
    Disassembler d(true);
    // 89 D8 : mov eax, ebx
    const auto bytes = make_bytes(0x89, 0xD8);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->operand_count == 2);
    CHECK(r->operands[0].kind == OperandKind::kReg);
    CHECK(r->operands[1].kind == OperandKind::kReg);
    CHECK_FALSE(r->is_call);
    CHECK_FALSE(r->is_jump);
    CHECK_FALSE(r->is_return);
    CHECK(r->is_fallthrough);
    CHECK(r->mnemonic_str == std::string_view{"mov"});
}

TEST_CASE("decode classifies kImm on mov eax, 0x1234") {
    Disassembler d(true);
    // B8 34 12 00 00 : mov eax, 0x1234
    const auto bytes = make_bytes(0xB8, 0x34, 0x12, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->operand_count == 2);
    CHECK(r->operands[0].kind == OperandKind::kReg);
    CHECK(r->operands[1].kind == OperandKind::kImm);
    CHECK(r->operands[1].imm == 0x1234U);
}

TEST_CASE("decode classifies kPcRel on near call") {
    Disassembler d(true);
    // E8 00 00 00 00 : call +0  -> target is next_va (0x1005)
    const auto bytes = make_bytes(0xE8, 0x00, 0x00, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->is_call);
    CHECK(r->operand_count >= 1);
    CHECK(r->operands[0].kind == OperandKind::kPcRel);
    REQUIRE(r->branch_target.has_value());
    CHECK(*r->branch_target == 0x1005U);
    // A call is a fallthrough for CFG purposes
    CHECK(r->is_fallthrough);
}

TEST_CASE("decode classifies kRipRel on x64 RIP-relative load") {
    Disassembler d(true);
    // 48 8B 05 00 00 00 00 : mov rax, [rip+0x0]  (target == next_va)
    const auto bytes = make_bytes(0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x2000);
    REQUIRE(r.has_value());
    CHECK(r->operand_count == 2);
    CHECK(r->operands[0].kind == OperandKind::kReg);
    CHECK(r->operands[1].kind == OperandKind::kRipRel);
    CHECK(r->operands[1].disp == 0);
}

TEST_CASE("decode classifies kImmMem on 32-bit absolute memory access") {
    Disassembler d(false);
    // A1 78 56 34 12 : mov eax, [0x12345678]  (x86)
    const auto bytes = make_bytes(0xA1, 0x78, 0x56, 0x34, 0x12);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->operand_count == 2);
    CHECK(r->operands[0].kind == OperandKind::kReg);
    CHECK(r->operands[1].kind == OperandKind::kImmMem);
    CHECK(r->operands[1].disp == static_cast<std::int64_t>(0x12345678));
}

TEST_CASE("decode classifies kRegMem on [rbx+8]") {
    Disassembler d(true);
    // 8B 43 08 : mov eax, [rbx+8]
    const auto bytes = make_bytes(0x8B, 0x43, 0x08);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->operand_count == 2);
    CHECK(r->operands[1].kind == OperandKind::kRegMem);
    CHECK(r->operands[1].base_reg == ZYDIS_REGISTER_RBX);
    CHECK(r->operands[1].index_reg == ZYDIS_REGISTER_NONE);
    CHECK(r->operands[1].disp == 8);
}

TEST_CASE("decode classifies kSib on [rbx+rcx*4+0x10]") {
    Disassembler d(true);
    // 8B 44 8B 10 : mov eax, [rbx+rcx*4+0x10]
    const auto bytes = make_bytes(0x8B, 0x44, 0x8B, 0x10);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->operand_count == 2);
    CHECK(r->operands[1].kind == OperandKind::kSib);
    CHECK(r->operands[1].base_reg == ZYDIS_REGISTER_RBX);
    CHECK(r->operands[1].index_reg == ZYDIS_REGISTER_RCX);
    CHECK(r->operands[1].scale == 4);
    CHECK(r->operands[1].disp == 0x10);
}

TEST_CASE("decode classifies kSib on an x64 SIB-encoded absolute address") {
    Disassembler d(true);
    // 8B 04 25 30 00 00 00 : mov eax, [0x30]. On x64 a non-RIP absolute address must be
    // SIB-encoded (mod=00, rm=100, base=101)
    const auto bytes = make_bytes(0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->operand_count == 2);
    CHECK(r->operands[1].kind == OperandKind::kSib);
    CHECK(r->operands[1].base_reg == ZYDIS_REGISTER_NONE);
    CHECK(r->operands[1].index_reg == ZYDIS_REGISTER_NONE);
    CHECK(r->operands[1].disp == 0x30);
}

TEST_CASE("decode classifies kSib on a gs segment-relative SIB access") {
    Disassembler d(true);
    // 65 48 8B 04 25 30 00 00 00 : mov rax, gs:[0x30] (TEB self-pointer read)
    const auto bytes = make_bytes(0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->operand_count == 2);
    CHECK(r->operands[1].kind == OperandKind::kSib);
    CHECK(r->has_prefix_gs);
    CHECK(r->operands[1].disp == 0x30);
}

TEST_CASE("decode flags ret as returning, not fallthrough") {
    Disassembler d(true);
    // C3 : ret
    const auto bytes = make_bytes(0xC3);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->is_return);
    CHECK_FALSE(r->is_call);
    CHECK_FALSE(r->is_jump);
    CHECK_FALSE(r->is_fallthrough);
}

TEST_CASE("decode flags conditional jump") {
    Disassembler d(true);
    // 74 02 : jz +2
    const auto bytes = make_bytes(0x74, 0x02);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->is_jump);
    CHECK(r->is_conditional);
    CHECK(r->is_fallthrough);
    REQUIRE(r->branch_target.has_value());
    CHECK(*r->branch_target == 0x1004U);
}

TEST_CASE("decode flags unconditional jmp as not falling through") {
    Disassembler d(true);
    // EB 05 : jmp +5
    const auto bytes = make_bytes(0xEB, 0x05);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->is_jump);
    CHECK_FALSE(r->is_conditional);
    CHECK_FALSE(r->is_fallthrough);
    REQUIRE(r->branch_target.has_value());
    CHECK(*r->branch_target == 0x1007U);
}

// vivisect's envi iflag_lookup marks several non-branch classes IF_NOFALL, so papa
// must stop a block on them or recovery walks an int3 pad into the next function
TEST_CASE("decode flags int3 as not falling through") {
    Disassembler d(true);
    // CC : int3
    const auto bytes = make_bytes(0xCC);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->is_call);
    CHECK_FALSE(r->is_jump);
    CHECK_FALSE(r->is_return);
    CHECK_FALSE(r->is_fallthrough);
}

TEST_CASE("decode flags hlt as not falling through") {
    Disassembler d(true);
    // F4 : hlt
    const auto bytes = make_bytes(0xF4);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->is_fallthrough);
}

TEST_CASE("decode flags ud2 as not falling through") {
    Disassembler d(true);
    // 0F 0B : ud2
    const auto bytes = make_bytes(0x0F, 0x0B);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->is_fallthrough);
}

TEST_CASE("decode flags into as not falling through") {
    Disassembler d(false);  // into is only valid in 32-bit mode
    // CE : into
    const auto bytes = make_bytes(0xCE);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->is_fallthrough);
}

TEST_CASE("decode flags iret as not falling through") {
    Disassembler d(false);
    // CF : iret
    const auto bytes = make_bytes(0xCF);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->is_fallthrough);
}

TEST_CASE("decode flags int 0x29 fastfail as not falling through") {
    Disassembler d(true);
    // CD 29 : int 0x29 (RtlFailFast, does not return)
    const auto bytes = make_bytes(0xCD, 0x29);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->is_fallthrough);
}

TEST_CASE("decode keeps int 0x2e (syscall gate) falling through") {
    // vivisect treats the Windows syscall interrupt as a returning call
    Disassembler d(true);
    // CD 2E : int 0x2e
    const auto bytes = make_bytes(0xCD, 0x2E);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->is_fallthrough);
}

TEST_CASE("decode detects fs segment prefix") {
    Disassembler d(true);
    // 64 48 8B 04 25 30 00 00 00 : mov rax, fs:[0x30]
    const auto bytes = make_bytes(0x64, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->has_prefix_fs);
    CHECK_FALSE(r->has_prefix_gs);
}

TEST_CASE("decode detects gs segment prefix for x64 PEB access") {
    Disassembler d(true);
    // 65 48 8B 04 25 60 00 00 00 : mov rax, gs:[0x60]  (PEB)
    const auto bytes = make_bytes(0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    REQUIRE(r.has_value());
    CHECK(r->has_prefix_gs);
    CHECK_FALSE(r->has_prefix_fs);
}

TEST_CASE("stack_registers returns width-appropriate set") {
    Disassembler d64(true);
    const auto regs64 = d64.stack_registers();
    REQUIRE(regs64.size() == 2);
    CHECK(regs64[0] == ZYDIS_REGISTER_RSP);
    CHECK(regs64[1] == ZYDIS_REGISTER_RBP);

    Disassembler d32(false);
    const auto regs32 = d32.stack_registers();
    REQUIRE(regs32.size() == 2);
    CHECK(regs32[0] == ZYDIS_REGISTER_ESP);
    CHECK(regs32[1] == ZYDIS_REGISTER_EBP);
}

TEST_CASE("decode does not over-read past buffer end") {
    Disassembler d(true);
    // E8 needs 4 more bytes
    // Provide only 3 so decoder must fail gracefully
    const auto bytes = make_bytes(0xE8, 0x00, 0x00, 0x00);
    const auto r = d.decode(std::span<const std::byte>(bytes), 0x1000);
    CHECK_FALSE(r.has_value());
    CHECK(r.error().kind == papa::ErrorKind::kDisassemblyFailed);
}

TEST_CASE("decode streams first 1000 instructions of notepad.exe .text") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    const auto& img = *res;

    // Locate .text
    const papa::pe::ParsedSection* text = nullptr;
    for (const auto& s : img.sections()) {
        if (s.name == ".text") {
            text = &s;
            break;
        }
    }
    REQUIRE(text != nullptr);

    Disassembler dis(img.is_64bit());

    const auto bytes = img.read_at_rva(text->virtual_address, text->raw_size);
    REQUIRE(bytes.has_value());

    std::span<const std::byte> cursor = *bytes;
    std::uint64_t va = img.image_base() + text->virtual_address;

    std::size_t decoded = 0;
    std::size_t hard_cap = 1000;
    while (!cursor.empty() && decoded < hard_cap) {
        const auto ins = dis.decode(cursor, va);
        if (!ins) {
            // A linear sweep may hit padding bytes, so advance by one and try again rather
            // than letting a bad byte fault the sweep
            cursor = cursor.subspan(1);
            va    += 1;
            continue;
        }
        CHECK(ins->length >= 1);
        CHECK(ins->length <= cursor.size());
        cursor = cursor.subspan(ins->length);
        va    += ins->length;
        ++decoded;
    }
    // very soft floor: .text is much larger than 500 insns in any real PE
    CHECK(decoded >= 500);
}
