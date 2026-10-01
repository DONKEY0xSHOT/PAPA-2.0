#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/insn.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/papa_native/imports.h"
#include "papa/features/extractors/papa_native/indirect_calls.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include "pe_builder.h"
#include "test_support.h"

using papa::features::AbsoluteVirtualAddress;
using papa::features::Characteristic;
using papa::features::FeatureTag;
using papa::features::Mnemonic;
using papa::features::Number;
using papa::features::Offset;
using papa::features::OperandNumber;
using papa::features::OperandOffset;
using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::DecodedOperand;
using papa::features::extractors::papa_native::Function;
using papa::features::extractors::papa_native::OperandKind;
using papa::features::extractors::papa_native::insn::extract_bytes;
using papa::features::extractors::papa_native::insn::extract_call_plus_5;
using papa::features::extractors::papa_native::insn::extract_cross_section_flow;
using papa::features::extractors::papa_native::insn::extract_indirect_call;
using papa::features::extractors::papa_native::insn::extract_mnemonic;
using papa::features::extractors::papa_native::insn::extract_number;
using papa::features::extractors::papa_native::insn::extract_offset;
using papa::features::extractors::papa_native::insn::extract_peb_access;
using papa::features::extractors::papa_native::insn::extract_segment_access;
using papa::features::extractors::papa_native::insn::extract_nzxor;
using papa::features::extractors::papa_native::insn::extract_string;
using papa::features::extractors::papa_native::insn::is_security_cookie;

namespace pn = papa::features::extractors::papa_native;

namespace pt = papa_tests;

namespace {

// Build a synthetic DecodedInsn for unit testing. Real tests of the disassembler live
// in test_disassembler.cpp
[[nodiscard]] DecodedInsn make_insn(std::uint64_t va, std::string_view mnem) {
    DecodedInsn ins;
    ins.va = va;
    ins.length = 1;
    ins.mnemonic_str = mnem;
    return ins;
}

}  // namespace

TEST_CASE("insn: extract_mnemonic emits the lower-cased spelling at the insn VA") {
    auto ins = make_insn(0x401000, "xor");
    auto r = extract_mnemonic(ins);
    REQUIRE(r.has_value());
    CHECK(r->first->tag() == FeatureTag::kMnemonic);
    CHECK(static_cast<const Mnemonic*>(r->first.get())->value() == "xor");
    CHECK(std::get<AbsoluteVirtualAddress>(r->second).v == 0x401000U);
}

TEST_CASE("insn: extract_mnemonic returns nullopt on empty mnemonic") {
    auto ins = make_insn(0x401000, "");
    CHECK_FALSE(extract_mnemonic(ins).has_value());
}

TEST_CASE("insn: extract_call_plus_5 fires only when the target equals va+5") {
    auto ins = make_insn(0x4000, "call");
    ins.is_call = true;
    ins.branch_target = 0x4005;
    auto r = extract_call_plus_5(ins);
    REQUIRE(r.has_value());
    CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "call $+5");
}

TEST_CASE("insn: extract_call_plus_5 ignores non-call instructions") {
    auto ins = make_insn(0x4000, "jmp");
    ins.is_call = false;
    ins.branch_target = 0x4005;
    CHECK_FALSE(extract_call_plus_5(ins).has_value());
}

TEST_CASE("insn: extract_call_plus_5 ignores calls without a target") {
    auto ins = make_insn(0x4000, "call");
    ins.is_call = true;
    ins.branch_target = std::nullopt;
    CHECK_FALSE(extract_call_plus_5(ins).has_value());
}

TEST_CASE("insn: extract_call_plus_5 ignores calls with non-matching target") {
    auto ins = make_insn(0x4000, "call");
    ins.is_call = true;
    ins.branch_target = 0x4010;
    CHECK_FALSE(extract_call_plus_5(ins).has_value());
}

TEST_CASE("insn: extract_indirect_call accepts kReg, kRegMem, kSib operands") {
    DecodedInsn ins = make_insn(0x100, "call");
    ins.is_call = true;
    ins.operand_count = 1;

    ins.operands[0].kind = OperandKind::kReg;
    REQUIRE(extract_indirect_call(ins).has_value());

    ins.operands[0].kind = OperandKind::kRegMem;
    REQUIRE(extract_indirect_call(ins).has_value());

    ins.operands[0].kind = OperandKind::kSib;
    REQUIRE(extract_indirect_call(ins).has_value());
}

TEST_CASE("insn: extract_indirect_call rejects PC-relative direct calls") {
    DecodedInsn ins = make_insn(0x100, "call");
    ins.is_call = true;
    ins.operand_count = 1;
    ins.operands[0].kind = OperandKind::kPcRel;
    CHECK_FALSE(extract_indirect_call(ins).has_value());
}

TEST_CASE("insn: extract_indirect_call rejects non-call instructions") {
    DecodedInsn ins = make_insn(0x100, "jmp");
    ins.is_call = false;
    ins.operand_count = 1;
    ins.operands[0].kind = OperandKind::kReg;
    CHECK_FALSE(extract_indirect_call(ins).has_value());
}

TEST_CASE("insn: extract_segment_access emits one feature per active prefix") {
    DecodedInsn ins = make_insn(0x100, "mov");
    ins.has_prefix_fs = true;
    ins.has_prefix_gs = false;
    auto fs_only = extract_segment_access(ins);
    REQUIRE(fs_only.size() == 1);
    CHECK(static_cast<const Characteristic*>(fs_only[0].first.get())->value() == "fs access");

    ins.has_prefix_fs = false;
    ins.has_prefix_gs = true;
    auto gs_only = extract_segment_access(ins);
    REQUIRE(gs_only.size() == 1);
    CHECK(static_cast<const Characteristic*>(gs_only[0].first.get())->value() == "gs access");

    ins.has_prefix_fs = true;
    ins.has_prefix_gs = true;
    auto both = extract_segment_access(ins);
    CHECK(both.size() == 2);

    ins.has_prefix_fs = false;
    ins.has_prefix_gs = false;
    auto none = extract_segment_access(ins);
    CHECK(none.empty());
}

TEST_CASE("insn: extract_peb_access detects fs:[0x30] on x86") {
    DecodedInsn ins = make_insn(0x100, "mov");
    ins.has_prefix_fs = true;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[1].kind = OperandKind::kRegMem;
    ins.operands[1].disp = 0x30;
    auto r = extract_peb_access(ins, /*is_64bit=*/false);
    REQUIRE(r.has_value());
    CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "peb access");
}

TEST_CASE("insn: extract_peb_access detects gs:[0x60] on x64") {
    DecodedInsn ins = make_insn(0x100, "mov");
    ins.has_prefix_gs = true;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[1].kind = OperandKind::kRegMem;
    ins.operands[1].disp = 0x60;
    auto r = extract_peb_access(ins, /*is_64bit=*/true);
    REQUIRE(r.has_value());
}

TEST_CASE("insn: extract_peb_access requires both the prefix and the offset") {
    DecodedInsn ins = make_insn(0x100, "mov");
    ins.has_prefix_fs = true;
    ins.operand_count = 1;
    ins.operands[0].kind = OperandKind::kRegMem;
    ins.operands[0].disp = 0x60;             // wrong offset for x86
    CHECK_FALSE(extract_peb_access(ins, false).has_value());

    ins.has_prefix_fs = false;
    ins.operands[0].disp = 0x30;             // right offset, missing prefix
    CHECK_FALSE(extract_peb_access(ins, false).has_value());
}

namespace {

using Features = std::vector<papa::features::extractors::FeatureWithAddress>;

// Where papa_tests::insn places an instruction, and so where its features land
constexpr std::uint64_t kAt = 0x1000;

// A parsed builder image and the builder that made it
struct Image {
    pt::PeBuilder     builder;
    papa::pe::PeImage image;
};

// An image of the given bitness whose .data, the last section in the file, holds data
[[nodiscard]] Image make_image(bool x64, std::vector<std::uint8_t> data) {
    pt::PeBuilder b;
    b.x64  = x64;
    b.code = {0xC3};
    b.data = std::move(data);
    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    return {std::move(b), std::move(*img)};
}

[[nodiscard]] papa::features::extractors::FeatureWithAddress num(std::uint64_t v) {
    return {pt::feat<Number>(Number::Value{v}), pt::va(kAt)};
}

[[nodiscard]] papa::features::extractors::FeatureWithAddress opnum(std::size_t i, std::uint64_t v) {
    return {pt::feat<OperandNumber>(i, OperandNumber::Value{v}), pt::va(kAt)};
}

[[nodiscard]] papa::features::extractors::FeatureWithAddress off(std::int64_t v) {
    return {pt::feat<Offset>(v), pt::va(kAt)};
}

[[nodiscard]] papa::features::extractors::FeatureWithAddress opoff(std::size_t i, std::int64_t v) {
    return {pt::feat<OperandOffset>(i, v), pt::va(kAt)};
}

// The instruction encoded by bytes, decoded at kAt
template <std::size_t N>
[[nodiscard]] DecodedInsn decode(bool x64, const std::array<std::byte, N>& bytes) {
    const pn::Disassembler dis(x64);
    auto ins = dis.decode(bytes, kAt);
    REQUIRE(ins.has_value());
    return *ins;
}

// A copy of ins whose memory operand i is marked SIB-encoded
[[nodiscard]] DecodedInsn with_sib(DecodedInsn ins, std::size_t i) {
    ins.operands[i].sib_encoded = true;
    return ins;
}

}  // namespace

TEST_CASE("insn: extract_number emits each immediate at its operation width unless it is a pointer") {
    const Image x64 = make_image(true, std::vector<std::uint8_t>(0x10, 0x11));
    const Image x86 = make_image(false, std::vector<std::uint8_t>(0x10, 0x11));
    struct Row {
        const char*  label;
        const Image* image;
        DecodedInsn  ins;
        Features     expected;
    };
    const std::vector<Row> rows{
        {"mov reg, imm yields the number of its operand", &x64,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_EAX, 4), pt::imm(0x1234, 4)),
         {num(0x1234), opnum(1, 0x1234)}},
        {"a sign-extended immediate keeps the register's width", &x64,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_AL, 1), pt::imm(~0ULL, 1)),
         {num(0xFF), opnum(1, 0xFF)}},
        {"an immediate alone masks to 32 bits on x86", &x86,
         pt::insn(ZYDIS_MNEMONIC_PUSH, pt::imm(0xFFFFFFFF80000002ULL, 4)),
         {num(0x80000002), opnum(0, 0x80000002)}},
        {"add esp, k is the one form whose number is dropped", &x86,
         pt::insn(ZYDIS_MNEMONIC_ADD, pt::reg(ZYDIS_REGISTER_ESP, 4), pt::imm(0x20, 4)), {}},
        {"sub esp, k keeps its number", &x86,
         pt::insn(ZYDIS_MNEMONIC_SUB, pt::reg(ZYDIS_REGISTER_ESP, 4), pt::imm(0x64, 4)),
         {num(0x64), opnum(1, 0x64)}},
        {"add rsp, k keeps its number but adds no offset hint", &x64,
         pt::insn(ZYDIS_MNEMONIC_ADD, pt::reg(ZYDIS_REGISTER_RSP, 8), pt::imm(0x20, 1)),
         {num(0x20), opnum(1, 0x20)}},
        {"add reg, small adds a structure offset hint", &x64,
         pt::insn(ZYDIS_MNEMONIC_ADD, pt::reg(ZYDIS_REGISTER_EAX, 4), pt::imm(0x10, 4)),
         {num(0x10), opnum(1, 0x10), off(0x10), opoff(1, 0x10)}},
        {"sub reg, small adds no offset hint", &x64,
         pt::insn(ZYDIS_MNEMONIC_SUB, pt::reg(ZYDIS_REGISTER_EAX, 4), pt::imm(0x10, 4)),
         {num(0x10), opnum(1, 0x10)}},
        {"an immediate that is a readable address is left to bytes and strings", &x64,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_RAX, 8),
                  pt::imm(x64.builder.data_va(4), 8)),
         {}},
        {"an address no section maps is still a number", &x86,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_EAX, 4), pt::imm(0x00500000, 4)),
         {num(0x00500000), opnum(1, 0x00500000)}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(pt::describe(extract_number(row.ins, row.image->image)) == pt::describe(row.expected));
    }
}

TEST_CASE("insn: memory operands yield offsets, and a plain lea displacement a number too") {
    const Image x64 = make_image(true, std::vector<std::uint8_t>(0x10, 0x11));
    const Image x86 = make_image(false, std::vector<std::uint8_t>(0x10, 0x11));
    const auto  data = static_cast<std::int64_t>(x86.builder.data_va(0));
    struct Row {
        const char*  label;
        const Image* image;
        DecodedInsn  ins;
        Features     expected;  // what extract_offset then extract_number yield
    };
    const std::vector<Row> rows{
        {"[reg+disp] yields the offset of its operand", &x64,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_EAX, 4),
                  pt::mem(ZYDIS_REGISTER_EBX, 0x20, 4)),
         {off(0x20), opoff(1, 0x20)}},
        {"a bare [reg] is offset 0", &x64,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_EAX, 4),
                  pt::mem(ZYDIS_REGISTER_EAX, 0, 4)),
         {off(0), opoff(1, 0)}},
        {"a frame pointer access is skipped on x64", &x64,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_RAX, 8),
                  pt::mem(ZYDIS_REGISTER_RBP, 0x10, 8)),
         {}},
        {"a frame pointer access is skipped on x86", &x86,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_EAX, 4),
                  pt::mem(ZYDIS_REGISTER_EBP, 0x10, 4)),
         {}},
        {"a stack pointer access is skipped on x86", &x86,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_EAX, 4),
                  pt::mem(ZYDIS_REGISTER_ESP, 0x10, 4)),
         {}},
        {"an rsp access is kept on x64", &x64,
         pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_RAX, 8),
                  pt::mem(ZYDIS_REGISTER_RSP, 0x10, 8)),
         {off(0x10), opoff(1, 0x10)}},
        {"a SIB-encoded stack base is kept on x86", &x86,
         with_sib(pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_EAX, 4),
                           pt::mem(ZYDIS_REGISTER_ESP, 0x10, 4)),
                  1),
         {off(0x10), opoff(1, 0x10)}},
        {"mov rax, gs:[0x30] is SIB-encoded with no base, so offset 0 and no number", &x64,
         decode(true, pt::bytes(0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00)),
         {off(0), opoff(1, 0)}},
        {"lea rcx, [r12+0xB8] needs a SIB byte, so it yields no number", &x64,
         decode(true, pt::bytes(0x49, 0x8D, 0x8C, 0x24, 0xB8, 0x00, 0x00, 0x00)),
         {off(0xB8), opoff(1, 0xB8)}},
        {"lea rcx, [rbx+0x10] also yields its displacement as a number", &x64,
         decode(true, pt::bytes(0x48, 0x8D, 0x4B, 0x10)),
         {off(0x10), opoff(1, 0x10), num(0x10), opnum(1, 0x10)}},
        {"lea from a stack base yields no number", &x64,
         pt::insn(ZYDIS_MNEMONIC_LEA, pt::reg(ZYDIS_REGISTER_RCX, 8),
                  pt::mem(ZYDIS_REGISTER_RSP, 0x20, 8)),
         {off(0x20), opoff(1, 0x20)}},
        {"lea whose displacement is a readable address yields no number", &x86,
         pt::insn(ZYDIS_MNEMONIC_LEA, pt::reg(ZYDIS_REGISTER_ECX, 4),
                  pt::mem(ZYDIS_REGISTER_EBX, data, 4)),
         {off(data), opoff(1, data)}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        Features got = extract_offset(row.ins, row.image->image);
        for (auto& fa : extract_number(row.ins, row.image->image)) { got.push_back(std::move(fa)); }
        CHECK(pt::describe(got) == pt::describe(row.expected));
    }
}

TEST_CASE("insn: an operand pointing at data yields bytes unless they are zero or text, and a string") {
    // .data, the last section in the file, holds each kind of target at its own offset
    constexpr std::size_t kBlob = 0x000, kAscii = 0x040, kWide = 0x080, kZeros = 0x0A0;
    constexpr std::size_t kFullAscii = 0x200, kFullWide = 0x300, kTail = 0x5F8;
    std::vector<std::uint8_t> data(0x600, 0);
    for (std::size_t i = 0; i < 8; ++i) {
        data[kBlob + i] = static_cast<std::uint8_t>(0xF0 + i);
        data[kTail + i] = static_cast<std::uint8_t>(0x81 + i);
    }
    const std::string ascii = "ascii text";
    const std::string wide  = "wide text";
    std::copy(ascii.begin(), ascii.end(), data.begin() + kAscii);
    for (std::size_t i = 0; i < wide.size(); ++i) {
        data[kWide + 2U * i] = static_cast<std::uint8_t>(wide[i]);
    }
    std::string full_ascii;
    std::string full_wide;
    for (std::size_t i = 0; i < 0x100; ++i) {
        full_ascii.push_back(static_cast<char>('A' + i % 26U));
        data[kFullAscii + i] = static_cast<std::uint8_t>(full_ascii.back());
        if (i % 2U == 0U) {
            full_wide.push_back(static_cast<char>('a' + i / 2U % 26U));
            data[kFullWide + i] = static_cast<std::uint8_t>(full_wide.back());
        }
    }
    const Image x64 = make_image(true, data);

    const auto data_va = [&x64](std::size_t at) { return x64.builder.data_va(static_cast<std::uint32_t>(at)); };
    const auto bytes_at = [&data](std::size_t at, std::size_t n) {
        std::vector<std::byte> out;
        for (std::size_t i = at; i < at + n; ++i) { out.push_back(std::byte{data[i]}); }
        return papa::features::extractors::FeatureWithAddress{
            pt::feat<papa::features::Bytes>(std::move(out)), pt::va(kAt)};
    };
    const auto text = [](std::string s) {
        return papa::features::extractors::FeatureWithAddress{
            pt::feat<papa::features::String>(std::move(s)), pt::va(kAt)};
    };
    const auto load = [](std::uint64_t target) {
        return pt::insn(ZYDIS_MNEMONIC_MOV, pt::reg(ZYDIS_REGISTER_RCX, 8), pt::imm(target, 8));
    };
    DecodedInsn call = pt::insn(ZYDIS_MNEMONIC_CALL, pt::imm(data_va(kAscii), 8));
    call.is_call     = true;

    struct Row {
        const char* label;
        DecodedInsn ins;
        Features    expected;  // what extract_bytes then extract_string yield
    };
    const std::vector<Row> rows{
        {"binary data yields the bytes read from it", load(data_va(kBlob)),
         {bytes_at(kBlob, 0x100)}},
        {"a short string followed by other data yields bytes and the string",
         load(data_va(kAscii)), {bytes_at(kAscii, 0x100), text(ascii)}},
        {"a short UTF-16 string yields bytes and the string", load(data_va(kWide)),
         {bytes_at(kWide, 0x100), text(wide)}},
        {"all zero data yields nothing", load(data_va(kZeros)), {}},
        {"a window of ASCII text yields only the string", load(data_va(kFullAscii)),
         {text(full_ascii)}},
        {"a window of UTF-16 text yields only the string", load(data_va(kFullWide)),
         {text(full_wide)}},
        {"data at the end of the file yields the bytes that are there", load(data_va(kTail)),
         {bytes_at(kTail, 8)}},
        {"an address below the image yields nothing", load(0xDEADBEEF), {}},
        {"an address no section maps yields nothing", load(x64.image.image_base() + 0x00F00000U),
         {}},
        {"a call's operand yields no bytes but still its string", call, {text(ascii)}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        Features got = extract_bytes(row.ins, x64.image);
        for (auto& fa : extract_string(row.ins, x64.image)) { got.push_back(std::move(fa)); }
        CHECK(pt::describe(got) == pt::describe(row.expected));
    }
}

TEST_CASE("insn: extract_flirt_call_api emits the FLIRT name and its stripped form") {
    // call <pcrel target 0x54a250>, where FLIRT identified the target as the
    // statically-linked CRT routine __beginthreadex
    DecodedInsn ins = make_insn(0x004afdf4, "call");
    ins.zyd_mnem      = ZYDIS_MNEMONIC_CALL;
    ins.is_call       = true;
    ins.operand_count = 1;
    ins.operands[0].kind = OperandKind::kPcRel;
    ins.branch_target = 0x0054a250ULL;

    const auto lookup = [](std::uint64_t va) -> std::optional<std::string> {
        if (va == 0x0054a250ULL) { return std::string{"__beginthreadex"}; }
        return std::nullopt;
    };
    const auto out =
        papa::features::extractors::papa_native::insn::extract_flirt_call_api(ins, lookup);

    const papa::features::Api want_full{"__beginthreadex"};
    const papa::features::Api want_stripped{"_beginthreadex"};
    bool has_full = false;
    bool has_stripped = false;
    for (const auto& fa : out) {
        if (fa.first->equals(want_full)) { has_full = true; }
        if (fa.first->equals(want_stripped)) { has_stripped = true; }
    }
    CHECK(has_full);
    CHECK(has_stripped);
}

TEST_CASE("insn: extract_nzxor fires on xor of distinct registers") {
    DecodedInsn xor_insn = make_insn(0x4000, "xor");
    xor_insn.zyd_mnem = ZYDIS_MNEMONIC_XOR;
    xor_insn.operand_count = 2;
    xor_insn.operands[0].kind = OperandKind::kReg;
    xor_insn.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    xor_insn.operands[1].kind = OperandKind::kReg;
    xor_insn.operands[1].base_reg = ZYDIS_REGISTER_EBX;

    Function fn = papa_tests::single_block_function({xor_insn});
    auto r = extract_nzxor(fn, fn.basic_blocks[0], xor_insn, /*is_64bit=*/false);
    REQUIRE(r.has_value());
    CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "nzxor");
}

TEST_CASE("insn: extract_nzxor suppresses xor reg, reg with the same register") {
    DecodedInsn ins = make_insn(0x4000, "xor");
    ins.zyd_mnem = ZYDIS_MNEMONIC_XOR;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    ins.operands[1].kind = OperandKind::kReg;
    ins.operands[1].base_reg = ZYDIS_REGISTER_EAX;

    Function fn = papa_tests::single_block_function({ins});
    CHECK_FALSE(extract_nzxor(fn, fn.basic_blocks[0], ins, false).has_value());
}

TEST_CASE("insn: extract_nzxor suppresses prologue cookie xor") {
    // Cookie xor lives in the first kSecurityCookieBytesDelta bytes of the entry block
    DecodedInsn cookie = make_insn(0x4010, "xor");
    cookie.zyd_mnem = ZYDIS_MNEMONIC_XOR;
    cookie.length   = 5;
    cookie.operand_count = 2;
    cookie.operands[0].kind = OperandKind::kReg;
    cookie.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    cookie.operands[1].kind = OperandKind::kReg;
    cookie.operands[1].base_reg = ZYDIS_REGISTER_EBP;

    Function fn = papa_tests::single_block_function({cookie});
    fn.basic_blocks[0].va = 0x4000;       // prologue starts here
    CHECK(is_security_cookie(fn, fn.basic_blocks[0], cookie, false));
    CHECK_FALSE(extract_nzxor(fn, fn.basic_blocks[0], cookie, false).has_value());
}

TEST_CASE("insn: extract_nzxor ignores non-xor mnemonics") {
    DecodedInsn ins = make_insn(0x4000, "and");
    ins.zyd_mnem = ZYDIS_MNEMONIC_AND;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    ins.operands[1].kind = OperandKind::kReg;
    ins.operands[1].base_reg = ZYDIS_REGISTER_EBX;

    Function fn = papa_tests::single_block_function({ins});
    CHECK_FALSE(extract_nzxor(fn, fn.basic_blocks[0], ins, false).has_value());
}

namespace {

// Build a function whose entry block contains the given instructions in order
[[nodiscard]] DecodedInsn make_mov_reg_imm(std::uint64_t va,
                                           ZydisRegister dst,
                                           std::uint64_t imm) {
    DecodedInsn d = make_insn(va, "mov");
    d.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    d.length   = 5;
    d.operand_count = 2;
    d.operands[0].kind = OperandKind::kReg;
    d.operands[0].base_reg = dst;
    d.operands[1].kind = OperandKind::kImm;
    d.operands[1].imm  = imm;
    return d;
}

[[nodiscard]] DecodedInsn make_call_reg(std::uint64_t va, ZydisRegister reg) {
    DecodedInsn d = make_insn(va, "call");
    d.zyd_mnem = ZYDIS_MNEMONIC_CALL;
    d.is_call  = true;
    d.length   = 2;
    d.operand_count = 1;
    d.operands[0].kind = OperandKind::kReg;
    d.operands[0].base_reg = reg;
    return d;
}

}  // namespace

TEST_CASE("indirect_calls: find_definition recovers mov reg, imm") {
    auto def_insn  = make_mov_reg_imm(0x4000, ZYDIS_REGISTER_EAX, 0xCAFEBABE);
    auto call_insn = make_call_reg(0x4005, ZYDIS_REGISTER_EAX);

    Function fn = papa_tests::single_block_function({def_insn, call_insn});
    auto def = papa::features::extractors::papa_native::find_definition(
        fn, 0x4005U, ZYDIS_REGISTER_EAX, /*is_64bit=*/false);
    REQUIRE(def.has_value());
    CHECK(def->site_va == 0x4000U);
    REQUIRE(def->value.has_value());
    CHECK(*def->value == 0xCAFEBABEULL);
}

TEST_CASE("indirect_calls: find_definition resolves enclosing register aliases") {
    // mov rax, imm -> eax read should resolve under x64 mode
    auto def_insn  = make_mov_reg_imm(0x4000, ZYDIS_REGISTER_RAX, 0x1000);
    auto call_insn = make_call_reg(0x4007, ZYDIS_REGISTER_EAX);

    Function fn = papa_tests::single_block_function({def_insn, call_insn});
    auto def = papa::features::extractors::papa_native::find_definition(
        fn, 0x4007U, ZYDIS_REGISTER_EAX, /*is_64bit=*/true);
    REQUIRE(def.has_value());
    REQUIRE(def->value.has_value());
    CHECK(*def->value == 0x1000U);
}

TEST_CASE("indirect_calls: find_definition rejects partial-width writes") {
    // mov al, 0x10 does not define rax under x64 because the upper bits remain
    DecodedInsn partial = make_insn(0x4000, "mov");
    partial.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    partial.length   = 2;
    partial.operand_count = 2;
    partial.operands[0].kind = OperandKind::kReg;
    partial.operands[0].base_reg = ZYDIS_REGISTER_AL;
    partial.operands[1].kind = OperandKind::kImm;
    partial.operands[1].imm  = 0x10;

    auto call_insn = make_call_reg(0x4002, ZYDIS_REGISTER_RAX);
    Function fn = papa_tests::single_block_function({partial, call_insn});
    auto def = papa::features::extractors::papa_native::find_definition(
        fn, 0x4002U, ZYDIS_REGISTER_RAX, /*is_64bit=*/true);
    CHECK_FALSE(def.has_value());
}

TEST_CASE("indirect_calls: find_definition returns nullopt with no preceding write") {
    auto call_insn = make_call_reg(0x4000, ZYDIS_REGISTER_EAX);
    Function fn = papa_tests::single_block_function({call_insn});
    auto def = papa::features::extractors::papa_native::find_definition(
        fn, 0x4000U, ZYDIS_REGISTER_EAX, false);
    CHECK_FALSE(def.has_value());
}

TEST_CASE("insn: build_import_table indexes every import, delayed or by ordinal, by its IAT VA") {
    pt::PeBuilder b;
    b.code          = {0xC3};
    b.imports       = {{"kernel32.dll", {"CreateFileW", "#9"}}, {"ws2_32.dll", {"#6"}}};
    b.delay_imports = {{"user32.dll", {"MessageBoxW"}}};
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());

    const auto table = pn::build_import_table(*img);
    const auto imps  = img->imports();
    REQUIRE(imps.size() == 4);
    CHECK(table.by_iat_va.size() == imps.size());
    for (const papa::pe::ParsedImport& row : imps) {
        CAPTURE(row.iat_va);
        const auto it = table.by_iat_va.find(row.iat_va);
        REQUIRE(it != table.by_iat_va.end());
        CHECK(it->second == &row);
    }
    CHECK(table.by_iat_va.count(b.iat_va("user32.dll", "MessageBoxW")) == 1);
}

namespace {

// Points the rel32 at code offset disp_at of the instruction at offset at, len bytes
// long, at target
void point(pt::PeBuilder& b, std::uint32_t at, std::uint32_t len, std::uint32_t disp_at,
           std::uint64_t target) {
    pt::detail::poke(b.code, disp_at, static_cast<std::int32_t>(target - b.code_va(at + len)));
}

}  // namespace

TEST_CASE("insn: extract_cross_section_flow flags a branch into another section that is no import") {
    for (const bool x64 : {true, false}) {
        CAPTURE(x64);
        pt::PeBuilder b;
        b.x64     = x64;
        b.code    = std::vector<std::uint8_t>(0x20, 0x90);
        b.imports = {{"kernel32.dll", {"VirtualAllocEx"}}};
        b.data    = std::vector<std::uint8_t>(0x10, 0);
        b.extra_sections = {{".text2", {0xC3},
                             pt::PeBuilder::kScnCode | pt::PeBuilder::kScnExecute |
                                 pt::PeBuilder::kScnRead,
                             0}};
        const std::uint64_t iat   = b.iat_va("kernel32.dll", "VirtualAllocEx");
        const std::uint64_t slot  = b.data_va(8);
        const std::uint64_t text2 = b.base() + b.section_rva(".text2");
        const auto img = papa::pe::PeParser::parse(b.build());
        REQUIRE(img.has_value());
        const auto             table = pn::build_import_table(*img);
        const pn::Disassembler dis(x64);

        // The branch sits at code offset 0x10. Its operand reads the target through
        // memory, absolute on x86 and rip-relative on x64
        const std::uint64_t at       = b.code_va(0x10);
        const auto          via_slot = [&](std::uint8_t modrm_op, std::uint64_t target) {
            const std::uint32_t field = x64 ? static_cast<std::uint32_t>(target - (at + 6U))
                                            : static_cast<std::uint32_t>(target);
            return std::vector<std::uint8_t>{0xFF, modrm_op,
                                             static_cast<std::uint8_t>(field),
                                             static_cast<std::uint8_t>(field >> 8U),
                                             static_cast<std::uint8_t>(field >> 16U),
                                             static_cast<std::uint8_t>(field >> 24U)};
        };
        const auto direct = [at](std::uint8_t opcode, std::uint64_t target) {
            const auto field = static_cast<std::uint32_t>(target - (at + 5U));
            return std::vector<std::uint8_t>{opcode, static_cast<std::uint8_t>(field),
                                             static_cast<std::uint8_t>(field >> 8U),
                                             static_cast<std::uint8_t>(field >> 16U),
                                             static_cast<std::uint8_t>(field >> 24U)};
        };
        struct Row {
            const char*               label;
            std::vector<std::uint8_t> code;
            bool                      flagged;
        };
        const std::vector<Row> rows{
            {"call [slot] with the slot in .data", via_slot(0x15, slot), true},
            {"jmp [slot] with the slot in .data", via_slot(0x25, slot), true},
            {"call [iat] is an import call", via_slot(0x15, iat), false},
            {"call rel32 within .text", direct(0xE8, b.code_va(0)), false},
            {"jmp rel32 into a second executable section", direct(0xE9, text2), true},
            {"call rel32 to an address no section maps", direct(0xE8, b.base() + 0x00F00000U),
             false},
            {"call rel32 below the image base", direct(0xE8, at - 0x01000000U), false},
            {"call through a register has no static target", {0xFF, 0xD0}, false},
            {"mov is no branch", {0x8B, 0xC1}, false},
        };
        for (const Row& row : rows) {
            CAPTURE(row.label);
            const auto ins = dis.decode(std::as_bytes(std::span(row.code)), at);
            REQUIRE(ins.has_value());
            const auto got = extract_cross_section_flow(*ins, *img, table);
            REQUIRE(got.has_value() == row.flagged);
            if (row.flagged) {
                CHECK(pt::describe(*got) ==
                      pt::describe(papa::features::extractors::FeatureWithAddress{
                          pt::feat<Characteristic>("cross section flow"), pt::va(at)}));
            }
        }

        // A branch the image does not contain is not judged
        const std::vector<std::uint8_t> call = direct(0xE8, slot);
        const auto below = dis.decode(std::as_bytes(std::span(call)), 0x1000);
        REQUIRE(below.has_value());
        CHECK_FALSE(extract_cross_section_flow(*below, *img, table).has_value());
    }
}

namespace {

// The api features of every instruction of every function the backend recovers, keyed
// by instruction address. No FLIRT signatures, so every build sees the same functions
[[nodiscard]] std::map<std::uint64_t, Features> api_by_insn(const papa::pe::PeImage& img) {
    const pn::flirt::FlirtSignatureSet no_sigs;
    auto backend = pn::PapaNativeBackend::build(img, no_sigs);
    REQUIRE(backend.has_value());
    std::map<std::uint64_t, Features> out;
    for (const Function& f : backend->functions()) {
        for (const auto& bb : f.basic_blocks) {
            for (const DecodedInsn& ins : bb.instructions) {
                auto feats = pn::insn::extract_api_features(f, ins, img, backend->imports(),
                                                            backend->disassembler());
                if (!feats.empty()) { out.emplace(ins.va, std::move(feats)); }
            }
        }
    }
    return out;
}

// One expected api use: the instruction's code offset and the names it yields
struct ApiRow {
    const char*              label;
    std::uint32_t            at;
    std::vector<std::string> names;
};

// Checks that each row's instruction yields exactly its names, and nothing else does
void check_api(const pt::PeBuilder& b, const std::vector<ApiRow>& rows) {
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());
    auto by_insn = api_by_insn(*img);
    for (const ApiRow& row : rows) {
        CAPTURE(row.label);
        Features want;
        for (const std::string& name : row.names) {
            want.emplace_back(pt::feat<papa::features::Api>(name), pt::va(b.code_va(row.at)));
        }
        CHECK(pt::describe(by_insn[b.code_va(row.at)]) == pt::describe(want));
        by_insn.erase(b.code_va(row.at));
    }
    for (const auto& [at, feats] : by_insn) {
        CAPTURE(at);
        CHECK(pt::describe(feats).empty());
    }
}

const std::vector<std::string> kCreateFileW{"kernel32.CreateFileW", "CreateFileW",
                                            "kernel32.CreateFile", "CreateFile"};
const std::vector<std::string> kWriteFile{"kernel32.WriteFile", "WriteFile"};

}  // namespace

TEST_CASE("api: x64 calls through the IAT, thunk chains and registers name their import") {
    pt::PeBuilder b;
    b.imports = {{"kernel32.dll", {"CreateFileW", "WriteFile"}},
                 {"ws2_32.dll", {"#6"}},
                 {"mydll.dll", {"#3"}}};
    b.data.assign(0x10, 0);

    // Thunks, then one function per use, each its own .pdata row
    const auto thunk     = b.add_function({0xFF, 0x25, 0, 0, 0, 0});            // jmp [rip+]
    const auto endbr     = b.add_function({0xF3, 0x0F, 0x1E, 0xFA,              // endbr64
                                           0xFF, 0x25, 0, 0, 0, 0});            // jmp [rip+]
    const auto hop2      = b.add_function({0xE9, 0, 0, 0, 0});                  // jmp thunk
    const auto hop1      = b.add_function({0xE9, 0, 0, 0, 0});                  // jmp hop2
    const auto self_loop = b.add_function({0xEB, 0xFE});                        // jmp $
    const auto not_thunk = b.add_function({0x33, 0xC0, 0xC3});                  // xor eax, eax
    const auto reg_thunk = b.add_function({0xFF, 0xE0});                        // jmp rax
    const std::vector<std::uint8_t> call_rel{0xE8, 0, 0, 0, 0, 0xC3};
    const std::vector<std::uint8_t> call_mem{0xFF, 0x15, 0, 0, 0, 0, 0xC3};
    const auto via_iat   = b.add_function(call_mem);
    const auto ordinal   = b.add_function(call_mem);
    const auto unnamed   = b.add_function(call_mem);
    const auto via_slot  = b.add_function(call_mem);
    const auto to_thunk  = b.add_function(call_rel);
    const auto to_endbr  = b.add_function(call_rel);
    const auto to_chain  = b.add_function(call_rel);
    const auto to_loop   = b.add_function(call_rel);
    const auto to_code   = b.add_function(call_rel);
    const auto to_reg    = b.add_function(call_rel);
    // mov rax, [rip+] / call rax / ret
    const auto reg_same = b.add_function({0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xFF, 0xD0, 0xC3});
    const auto reg_slot = b.add_function({0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xFF, 0xD0, 0xC3});
    // mov rax, [rip+] / test ecx, ecx / jz L / nop / L: call rax / ret
    const auto reg_pred = b.add_function(
        {0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x85, 0xC9, 0x74, 0x01, 0x90, 0xFF, 0xD0, 0xC3});
    // The same with a second test edx, edx / jz / nop between, so the mov is two blocks up
    const auto reg_far = b.add_function({0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x85, 0xC9, 0x74, 0x01,
                                         0x90, 0x85, 0xD2, 0x74, 0x01, 0x90, 0xFF, 0xD0, 0xC3});
    // mov rax, [rip+] / ret
    const auto no_call = b.add_function({0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xC3});

    const std::uint64_t create = b.iat_va("kernel32.dll", "CreateFileW");
    const std::uint64_t write  = b.iat_va("kernel32.dll", "WriteFile");
    point(b, thunk, 6, thunk + 2, create);
    point(b, endbr + 4, 6, endbr + 6, write);
    point(b, hop2, 5, hop2 + 1, b.code_va(thunk));
    point(b, hop1, 5, hop1 + 1, b.code_va(hop2));
    point(b, via_iat, 6, via_iat + 2, create);
    point(b, ordinal, 6, ordinal + 2, b.iat_va("ws2_32.dll", "#6"));
    point(b, unnamed, 6, unnamed + 2, b.iat_va("mydll.dll", "#3"));
    point(b, via_slot, 6, via_slot + 2, b.data_va(0));
    point(b, to_thunk, 5, to_thunk + 1, b.code_va(thunk));
    point(b, to_endbr, 5, to_endbr + 1, b.code_va(endbr));
    point(b, to_chain, 5, to_chain + 1, b.code_va(hop1));
    point(b, to_loop, 5, to_loop + 1, b.code_va(self_loop));
    point(b, to_code, 5, to_code + 1, b.code_va(not_thunk));
    point(b, to_reg, 5, to_reg + 1, b.code_va(reg_thunk));
    point(b, reg_same, 7, reg_same + 3, write);
    point(b, reg_slot, 7, reg_slot + 3, b.data_va(0));
    point(b, reg_pred, 7, reg_pred + 3, create);
    point(b, reg_far, 7, reg_far + 3, write);
    point(b, no_call, 7, no_call + 3, create);

    check_api(b, {
        {"a jmp [rip+iat] thunk", thunk, kCreateFileW},
        {"the jmp after endbr64", endbr + 4, kWriteFile},
        {"a jmp to a thunk", hop2, kCreateFileW},
        {"a jmp to a jmp to a thunk", hop1, kCreateFileW},
        {"call [rip+iat]", via_iat, kCreateFileW},
        {"an ordinal the table names", ordinal, {"ws2_32.getsockname", "getsockname"}},
        {"an ordinal the table cannot name", unnamed, {"mydll.#3", "#3"}},
        {"call [rip+slot] where the slot is no import", via_slot, {}},
        {"a call to a thunk", to_thunk, kCreateFileW},
        {"a call to a thunk that starts with endbr64", to_endbr, kWriteFile},
        {"a call through a two-hop jmp chain", to_chain, kCreateFileW},
        {"a call to a jmp to itself stops at the depth limit", to_loop, {}},
        {"a call to code that is no thunk", to_code, {}},
        {"a call to a jmp through a register", to_reg, {}},
        {"call rax after mov rax, [rip+iat] in the same block", reg_same + 7, kWriteFile},
        {"call rax after mov rax from a slot that is no import", reg_slot + 7, {}},
        {"call rax whose mov is in the block before", reg_pred + 12, kCreateFileW},
        {"call rax whose mov is two blocks before", reg_far + 17, kWriteFile},
        {"a mov from the IAT is no api use", no_call, {}},
    });
}

TEST_CASE("api: x86 calls through the IAT, a thunk and a register name their import") {
    pt::PeBuilder b;
    b.x64     = false;
    b.imports = {{"kernel32.dll", {"CreateFileW", "WriteFile"}}};
    // jmp [iat] / int3 / call [iat] / call thunk / mov eax, [iat] / call eax / ret
    b.code = {0xFF, 0x25, 0, 0, 0, 0, 0xCC,
              0xFF, 0x15, 0, 0, 0, 0,
              0xE8, 0, 0, 0, 0,
              0xA1, 0, 0, 0, 0,
              0xFF, 0xD0,
              0xC3};
    b.entry_offset = 7;
    b.exports      = {{"thunk", 0, ""}};
    const auto abs32 = [&b](std::uint32_t at, std::uint64_t target) {
        pt::detail::poke(b.code, at, static_cast<std::uint32_t>(target));
    };
    abs32(2, b.iat_va("kernel32.dll", "CreateFileW"));
    abs32(9, b.iat_va("kernel32.dll", "CreateFileW"));
    point(b, 13, 5, 14, b.code_va(0));
    abs32(19, b.iat_va("kernel32.dll", "WriteFile"));

    check_api(b, {
        {"a jmp [iat] thunk", 0, kCreateFileW},
        {"call [iat]", 7, kCreateFileW},
        {"a call to a thunk", 13, kCreateFileW},
        {"call eax after mov eax, [iat]", 23, kWriteFile},
    });
}
