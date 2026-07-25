#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/insn.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/indirect_calls.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <Zydis/Zydis.h>

#include <filesystem>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include "fixture_paths.h"

using papa::features::AbsoluteVirtualAddress;
using papa::features::Characteristic;
using papa::features::FeatureTag;
using papa::features::Mnemonic;
using papa::features::Number;
using papa::features::Offset;
using papa::features::OperandNumber;
using papa::features::OperandOffset;
using papa::features::extractors::papa_native::BasicBlock;
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

namespace {

// Build a synthetic DecodedInsn for unit testing
// Real tests of the disassembler live in test_disassembler.cpp
// Here we want
// to drive the extractor logic without paying decoder setup costs
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

// Cached image fixture
// Tests share a single parse to keep total runtime low
// notepad.exe is the lowest-cost real-PE fixture we ship for unit tests
[[nodiscard]] const papa::pe::PeImage* notepad_image() {
    static std::optional<papa::pe::PeImage> cached;
    static bool tried = false;
    if (!tried) {
        tried = true;
        const auto path = papa_tests::fixture_path("notepad.exe");
        if (std::filesystem::exists(path)) {
            auto r = papa::pe::PeParser::parse_file(path);
            if (r) { cached.emplace(std::move(*r)); }
        }
    }
    return cached.has_value() ? &*cached : nullptr;
}

// chrome.exe carries the indirect-call shellcode pattern the cross-section
// extractor must recognize. Cached like notepad to keep runtime low
[[nodiscard]] const papa::pe::PeImage* chrome_image() {
    static std::optional<papa::pe::PeImage> cached;
    static bool tried = false;
    if (!tried) {
        tried = true;
        const auto path = papa_tests::fixture_path("chrome.exe");
        if (std::filesystem::exists(path)) {
            auto r = papa::pe::PeParser::parse_file(path);
            if (r) { cached.emplace(std::move(*r)); }
        }
    }
    return cached.has_value() ? &*cached : nullptr;
}

// Everything.exe is the 32-bit fixture, needed to exercise x86-specific number
// width handling. Cached like the others to keep runtime low
[[nodiscard]] const papa::pe::PeImage* everything_image() {
    static std::optional<papa::pe::PeImage> cached;
    static bool tried = false;
    if (!tried) {
        tried = true;
        const auto path = papa_tests::fixture_path("Everything.exe");
        if (std::filesystem::exists(path)) {
            auto r = papa::pe::PeParser::parse_file(path);
            if (r) { cached.emplace(std::move(*r)); }
        }
    }
    return cached.has_value() ? &*cached : nullptr;
}

}  // namespace

TEST_CASE("insn: extract_number emits Number + OperandNumber for non-pointer immediates") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    DecodedInsn ins = make_insn(0x401000, "mov");
    ins.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    ins.operands[1].kind = OperandKind::kImm;
    ins.operands[1].imm  = 0x1234U;          // not a valid VA in notepad
    auto out = extract_number(ins, *img);
    REQUIRE(out.size() == 2);
    CHECK(out[0].first->tag() == FeatureTag::kNumber);
    CHECK(out[1].first->tag() == FeatureTag::kOperandNumber);
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

TEST_CASE("insn: extract_number masks a high-bit imm-only value to 32 bits on x86") {
    const auto* img = everything_image();
    if (img == nullptr) {
        MESSAGE("Everything.exe fixture missing, skipping");
        return;
    }
    REQUIRE_FALSE(img->is_64bit());
    // push 0x80000002 (HKEY_LOCAL_MACHINE). Zydis sign-extends the imm32 to 64
    // bits, so the operand arrives as 0xffffffff80000002. On a 32-bit image the
    // number must be the 32-bit value 0x80000002, the way capa emits it, so the
    // persist-via-Run and inspect-section rules see the constants they expect
    DecodedInsn ins = make_insn(0x401000, "push");
    ins.zyd_mnem = ZYDIS_MNEMONIC_PUSH;
    ins.operand_count = 1;
    ins.operands[0].kind = OperandKind::kImm;
    ins.operands[0].imm  = 0xFFFFFFFF80000002ULL;
    auto out = extract_number(ins, *img);
    REQUIRE(out.size() >= 1);
    const auto* num = dynamic_cast<const Number*>(out[0].first.get());
    REQUIRE(num != nullptr);
    REQUIRE(std::holds_alternative<std::uint64_t>(num->value()));
    CHECK(std::get<std::uint64_t>(num->value()) == 0x80000002ULL);
}

TEST_CASE("insn: extract_number suppresses the number only for 'add esp, k'") {
    // capa's extract_op_number_features skips the immediate solely of
    // `add esp, imm` (the cdecl cleanup after a call), keyed on
    // opers[0].reg == REG_ESP. It does NOT skip `sub esp`, `add rsp`, or
    // `sub rsp` (viv/insn.py), so neither do we
    const auto* x86 = everything_image();   // 32-bit
    const auto* x64 = notepad_image();       // 64-bit
    if (x86 == nullptr || x64 == nullptr) {
        MESSAGE("fixtures missing, skipping");
        return;
    }
    REQUIRE_FALSE(x86->is_64bit());
    REQUIRE(x64->is_64bit());

    const auto arith = [](ZydisMnemonic m, ZydisRegister dst, std::uint64_t imm) {
        DecodedInsn ins = make_insn(0x401000, "x");
        ins.zyd_mnem = m;
        ins.operand_count = 2;
        ins.operands[0].kind = OperandKind::kReg;
        ins.operands[0].base_reg = dst;
        ins.operands[1].kind = OperandKind::kImm;
        ins.operands[1].imm = imm;
        return ins;
    };
    const auto has_number = [](const auto& out) {
        for (const auto& fa : out) {
            if (fa.first->tag() == FeatureTag::kNumber) { return true; }
        }
        return false;
    };

    // add esp, k -> suppressed (the one form capa skips)
    CHECK(extract_number(arith(ZYDIS_MNEMONIC_ADD, ZYDIS_REGISTER_ESP, 0x20U), *x86).empty());
    // sub esp, k -> Number kept (this closes the certutil_x86 sub esp, 0x64 FN)
    CHECK(has_number(extract_number(arith(ZYDIS_MNEMONIC_SUB, ZYDIS_REGISTER_ESP, 0x64U), *x86)));
    // add rsp, k -> Number kept (capa's REG_ESP check excludes the 64-bit rsp)
    CHECK(has_number(extract_number(arith(ZYDIS_MNEMONIC_ADD, ZYDIS_REGISTER_RSP, 0x20U), *x64)));
}

TEST_CASE("insn: extract_number adds Offset hint for 'add reg, small'") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    DecodedInsn ins = make_insn(0x401000, "add");
    ins.zyd_mnem = ZYDIS_MNEMONIC_ADD;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    ins.operands[1].kind = OperandKind::kImm;
    ins.operands[1].imm  = 0x10U;
    auto out = extract_number(ins, *img);
    // Expect Number + OperandNumber + Offset + OperandOffset
    REQUIRE(out.size() == 4);
    bool seen_offset = false;
    for (const auto& [feat, _addr] : out) {
        if (feat->tag() == FeatureTag::kOffset) { seen_offset = true; }
    }
    CHECK(seen_offset);
}

TEST_CASE("insn: extract_number does not add an Offset hint for 'sub reg, small'") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    // capa adds the struct-offset hint only for add, never sub, so a sub
    // immediate yields Number + OperandNumber but no Offset
    DecodedInsn ins = make_insn(0x401000, "sub");
    ins.zyd_mnem = ZYDIS_MNEMONIC_SUB;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    ins.operands[1].kind = OperandKind::kImm;
    ins.operands[1].imm  = 0x10U;
    auto out = extract_number(ins, *img);
    REQUIRE(out.size() == 2);
    for (const auto& [feat, _addr] : out) {
        CHECK(feat->tag() != FeatureTag::kOffset);
        CHECK(feat->tag() != FeatureTag::kOperandOffset);
    }
}

TEST_CASE("insn: extract_offset emits Offset + OperandOffset for non-stack base") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    DecodedInsn ins = make_insn(0x401000, "mov");
    ins.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[1].kind = OperandKind::kRegMem;
    ins.operands[1].base_reg = ZYDIS_REGISTER_EBX;
    ins.operands[1].disp = 0x20;
    auto out = extract_offset(ins, *img);
    REQUIRE(out.size() == 2);
    CHECK(out[0].first->tag() == FeatureTag::kOffset);
    CHECK(out[1].first->tag() == FeatureTag::kOperandOffset);
}

TEST_CASE("insn: extract_offset emits Offset(0) for a bare [reg] dereference") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    // capa yields offset(0) for [reg] with no displacement. The runtime-linking
    // rules count these mov reg, [reg] Flink walk steps via count(offset(0))
    DecodedInsn ins = make_insn(0x401000, "mov");
    ins.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[1].kind = OperandKind::kRegMem;
    ins.operands[1].base_reg = ZYDIS_REGISTER_EAX;
    ins.operands[1].disp = 0;
    auto out = extract_offset(ins, *img);
    REQUIRE(out.size() == 2);
    CHECK(out[0].first->tag() == FeatureTag::kOffset);
    CHECK(out[1].first->tag() == FeatureTag::kOperandOffset);
}

TEST_CASE("insn: extract_offset skips stack-frame relative accesses") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    DecodedInsn ins = make_insn(0x401000, "mov");
    ins.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[1].kind = OperandKind::kRegMem;
    ins.operands[1].base_reg = img->is_64bit() ? ZYDIS_REGISTER_RBP : ZYDIS_REGISTER_EBP;
    ins.operands[1].disp = 0x10;
    auto out = extract_offset(ins, *img);
    CHECK(out.empty());
}

TEST_CASE("insn: extract_offset keeps a SIB-encoded stack-base offset") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    // capa excludes the stack/frame base only for a plain [reg+disp] without a
    // SIB byte. [rsp+disp] forces a SIB byte (i386SibOper), so capa keeps its
    // offset and papa must too. The classification key is sib_encoded, not the
    // operand kind, since papa keys kind on the index register
    DecodedInsn ins = make_insn(0x401000, "mov");
    ins.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[1].kind = OperandKind::kRegMem;
    ins.operands[1].base_reg = img->is_64bit() ? ZYDIS_REGISTER_RSP : ZYDIS_REGISTER_ESP;
    ins.operands[1].disp = 0x10;
    ins.operands[1].sib_encoded = true;
    auto out = extract_offset(ins, *img);
    REQUIRE(out.size() == 2);
    CHECK(out[0].first->tag() == FeatureTag::kOffset);
    CHECK(out[1].first->tag() == FeatureTag::kOperandOffset);
}

TEST_CASE("insn: SIB-encoded gs:[0x30] yields an offset, never a number") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    // 65 48 8B 04 25 30 00 00 00 : mov rax, gs:[0x30]
    // This shape made papa over-emit number(0x30) and falsely match
    // get-process-heap-force-flags. capa treats the SIB displacement as an
    // offset only, so extract_number must stay silent and extract_offset must
    // surface Offset(0x30)
    papa::features::extractors::papa_native::Disassembler dis(true);
    const std::array<std::byte, 9> bytes{
        std::byte{0x65}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x04},
        std::byte{0x25}, std::byte{0x30}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}};
    const auto ins = dis.decode(std::span<const std::byte>(bytes), 0x401000);
    REQUIRE(ins.has_value());
    CHECK(ins->operands[1].kind == OperandKind::kSib);
    CHECK(extract_number(*ins, *img).empty());
    const auto offs = extract_offset(*ins, *img);
    REQUIRE(offs.size() == 2);
    CHECK(offs[0].first->tag() == FeatureTag::kOffset);
    CHECK(offs[1].first->tag() == FeatureTag::kOperandOffset);
    // The 0x30 is an absolute address (vivisect's i386SibOper.imm) with disp 0,
    // so capa surfaces offset(0), not offset(0x30). This is what lets the
    // runtime-linking rules count gs:[0x60] as one of their offset(0) steps
    CHECK(offs[0].first->to_string() == "offset(0)");
}

TEST_CASE("insn: lea with a SIB-encoded base surfaces an offset, never a number") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    // 49 8D 8C 24 B8 00 00 00 : lea rcx, [r12 + 0xB8]
    // r12 forces a SIB byte, so vivisect decodes the operand as i386SibOper and
    // capa emits no number from it: only the non-SIB i386RegMemOper lea surfaces
    // the displacement as a number (insn.py extract_op_offset_features). papa
    // over-emitted number(0xB8), falsely matching get-number-of-processors on
    // msedge at 0x14009a8d0
    papa::features::extractors::papa_native::Disassembler dis(true);
    const std::array<std::byte, 8> bytes{
        std::byte{0x49}, std::byte{0x8D}, std::byte{0x8C}, std::byte{0x24},
        std::byte{0xB8}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    const auto ins = dis.decode(std::span<const std::byte>(bytes), 0x401000);
    REQUIRE(ins.has_value());
    REQUIRE(ins->zyd_mnem == ZYDIS_MNEMONIC_LEA);
    REQUIRE(ins->operand_count == 2);

    bool has_number = false;
    bool has_offset = false;
    for (const auto& fa : extract_offset(*ins, *img)) {
        const auto t = fa.first->tag();
        if (t == FeatureTag::kNumber || t == FeatureTag::kOperandNumber) {
            has_number = true;
        }
        if (t == FeatureTag::kOffset || t == FeatureTag::kOperandOffset) {
            has_offset = true;
        }
    }
    CHECK(has_offset);
    CHECK_FALSE(has_number);
    // The number extractor itself never fires for a memory operand
    CHECK(extract_number(*ins, *img).empty());
}

// A non-SIB base+disp lea is i386RegMemOper, where capa does surface the
// displacement as a number, so papa must keep emitting it there
TEST_CASE("insn: lea with a non-SIB base surfaces the displacement as a number") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    // 48 8D 4B 10 : lea rcx, [rbx + 0x10]  (rbx needs no SIB byte)
    papa::features::extractors::papa_native::Disassembler dis(true);
    const std::array<std::byte, 4> bytes{
        std::byte{0x48}, std::byte{0x8D}, std::byte{0x4B}, std::byte{0x10}};
    const auto ins = dis.decode(std::span<const std::byte>(bytes), 0x401000);
    REQUIRE(ins.has_value());
    REQUIRE(ins->zyd_mnem == ZYDIS_MNEMONIC_LEA);
    bool has_number = false;
    for (const auto& fa : extract_offset(*ins, *img)) {
        const auto t = fa.first->tag();
        if (t == FeatureTag::kNumber || t == FeatureTag::kOperandNumber) {
            has_number = true;
        }
    }
    CHECK(has_number);
}

TEST_CASE("insn: extract_bytes returns empty for unreadable target") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    DecodedInsn ins = make_insn(0x401000, "mov");
    ins.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[1].kind = OperandKind::kImm;
    ins.operands[1].imm  = 0xDEADBEEFULL;     // outside any section
    auto out = extract_bytes(ins, *img);
    CHECK(out.empty());
}

TEST_CASE("insn: extract_string returns empty when target is unreadable") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    DecodedInsn ins = make_insn(0x401000, "mov");
    ins.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    ins.operand_count = 2;
    ins.operands[0].kind = OperandKind::kReg;
    ins.operands[1].kind = OperandKind::kImm;
    ins.operands[1].imm  = 0xDEADBEEFULL;
    auto out = extract_string(ins, *img);
    CHECK(out.empty());
}

namespace {

// Build a one-block function used as nzxor security-cookie test scaffold
// The block carries a configurable instruction list and the prologue/epilogue
// extents are derived from the first/last instruction
[[nodiscard]] Function make_function_with_block(std::vector<DecodedInsn> insns) {
    Function fn;
    fn.va = insns.empty() ? 0U : insns.front().va;
    BasicBlock bb;
    bb.va = fn.va;
    bb.instructions = std::move(insns);
    fn.basic_blocks.push_back(std::move(bb));
    return fn;
}

}  // namespace

TEST_CASE("insn: extract_nzxor fires on xor of distinct registers") {
    DecodedInsn xor_insn = make_insn(0x4000, "xor");
    xor_insn.zyd_mnem = ZYDIS_MNEMONIC_XOR;
    xor_insn.operand_count = 2;
    xor_insn.operands[0].kind = OperandKind::kReg;
    xor_insn.operands[0].base_reg = ZYDIS_REGISTER_EAX;
    xor_insn.operands[1].kind = OperandKind::kReg;
    xor_insn.operands[1].base_reg = ZYDIS_REGISTER_EBX;

    Function fn = make_function_with_block({xor_insn});
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

    Function fn = make_function_with_block({ins});
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

    Function fn = make_function_with_block({cookie});
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

    Function fn = make_function_with_block({ins});
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

    Function fn = make_function_with_block({def_insn, call_insn});
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

    Function fn = make_function_with_block({def_insn, call_insn});
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
    Function fn = make_function_with_block({partial, call_insn});
    auto def = papa::features::extractors::papa_native::find_definition(
        fn, 0x4002U, ZYDIS_REGISTER_RAX, /*is_64bit=*/true);
    CHECK_FALSE(def.has_value());
}

TEST_CASE("indirect_calls: find_definition returns nullopt with no preceding write") {
    auto call_insn = make_call_reg(0x4000, ZYDIS_REGISTER_EAX);
    Function fn = make_function_with_block({call_insn});
    auto def = papa::features::extractors::papa_native::find_definition(
        fn, 0x4000U, ZYDIS_REGISTER_EAX, false);
    CHECK_FALSE(def.has_value());
}

TEST_CASE("insn: build_import_table indexes imports by their IAT VA") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto table = papa::features::extractors::papa_native::build_import_table(*img);
    CHECK(table.by_iat_va.size() > 0U);
    // Every entry's recorded IAT VA must round-trip back to the original row
    for (const auto& [va, row] : table.by_iat_va) {
        REQUIRE(row != nullptr);
        CHECK(row->iat_va == va);
    }
}

TEST_CASE("insn: extract_cross_section_flow flags an indirect call through a non-import data slot") {
    const auto* img = chrome_image();
    if (img == nullptr) {
        MESSAGE("chrome.exe fixture missing, skipping");
        return;
    }
    papa::features::extractors::papa_native::Disassembler dis(img->is_64bit());
    const auto table = papa::features::extractors::papa_native::build_import_table(*img);

    const auto decode_at = [&](std::uint64_t va) -> DecodedInsn {
        const auto bytes = img->read_at_rva(va - img->image_base(), 16);
        REQUIRE(bytes.has_value());
        auto ins = dis.decode(*bytes, va);
        REQUIRE(ins.has_value());
        return *ins;
    };

    // 0x14003da3b: call qword ptr [rip+0x265d9f] reads a function pointer from a
    // .rdata slot (not the IAT) in a different section than the .text call site.
    // capa emits "cross section flow" here, so papa must too
    CHECK(extract_cross_section_flow(decode_at(0x14003da3bULL), *img, table).has_value());

    // 0x14003d856: a call to the VirtualAllocEx IAT slot. capa skips import
    // calls, so this must not be flagged as cross-section flow
    CHECK_FALSE(extract_cross_section_flow(decode_at(0x14003d856ULL), *img, table).has_value());
}

TEST_CASE("insn: extract_api_features ignores non-call instructions") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    papa::features::extractors::papa_native::Disassembler disasm(img->is_64bit());
    auto table = papa::features::extractors::papa_native::build_import_table(*img);

    DecodedInsn ins = make_insn(0x401000, "mov");
    ins.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    ins.is_call  = false;
    Function fn = make_function_with_block({ins});

    auto out = papa::features::extractors::papa_native::insn::extract_api_features(
        fn, fn.basic_blocks[0], ins, *img, table, disasm);
    CHECK(out.empty());
}

TEST_CASE("insn: extract_api_features yields names when target hits the IAT") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    papa::features::extractors::papa_native::Disassembler disasm(img->is_64bit());
    auto table = papa::features::extractors::papa_native::build_import_table(*img);

    // Pick any IAT VA from the table to drive the kImmMem path
    REQUIRE_FALSE(table.by_iat_va.empty());
    const std::uint64_t iat_va = table.by_iat_va.begin()->first;

    DecodedInsn ins = make_insn(0x401000, "call");
    ins.zyd_mnem = ZYDIS_MNEMONIC_CALL;
    ins.is_call  = true;
    ins.length   = 6;
    ins.operand_count = 1;
    ins.operands[0].kind = OperandKind::kImmMem;
    ins.operands[0].disp = static_cast<std::int64_t>(iat_va);

    Function fn = make_function_with_block({ins});
    auto out = papa::features::extractors::papa_native::insn::extract_api_features(
        fn, fn.basic_blocks[0], ins, *img, table, disasm);
    CHECK_FALSE(out.empty());
    for (const auto& [feat, _addr] : out) {
        CHECK(feat->tag() == FeatureTag::kApi);
    }
}

TEST_CASE("insn: extract_api_features returns nothing when no IAT match found") {
    const auto* img = notepad_image();
    if (img == nullptr) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    papa::features::extractors::papa_native::Disassembler disasm(img->is_64bit());
    auto table = papa::features::extractors::papa_native::build_import_table(*img);

    DecodedInsn ins = make_insn(0x401000, "call");
    ins.zyd_mnem = ZYDIS_MNEMONIC_CALL;
    ins.is_call  = true;
    ins.length   = 6;
    ins.operand_count = 1;
    ins.operands[0].kind = OperandKind::kImmMem;
    ins.operands[0].disp = 0xDEADBEEF;             // no IAT lives there

    Function fn = make_function_with_block({ins});
    auto out = papa::features::extractors::papa_native::insn::extract_api_features(
        fn, fn.basic_blocks[0], ins, *img, table, disasm);
    CHECK(out.empty());
}
