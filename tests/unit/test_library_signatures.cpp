#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/library_signatures.h"

#include <Zydis/Zydis.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

using papa::features::extractors::papa_native::BasicBlock;
using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::DecodedOperand;
using papa::features::extractors::papa_native::Function;
using papa::features::extractors::papa_native::LibrarySignatureSet;
using papa::features::extractors::papa_native::OperandKind;
using papa::features::extractors::papa_native::PrologueSignature;
using papa::features::extractors::papa_native::parse_signature_entry;

namespace {

/// Build a single-block, single-instruction function used to exercise the
/// thunk classifier.
[[nodiscard]] Function make_single_insn_function(DecodedInsn ins) {
    Function fn;
    fn.va = ins.va;
    BasicBlock bb;
    bb.va = ins.va;
    bb.instructions.push_back(std::move(ins));
    fn.basic_blocks.push_back(std::move(bb));
    return fn;
}

[[nodiscard]] DecodedInsn make_jmp_iat(std::uint64_t va) {
    DecodedInsn d;
    d.va = va;
    d.length = 6;
    d.is_jump = true;
    d.is_conditional = false;
    d.operand_count = 1;
    d.operands[0].kind = OperandKind::kRipRel;
    d.operands[0].disp = 0x100;
    return d;
}

}  // namespace

TEST_CASE("library_signatures: parse_signature_entry accepts hex pairs and ?? wildcards") {
    auto sig = parse_signature_entry("test", "AA BB ?? CC");
    REQUIRE(sig.has_value());
    CHECK(sig->name == "test");
    REQUIRE(sig->bytes.size() == 4);
    REQUIRE(sig->bytes[0].has_value());
    CHECK(*sig->bytes[0] == 0xAA);
    CHECK(*sig->bytes[1] == 0xBB);
    CHECK_FALSE(sig->bytes[2].has_value());
    CHECK(*sig->bytes[3] == 0xCC);
}

TEST_CASE("library_signatures: parse_signature_entry rejects malformed input") {
    CHECK_FALSE(parse_signature_entry("", "").has_value());
    CHECK_FALSE(parse_signature_entry("bad", "Z1").has_value());
    CHECK_FALSE(parse_signature_entry("trailing", "AA B").has_value());
}

TEST_CASE("library_signatures: matches_signature obeys wildcard slots") {
    LibrarySignatureSet set;
    std::vector<PrologueSignature> sigs;
    sigs.push_back(*parse_signature_entry("p1", "48 83 EC 28 E8 ?? ?? ?? ??"));
    set.set_signatures(std::move(sigs));

    // Exact opcode bytes match; the four 0x?? slots are free
    const std::array<std::uint8_t, 9> match{
        0x48, 0x83, 0xEC, 0x28, 0xE8, 0xDE, 0xAD, 0xBE, 0xEF};
    CHECK(set.matches_signature(std::span<const std::uint8_t>(match)));

    // Different leading byte should miss
    const std::array<std::uint8_t, 9> miss{
        0x49, 0x83, 0xEC, 0x28, 0xE8, 0xDE, 0xAD, 0xBE, 0xEF};
    CHECK_FALSE(set.matches_signature(std::span<const std::uint8_t>(miss)));

    // Buffer shorter than the signature is not a match
    const std::array<std::uint8_t, 4> too_short{0x48, 0x83, 0xEC, 0x28};
    CHECK_FALSE(set.matches_signature(std::span<const std::uint8_t>(too_short)));
}

TEST_CASE("library_signatures: is_thunk flags single-block jmp [iat] functions") {
    const auto fn = make_single_insn_function(make_jmp_iat(0x1000));
    CHECK(LibrarySignatureSet::is_thunk(fn));
}

TEST_CASE("library_signatures: is_thunk rejects multi-block functions") {
    auto fn = make_single_insn_function(make_jmp_iat(0x1000));
    BasicBlock bb2;
    bb2.va = 0x2000;
    fn.basic_blocks.push_back(std::move(bb2));
    CHECK_FALSE(LibrarySignatureSet::is_thunk(fn));
}

TEST_CASE("library_signatures: is_thunk rejects multi-instruction blocks") {
    DecodedInsn extra;
    extra.va = 0x1006;
    extra.length = 1;
    auto fn = make_single_insn_function(make_jmp_iat(0x1000));
    fn.basic_blocks.front().instructions.push_back(std::move(extra));
    CHECK_FALSE(LibrarySignatureSet::is_thunk(fn));
}

TEST_CASE("library_signatures: is_thunk rejects conditional jumps and register operands") {
    {
        auto cond = make_jmp_iat(0x1000);
        cond.is_conditional = true;
        const auto fn = make_single_insn_function(std::move(cond));
        CHECK_FALSE(LibrarySignatureSet::is_thunk(fn));
    }
    {
        auto reg = make_jmp_iat(0x1000);
        reg.operands[0].kind = OperandKind::kReg;
        const auto fn = make_single_insn_function(std::move(reg));
        CHECK_FALSE(LibrarySignatureSet::is_thunk(fn));
    }
}

TEST_CASE("library_signatures: classify_as_library combines thunk + pattern checks") {
    LibrarySignatureSet set;
    std::vector<PrologueSignature> sigs;
    sigs.push_back(*parse_signature_entry("crt", "48 83 EC 28 E8 ?? ?? ?? ??"));
    set.set_signatures(std::move(sigs));

    Function not_a_thunk;
    not_a_thunk.va = 0x1000;
    BasicBlock bb;
    bb.va = 0x1000;
    DecodedInsn ins1;
    ins1.va = 0x1000;
    ins1.length = 4;
    bb.instructions.push_back(std::move(ins1));
    DecodedInsn ins2;
    ins2.va = 0x1004;
    ins2.length = 1;
    bb.instructions.push_back(std::move(ins2));
    not_a_thunk.basic_blocks.push_back(std::move(bb));

    const std::array<std::uint8_t, 9> bytes{
        0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00, 0x00, 0x00, 0x00};
    CHECK(set.classify_as_library(not_a_thunk,
        std::span<const std::uint8_t>(bytes)));

    // Same function shape with non-matching prologue stays application code
    const std::array<std::uint8_t, 9> different{
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x90};
    CHECK_FALSE(set.classify_as_library(not_a_thunk,
        std::span<const std::uint8_t>(different)));
}

TEST_CASE("library_signatures: make_default loads the bundled MSVC CRT pack") {
    const auto set = LibrarySignatureSet::make_default();
    CHECK(set.signatures().size() >= 8U);
    for (const auto& sig : set.signatures()) {
        CHECK_FALSE(sig.name.empty());
        CHECK_FALSE(sig.bytes.empty());
    }
}
