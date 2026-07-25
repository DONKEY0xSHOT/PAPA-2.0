#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/library_signatures.h"

#include <Zydis/Zydis.h>

#include <cstdint>
#include <span>

using papa::features::extractors::papa_native::BasicBlock;
using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::DecodedOperand;
using papa::features::extractors::papa_native::Function;
using papa::features::extractors::papa_native::LibrarySignatureSet;
using papa::features::extractors::papa_native::OperandKind;

namespace {

/// Build a single-block, single-instruction function used to exercise the
/// thunk classifier
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

TEST_CASE("library_signatures: classify_as_library flags a thunk regardless of bytes") {
    const auto set = LibrarySignatureSet::make_default();
    const auto fn = make_single_insn_function(make_jmp_iat(0x1000));
    // A thunk is library code by structure alone, so FLIRT is never consulted
    CHECK(set.classify_as_library(fn, std::span<const std::uint8_t>{}));
}

TEST_CASE("library_signatures: make_default carries the embedded FLIRT set") {
    const auto sigs = LibrarySignatureSet::make_default();
#if defined(_WIN32) && defined(_MSC_VER)
    CHECK(sigs.flirt_tree_count() == 3U);
#else
    CHECK(sigs.flirt_tree_count() == 0U);
#endif
}
