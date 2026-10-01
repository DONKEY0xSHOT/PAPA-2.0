#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/function.h"

#include <Zydis/Zydis.h>

#include <cstdint>

using papa::features::extractors::papa_native::BasicBlock;
using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::DecodedOperand;
using papa::features::extractors::papa_native::Function;
using papa::features::extractors::papa_native::function_::is_thunk;
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

TEST_CASE("is_thunk: flags single-block jmp [iat] functions") {
    const auto fn = make_single_insn_function(make_jmp_iat(0x1000));
    CHECK(is_thunk(fn));
}

TEST_CASE("is_thunk: rejects multi-block functions") {
    auto fn = make_single_insn_function(make_jmp_iat(0x1000));
    BasicBlock bb2;
    bb2.va = 0x2000;
    fn.basic_blocks.push_back(std::move(bb2));
    CHECK_FALSE(is_thunk(fn));
}

TEST_CASE("is_thunk: rejects multi-instruction blocks") {
    DecodedInsn extra;
    extra.va = 0x1006;
    extra.length = 1;
    auto fn = make_single_insn_function(make_jmp_iat(0x1000));
    fn.basic_blocks.front().instructions.push_back(std::move(extra));
    CHECK_FALSE(is_thunk(fn));
}

TEST_CASE("is_thunk: rejects conditional jumps and register operands") {
    {
        auto cond = make_jmp_iat(0x1000);
        cond.is_conditional = true;
        const auto fn = make_single_insn_function(std::move(cond));
        CHECK_FALSE(is_thunk(fn));
    }
    {
        auto reg = make_jmp_iat(0x1000);
        reg.operands[0].kind = OperandKind::kReg;
        const auto fn = make_single_insn_function(std::move(reg));
        CHECK_FALSE(is_thunk(fn));
    }
}
