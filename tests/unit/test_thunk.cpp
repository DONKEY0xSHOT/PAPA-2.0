#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/function.h"

#include <Zydis/Zydis.h>

#include "test_support.h"

#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

using papa::features::extractors::papa_native::BasicBlock;
using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::DecodedOperand;
using papa::features::extractors::papa_native::function_::is_thunk;
using papa::features::extractors::papa_native::OperandKind;

namespace {

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

TEST_CASE("is_thunk: flags only a function of one block holding one unconditional jmp [iat]") {
    using papa::features::extractors::papa_native::Function;
    const auto with = [](auto change) {
        auto fn = papa_tests::single_block_function({make_jmp_iat(0x1000)});
        change(fn);
        return fn;
    };
    struct Row {
        std::string_view label;
        Function         fn;
        bool             thunk;
    };
    const std::vector<Row> rows{
        {"a single-block jmp [iat] function", with([](Function&) {}), true},
        {"a second block", with([](Function& fn) {
             BasicBlock bb2;
             bb2.va = 0x2000;
             fn.basic_blocks.push_back(std::move(bb2));
         }),
         false},
        {"a second instruction in the block", with([](Function& fn) {
             DecodedInsn extra;
             extra.va = 0x1006;
             extra.length = 1;
             fn.basic_blocks.front().instructions.push_back(std::move(extra));
         }),
         false},
        {"a conditional jump", with([](Function& fn) {
             fn.basic_blocks.front().instructions.front().is_conditional = true;
         }),
         false},
        {"a register operand", with([](Function& fn) {
             fn.basic_blocks.front().instructions.front().operands[0].kind = OperandKind::kReg;
         }),
         false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(is_thunk(row.fn) == row.thunk);
    }
}
