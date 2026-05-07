#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/basic_block.h"
#include "papa/features/extractors/papa_native/function.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using papa::features::Characteristic;
using papa::features::FeatureTag;
using papa::features::FunctionName;
using papa::features::extractors::papa_native::BasicBlock;
using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::DecodedOperand;
using papa::features::extractors::papa_native::Function;
using papa::features::extractors::papa_native::OperandKind;
using papa::features::extractors::papa_native::basic_block::extract_basic_block_features;
using papa::features::extractors::papa_native::basic_block::extract_stack_string;
using papa::features::extractors::papa_native::basic_block::extract_tight_loop;
using papa::features::extractors::papa_native::function_::extract_calls_from;
using papa::features::extractors::papa_native::function_::extract_calls_to;
using papa::features::extractors::papa_native::function_::extract_function_name;
using papa::features::extractors::papa_native::function_::extract_loop;
using papa::features::extractors::papa_native::function_::extract_recursive_call;

namespace {

[[nodiscard]] DecodedInsn make_call(std::uint64_t va, std::uint64_t target) {
    DecodedInsn d;
    d.va = va;
    d.length = 5;
    d.zyd_mnem = ZYDIS_MNEMONIC_CALL;
    d.is_call  = true;
    d.branch_target = target;
    d.operand_count = 1;
    d.operands[0].kind = OperandKind::kPcRel;
    d.operands[0].imm  = target;
    return d;
}

[[nodiscard]] DecodedInsn make_mov_stack_imm(std::uint64_t va,
                                             ZydisRegister stack_base,
                                             std::int64_t  disp,
                                             std::uint64_t imm,
                                             std::size_t   width) {
    DecodedInsn d;
    d.va = va;
    d.length = 7;
    d.zyd_mnem = ZYDIS_MNEMONIC_MOV;
    d.operand_count = 2;
    d.operands[0].kind = OperandKind::kRegMem;
    d.operands[0].base_reg = stack_base;
    d.operands[0].disp = disp;
    d.operands[1].kind = OperandKind::kImm;
    d.operands[1].imm  = imm;
    d.operands[1].width_bytes = width;
    return d;
}

}  // namespace

TEST_CASE("basic_block: extract_tight_loop fires when a successor equals the BB VA") {
    BasicBlock bb;
    bb.va = 0x4000;
    bb.successors.push_back(0x4000);
    auto r = extract_tight_loop(bb);
    REQUIRE(r.has_value());
    CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "tight loop");
}

TEST_CASE("basic_block: extract_tight_loop ignores non-self successors") {
    BasicBlock bb;
    bb.va = 0x4000;
    bb.successors.push_back(0x5000);
    CHECK_FALSE(extract_tight_loop(bb).has_value());
}

TEST_CASE("basic_block: extract_stack_string detects 8 printable bytes via two dword stores") {
    BasicBlock bb;
    bb.va = 0x4000;
    // Two consecutive 4-byte stores of "ABCD" + "EFGH" form an 8-byte run
    bb.instructions.push_back(make_mov_stack_imm(
        0x4000, ZYDIS_REGISTER_ESP, 0x00,
        /*imm=*/0x44434241U /* "ABCD" little-endian */, /*width=*/4));
    bb.instructions.push_back(make_mov_stack_imm(
        0x4007, ZYDIS_REGISTER_ESP, 0x04,
        /*imm=*/0x48474645U /* "EFGH" little-endian */, /*width=*/4));
    auto r = extract_stack_string(bb, /*is_64bit=*/false);
    REQUIRE(r.has_value());
    CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "stack string");
}

TEST_CASE("basic_block: extract_stack_string ignores non-stack stores") {
    BasicBlock bb;
    bb.va = 0x4000;
    bb.instructions.push_back(make_mov_stack_imm(
        0x4000, ZYDIS_REGISTER_EAX, 0x00, 0x44434241U, 4));
    CHECK_FALSE(extract_stack_string(bb, false).has_value());
}

TEST_CASE("basic_block: extract_stack_string resets on non-printable byte") {
    BasicBlock bb;
    bb.va = 0x4000;
    bb.instructions.push_back(make_mov_stack_imm(
        0x4000, ZYDIS_REGISTER_ESP, 0x00, 0x00010203U, 4));   // non-printable bytes
    CHECK_FALSE(extract_stack_string(bb, false).has_value());
}

TEST_CASE("function: extract_loop detects a non-trivial SCC") {
    Function fn;
    fn.va = 0x4000;
    BasicBlock a;
    a.va = 0x4000;
    a.successors.push_back(0x4010);
    BasicBlock b;
    b.va = 0x4010;
    b.successors.push_back(0x4000);   // back-edge forms a 2-node cycle
    fn.basic_blocks.push_back(std::move(a));
    fn.basic_blocks.push_back(std::move(b));
    auto r = extract_loop(fn);
    REQUIRE(r.has_value());
    CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "loop");
}

TEST_CASE("function: extract_loop ignores acyclic CFGs") {
    Function fn;
    fn.va = 0x4000;
    BasicBlock a;
    a.va = 0x4000;
    a.successors.push_back(0x4010);
    BasicBlock b;
    b.va = 0x4010;
    fn.basic_blocks.push_back(std::move(a));
    fn.basic_blocks.push_back(std::move(b));
    CHECK_FALSE(extract_loop(fn).has_value());
}

TEST_CASE("function: extract_loop ignores trivial single-node SCCs without self-edge") {
    Function fn;
    fn.va = 0x4000;
    BasicBlock only;
    only.va = 0x4000;
    fn.basic_blocks.push_back(std::move(only));
    CHECK_FALSE(extract_loop(fn).has_value());
}

TEST_CASE("function: extract_calls_from emits one feature per resolvable call") {
    Function fn;
    fn.va = 0x4000;
    BasicBlock bb;
    bb.va = 0x4000;
    bb.instructions.push_back(make_call(0x4000, 0x5000));
    bb.instructions.push_back(make_call(0x4005, 0x6000));
    fn.basic_blocks.push_back(std::move(bb));
    auto out = extract_calls_from(fn);
    CHECK(out.size() == 2);
}

TEST_CASE("function: extract_calls_to mirrors fn.callers populated by CFG") {
    Function fn;
    fn.va = 0x4000;
    fn.callers = {0x3000, 0x3500};
    auto out = extract_calls_to(fn);
    CHECK(out.size() == 2);
    for (const auto& [feat, _addr] : out) {
        CHECK(feat->tag() == FeatureTag::kCharacteristic);
        CHECK(static_cast<const Characteristic*>(feat.get())->value() == "calls to");
    }
}

TEST_CASE("function: extract_recursive_call fires on a self-call") {
    Function fn;
    fn.va = 0x4000;
    BasicBlock bb;
    bb.va = 0x4000;
    bb.instructions.push_back(make_call(0x4010, /*target=*/0x4000));
    fn.basic_blocks.push_back(std::move(bb));
    auto r = extract_recursive_call(fn);
    REQUIRE(r.has_value());
    CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "recursive call");
}

TEST_CASE("function: extract_function_name only emits when symbol is non-empty") {
    Function fn;
    fn.va = 0x4000;
    CHECK_FALSE(extract_function_name(fn, "").has_value());
    auto r = extract_function_name(fn, "MyFunction");
    REQUIRE(r.has_value());
    CHECK(static_cast<const FunctionName*>(r->first.get())->value() == "MyFunction");
}
