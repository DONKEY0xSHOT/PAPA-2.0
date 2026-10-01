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
#include <string_view>
#include <utility>
#include <vector>

#include "test_support.h"

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

TEST_CASE("basic_block: extract_tight_loop fires only when a successor is the block itself") {
    struct Row {
        std::string_view           label;
        std::vector<std::uint64_t> successors;
        bool                       fires;
    };
    const std::vector<Row> rows{
        {"a successor equal to the block VA", {0x4000}, true},
        {"a successor elsewhere", {0x5000}, false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        BasicBlock bb;
        bb.va = 0x4000;
        bb.successors = row.successors;
        const auto r = extract_tight_loop(bb);
        CHECK(r.has_value() == row.fires);
        if (r.has_value() && row.fires) {
            CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "tight loop");
        }
    }
}

TEST_CASE("basic_block: extract_stack_string needs a run of printable bytes stored to the stack") {
    struct Row {
        std::string_view         label;
        std::vector<DecodedInsn> insns;
        bool                     fires;
    };
    const std::vector<Row> rows{
        // Two consecutive 4-byte stores of "ABCD" and "EFGH", little-endian, form an 8-byte run
        {"8 printable bytes via two dword stores",
         {make_mov_stack_imm(0x4000, ZYDIS_REGISTER_ESP, 0x00, 0x44434241U, 4),
          make_mov_stack_imm(0x4007, ZYDIS_REGISTER_ESP, 0x04, 0x48474645U, 4)},
         true},
        {"a store that does not go to the stack",
         {make_mov_stack_imm(0x4000, ZYDIS_REGISTER_EAX, 0x00, 0x44434241U, 4)}, false},
        {"non-printable bytes reset the run",
         {make_mov_stack_imm(0x4000, ZYDIS_REGISTER_ESP, 0x00, 0x00010203U, 4)}, false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        BasicBlock bb;
        bb.va = 0x4000;
        bb.instructions = row.insns;
        const auto r = extract_stack_string(bb, /*is_64bit=*/false);
        CHECK(r.has_value() == row.fires);
        if (r.has_value() && row.fires) {
            CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "stack string");
        }
    }
}

TEST_CASE("function: extract_loop fires on a cycle of two or more blocks, as capa counts loops") {
    // Each block is its VA and its successors, the first block being the entry
    using Graph = std::vector<std::pair<std::uint64_t, std::vector<std::uint64_t>>>;
    struct Row {
        std::string_view label;
        Graph            graph;
        bool             loop;
    };
    const std::vector<Row> rows{
        {"a back-edge forming a 2-node cycle", {{0x4000, {0x4010}}, {0x4010, {0x4000}}}, true},
        {"an acyclic CFG", {{0x4000, {0x4010}}, {0x4010, {}}}, false},
        {"a single node without a self-edge", {{0x4000, {}}}, false},
        // A size-one component, which capa does not count
        {"a lone self-loop", {{0x4000, {0x4000, 0x4010}}, {0x4010, {}}}, false},
        // The last block is reached twice, but no path returns
        {"reconverging paths",
         {{0x4000, {0x4010, 0x4020}}, {0x4010, {0x4030}}, {0x4020, {0x4030}}, {0x4030, {}}}, false},
        {"a cycle reached only from a later block",
         {{0x4000, {}}, {0x4010, {0x4020}}, {0x4020, {0x4010}}}, true},
        // A jcc to the next block gives two identical edges
        {"several entry-less blocks and duplicate edges",
         {{0x4000, {}}, {0x4010, {0x4020, 0x4020}}, {0x4020, {}}}, false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        std::vector<BasicBlock> blocks;
        for (const auto& [va, successors] : row.graph) {
            BasicBlock bb;
            bb.va = va;
            bb.successors = successors;
            blocks.push_back(std::move(bb));
        }
        const auto r = extract_loop(papa_tests::function(std::move(blocks)));
        CHECK(r.has_value() == row.loop);
        if (r.has_value() && row.loop) {
            CHECK(static_cast<const Characteristic*>(r->first.get())->value() == "loop");
        }
    }
}

namespace {

// A straight chain of blocks, optionally closed back to the entry
[[nodiscard]] Function block_chain(std::size_t count, bool close_cycle) {
    Function fn;
    fn.va = 0x10000;
    fn.basic_blocks.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        BasicBlock bb;
        bb.va = fn.va + (2 * i);
        if (i + 1 < count) {
            bb.successors.push_back(bb.va + 2);
        } else if (close_cycle) {
            bb.successors.push_back(fn.va);
        }
        fn.basic_blocks.push_back(std::move(bb));
    }
    return fn;
}

}  // namespace

TEST_CASE("function: extract_loop survives a 300k-block chain") {
    CHECK_FALSE(extract_loop(block_chain(300000, false)).has_value());
    CHECK(extract_loop(block_chain(300000, true)).has_value());
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
