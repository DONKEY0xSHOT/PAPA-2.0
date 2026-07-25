#include <cstdint>
#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/viv/codeblocks.h"

namespace pv = papa::features::extractors::papa_native::viv;

namespace {

// A no-fall predicate that never fires, for tests that do not exercise IF_NOFALL
bool never_no_fall(std::uint64_t) {
    return false;
}

// A parse predicate that always succeeds, for tests whose locations all decode
bool always_parses(std::uint64_t) {
    return true;
}

}  // namespace

TEST_CASE("codeblocks builds one straight-line block ending where locations end (Stop-A)") {
    pv::LocationDb loc;
    // Three ops covering 0x1000..0x1005, then nothing at 0x1005
    loc.add_location(0x1000, 2, pv::LocType::kOp);
    loc.add_location(0x1002, 2, pv::LocType::kOp);
    loc.add_location(0x1004, 1, pv::LocType::kOp);
    const pv::XrefDb  xrefs;
    pv::CodeBlockStore store;

    pv::analyze_function(loc, xrefs, never_no_fall, always_parses, 0x1000, store);

    const auto& blocks = store.function_blocks(0x1000);
    REQUIRE(blocks.size() == 1);
    CHECK(blocks[0].va == 0x1000);
    CHECK(blocks[0].size == 5);  // truncated at 0x1005, the first undefined address
    CHECK(blocks[0].function_va == 0x1000);
    // The single owner of the block start is this block
    const auto owned = store.code_block(0x1000);
    REQUIRE(owned.has_value());
    CHECK(owned->size == 5);
}

TEST_CASE("codeblocks truncates the block at the first undefined address") {
    pv::LocationDb loc;
    loc.add_location(0x2000, 2, pv::LocType::kOp);
    // nothing at 0x2002
    const pv::XrefDb  xrefs;
    pv::CodeBlockStore store;

    pv::analyze_function(loc, xrefs, never_no_fall, always_parses, 0x2000, store);

    const auto& blocks = store.function_blocks(0x2000);
    REQUIRE(blocks.size() == 1);
    CHECK(blocks[0].va == 0x2000);
    CHECK(blocks[0].size == 2);
}

TEST_CASE("codeblocks splits a block at a branch (Split-B), starting blocks at target and fall-through") {
    pv::LocationDb loc;
    loc.add_location(0x1000, 2, pv::LocType::kOp);  // conditional jump to 0x1010
    loc.add_location(0x1002, 2, pv::LocType::kOp);  // fall-through block
    // 0x1004 undefined
    loc.add_location(0x1010, 1, pv::LocType::kOp);  // branch-target block
    // 0x1011 undefined
    pv::XrefDb xrefs;
    xrefs.add_code_xref(0x1000, 0x1010, pv::kBrCond);
    pv::CodeBlockStore store;

    pv::analyze_function(loc, xrefs, never_no_fall, always_parses, 0x1000, store);

    const auto& blocks = store.function_blocks(0x1000);
    REQUIRE(blocks.size() == 3);
    CHECK(blocks[0].va == 0x1000);
    CHECK(blocks[0].size == 2);  // ends at the branch instruction's next address
    CHECK(blocks[1].va == 0x1002);
    CHECK(blocks[1].size == 2);
    CHECK(blocks[2].va == 0x1010);
    CHECK(blocks[2].size == 1);
}

TEST_CASE("codeblocks splits a block at a join (Split-C), an address with an inbound xref") {
    pv::LocationDb loc;
    loc.add_location(0x2000, 2, pv::LocType::kOp);
    loc.add_location(0x2002, 2, pv::LocType::kOp);
    loc.add_location(0x2004, 2, pv::LocType::kOp);  // reached from outside, so a block start
    // 0x2006 undefined
    pv::XrefDb xrefs;
    xrefs.add_code_xref(0x9000, 0x2004, pv::kBrCond);  // an external branch into 0x2004
    pv::CodeBlockStore store;

    pv::analyze_function(loc, xrefs, never_no_fall, always_parses, 0x2000, store);

    const auto& blocks = store.function_blocks(0x2000);
    REQUIRE(blocks.size() == 2);
    CHECK(blocks[0].va == 0x2000);
    CHECK(blocks[0].size == 4);  // ends where the join begins
    CHECK(blocks[1].va == 0x2004);
    CHECK(blocks[1].size == 2);
}

TEST_CASE("codeblocks ends a block after a no-fall instruction (IF_NOFALL)") {
    pv::LocationDb loc;
    loc.add_location(0x3000, 2, pv::LocType::kOp);
    loc.add_location(0x3002, 1, pv::LocType::kOp);  // a no-fall instruction (e.g. ret)
    loc.add_location(0x3003, 2, pv::LocType::kOp);  // must NOT be pulled into the block
    pv::XrefDb xrefs;
    const auto no_fall = [](std::uint64_t va) { return va == 0x3002; };
    pv::CodeBlockStore store;

    pv::analyze_function(loc, xrefs, no_fall, always_parses, 0x3000, store);

    const auto& blocks = store.function_blocks(0x3000);
    REQUIRE(blocks.size() == 1);
    CHECK(blocks[0].va == 0x3000);
    CHECK(blocks[0].size == 3);  // 0x3000..0x3003, ending after the no-fall op
}

TEST_CASE("CodeBlockStore keeps a shared block in every owning function and records the last owner") {
    pv::CodeBlockStore store;
    // The same block start is registered by two functions, a shared block
    store.add_code_block(0x1500, 0x10, /*function_va=*/0x1000);
    store.add_code_block(0x1500, 0x10, /*function_va=*/0x2000);

    // Multi-owner: the block appears in both functions' lists (getFunctionBlocks)
    REQUIRE(store.function_blocks(0x1000).size() == 1);
    CHECK(store.function_blocks(0x1000)[0].va == 0x1500);
    REQUIRE(store.function_blocks(0x2000).size() == 1);
    CHECK(store.function_blocks(0x2000)[0].va == 0x1500);

    // Single-owner: the last writer owns the block start (getCodeBlock)
    const auto owner = store.code_block(0x1500);
    REQUIRE(owner.has_value());
    CHECK(owner->function_va == 0x2000);
}

TEST_CASE("codeblocks drops a function whose flow reaches an unparseable op (bad-opcode break)") {
    // The enclosing function's entry parses, but its flow marches into a region
    // an overlapping decode left claiming LOC_OP at an address whose bytes do not
    // decode. vivisect breaks the walk there without recording the block, so the
    // function ends with zero blocks. This is the FLIRT overlap graph-build
    // failure (cmd_x64 0x1400303ac)
    pv::LocationDb loc;
    loc.add_location(0x1000, 2, pv::LocType::kOp);  // entry, parses
    loc.add_location(0x1002, 2, pv::LocType::kOp);  // reached, but does not parse
    // 0x1004 onward undefined
    const pv::XrefDb   xrefs;
    pv::CodeBlockStore store;
    // Only 0x1002 fails to reparse, mimicking the misaligned overlap byte
    const auto can_parse = [](std::uint64_t va) { return va != 0x1002; };

    pv::analyze_function(loc, xrefs, never_no_fall, can_parse, 0x1000, store);

    // The block starting 0x1000 never gets a size (the walk broke before Stop-A),
    // so Skip-D drops it and the function has no blocks
    CHECK(store.function_blocks(0x1000).empty());
}

TEST_CASE("codeblocks drops a function whose entry is undefined (Skip-D, zero size)") {
    const pv::LocationDb loc;  // empty: nothing defined at the entry
    const pv::XrefDb     xrefs;
    pv::CodeBlockStore   store;

    pv::analyze_function(loc, xrefs, never_no_fall, always_parses, 0x3000, store);

    // The entry block has size 0, so no block is registered
    CHECK(store.function_blocks(0x3000).empty());
}
