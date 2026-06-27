// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the PAPA authors

// MSVC: <ostream> must precede doctest so std::string pretty-printing compiles
#include <ostream>

#include "doctest.h"

#include "papa/constants.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/jump_tables.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>
#include <vector>
#include "fixture_paths.h"

using papa::features::extractors::papa_native::BasicBlock;
using papa::features::extractors::papa_native::Cfg;
using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::Disassembler;
using papa::features::extractors::papa_native::Function;
using papa::features::extractors::papa_native::JumpTableResolver;
using papa::features::extractors::papa_native::JumpTableTargets;
using papa::features::extractors::papa_native::PdataEntryKind;

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");

// Helper to construct a byte array from an integer list
template <typename... B>
constexpr auto make_bytes(B... bs) {
    return std::array<std::byte, sizeof...(B)>{ std::byte{static_cast<std::uint8_t>(bs)}... };
}

// Look up a BB by leader VA
// Null when absent
const BasicBlock* find_bb(const Function& fn, std::uint64_t va) {
    for (const auto& bb : fn.basic_blocks) {
        if (bb.va == va) {
            return &bb;
        }
    }
    return nullptr;
}

}  // namespace

TEST_CASE("recover_one on straight-line ret yields one BB terminating in ret") {
    // 0x1000: C3   ret
    const auto bytes = make_bytes(0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x1000, d);
    const auto fn = Cfg::recover_one(reader, 0x1000);
    REQUIRE(fn.has_value());
    CHECK(fn->va == 0x1000U);
    REQUIRE(fn->basic_blocks.size() == 1);
    CHECK(fn->basic_blocks[0].va == 0x1000U);
    REQUIRE(fn->basic_blocks[0].instructions.size() == 1);
    CHECK(fn->basic_blocks[0].instructions[0].is_return);
    CHECK(fn->basic_blocks[0].successors.empty());
}

TEST_CASE("recover_one decodes the fallthrough after an ordinary call") {
    // 0x1000: E8 FB 0F 00 00   call 0x2000
    // 0x1005: C3               ret
    // An ordinary call falls through, so the ret after it is part of the body.
    const auto bytes = make_bytes(0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x1000, d);
    const auto fn = Cfg::recover_one(reader, 0x1000);
    REQUIRE(fn.has_value());
    std::size_t insn_count = 0;
    for (const auto& bb : fn->basic_blocks) {
        insn_count += bb.instructions.size();
    }
    CHECK(insn_count == 2);
}

TEST_CASE("recover_one stops at a call the no-return oracle rejects") {
    // 0x1000: E8 FB 0F 00 00   call 0x2000   (oracle marks this no-return)
    // 0x1005: C3               ret           (must not be decoded)
    // A no-return call has no fallthrough, mirroring vivisect's NOFALL pruning.
    const auto bytes = make_bytes(0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x1000, d);
    const auto noret = [](const DecodedInsn& ins) { return ins.is_call; };
    const auto fn = Cfg::recover_one(reader, 0x1000, JumpTableResolver{}, noret);
    REQUIRE(fn.has_value());
    std::size_t insn_count = 0;
    for (const auto& bb : fn->basic_blocks) {
        insn_count += bb.instructions.size();
    }
    CHECK(insn_count == 1);
    REQUIRE(fn->basic_blocks.size() == 1);
    REQUIRE(fn->basic_blocks[0].instructions.size() == 1);
    CHECK(fn->basic_blocks[0].instructions[0].is_call);
    CHECK(fn->basic_blocks[0].successors.empty());
}

TEST_CASE("classify_pdata_unwind seeds v1, skips chained, stops on v2 or unreadable") {
    // v1 (ver=1), no flags -> a real function entry.
    CHECK(Cfg::classify_pdata_unwind(std::uint8_t{0x01}) == PdataEntryKind::kSeed);
    // v1 with UNW_FLAG_CHAININFO set (Flags bit 2: VerFlags = 1 | (4 << 3) = 0x21).
    CHECK(Cfg::classify_pdata_unwind(std::uint8_t{0x21}) ==
          PdataEntryKind::kSkipChained);
    // v2 UNWIND_INFO (ver=2): vivisect bails on the rest of the .pdata.
    CHECK(Cfg::classify_pdata_unwind(std::uint8_t{0x02}) == PdataEntryKind::kStop);
    // An unreadable or invalid unwind pointer also bails the walk.
    CHECK(Cfg::classify_pdata_unwind(std::nullopt) == PdataEntryKind::kStop);
}

TEST_CASE("recover_one stops at an int3 pad and does not walk into the next function") {
    // The MSVC cookie-failure tail: a branch reaches a `call; int3` block, and
    // the int3 (envi INS_DEBUG, IF_NOFALL) must end the function. Walking past
    // it decodes the adjacent function (here a `mov edi, edi` hot-patch stub),
    // which is the ipconfig get-MAC over-merge this guards against.
    // 0x1000: 89 D8            mov eax, ebx
    // 0x1002: 74 03            jz  0x1007        (taken -> cookie-fail block)
    // 0x1004: 90               nop
    // 0x1005: 90               nop
    // 0x1006: C3               ret              (normal return path)
    // 0x1007: E8 F4 0F 00 00   call 0x2000      (returns, falls through to int3)
    // 0x100C: CC               int3             (NOFALL: function ends here)
    // 0x100D: 8B FF            mov edi, edi     (NEXT function, must not decode)
    // 0x100F: C3               ret
    const auto bytes = make_bytes(0x89, 0xD8, 0x74, 0x03, 0x90, 0x90, 0xC3,
                                  0xE8, 0xF4, 0x0F, 0x00, 0x00, 0xCC, 0x8B,
                                  0xFF, 0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x1000, d);
    const auto fn = Cfg::recover_one(reader, 0x1000);
    REQUIRE(fn.has_value());

    std::size_t insn_count = 0;
    std::uint64_t max_va = 0;
    bool saw_next_function = false;
    for (const auto& bb : fn->basic_blocks) {
        for (const auto& ins : bb.instructions) {
            insn_count += 1;
            max_va = std::max(max_va, ins.va);
            if (ins.va >= 0x100DU) {
                saw_next_function = true;
            }
        }
    }
    // mov, jz, nop, nop, ret, call, int3
    CHECK(insn_count == 7);
    CHECK(max_va == 0x100CU);
    CHECK_FALSE(saw_next_function);

    const auto* trap_bb = find_bb(*fn, 0x1007U);
    REQUIRE(trap_bb != nullptr);
    CHECK(trap_bb->instructions.back().va == 0x100CU);
    CHECK(trap_bb->successors.empty());
}

TEST_CASE("split_at_external_branch_targets splits a block a sibling branches into") {
    // vivisect ends a block at any instruction with an incoming code xref, so a
    // cross-function branch into the middle of a shared block (an SEH funclet
    // reached by a pointer and by a sibling's jump) splits it. papa's
    // per-function leader analysis misses this, co-locating features capa keeps
    // in separate basic blocks (the robocopy get-process-heap-force-flags FP).
    Disassembler d(true);

    // Function B at 0x2000 is one straight-line block until the split.
    //   0x2000: 90  nop
    //   0x2001: 90  nop
    //   0x2002: C3  ret
    const auto bbytes = make_bytes(0x90, 0x90, 0xC3);
    const auto breader = Cfg::make_span_reader(std::span<const std::byte>(bbytes), 0x2000, d);
    auto fnB = Cfg::recover_one(breader, 0x2000);
    REQUIRE(fnB.has_value());
    REQUIRE(fnB->basic_blocks.size() == 1);

    // Function A at 0x1000 jumps into the middle of B's block (to 0x2001).
    //   0x1000: E9 FC 0F 00 00   jmp 0x2001
    const auto abytes = make_bytes(0xE9, 0xFC, 0x0F, 0x00, 0x00);
    const auto areader = Cfg::make_span_reader(std::span<const std::byte>(abytes), 0x1000, d);
    auto fnA = Cfg::recover_one(areader, 0x1000);
    REQUIRE(fnA.has_value());
    REQUIRE(fnA->basic_blocks.size() == 1);
    REQUIRE(fnA->basic_blocks[0].instructions[0].branch_target.has_value());
    REQUIRE(*fnA->basic_blocks[0].instructions[0].branch_target == 0x2001U);

    std::vector<Function> funcs;
    funcs.push_back(std::move(*fnA));
    funcs.push_back(std::move(*fnB));
    Cfg::split_at_external_branch_targets(funcs);

    // B keeps all its instructions but is now two blocks split at the target.
    const Function& B = funcs[1];
    CHECK(B.basic_blocks.size() == 2);
    CHECK(find_bb(B, 0x2000U) != nullptr);
    CHECK(find_bb(B, 0x2001U) != nullptr);
    std::size_t b_insns = 0;
    for (const auto& bb : B.basic_blocks) {
        b_insns += bb.instructions.size();
    }
    CHECK(b_insns == 3);
    // A has no incoming cross-function branch, so it is unchanged.
    CHECK(funcs[0].basic_blocks.size() == 1);
}

TEST_CASE("recover_one builds three BBs for a conditional skip") {
    // 0x1000: 89 D8       mov eax, ebx
    // 0x1002: 74 02       jz  0x1006
    // 0x1004: 90          nop
    // 0x1005: 90          nop
    // 0x1006: C3          ret
    const auto bytes = make_bytes(0x89, 0xD8, 0x74, 0x02, 0x90, 0x90, 0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x1000, d);
    const auto fn = Cfg::recover_one(reader, 0x1000);
    REQUIRE(fn.has_value());
    REQUIRE(fn->basic_blocks.size() == 3);

    const auto* bb_entry = find_bb(*fn, 0x1000U);
    const auto* bb_fall  = find_bb(*fn, 0x1004U);
    const auto* bb_exit  = find_bb(*fn, 0x1006U);
    REQUIRE(bb_entry != nullptr);
    REQUIRE(bb_fall  != nullptr);
    REQUIRE(bb_exit  != nullptr);

    // entry ends in the jz and branches to both the fall-through and taken edge
    CHECK(bb_entry->successors.size() == 2);
    CHECK(std::find(bb_entry->successors.begin(), bb_entry->successors.end(), 0x1004U)
              != bb_entry->successors.end());
    CHECK(std::find(bb_entry->successors.begin(), bb_entry->successors.end(), 0x1006U)
              != bb_entry->successors.end());

    // middle BB falls through to the exit BB
    CHECK(bb_fall->successors.size() == 1);
    CHECK(bb_fall->successors[0] == 0x1006U);

    // exit is the ret BB
    // Predecessors are the two inbound edges
    CHECK(bb_exit->successors.empty());
    CHECK(bb_exit->predecessors.size() == 2);
}

TEST_CASE("recover_one discovers a self-loop via conditional backwards jump") {
    // 0x2000: 89 D8        mov  eax, ebx
    // 0x2002: 83 E8 01     sub  eax, 1
    // 0x2005: 75 FB        jnz  0x2002
    // 0x2007: C3           ret
    const auto bytes = make_bytes(0x89, 0xD8, 0x83, 0xE8, 0x01, 0x75, 0xFB, 0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x2000, d);
    const auto fn = Cfg::recover_one(reader, 0x2000);
    REQUIRE(fn.has_value());
    REQUIRE(fn->basic_blocks.size() == 3);

    const auto* loop = find_bb(*fn, 0x2002U);
    REQUIRE(loop != nullptr);
    // the self-edge (0x2002 -> 0x2002) proves the loop was detected
    CHECK(std::find(loop->successors.begin(), loop->successors.end(), 0x2002U)
              != loop->successors.end());
    CHECK(std::find(loop->predecessors.begin(), loop->predecessors.end(), 0x2002U)
              != loop->predecessors.end());
}

TEST_CASE("recover_one follows a resolved indirect jump into its case bodies") {
    // 0x1000: 31 C0   xor eax, eax     (falls through)
    // 0x1002: FF E0   jmp rax          (indirect, target known only via resolver)
    // 0x1004: 90      nop              (case body, reachable only through the jump)
    // 0x1005: C3      ret
    const auto bytes = make_bytes(0x31, 0xC0, 0xFF, 0xE0, 0x90, 0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x1000, d);

    const JumpTableResolver resolver =
        [](std::span<const DecodedInsn> window) -> std::optional<JumpTableTargets> {
        if (window.empty()) { return std::nullopt; }
        const DecodedInsn& last = window.back();
        if (last.is_jump && !last.is_conditional && !last.branch_target.has_value()) {
            JumpTableTargets jt;
            jt.targets.push_back(0x1004U);
            return jt;
        }
        return std::nullopt;
    };

    const auto fn = Cfg::recover_one(reader, 0x1000, resolver);
    REQUIRE(fn.has_value());

    std::vector<std::uint64_t> vas;
    for (const auto& bb : fn->basic_blocks) {
        for (const auto& ins : bb.instructions) { vas.push_back(ins.va); }
    }
    // the hidden case body and its return are recovered through the resolver
    CHECK(std::find(vas.begin(), vas.end(), 0x1004U) != vas.end());
    CHECK(std::find(vas.begin(), vas.end(), 0x1005U) != vas.end());
    CHECK(vas.size() == 4U);
    // the case target starts its own basic block
    CHECK(find_bb(*fn, 0x1004U) != nullptr);
}

TEST_CASE("recover_one records direct call targets as callees but does not descend") {
    // Two adjacent functions at 0x3000 and 0x3010
    // fn A: call fn B then ret
    // fn B: ret
    // 0x3000: E8 0B 00 00 00   call 0x3010
    // 0x3005: C3               ret
    // 0x3006..0x300F: padding  (90 nops)
    // 0x3010: C3               ret
    const auto bytes = make_bytes(
        0xE8, 0x0B, 0x00, 0x00, 0x00,  // call 0x3010 (target = 0x3005 + 0x0B)
        0xC3,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x3000, d);
    const auto fn_a = Cfg::recover_one(reader, 0x3000);
    REQUIRE(fn_a.has_value());

    // only two instructions should be inside fn_a: the call and the ret
    REQUIRE(fn_a->basic_blocks.size() == 1);
    CHECK(fn_a->basic_blocks[0].instructions.size() == 2);
    CHECK(fn_a->basic_blocks[0].instructions[0].is_call);
    CHECK(fn_a->basic_blocks[0].instructions[1].is_return);

    // the callee target is recorded in the function-level callee list
    REQUIRE(fn_a->callees.size() == 1);
    CHECK(fn_a->callees[0] == 0x3010U);
}

TEST_CASE("make_span_reader rejects out-of-range VAs") {
    const auto bytes = make_bytes(0xC3);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x1000, d);
    CHECK_FALSE(reader(0x0FFFU).has_value());     // below base
    CHECK_FALSE(reader(0x1100U).has_value());     // past end
}

TEST_CASE("recover_one returns a minimal function when the first byte fails to decode") {
    // 0x06 is invalid in long mode so the first and only decode fails
    const auto bytes = make_bytes(0x06);
    Disassembler d(true);
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(bytes), 0x4000, d);
    const auto fn = Cfg::recover_one(reader, 0x4000);
    REQUIRE(fn.has_value());
    CHECK(fn->basic_blocks.empty());
}

namespace {

// Build a byte region of the given size filled with int3, then splice in the
// listed instruction bytes at their offsets. Offsets are region-relative.
std::vector<std::byte> region_with(
    std::size_t size,
    std::initializer_list<std::pair<std::size_t, std::vector<std::uint8_t>>> patches) {
    std::vector<std::byte> region(size, std::byte{0xCC});
    for (const auto& [off, bytes] : patches) {
        std::size_t i = off;
        for (std::uint8_t b : bytes) { region[i++] = std::byte{b}; }
    }
    return region;
}

bool function_covers(const Function& fn, std::uint64_t va) {
    for (const auto& bb : fn.basic_blocks) {
        for (const auto& ins : bb.instructions) {
            if (ins.va == va) { return true; }
        }
    }
    return false;
}

const Function* function_at(const std::vector<Function>& funcs, std::uint64_t va) {
    for (const auto& f : funcs) {
        if (f.va == va) { return &f; }
    }
    return nullptr;
}

}  // namespace

TEST_CASE("recover_seeded shares a jump-only pdata begin's blocks with its caller") {
    Disassembler d(true);
    // 0x1000 entry calls 0x2000, then jumps to 0x1100, a pdata begin reached only
    // by this jump. At 0x1100 a mov of 0x36 then a ret. At 0x2000 a lone ret, and
    // 0x2000 is a call target.
    const auto region = region_with(0x1010, {
        {0x000, {0xE8, 0xFB, 0x0F, 0x00, 0x00}},  // call 0x2000
        {0x005, {0xE9, 0xF6, 0x00, 0x00, 0x00}},  // jmp  0x1100
        {0x100, {0xB8, 0x36, 0x00, 0x00, 0x00}},  // mov  eax, 0x36
        {0x105, {0xC3}},                          // ret
        {0x1000, {0xC3}},                         // ret at 0x2000
    });
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(region), 0x1000, d);
    const std::array<std::uint64_t, 1> entries{0x1000};
    const std::array<std::uint64_t, 3> starts{0x1000, 0x1100, 0x2000};
    const std::array<std::pair<std::uint64_t, std::uint64_t>, 3> ranges{
        {{0x1000, 0x1100}, {0x1100, 0x2000}, {0x2000, 0x2001}}};

    const auto funcs = Cfg::recover_seeded(reader, entries, starts, ranges);
    REQUIRE(funcs.has_value());
    // 0x1100 is a seeded .pdata begin, so it stays a function in its own right
    // (vivisect's shared-block model), even though only a jump reaches it.
    CHECK(function_at(*funcs, 0x1100) != nullptr);
    // The entry still reaches and covers 0x1100's blocks (shared, not moved), so
    // a function-scope rule on the entry sees them.
    const Function* entry = function_at(*funcs, 0x1000);
    REQUIRE(entry != nullptr);
    CHECK(function_covers(*entry, 0x1100));
    // The called function stays its own.
    CHECK(function_at(*funcs, 0x2000) != nullptr);
}

TEST_CASE("recover_seeded keeps a pdata begin that is a call target") {
    Disassembler d(true);
    // 0x1000 jumps to 0x1100. At 0x1100 a mov of 0x36 then a ret. At 0x3000 a
    // call to 0x1100 then a ret, so 0x1100 is reached by a jump AND a call and is
    // therefore a real function entry.
    const auto region = region_with(0x2010, {
        {0x000,  {0xE9, 0xFB, 0x00, 0x00, 0x00}},  // jmp  0x1100
        {0x100,  {0xB8, 0x36, 0x00, 0x00, 0x00}},  // mov  eax, 0x36
        {0x105,  {0xC3}},                          // ret
        {0x2000, {0xE8, 0xFB, 0xE0, 0xFF, 0xFF}},  // call 0x1100  (from 0x3000)
        {0x2005, {0xC3}},                          // ret
    });
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(region), 0x1000, d);
    const std::array<std::uint64_t, 2> entries{0x1000, 0x3000};
    const std::array<std::uint64_t, 3> starts{0x1000, 0x1100, 0x3000};
    const std::array<std::pair<std::uint64_t, std::uint64_t>, 3> ranges{
        {{0x1000, 0x1100}, {0x1100, 0x3000}, {0x3000, 0x3010}}};

    const auto funcs = Cfg::recover_seeded(reader, entries, starts, ranges);
    REQUIRE(funcs.has_value());
    // Because something calls 0x1100, it remains a separate function.
    CHECK(function_at(*funcs, 0x1100) != nullptr);
}

TEST_CASE("recover_seeded shares a chain of jump-only pdata begins with the entry") {
    Disassembler d(true);
    // 0x1000 jumps to 0x1100, which jumps to 0x1200, which holds a mov of 0x5c
    // then a ret. Neither 0x1100 nor 0x1200 is a call target, but both are seeded
    // .pdata begins, so they stay functions and the entry shares their blocks.
    const auto region = region_with(0x1210, {
        {0x000, {0xE9, 0xFB, 0x00, 0x00, 0x00}},  // jmp 0x1100
        {0x100, {0xE9, 0xFB, 0x00, 0x00, 0x00}},  // jmp 0x1200
        {0x200, {0xB8, 0x5C, 0x00, 0x00, 0x00}},  // mov eax, 0x5c
        {0x205, {0xC3}},                          // ret
    });
    const auto reader = Cfg::make_span_reader(std::span<const std::byte>(region), 0x1000, d);
    const std::array<std::uint64_t, 1> entries{0x1000};
    const std::array<std::uint64_t, 3> starts{0x1000, 0x1100, 0x1200};
    const std::array<std::pair<std::uint64_t, std::uint64_t>, 3> ranges{
        {{0x1000, 0x1100}, {0x1100, 0x1200}, {0x1200, 0x1210}}};

    const auto funcs = Cfg::recover_seeded(reader, entries, starts, ranges);
    REQUIRE(funcs.has_value());
    // Both seeded begins stay functions in their own right (shared-block model).
    CHECK(function_at(*funcs, 0x1100) != nullptr);
    CHECK(function_at(*funcs, 0x1200) != nullptr);
    const Function* entry = function_at(*funcs, 0x1000);
    REQUIRE(entry != nullptr);
    CHECK(function_covers(*entry, 0x1200));  // reached the deepest continuation (shared)
}

TEST_CASE("find_function_prologues finds vivisect i386 prologues in gaps only") {
    std::vector<std::uint8_t> code(0x70, 0x42u);   // 0x42 filler is not a prologue
    std::vector<std::uint8_t> covered(0x70, 0u);
    // A recovered function already covers [0x00, 0x10).
    for (std::size_t i = 0; i < 0x10; ++i) { covered[i] = 1u; }
    // 0x10 int3 pad, then push ebp; mov ebp, esp at 0x11: boundary + prologue + gap.
    code[0x10] = 0xCCu;
    code[0x11] = 0x55u; code[0x12] = 0x8Bu; code[0x13] = 0xECu;
    // 0x20 nop pad, then push ebp; mov ebp, esp at 0x21, but it is covered.
    code[0x20] = 0x90u;
    code[0x21] = 0x55u; code[0x22] = 0x8Bu; code[0x23] = 0xECu;
    for (std::size_t i = 0x21; i < 0x24; ++i) { covered[i] = 1u; }
    // 0x31 push ebp prologue but the byte before it (0x42) is not a boundary.
    code[0x31] = 0x55u; code[0x32] = 0x8Bu; code[0x33] = 0xECu;
    // 0x40 ret, then mov edi, edi; push ebp; mov ebp, esp at 0x41: hotpatch prologue.
    code[0x40] = 0xC3u;
    code[0x41] = 0x8Bu; code[0x42] = 0xFFu; code[0x43] = 0x55u;
    code[0x44] = 0x8Bu; code[0x45] = 0xECu;
    // 0x50 int3 pad, then sub esp, 0x40 at 0x51: not a vivisect signature, ignored.
    code[0x50] = 0xCCu;
    code[0x51] = 0x81u; code[0x52] = 0xECu;
    code[0x53] = 0x40u; code[0x54] = 0x00u; code[0x55] = 0x00u; code[0x56] = 0x00u;

    const auto seeds = Cfg::find_function_prologues(code, 0x1000u, covered);
    const std::vector<std::uint64_t> want{0x1011u, 0x1041u};
    CHECK(seeds == want);
}

TEST_CASE("recover on notepad.exe seeds at least the entry point and several exports/pdata") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    Disassembler d(res->is_64bit());

    const auto funcs = Cfg::recover(*res, d);
    REQUIRE(funcs.has_value());

    // very soft floor
    // Notepad has many hundreds of functions reachable from
    // entry + .pdata alone, but we cap conservatively to stay test-stable
    CHECK(funcs->size() >= 50);

    // entry point must appear as a recovered function
    const std::uint64_t entry_va = res->image_base() + res->entry_point_rva();
    const bool has_entry = std::any_of(funcs->begin(), funcs->end(),
        [&](const Function& f) { return f.va == entry_va; });
    CHECK(has_entry);

    // caller backlinks must be non-empty for at least one recovered function
    const bool any_callers = std::any_of(funcs->begin(), funcs->end(),
        [](const Function& f) { return !f.callers.empty(); });
    CHECK(any_callers);
}
