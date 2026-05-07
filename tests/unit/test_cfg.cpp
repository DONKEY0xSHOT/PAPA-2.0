#include <ostream>

#include "doctest.h"

#include "papa/constants.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>

using papa::features::extractors::papa_native::BasicBlock;
using papa::features::extractors::papa_native::Cfg;
using papa::features::extractors::papa_native::DecodedInsn;
using papa::features::extractors::papa_native::Disassembler;
using papa::features::extractors::papa_native::Function;

namespace {

constexpr std::string_view kNotepad = "C:/Windows/System32/notepad.exe";

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
