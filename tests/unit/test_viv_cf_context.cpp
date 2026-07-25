#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <ostream>
#include <span>
#include <unordered_set>
#include <utility>
#include <vector>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/viv/cf_context.h"
#include "papa/features/extractors/papa_native/viv/xref_db.h"

namespace pn = papa::features::extractors::papa_native;
namespace pv = papa::features::extractors::papa_native::viv;

using pn::DecodedInsn;
using pn::Disassembler;

namespace {

template <typename... B>
constexpr auto make_bytes(B... bs) {
    return std::array<std::byte, sizeof...(B)>{
        std::byte{static_cast<std::uint8_t>(bs)}...};
}

}  // namespace

TEST_CASE("CodeFlowContext decodes a straight-line run once (decode-once gate)") {
    const Disassembler d(/*is_64bit=*/false);
    // 0x1000: 90 nop / 0x1001: 90 nop / 0x1002: c3 ret
    const auto bytes  = make_bytes(0x90, 0x90, 0xC3);
    const auto reader = pn::cfg::make_span_reader(bytes, 0x1000, d);

    std::unordered_set<std::uint64_t> defined;
    std::vector<std::uint64_t>        decoded;
    pv::CodeFlowContext cf(
        reader, [](std::uint64_t) { return true; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&, std::span<const pv::CfBranch>) {
            decoded.push_back(va);
            defined.insert(va);
        },
        [](std::uint64_t) {});

    cf.add_code_flow(0x1000);
    CHECK(decoded == std::vector<std::uint64_t>{0x1000, 0x1001, 0x1002});

    // Re-running does not re-decode: every address is already defined
    decoded.clear();
    cf.add_code_flow(0x1000);
    CHECK(decoded.empty());
}

TEST_CASE("CodeFlowContext explores both edges of a conditional branch and records the non-fall xref") {
    const Disassembler d(/*is_64bit=*/false);
    // 0x1000: 74 03   jz 0x1005   (fall-through 0x1002, branch target 0x1005)
    // 0x1002: c3      ret
    // 0x1003: 90 90   padding
    // 0x1005: c3      ret
    const auto bytes  = make_bytes(0x74, 0x03, 0xC3, 0x90, 0x90, 0xC3);
    const auto reader = pn::cfg::make_span_reader(bytes, 0x1000, d);

    std::unordered_set<std::uint64_t> defined;
    std::vector<std::uint64_t>        decoded;
    pv::XrefDb                        xrefs;
    pv::CodeFlowContext cf(
        reader, [](std::uint64_t) { return true; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&,
            std::span<const pv::CfBranch> branches) {
            decoded.push_back(va);
            defined.insert(va);
            for (const pv::CfBranch& br : branches) {
                if (br.target.has_value() && (br.flags & pv::kBrFall) == 0) {
                    xrefs.add_code_xref(va, *br.target, br.flags);
                }
            }
        },
        [](std::uint64_t) {});

    cf.add_code_flow(0x1000);

    // Fall-through is explored before the branch target: getBranches yields
    // [fall, target] and the worklist consumes from the end
    CHECK(decoded == std::vector<std::uint64_t>{0x1000, 0x1002, 0x1005});
    // The conditional edge is recorded as a BR_COND xref, the fall-through is not
    CHECK(xrefs.has_code_xref_to(0x1005));
    CHECK_FALSE(xrefs.has_code_xref_to(0x1002));
    const auto& from = xrefs.code_xrefs_from(0x1000);
    REQUIRE(from.size() == 1);
    CHECK(from[0].to_va == 0x1005);
    CHECK((from[0].branch_flags & pv::kBrCond) != 0);
}

TEST_CASE("CodeFlowContext descends into a call to completion before the caller's fall-through") {
    const Disassembler d(/*is_64bit=*/false);
    std::array<std::byte, 0x1001> region{};
    region.fill(std::byte{0x90});
    // 0x1000: e8 fb 0f 00 00   call 0x2000  (rel32 = 0x2000 - 0x1005 = 0xFFB)
    region[0x000] = std::byte{0xE8};
    region[0x001] = std::byte{0xFB};
    region[0x002] = std::byte{0x0F};
    region[0x003] = std::byte{0x00};
    region[0x004] = std::byte{0x00};
    region[0x005] = std::byte{0x90};  // nop, the fall-through after the call
    region[0x006] = std::byte{0xC3};  // ret
    region[0x1000] = std::byte{0xC3};  // 0x2000: ret, the callee
    const auto reader = pn::cfg::make_span_reader(region, 0x1000, d);

    // The event log interleaves opcodes and completed functions. A function
    // event is tagged with the high bit so the two can be told apart
    constexpr std::uint64_t kFn = 1ULL << 63;
    std::unordered_set<std::uint64_t> defined;
    std::vector<std::uint64_t>        log;
    pv::CodeFlowContext cf(
        reader, [](std::uint64_t) { return true; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&, std::span<const pv::CfBranch>) {
            log.push_back(va);
            defined.insert(va);
        },
        [&](std::uint64_t va) { log.push_back(kFn | va); });

    cf.add_entry_point(0x1000);

    // The callee 0x2000 is fully analyzed (its on_function fires) before the
    // caller's fall-through 0x1005 is ever decoded: the post-order DFS
    const auto fn_callee = std::find(log.begin(), log.end(), kFn | 0x2000);
    const auto op_fall   = std::find(log.begin(), log.end(), 0x1005ULL);
    REQUIRE(fn_callee != log.end());
    REQUIRE(op_fall != log.end());
    CHECK(fn_callee < op_fall);
    // The callee body was decoded and both functions completed
    CHECK(std::find(log.begin(), log.end(), 0x2000ULL) != log.end());
    CHECK(std::find(log.begin(), log.end(), kFn | 0x1000) != log.end());
}

TEST_CASE("CodeFlowContext delays a function that tail-jumps into an in-analysis ancestor") {
    const Disassembler d(/*is_64bit=*/false);
    std::array<std::byte, 0x2005> region{};
    region.fill(std::byte{0x90});
    // 0x1000: e8 fb 0f 00 00   call 0x2000  (rel32 = 0x2000 - 0x1005 = 0xFFB)
    region[0x000] = std::byte{0xE8};
    region[0x001] = std::byte{0xFB};
    region[0x002] = std::byte{0x0F};
    region[0x003] = std::byte{0x00};
    region[0x004] = std::byte{0x00};
    region[0x005] = std::byte{0xC3};  // 0x1005: ret
    // 0x2000: e9 fb ef ff ff   jmp 0x1000  (rel32 = 0x1000 - 0x2005 = -0x1005), a
    // tail-jump back into the entry of the still-in-analysis caller
    region[0x1000] = std::byte{0xE9};
    region[0x1001] = std::byte{0xFB};
    region[0x1002] = std::byte{0xEF};
    region[0x1003] = std::byte{0xFF};
    region[0x1004] = std::byte{0xFF};
    const auto reader = pn::cfg::make_span_reader(region, 0x1000, d);

    std::unordered_set<std::uint64_t> defined;
    std::vector<std::uint64_t>        fn_order;
    pv::CodeFlowContext cf(
        reader, [](std::uint64_t) { return true; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&, std::span<const pv::CfBranch>) {
            defined.insert(va);
        },
        [&](std::uint64_t va) { fn_order.push_back(va); });

    cf.add_entry_point(0x1000);

    // 0x2000 tail-jumps into 0x1000, which is still being flowed, so 0x2000's
    // registration is deferred until 0x1000 completes: 0x1000 is reported first,
    // the reverse of the plain post-order [0x2000, 0x1000]
    REQUIRE(fn_order.size() == 2);
    CHECK(fn_order[0] == 0x1000);
    CHECK(fn_order[1] == 0x2000);
}

TEST_CASE("CodeFlowContext explores jump-table cases intra-procedurally, not as calls") {
    const Disassembler d(/*is_64bit=*/false);
    std::array<std::byte, 0x1201> region{};
    region.fill(std::byte{0x90});
    // 0x1000: ff e0   jmp eax   (an indirect jump the stub resolver recognizes)
    region[0x000] = std::byte{0xFF};
    region[0x001] = std::byte{0xE0};
    region[0x100] = std::byte{0xC3};  // 0x1100: ret  (case 0)
    region[0x200] = std::byte{0xC3};  // 0x1200: ret  (case 1)
    const auto reader = pn::cfg::make_span_reader(region, 0x1000, d);

    const pn::JumpTableResolver resolve =
        [](std::span<const DecodedInsn>) -> std::optional<pn::JumpTableTargets> {
        pn::JumpTableTargets jt;
        jt.targets = {0x1100, 0x1200};
        return jt;
    };

    std::unordered_set<std::uint64_t> defined;
    std::unordered_set<std::uint64_t> decoded;
    int                               function_events = 0;
    pv::CodeFlowContext cf(
        reader, [](std::uint64_t) { return true; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&, std::span<const pv::CfBranch>) {
            decoded.insert(va);
            defined.insert(va);
        },
        [&](std::uint64_t) { ++function_events; }, resolve);

    cf.add_entry_point(0x1000);

    // Both cases are decoded (explored) but neither becomes its own function:
    // they are intra-procedural branch targets, not calls
    CHECK(decoded.count(0x1000) == 1);
    CHECK(decoded.count(0x1100) == 1);
    CHECK(decoded.count(0x1200) == 1);
    CHECK(function_events == 1);
}

TEST_CASE("CodeFlowContext suppresses the fall-through after a call to a no-return function") {
    const Disassembler d(/*is_64bit=*/false);
    std::array<std::byte, 0x1001> region{};
    region.fill(std::byte{0x90});
    // 0x1000: e8 fb 0f 00 00   call 0x2000  (rel32 = 0x2000 - 0x1005 = 0xFFB)
    region[0x000] = std::byte{0xE8};
    region[0x001] = std::byte{0xFB};
    region[0x002] = std::byte{0x0F};
    region[0x003] = std::byte{0x00};
    region[0x004] = std::byte{0x00};
    region[0x005] = std::byte{0x90};   // 0x1005: nop, the fall-through after the call
    region[0x006] = std::byte{0xC3};   // 0x1006: ret
    region[0x1000] = std::byte{0xC3};  // 0x2000: ret, the no-return callee
    const auto reader = pn::cfg::make_span_reader(region, 0x1000, d);

    std::unordered_set<std::uint64_t> defined;
    std::unordered_set<std::uint64_t> decoded;
    pv::CodeFlowContext cf(
        reader, [](std::uint64_t) { return true; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&, std::span<const pv::CfBranch>) {
            decoded.insert(va);
            defined.insert(va);
        },
        [](std::uint64_t) {}, /*resolve_jt=*/{},
        /*is_no_return_call=*/[](const DecodedInsn& op) {
            return op.is_call && op.branch_target == 0x2000;
        });

    cf.add_entry_point(0x1000);

    // The callee is analyzed, but because it does not return, the fall-through
    // after the call is never decoded (no phantom block)
    CHECK(decoded.count(0x1000) == 1);
    CHECK(decoded.count(0x2000) == 1);
    CHECK(decoded.count(0x1005) == 0);
    CHECK(decoded.count(0x1006) == 0);
}

TEST_CASE("CodeFlowContext caps call-descent depth over a crafted deep chain") {
    const Disassembler d(/*is_64bit=*/false);
    // A chain of 6-byte functions, each `call +1` then `ret`, so function i at
    // base + i*6 calls function i+1. Longer than the descent cap, so a naive
    // recursive descent would overflow the stack
    const std::size_t chain_len = pv::kMaxDescentDepth + 20;
    const std::size_t region_size = chain_len * 6;
    std::vector<std::byte> region(region_size, std::byte{0x00});
    for (std::size_t i = 0; i < chain_len; ++i) {
        const std::size_t off = i * 6;
        region[off + 0] = std::byte{0xE8};  // call rel32 = +1 -> next function
        region[off + 1] = std::byte{0x01};
        region[off + 2] = std::byte{0x00};
        region[off + 3] = std::byte{0x00};
        region[off + 4] = std::byte{0x00};
        region[off + 5] = std::byte{0xC3};  // ret
    }
    const std::uint64_t base   = 0x1000;
    const auto          reader = pn::cfg::make_span_reader(region, base, d);

    std::unordered_set<std::uint64_t> defined;
    int                               function_events = 0;
    pv::CodeFlowContext cf(
        reader,
        [&](std::uint64_t va) { return va < base + region_size; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&, std::span<const pv::CfBranch>) {
            defined.insert(va);
        },
        [&](std::uint64_t) { ++function_events; });

    // The chain is longer than the cap, so descent stops cleanly at the cap
    // without a stack overflow, registering exactly the reachable-within-cap
    // functions rather than the whole chain
    cf.add_entry_point(base);
    CHECK(function_events > 0);
    CHECK(function_events <= static_cast<int>(pv::kMaxDescentDepth));
    CHECK(function_events < static_cast<int>(chain_len));
}

TEST_CASE("CodeFlowContext reports each resolved jump-table case to on_branch_table") {
    const Disassembler d(/*is_64bit=*/false);
    std::array<std::byte, 0x1201> region{};
    region.fill(std::byte{0x90});
    region[0x000] = std::byte{0xFF};  // 0x1000: ff e0  jmp eax
    region[0x001] = std::byte{0xE0};
    region[0x100] = std::byte{0xC3};  // 0x1100: ret
    region[0x200] = std::byte{0xC3};  // 0x1200: ret
    const auto reader = pn::cfg::make_span_reader(region, 0x1000, d);
    const pn::JumpTableResolver resolve =
        [](std::span<const DecodedInsn>) -> std::optional<pn::JumpTableTargets> {
        pn::JumpTableTargets jt;
        jt.targets = {0x1100, 0x1200};
        return jt;
    };

    std::unordered_set<std::uint64_t>                        defined;
    std::vector<std::pair<std::uint64_t, std::uint64_t>>     table_edges;
    pv::CodeFlowContext cf(
        reader, [](std::uint64_t) { return true; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&, std::span<const pv::CfBranch>) {
            defined.insert(va);
        },
        [](std::uint64_t) {}, resolve, /*is_no_return_call=*/{},
        [&](std::uint64_t from, std::uint64_t to) {
            table_edges.emplace_back(from, to);
        });

    cf.add_entry_point(0x1000);

    // The dispatch jump at 0x1000 reports one edge to each case target, the
    // cross-reference codeblocks needs to split a block at each case
    REQUIRE(table_edges.size() == 2);
    CHECK(table_edges[0].first == 0x1000);
    CHECK(table_edges[0].second == 0x1100);
    CHECK(table_edges[1].first == 0x1000);
    CHECK(table_edges[1].second == 0x1200);
}

TEST_CASE("CodeFlowContext does not descend into a call already on the active path") {
    const Disassembler d(/*is_64bit=*/false);
    std::array<std::byte, 0x0C> region{};
    region.fill(std::byte{0x90});
    // 0x1000: e8 fb ff ff ff   call 0x1000  (rel32 = 0x1000 - 0x1005 = -5), self-recursive
    region[0x000] = std::byte{0xE8};
    region[0x001] = std::byte{0xFB};
    region[0x002] = std::byte{0xFF};
    region[0x003] = std::byte{0xFF};
    region[0x004] = std::byte{0xFF};
    region[0x005] = std::byte{0xC3};  // ret
    const auto reader = pn::cfg::make_span_reader(region, 0x1000, d);

    std::unordered_set<std::uint64_t> defined;
    int                               function_events = 0;
    pv::CodeFlowContext cf(
        reader, [](std::uint64_t) { return true; },
        [&](std::uint64_t va) { return defined.count(va) != 0; },
        [&](std::uint64_t va, const DecodedInsn&, std::span<const pv::CfBranch>) {
            defined.insert(va);
        },
        [&](std::uint64_t) { ++function_events; });

    // The self-call is on the active path, so the recursion guard stops it from
    // descending forever. The entry is made exactly once
    cf.add_entry_point(0x1000);
    CHECK(function_events == 1);
}
