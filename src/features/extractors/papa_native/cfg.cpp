#include "papa/features/extractors/papa_native/cfg.h"

#include "papa/constants.h"
#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

namespace {

// Set of addresses used by seed collection and basic block leader analysis
// Packing multiple reasons into one set keeps leader computation branch-free
using AddrSet = std::unordered_set<std::uint64_t>;

// Read a little-endian scalar from a byte span with full bounds checks
template <typename T>
[[nodiscard]] bool read_le(std::span<const std::byte> buf, std::size_t off, T& out) noexcept {
    if (off > buf.size() || sizeof(T) > buf.size() - off) {
        return false;
    }
    std::memcpy(&out, buf.data() + off, sizeof(T));
    return true;
}

// True when va lies within the image's virtual footprint
// Used to guard seed enqueues against malformed inputs
[[nodiscard]] bool va_in_image(const pe::PeImage& image, std::uint64_t va) noexcept {
    const std::uint64_t base = image.image_base();
    if (va < base) {
        return false;
    }
    const std::uint64_t rva = va - base;
    return rva < image.size_of_image();
}

// Collect seeds from the entry point and every non-forwarded export
void seed_entry_and_exports(const pe::PeImage& image, AddrSet& seeds) {
    const std::uint64_t base = image.image_base();
    if (image.entry_point_rva() != 0) {
        seeds.insert(base + image.entry_point_rva());
    }
    for (const auto& e : image.exports()) {
        // Forwarders have VA zero by construction in the parser
        if (e.forwarder.has_value() || e.va == 0) {
            continue;
        }
        seeds.insert(e.va);
    }
}

// TLS callbacks run before main and are excellent function seeds
void seed_tls_callbacks(const pe::PeImage& image, AddrSet& seeds) {
    for (std::uint64_t cb : image.tls_callbacks_va()) {
        if (cb != 0 && va_in_image(image, cb)) {
            seeds.insert(cb);
        }
    }
}

/// Authoritative [start, end) ranges from the x64 .pdata exception directory.
/// Used to suppress call-target seeds that fall inside an already-known
/// function but are not its entry point (a vivisect-style anti-over-splitting
/// guard).
struct PdataRanges {
    std::vector<std::pair<std::uint64_t, std::uint64_t>>  ranges;     // sorted by start
    std::unordered_set<std::uint64_t>                     starts;     // VA set
};

/// True when target_va is strictly inside a known pdata function but is not
/// the function's entry. Such targets are local control-flow, not function starts.
[[nodiscard]] bool is_internal_to_pdata_function(
    const PdataRanges& p, std::uint64_t target_va) noexcept {
    if (p.ranges.empty()) { return false; }
    if (p.starts.find(target_va) != p.starts.end()) { return false; }
    // Binary search for the rightmost range whose start <= target_va
    auto it = std::upper_bound(
        p.ranges.begin(), p.ranges.end(),
        std::make_pair(target_va, std::numeric_limits<std::uint64_t>::max()),
        [](const auto& q, const auto& r) { return q.first < r.first; });
    if (it == p.ranges.begin()) { return false; }
    --it;
    return target_va > it->first && target_va < it->second;
}

/// Iterate the .pdata RUNTIME_FUNCTION array and harvest authoritative
/// function entry points and end addresses. The end is exclusive.
[[nodiscard]] PdataRanges collect_pdata_ranges(const pe::PeImage& image) {
    PdataRanges out;
    if (!image.is_64bit()) { return out; }
    const pe::ParsedSection* pdata = nullptr;
    for (const auto& s : image.sections()) {
        if (s.name == ".pdata") { pdata = &s; break; }
    }
    if (pdata == nullptr) { return out; }
    const std::size_t count = pdata->raw_size / constants::kRuntimeFunctionSize;
    out.ranges.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t off = std::uint64_t{pdata->virtual_address} +
                                  i * constants::kRuntimeFunctionSize;
        auto bytes = image.read_at_rva(off, constants::kRuntimeFunctionSize);
        if (!bytes) { break; }
        std::uint32_t begin_rva = 0;
        std::uint32_t end_rva   = 0;
        if (!read_le<std::uint32_t>(*bytes, 0, begin_rva)) { break; }
        if (!read_le<std::uint32_t>(*bytes, 4, end_rva))   { break; }
        if (begin_rva == 0) { continue; }
        const std::uint64_t begin_va = image.image_base() + begin_rva;
        const std::uint64_t end_va   = image.image_base() + end_rva;
        if (!va_in_image(image, begin_va)) { continue; }
        out.ranges.emplace_back(begin_va, end_va);
        out.starts.insert(begin_va);
    }
    std::sort(out.ranges.begin(), out.ranges.end());
    return out;
}

/// Seed from x64 .pdata RUNTIME_FUNCTION entries.
/// Each record starts at BeginAddress.
void seed_pdata_x64(const pe::PeImage& image, AddrSet& seeds) {
    const auto ranges = collect_pdata_ranges(image);
    for (auto va : ranges.starts) { seeds.insert(va); }
}

// Partition a linear list of decoded instructions into basic blocks
// A leader is the function entry, any intra-function branch target, or any
// instruction immediately following a branch or return
void split_into_basic_blocks(Function& fn, std::vector<DecodedInsn> insns) {
    if (insns.empty()) {
        return;
    }
    std::sort(insns.begin(), insns.end(),
              [](const DecodedInsn& a, const DecodedInsn& b) { return a.va < b.va; });

    // Map VA to index for constant-time membership checks during leader analysis
    std::unordered_map<std::uint64_t, std::size_t> va_to_idx;
    va_to_idx.reserve(insns.size());
    for (std::size_t i = 0; i < insns.size(); ++i) {
        va_to_idx.emplace(insns[i].va, i);
    }

    // Compute the leader set
    // A leader starts a new basic block
    // A basic block ends at any jump or return so the fallthrough VA of such an
    // instruction is the next basic block's leader
    AddrSet leaders;
    leaders.insert(fn.va);
    for (const auto& ins : insns) {
        const bool ends_bb = ins.is_return || ins.is_jump;
        if (ends_bb) {
            const std::uint64_t next = ins.va + ins.length;
            if (va_to_idx.count(next) != 0) {
                leaders.insert(next);
            }
        }
        // An intra-function jump target is a leader when we actually decoded it
        if (ins.is_jump && ins.branch_target.has_value()) {
            const std::uint64_t tgt = *ins.branch_target;
            if (va_to_idx.count(tgt) != 0) {
                leaders.insert(tgt);
            }
        }
    }

    // Materialize basic blocks by walking instructions in order
    // A new basic block opens whenever the current VA is a leader
    std::vector<std::uint64_t> ordered_leaders(leaders.begin(), leaders.end());
    std::sort(ordered_leaders.begin(), ordered_leaders.end());

    fn.basic_blocks.reserve(ordered_leaders.size());
    std::size_t cursor = 0;
    for (std::size_t li = 0; li < ordered_leaders.size(); ++li) {
        const std::uint64_t leader_va = ordered_leaders[li];
        const std::uint64_t next_leader_va = (li + 1 < ordered_leaders.size())
            ? ordered_leaders[li + 1]
            : std::numeric_limits<std::uint64_t>::max();

        // Find first insn whose va is at or beyond leader_va
        while (cursor < insns.size() && insns[cursor].va < leader_va) {
            ++cursor;
        }
        if (cursor >= insns.size() || insns[cursor].va != leader_va) {
            // A leader without a decoded anchor means an unrecovered target
            // Skip it so the basic block table stays self-consistent
            continue;
        }

        BasicBlock bb;
        bb.va = leader_va;
        while (cursor < insns.size() && insns[cursor].va < next_leader_va) {
            bb.instructions.push_back(std::move(insns[cursor]));
            ++cursor;
        }
        fn.basic_blocks.push_back(std::move(bb));
    }

    // Wire successors from each basic block's terminator
    // Predecessors are derived from the same edges immediately after
    std::unordered_map<std::uint64_t, std::size_t> bb_va_to_idx;
    bb_va_to_idx.reserve(fn.basic_blocks.size());
    for (std::size_t i = 0; i < fn.basic_blocks.size(); ++i) {
        bb_va_to_idx.emplace(fn.basic_blocks[i].va, i);
    }

    auto add_edge = [&](std::size_t pred_idx, std::uint64_t succ_va) {
        auto it = bb_va_to_idx.find(succ_va);
        if (it == bb_va_to_idx.end()) {
            return;
        }
        fn.basic_blocks[pred_idx].successors.push_back(succ_va);
        fn.basic_blocks[it->second].predecessors.push_back(fn.basic_blocks[pred_idx].va);
    };

    for (std::size_t i = 0; i < fn.basic_blocks.size(); ++i) {
        auto& bb = fn.basic_blocks[i];
        if (bb.instructions.empty()) {
            continue;
        }
        const DecodedInsn& term = bb.instructions.back();
        const std::uint64_t fallthrough = term.va + term.length;

        if (term.is_return) {
            continue;
        }
        // is_jump covers conditional and unconditional branches alike
        if (term.is_jump && term.branch_target.has_value()) {
            add_edge(i, *term.branch_target);
        }
        if (term.is_fallthrough) {
            add_edge(i, fallthrough);
        }
    }

    // Deduplicate successor and predecessor lists for blocks with repeated edges
    for (auto& bb : fn.basic_blocks) {
        std::sort(bb.successors.begin(), bb.successors.end());
        bb.successors.erase(std::unique(bb.successors.begin(), bb.successors.end()),
                            bb.successors.end());
        std::sort(bb.predecessors.begin(), bb.predecessors.end());
        bb.predecessors.erase(std::unique(bb.predecessors.begin(), bb.predecessors.end()),
                              bb.predecessors.end());
    }
}

// Recover the instruction set of a single function by recursive descent
// Returns whatever was recovered when the per-function cap trips
// Capping shields PAPA from crafted self-modifying or pathological inputs
[[nodiscard]] Expected<Function> recover_one_impl(
    const InsnReader& read, std::uint64_t start_va) {
    Function fn;
    fn.va = start_va;

    // Map keeps one entry per va so overlapping flows never double-count
    std::unordered_map<std::uint64_t, DecodedInsn> seen;
    seen.reserve(64);

    std::deque<std::uint64_t> worklist;
    worklist.push_back(start_va);

    while (!worklist.empty()) {
        const std::uint64_t va = worklist.front();
        worklist.pop_front();
        if (seen.count(va) != 0) {
            continue;
        }
        if (seen.size() >= constants::kMaxInsnsPerFunction) {
            // Trip-wire against crafted or self-modifying-looking inputs
            break;
        }

        auto decoded = read(va);
        if (!decoded) {
            // A decode failure ends only this path
            // The rest of the function may still be recovered
            continue;
        }
        DecodedInsn ins = std::move(*decoded);

        // Record callee targets without following them into this function
        if (ins.is_call && ins.branch_target.has_value()) {
            fn.callees.push_back(*ins.branch_target);
        }

        // Enqueue the fallthrough when the insn does not end control flow
        if (ins.is_fallthrough) {
            worklist.push_back(va + ins.length);
        }
        // Enqueue branch targets of jumps and conditional jumps inside the function
        if ((ins.is_jump || ins.is_conditional) && ins.branch_target.has_value()) {
            worklist.push_back(*ins.branch_target);
        }

        seen.emplace(va, std::move(ins));
    }

    // Deduplicate callees once the worklist has been fully drained
    std::sort(fn.callees.begin(), fn.callees.end());
    fn.callees.erase(std::unique(fn.callees.begin(), fn.callees.end()), fn.callees.end());

    // Assemble the linear instruction list that split_into_basic_blocks expects
    std::vector<DecodedInsn> flat;
    flat.reserve(seen.size());
    for (auto& kv : seen) {
        flat.push_back(std::move(kv.second));
    }
    split_into_basic_blocks(fn, std::move(flat));
    return fn;
}

// Build the reverse-edge map: callees across all functions become callers
void fill_callers(std::vector<Function>& funcs) {
    std::unordered_map<std::uint64_t, std::size_t> by_va;
    by_va.reserve(funcs.size());
    for (std::size_t i = 0; i < funcs.size(); ++i) {
        by_va.emplace(funcs[i].va, i);
    }
    for (const auto& caller : funcs) {
        for (std::uint64_t callee_va : caller.callees) {
            auto it = by_va.find(callee_va);
            if (it == by_va.end()) {
                continue;
            }
            funcs[it->second].callers.push_back(caller.va);
        }
    }
    // Deduplicate per callee so one caller with two call sites counts once
    for (auto& f : funcs) {
        std::sort(f.callers.begin(), f.callers.end());
        f.callers.erase(std::unique(f.callers.begin(), f.callers.end()), f.callers.end());
    }
}

}  // namespace

// Public: build a reader that decodes through a PE image's virtual space
InsnReader Cfg::make_image_reader(const pe::PeImage& image, const Disassembler& disasm) {
    // The caller is responsible for keeping the image and disassembler alive
    // for the lifetime of the returned reader
    const pe::PeImage* img = &image;
    const Disassembler* dis = &disasm;
    return [img, dis](std::uint64_t va) -> Expected<DecodedInsn> {
        if (va < img->image_base()) {
            return Unexpected{make_error(ErrorKind::kOutOfBounds, "va below image base")};
        }
        const std::uint64_t rva = va - img->image_base();
        // Read up to one full x86 instruction
        // Near a section's end the returned span is shorter than that cap
        std::size_t want = constants::kMaxInsnBytes;
        auto bytes = img->read_at_rva(rva, want);
        while (!bytes && want > 0) {
            --want;
            bytes = img->read_at_rva(rva, want);
        }
        if (!bytes || bytes->empty()) {
            return Unexpected{make_error(ErrorKind::kOutOfBounds, "no bytes at va")};
        }
        return dis->decode(*bytes, va);
    };
}

// Public: build a reader over a fixed region
// Used by unit tests to feed synthetic instruction byte sequences
InsnReader Cfg::make_span_reader(std::span<const std::byte> region,
                                 std::uint64_t base_va,
                                 const Disassembler& disasm) {
    const Disassembler* dis = &disasm;
    // Copy the span into the closure
    // The pointed-to buffer must outlive the returned reader
    return [region, base_va, dis](std::uint64_t va) -> Expected<DecodedInsn> {
        if (va < base_va) {
            return Unexpected{make_error(ErrorKind::kOutOfBounds, "va below region base")};
        }
        const std::uint64_t off = va - base_va;
        if (off >= region.size()) {
            return Unexpected{make_error(ErrorKind::kOutOfBounds, "va past region end")};
        }
        const std::size_t avail = std::min<std::size_t>(
            constants::kMaxInsnBytes, region.size() - static_cast<std::size_t>(off));
        return dis->decode(region.subspan(static_cast<std::size_t>(off), avail), va);
    };
}

// Public: recover one function with a caller-provided reader
Expected<Function> Cfg::recover_one(const InsnReader& read, std::uint64_t start_va) {
    return recover_one_impl(read, start_va);
}

/// Whole-image function recovery across the seed worklist.
Expected<std::vector<Function>> Cfg::recover(
    const pe::PeImage& image, const Disassembler& disasm) {
    AddrSet seeds;
    seed_entry_and_exports(image, seeds);
    seed_tls_callbacks(image, seeds);

    // Cache the pdata ranges so the worklist can reject internal-call seeds
    // that would otherwise over-split functions whose bodies make tail-call
    // hops or jump-table jumps the disassembler classifies as CALL/JMP targets
    const auto pdata = collect_pdata_ranges(image);
    for (auto va : pdata.starts) { seeds.insert(va); }

    const auto reader = make_image_reader(image, disasm);

    std::vector<Function> funcs;
    AddrSet started;
    std::deque<std::uint64_t> worklist(seeds.begin(), seeds.end());
    started.insert(seeds.begin(), seeds.end());

    while (!worklist.empty()) {
        if (funcs.size() >= constants::kMaxFunctionsPerImage) {
            break;
        }
        const std::uint64_t start = worklist.front();
        worklist.pop_front();
        if (!va_in_image(image, start)) {
            continue;
        }
        auto fn = recover_one_impl(reader, start);
        if (!fn) {
            continue;
        }
        // Accept new callee seeds when:
        //   - the target is a confirmed pdata function entry, OR
        //   - the target sits wholly outside any pdata range
        //     (legitimate static functions the compiler omitted from pdata)
        // We reject targets interior to a pdata function because those are
        // intra-function jumps the disassembler classified as CALL/JMP and
        // vivisect/CAPA treat as part of the enclosing function
        for (std::uint64_t callee_va : fn->callees) {
            if (!va_in_image(image, callee_va))                  { continue; }
            if (is_internal_to_pdata_function(pdata, callee_va)) { continue; }
            if (started.insert(callee_va).second) {
                worklist.push_back(callee_va);
            }
        }
        funcs.push_back(std::move(*fn));
    }

    // Stable order makes callers and callees easier to reason about in tests
    std::sort(funcs.begin(), funcs.end(),
              [](const Function& a, const Function& b) { return a.va < b.va; });

    // Drop duplicate recoveries
    // A function may have been seeded more than once
    // For example through an export whose VA also appears in .pdata
    funcs.erase(std::unique(funcs.begin(), funcs.end(),
                            [](const Function& a, const Function& b) {
                                return a.va == b.va;
                            }),
                funcs.end());

    fill_callers(funcs);
    return funcs;
}

}  // namespace papa::features::extractors::papa_native
