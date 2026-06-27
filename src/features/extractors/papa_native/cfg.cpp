#include "papa/features/extractors/papa_native/cfg.h"

#include "papa/constants.h"
#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/emu_discovery.h"
#include "papa/features/extractors/papa_native/jump_tables.h"
#include "papa/features/extractors/papa_native/noreturn.h"
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

/// The pdata function range that contains va, when one does. Used to confine
/// resolved jump-table case targets to the dispatching function, matching how
/// vivisect attributes switch cases to a single function.
[[nodiscard]] std::optional<std::pair<std::uint64_t, std::uint64_t>>
enclosing_pdata_range(const PdataRanges& p, std::uint64_t va) noexcept {
    if (p.ranges.empty()) { return std::nullopt; }
    auto it = std::upper_bound(
        p.ranges.begin(), p.ranges.end(),
        std::make_pair(va, std::numeric_limits<std::uint64_t>::max()),
        [](const auto& q, const auto& r) { return q.first < r.first; });
    if (it == p.ranges.begin()) { return std::nullopt; }
    --it;
    if (va >= it->first && va < it->second) { return *it; }
    return std::nullopt;
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
        std::uint32_t begin_rva  = 0;
        std::uint32_t end_rva    = 0;
        std::uint32_t unwind_rva = 0;
        if (!read_le<std::uint32_t>(*bytes, 0, begin_rva))  { break; }
        if (!read_le<std::uint32_t>(*bytes, 4, end_rva))    { break; }
        if (!read_le<std::uint32_t>(*bytes, 8, unwind_rva)) { break; }
        // Read the UNWIND_INFO VerFlags byte and classify the entry the way
        // vivisect parsers/pe.py does. An invalid unwind pointer or a v2
        // (ver != 1) record bails the whole walk: begins past it are not seeded
        // here and are recovered through the pointer / emucode passes instead. A
        // UNW_FLAG_CHAININFO record is a cold-path function block, not an entry,
        // so it is skipped. Any other begin is a function entry.
        std::optional<std::uint8_t> verflags;
        const std::uint64_t uiva = image.image_base() + unwind_rva;
        if (va_in_image(image, uiva)) {
            if (auto uw = image.read_at_rva(unwind_rva, 1); uw && !uw->empty()) {
                verflags = static_cast<std::uint8_t>((*uw)[0]);
            }
        }
        const PdataEntryKind kind = Cfg::classify_pdata_unwind(verflags);
        if (kind == PdataEntryKind::kStop) { break; }
        if (kind == PdataEntryKind::kSkipChained) { continue; }

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

/// Build the production jump-table resolver. It reads 32-bit offset entries
/// straight from the image and confines the resolved case targets to the pdata
/// range of the dispatching function.
[[nodiscard]] JumpTableResolver
make_jump_table_resolver(const pe::PeImage& image, const PdataRanges& pdata) {
    const pe::PeImage* img = &image;
    const PdataRanges* p   = &pdata;
    return [img, p](std::span<const DecodedInsn> window)
               -> std::optional<JumpTableTargets> {
        if (window.empty()) { return std::nullopt; }
        std::uint64_t lo = img->image_base();
        std::uint64_t hi = img->image_base() + img->size_of_image();
        if (const auto range = enclosing_pdata_range(*p, window.back().va);
            range.has_value()) {
            lo = range->first;
            hi = range->second;
        }
        const TableReader read_u32 =
            [img](std::uint64_t va) -> std::optional<std::uint32_t> {
            if (va < img->image_base()) { return std::nullopt; }
            const auto bytes = img->read_at_rva(va - img->image_base(), 4);
            if (!bytes || bytes->size() < 4) { return std::nullopt; }
            std::uint32_t value = 0;
            std::memcpy(&value, bytes->data(), sizeof(value));
            return value;
        };

        // The 32-bit MSVC memory-indirect form jmp [index*scale + table] has a
        // constant table address, so it resolves without emulation. Bound the
        // case targets to the executable section that holds the dispatch.
        const DecodedInsn& jmp = window.back();
        if (const auto* sec = img->section_containing_rva(jmp.va - img->image_base());
            sec != nullptr &&
            (sec->characteristics & constants::kImageScnMemExecute) != 0) {
            const std::uint64_t sec_lo = img->image_base() + sec->virtual_address;
            const std::uint64_t sec_hi =
                sec_lo + std::max(sec->virtual_size, sec->raw_size);
            if (auto jt = resolve_memory_indirect_jump_table(jmp, sec_lo, sec_hi, read_u32);
                jt.has_value()) {
                return jt;
            }
        }
        return resolve_indexed_jump_table(window, img->is_64bit(), lo, hi, read_u32);
    };
}

// Partition a linear list of decoded instructions into basic blocks
// A leader is the function entry, any intra-function branch target, or any
// instruction immediately following a branch or return
void split_into_basic_blocks(Function& fn, std::vector<DecodedInsn> insns,
                             const AddrSet& extra_leaders) {
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

    // Indexed-jump case targets are leaders too. No decoded branch names them,
    // since the dispatch reaches them through a jump table, so they are seeded
    // explicitly here once their instructions have been recovered.
    for (const std::uint64_t leader : extra_leaders) {
        if (va_to_idx.count(leader) != 0) {
            leaders.insert(leader);
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
    const InsnReader& read, std::uint64_t start_va, const AddrSet& boundaries,
    const JumpTableResolver& resolve_jt, const NoReturnOracle& is_noreturn) {
    Function fn;
    fn.va = start_va;

    // A flow target that is another function's entry is a tail call or a shared
    // tail, not part of this function. Stopping there keeps papa's boundaries in
    // line with vivisect/CAPA, which treat each entry as its own function.
    const auto crosses_boundary = [&](std::uint64_t target) noexcept {
        return target != start_va && boundaries.count(target) != 0;
    };

    // Map keeps one entry per va so overlapping flows never double-count
    std::unordered_map<std::uint64_t, DecodedInsn> seen;
    seen.reserve(64);

    // Case targets discovered by resolving indexed indirect jumps, plus the byte
    // ranges of the offset tables those jumps read. The table bytes are data and
    // must never be decoded as instructions.
    AddrSet jt_targets;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> jt_data;

    // Rebuild the straight-line window of already-decoded instructions ending at
    // terminal by walking back through fall-through predecessors. This is the
    // context the jump-table resolver needs to recognize a switch dispatch.
    const auto window_ending_at =
        [&seen](const DecodedInsn& terminal) -> std::vector<DecodedInsn> {
        constexpr std::size_t kMaxWindow = 32;
        std::vector<DecodedInsn> rev;
        rev.push_back(terminal);
        std::uint64_t cur = terminal.va;
        for (std::size_t n = 0; n < kMaxWindow; ++n) {
            const DecodedInsn* pred = nullptr;
            for (const auto& kv : seen) {
                if (kv.first < cur && kv.first + kv.second.length == cur) {
                    pred = &kv.second;
                    break;
                }
            }
            if (pred == nullptr || !pred->is_fallthrough) { break; }
            rev.push_back(*pred);
            cur = pred->va;
        }
        return std::vector<DecodedInsn>(rev.rbegin(), rev.rend());
    };

    const auto in_jt_data = [&jt_data](std::uint64_t va) noexcept {
        for (const auto& region : jt_data) {
            if (va >= region.first && va < region.second) { return true; }
        }
        return false;
    };

    std::deque<std::uint64_t> worklist;
    worklist.push_back(start_va);

    while (!worklist.empty()) {
        const std::uint64_t va = worklist.front();
        worklist.pop_front();
        if (seen.count(va) != 0) {
            continue;
        }
        if (in_jt_data(va)) {
            // The bytes here are a jump-table offset array, not instructions
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

        // Enqueue the fallthrough when the insn does not end control flow. A
        // call whose target the no-return oracle rejects has no fallthrough,
        // matching vivisect's IF_NOFALL pruning after an exit/abort style call.
        const bool noreturn_call =
            ins.is_call && static_cast<bool>(is_noreturn) && is_noreturn(ins);
        if (ins.is_fallthrough && !noreturn_call) {
            const std::uint64_t fallthrough = va + ins.length;
            if (!crosses_boundary(fallthrough)) {
                worklist.push_back(fallthrough);
            }
        }
        // Enqueue branch targets of jumps and conditional jumps inside the function
        if ((ins.is_jump || ins.is_conditional) && ins.branch_target.has_value() &&
            !crosses_boundary(*ins.branch_target)) {
            worklist.push_back(*ins.branch_target);
        }

        // An indirect jump may be a switch dispatch, either through a register
        // (the x64 indexed idiom) or a constant-base memory table (the x86
        // jmp [index*scale + table] form). Resolving its table recovers the case
        // bodies recursive descent cannot reach, the way vivisect's switch
        // analysis does.
        if (resolve_jt && ins.is_jump && !ins.is_conditional &&
            !ins.branch_target.has_value() && ins.operand_count > 0 &&
            (ins.operands[0].kind == OperandKind::kReg ||
             ins.operands[0].kind == OperandKind::kSib)) {
            if (const auto jt = resolve_jt(window_ending_at(ins)); jt.has_value()) {
                for (const std::uint64_t target : jt->targets) {
                    fn.jumptable_targets.push_back(target);
                    if (!crosses_boundary(target)) {
                        jt_targets.insert(target);
                        worklist.push_back(target);
                    }
                }
                if (jt->table_size != 0) {
                    jt_data.emplace_back(jt->table_va,
                                         jt->table_va + jt->table_size);
                }
            }
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
    split_into_basic_blocks(fn, std::move(flat), jt_targets);
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

// Tail-call discrimination. A .pdata begin reached only by intra-procedural flow
// (a jump, conditional branch, or fallthrough) and never by a call is not a
// function of its own but a continuation of the function that reaches it. This
// is how vivisect and CAPA attribute such ranges, so a single logical function
// split across several .pdata entries is kept whole. For each real-entry
// function that flows into a continuation, recovery is redone across these soft
// boundaries (stopping only at real entries), folding the continuations in, and
// the now-absorbed continuation functions are dropped.
void merge_tail_continuations(std::vector<Function>& funcs,
                              const AddrSet& code_entries,
                              const AddrSet& call_targets,
                              const AddrSet& pdata_starts,
                              const InsnReader& read,
                              const JumpTableResolver& resolve_jt,
                              const NoReturnOracle& is_noreturn) {
    // Real function entries are code entries (PE entry, exports, TLS) plus the
    // targets of call instructions.
    AddrSet hard = code_entries;
    hard.insert(call_targets.begin(), call_targets.end());

    // Continuations are .pdata begins that became functions but are not real
    // entries, so nothing calls them and they are not an export or the entry.
    AddrSet absorbable;
    for (const auto& f : funcs) {
        if (pdata_starts.count(f.va) != 0 && hard.count(f.va) == 0) {
            absorbable.insert(f.va);
        }
    }
    if (absorbable.empty()) {
        return;
    }

    // Roots are real-entry functions whose control flow reaches a continuation,
    // by a branch target or by falling off the end of a block into one.
    AddrSet roots;
    for (const auto& f : funcs) {
        if (hard.count(f.va) == 0) {
            continue;
        }
        for (const auto& bb : f.basic_blocks) {
            if (bb.instructions.empty()) {
                continue;
            }
            const DecodedInsn& term = bb.instructions.back();
            const bool branches = (term.is_jump || term.is_conditional) &&
                                  term.branch_target.has_value() &&
                                  absorbable.count(*term.branch_target) != 0;
            const bool falls = term.is_fallthrough &&
                               absorbable.count(term.va + term.length) != 0;
            if (branches || falls) {
                roots.insert(f.va);
                break;
            }
        }
    }
    if (roots.empty()) {
        return;
    }

    // Re-recover each root across the soft boundaries so it absorbs the
    // continuations it reaches, transitively. The absorbed begins are kept as
    // their own functions too, reproducing vivisect's shared-block model: a
    // seeded .pdata begin is a function in its own right, and a block reached
    // from a root is shared rather than moved. Keeping the begin matters once the
    // root is marked a library function: capa still extracts the begin, so calc
    // 0x140001600 (a capability function sharing blocks with the mainCRTStartup
    // entry 0x140001870) is recovered even though the entry is library. A begin
    // vivisect never seeds (a v2-break or chained record, which
    // collect_pdata_ranges does not put in .pdata starts) is not in `funcs`, so
    // it exists only inside the root and a library root suppresses it the way
    // vivisect does (certutil 0x14011a760 inside mainCRTStartup 0x14011a9d0).
    for (std::uint64_t root : roots) {
        auto fn = recover_one_impl(read, root, hard, resolve_jt, is_noreturn);
        if (!fn) {
            continue;
        }
        for (auto& f : funcs) {
            if (f.va == root) {
                f = std::move(*fn);
                break;
            }
        }
    }
}

// Jump-table case attribution. A switch dispatch resolves to case targets that
// are intra-procedural continuations of the dispatching function, the way
// vivisect attributes them (the cases become code reached through the resolved
// table, so the pointers pass that later follows the relocated table entries
// finds them already located and does not make them functions). papa's pointer
// pass runs first and can seed a case target as its own function when the case
// entry is a relocated table pointer that emulates like code. Fold such cases
// back into the dispatcher unless the case is also a real entry (called, an
// export, or the image entry). The dispatcher is re-recovered so it absorbs its
// cases across the soft boundaries, and the absorbed case functions are dropped.
void merge_jumptable_cases(std::vector<Function>& funcs,
                           const AddrSet& call_targets,
                           const InsnReader& read,
                           const JumpTableResolver& resolve_jt,
                           const NoReturnOracle& is_noreturn) {
    // A switch case, and the blocks it branches into, is reached only through
    // intra-procedural flow and is never called, so the real function entries
    // are the call targets. vivisect attributes such blocks to the dispatching
    // function. When a pointer pass over-seeds a case (or a block it reaches) as
    // its own function, fold it back by re-recovering the dispatcher across every
    // non-call-target boundary so it absorbs its full extent, then dropping the
    // absorbed non-entry functions. The seed list is not a usable signal because
    // the pointer pass appends the over-seeded cases to it.
    const AddrSet& hard = call_targets;

    AddrSet all_entries;
    for (const auto& f : funcs) { all_entries.insert(f.va); }

    // Dispatcher roots: a function with a resolved jump-table target that was
    // independently seeded as its own non-call-target function.
    std::vector<std::uint64_t> roots;
    for (const auto& f : funcs) {
        for (std::uint64_t t : f.jumptable_targets) {
            if (t != f.va && all_entries.count(t) != 0 && hard.count(t) == 0) {
                roots.push_back(f.va);
                break;
            }
        }
    }
    if (roots.empty()) {
        return;
    }
    // An outer function has the lower entry, so absorb roots in ascending order
    // and skip any already folded into an earlier one.
    std::sort(roots.begin(), roots.end());

    AddrSet covered;
    AddrSet kept;
    for (std::uint64_t root : roots) {
        if (covered.count(root) != 0) {
            continue;
        }
        auto fn = recover_one_impl(read, root, hard, resolve_jt, is_noreturn);
        if (!fn) {
            continue;
        }
        for (const auto& bb : fn->basic_blocks) {
            for (const auto& ins : bb.instructions) { covered.insert(ins.va); }
        }
        for (auto& f : funcs) {
            if (f.va == root) { f = std::move(*fn); break; }
        }
        kept.insert(root);
    }

    // Drop non-call-target functions now folded into a dispatcher.
    funcs.erase(std::remove_if(funcs.begin(), funcs.end(),
                               [&](const Function& f) {
                                   return hard.count(f.va) == 0 &&
                                          covered.count(f.va) != 0 &&
                                          kept.count(f.va) == 0;
                               }),
                funcs.end());
}

// A function start in code without a .pdata table sits just past a boundary, a
// return or alignment padding. These are the bytes vivisect treats as the end of
// the prior function or filler between functions.
[[nodiscard]] bool is_boundary_byte(std::uint8_t b) noexcept {
    return b == 0xC3U || b == 0xCCU || b == 0x90U;  // ret, int3 pad, nop pad
}

// True when the bytes begin with one of vivisect's i386 function-entry
// signatures (vivisect/analysis/i386/__init__.py `sigs`). This is the exact set
// vivisect's funcentries pass matches. It deliberately omits bare `sub esp, imm`
// prologues: vivisect discovers those functions by emulation and call analysis,
// not by signature, so prologue-seeding them would over-recover functions that
// vivisect's static-plus-emulation passes leave undefined.
[[nodiscard]] bool is_x86_function_prologue(std::span<const std::uint8_t> b) noexcept {
    if (b.size() < 3U) {
        return false;
    }
    if (b[0] == 0x55U && b[1] == 0x8BU && b[2] == 0xECU) { return true; }  // push ebp / mov ebp, esp
    if (b[0] == 0x55U && b[1] == 0x89U && b[2] == 0xE5U) { return true; }  // push ebp / mov ebp, esp (gcc)
    if (b[0] == 0x56U && b[1] == 0x8BU && b[2] == 0xF1U) { return true; }  // push esi / mov esi, ecx
    if (b.size() >= 5U && b[0] == 0x8BU && b[1] == 0xFFU &&
        b[2] == 0x55U && b[3] == 0x8BU && b[4] == 0xECU) {
        return true;  // mov edi, edi / push ebp / mov ebp, esp
    }
    if (b.size() >= 8U && b[0] == 0x6AU && b[2] == 0x68U && b[7] == 0xE8U) {
        return true;  // push imm8 / push imm32 / call
    }
    return false;
}

// Recover functions in a binary that has no .pdata table (32-bit PEs) by scanning
// the undefined gaps of the main code section for prologues, seeding the matches,
// and re-running recovery until no new entries appear. Mirrors vivisect's
// funcentries pass, which prologue-scans only what earlier analysis left
// undefined. Each candidate is attempted once, which guarantees termination.
void seed_from_prologue_gaps(
    const pe::PeImage& image, const InsnReader& read,
    const JumpTableResolver& resolve_jt,
    std::vector<std::uint64_t>& entries,
    std::span<const std::uint64_t> starts,
    std::span<const std::pair<std::uint64_t, std::uint64_t>> ranges,
    std::vector<Function>& funcs) {
    const pe::ParsedSection* text = nullptr;
    for (const auto& s : image.sections()) {
        if (s.name == ".text") { text = &s; break; }
    }
    if (text == nullptr) { return; }

    const std::uint64_t text_base = image.image_base() + text->virtual_address;
    auto raw = image.read_at_rva(text->virtual_address, text->raw_size);
    if (!raw) { return; }
    std::vector<std::uint8_t> code;
    code.reserve(raw->size());
    for (const std::byte b : *raw) { code.push_back(static_cast<std::uint8_t>(b)); }

    constexpr int kMaxProloguePasses = 8;
    AddrSet attempted;
    for (int pass = 0; pass < kMaxProloguePasses; ++pass) {
        // Mark every byte already attributed to a recovered function so the scan
        // only considers genuine gaps.
        std::vector<std::uint8_t> covered(code.size(), 0U);
        for (const auto& f : funcs) {
            for (const auto& bb : f.basic_blocks) {
                for (const auto& ins : bb.instructions) {
                    if (ins.va < text_base) { continue; }
                    const std::size_t off = static_cast<std::size_t>(ins.va - text_base);
                    for (std::size_t k = 0; k < ins.length && off + k < covered.size(); ++k) {
                        covered[off + k] = 1U;
                    }
                }
            }
        }

        const auto cands = Cfg::find_function_prologues(code, text_base, covered);
        bool added = false;
        for (const std::uint64_t va : cands) {
            if (attempted.insert(va).second) {
                entries.push_back(va);
                added = true;
            }
        }
        if (!added) { break; }

        auto next = Cfg::recover_seeded(read, entries, starts, ranges, resolve_jt);
        if (!next) { break; }
        funcs = std::move(next.value());
    }
}

// Recover functions reachable only through function pointers (vtables,
// callbacks, fn-ptr tables, RIP-relative lea references). Mirrors vivisect's
// pointers + emucode passes: collect pointer candidates, emulate each undefined
// target, and seed the ones that behave like a function (watcher looks_good).
// The candidates are the static pointers find_pointer_candidates surfaces (data
// slots and reloc-stored pointers into code) unioned, on x64, with vivisect's
// amd64 code-derived REF_PTR set: the absolute targets of RIP-relative lea
// instructions in the already-recovered code. The latter is recomputed each pass
// because newly seeded functions expose their own lea references (this recovers,
// for example, certutil's adler32 at 0x140109160, referenced only by a
// `lea rdx, [rip + ...]` and absent from .pdata and the relocations). Iterates
// because a newly seeded island's direct-call closure can cover other
// candidates. Runs before the prologue gap-scan, the way vivisect runs pointers
// before its last-resort funcentries pass.
void seed_from_emucode_pointers(
    const pe::PeImage& image, const Disassembler& disasm, const InsnReader& read,
    const JumpTableResolver& resolve_jt,
    std::vector<std::uint64_t>& entries,
    std::span<const std::uint64_t> starts,
    std::span<const std::pair<std::uint64_t, std::uint64_t>> ranges,
    std::vector<Function>& funcs) {
    const std::vector<std::uint64_t> static_cands =
        emu::find_pointer_candidates(image);
    // x86 has no RIP-relative code-derived candidates, so with no static
    // pointers there is nothing to discover. x64 still runs to collect lea
    // targets from the recovered code.
    if (static_cands.empty() && !image.is_64bit()) { return; }
    const emu::ImageMaps maps = emu::build_image_maps(image);

    // Executable VA ranges a code-derived lea target must land in to be a
    // function candidate (emucode only emulates executable addresses).
    std::vector<std::pair<std::uint64_t, std::uint64_t>> exec_ranges;
    for (const pe::ParsedSection& s : image.sections()) {
        if ((s.characteristics & constants::kImageScnMemExecute) != 0) {
            const std::uint64_t b = image.image_base() + s.virtual_address;
            exec_ranges.emplace_back(b, b + s.virtual_size);
        }
    }
    const auto in_exec = [&exec_ranges](std::uint64_t v) {
        for (const auto& [lo, hi] : exec_ranges) {
            if (v >= lo && v < hi) { return true; }
        }
        return false;
    };

    constexpr int kMaxEmuPasses = 6;
    constexpr std::size_t kMaxEmuRunsPerImage = 40000;
    AddrSet attempted;
    std::size_t runs = 0;
    for (int pass = 0; pass < kMaxEmuPasses; ++pass) {
        // Every VA already attributed to a recovered function. Candidates inside
        // a recovered function are not separate functions, so skip them.
        AddrSet covered;
        for (const auto& f : funcs) {
            for (const auto& bb : f.basic_blocks) {
                for (const auto& ins : bb.instructions) { covered.insert(ins.va); }
            }
        }

        // The candidate set this pass: static pointers, plus (x64) the
        // RIP-relative lea targets in the recovered code that point into
        // executable space. Recomputed each pass as new functions appear.
        std::vector<std::uint64_t> candidates = static_cands;
        if (image.is_64bit()) {
            for (const auto& f : funcs) {
                for (const auto& bb : f.basic_blocks) {
                    for (const auto& ins : bb.instructions) {
                        if (const auto t = emu::riprel_lea_target(ins);
                            t.has_value() && in_exec(*t)) {
                            candidates.push_back(*t);
                        }
                    }
                }
            }
        }

        bool added = false;
        for (const std::uint64_t va : candidates) {
            if (covered.count(va) != 0) { continue; }
            if (!attempted.insert(va).second) { continue; }
            if (runs >= kMaxEmuRunsPerImage) { break; }
            ++runs;
            if (emu::validate_candidate(maps, disasm, va)) {
                entries.push_back(va);
                added = true;
            }
        }
        if (!added) { break; }

        auto next = Cfg::recover_seeded(read, entries, starts, ranges, resolve_jt);
        if (!next) { break; }
        funcs = std::move(next.value());
    }
}

// True when a function contains an indirect call or jump (operand 0 is not a
// pc-relative target). Only such functions can yield a new seed from the calling
// pass: a function whose only transfers are direct (call/jmp rel32, jcc) resolves
// every apicall to an already-known target, so emulating it cannot discover
// anything. Skipping the rest keeps the discovery result identical while avoiding
// a full-image emulation that finds nothing.
[[nodiscard]] bool has_indirect_control_flow(const Function& f) {
    for (const auto& bb : f.basic_blocks) {
        for (const auto& ins : bb.instructions) {
            if ((ins.is_call || ins.is_jump) && ins.operand_count > 0 &&
                ins.operands[0].kind != OperandKind::kPcRel) {
                return true;
            }
        }
    }
    return false;
}

// Recover functions reached only through runtime-resolved indirect calls.
// Mirrors vivisect's i386 calling pass (analysis/i386/calling.py + impemu
// AnalysisMonitor): emulate each recovered function and seed the executable
// targets its indirect calls resolve to (the "Emulation Found" path). Iterates
// because a newly seeded function exposes its own indirect calls. Runs after the
// pointers pass and before the prologue gap-scan, matching vivisect's order.
void seed_from_calling_emulation(
    const pe::PeImage& image, const Disassembler& disasm, const InsnReader& read,
    const JumpTableResolver& resolve_jt,
    std::vector<std::uint64_t>& entries,
    std::span<const std::uint64_t> starts,
    std::span<const std::pair<std::uint64_t, std::uint64_t>> ranges,
    std::vector<Function>& funcs) {
    const emu::ImageMaps maps = emu::build_image_maps(image);

    constexpr int kMaxEmuPasses = 6;
    constexpr std::size_t kMaxEmuRunsPerImage = 40000;
    AddrSet emulated;
    std::size_t runs = 0;
    for (int pass = 0; pass < kMaxEmuPasses; ++pass) {
        // Every VA already attributed to a recovered function, and the current
        // function entries. A resolved target inside either is not new.
        AddrSet covered;
        for (const auto& f : funcs) {
            for (const auto& bb : f.basic_blocks) {
                for (const auto& ins : bb.instructions) { covered.insert(ins.va); }
            }
        }
        AddrSet entryset(entries.begin(), entries.end());

        // Emulate each function once across the whole pass sequence. Functions
        // newly recovered this pass are emulated on the next pass. Only functions
        // with indirect control flow can yield a new seed.
        std::vector<std::uint64_t> to_emulate;
        for (const auto& f : funcs) {
            if (!has_indirect_control_flow(f)) { continue; }
            if (emulated.insert(f.va).second) { to_emulate.push_back(f.va); }
        }

        bool added = false;
        for (const std::uint64_t fva : to_emulate) {
            if (runs >= kMaxEmuRunsPerImage) { break; }
            ++runs;
            const std::vector<std::uint64_t> seeds =
                emu::discover_call_targets(maps, disasm, fva);
            for (const std::uint64_t s : seeds) {
                if (covered.count(s) != 0 || entryset.count(s) != 0) { continue; }
                entries.push_back(s);
                entryset.insert(s);
                added = true;
            }
        }
        if (!added) { break; }

        auto next = Cfg::recover_seeded(read, entries, starts, ranges, resolve_jt);
        if (!next) { break; }
        funcs = std::move(next.value());
    }
}

}  // namespace

PdataEntryKind
Cfg::classify_pdata_unwind(std::optional<std::uint8_t> verflags) noexcept {
    if (!verflags.has_value()) {
        return PdataEntryKind::kStop;
    }
    // VerFlags packs Version in bits 0..2 and Flags in bits 3..7.
    const unsigned ver = static_cast<unsigned>(*verflags) & 0x07U;
    if (ver != 1U) {
        return PdataEntryKind::kStop;
    }
    constexpr unsigned kUnwFlagChainInfo = 0x04U;
    const unsigned flags = static_cast<unsigned>(*verflags) >> 3;
    if ((flags & kUnwFlagChainInfo) != 0U) {
        return PdataEntryKind::kSkipChained;
    }
    return PdataEntryKind::kSeed;
}

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
Expected<Function> Cfg::recover_one(const InsnReader& read, std::uint64_t start_va,
                                    const JumpTableResolver& resolve_jt,
                                    const NoReturnOracle& is_noreturn) {
    const AddrSet no_boundaries;
    return recover_one_impl(read, start_va, no_boundaries, resolve_jt, is_noreturn);
}

std::vector<std::uint64_t> Cfg::find_function_prologues(
    std::span<const std::uint8_t> code, std::uint64_t base_va,
    std::span<const std::uint8_t> covered) {
    std::vector<std::uint64_t> out;
    if (code.size() < 4U) {
        return out;
    }
    // Start at 1 so the boundary byte (code[i-1]) exists. A candidate is the
    // first byte past a boundary that is not already covered by a recovered
    // function and that begins a known prologue.
    for (std::size_t i = 1U; i + 3U < code.size(); ++i) {
        if (i < covered.size() && covered[i] != 0U) {
            continue;
        }
        if (!is_boundary_byte(code[i - 1U])) {
            continue;
        }
        if (is_x86_function_prologue(code.subspan(i))) {
            out.push_back(base_va + static_cast<std::uint64_t>(i));
        }
    }
    return out;
}

/// Reader-driven core of whole-image recovery. See cfg.h.
Expected<std::vector<Function>> Cfg::recover_seeded(
    const InsnReader& read,
    std::span<const std::uint64_t> code_entries,
    std::span<const std::uint64_t> pdata_starts,
    std::span<const std::pair<std::uint64_t, std::uint64_t>> pdata_ranges,
    const JumpTableResolver& resolve_jt,
    const NoReturnOracle& is_noreturn) {
    // Reconstruct the pdata view used to reject call seeds that fall interior to
    // a pdata function (intra-function hops the decoder classified as targets).
    PdataRanges pdata;
    pdata.ranges.assign(pdata_ranges.begin(), pdata_ranges.end());
    std::sort(pdata.ranges.begin(), pdata.ranges.end());
    pdata.starts.insert(pdata_starts.begin(), pdata_starts.end());

    AddrSet seeds;
    seeds.insert(code_entries.begin(), code_entries.end());
    seeds.insert(pdata_starts.begin(), pdata_starts.end());

    std::vector<Function> funcs;
    AddrSet started(seeds.begin(), seeds.end());
    AddrSet call_targets;
    std::deque<std::uint64_t> worklist(seeds.begin(), seeds.end());

    while (!worklist.empty()) {
        if (funcs.size() >= constants::kMaxFunctionsPerImage) {
            break;
        }
        const std::uint64_t start = worklist.front();
        worklist.pop_front();
        auto fn = recover_one_impl(read, start, started, resolve_jt, is_noreturn);
        if (!fn) {
            continue;
        }
        // Accept new callee seeds unless they fall interior to a pdata function,
        // which marks an intra-function jump the decoder classified as a target
        // and vivisect/CAPA treat as part of the enclosing function. Every direct
        // call target is recorded so tail-call discrimination can tell a real
        // function entry from a jump-only continuation below.
        for (std::uint64_t callee_va : fn->callees) {
            call_targets.insert(callee_va);
            if (is_internal_to_pdata_function(pdata, callee_va)) { continue; }
            if (started.insert(callee_va).second) {
                worklist.push_back(callee_va);
            }
        }
        funcs.push_back(std::move(*fn));
    }

    // Fold .pdata begins reached only by intra-procedural flow into the function
    // that reaches them, matching vivisect/CAPA function boundaries.
    {
        const AddrSet code_entry_set(code_entries.begin(), code_entries.end());
        merge_tail_continuations(funcs, code_entry_set, call_targets, pdata.starts,
                                 read, resolve_jt, is_noreturn);
        // Fold switch-case targets a pointer pass over-seeded as their own
        // functions back into the dispatcher that reaches them by jump table.
        merge_jumptable_cases(funcs, call_targets, read, resolve_jt, is_noreturn);
    }

    // A seed that decodes to nothing (out of range or undecodable bytes) yields a
    // function with no blocks. Drop those so the table holds only real functions.
    funcs.erase(std::remove_if(funcs.begin(), funcs.end(),
                               [](const Function& f) { return f.basic_blocks.empty(); }),
                funcs.end());

    // Stable order makes callers and callees easier to reason about in tests
    std::sort(funcs.begin(), funcs.end(),
              [](const Function& a, const Function& b) { return a.va < b.va; });

    // Drop duplicate recoveries. A function may have been seeded more than once,
    // for example through an export whose VA also appears in .pdata.
    funcs.erase(std::unique(funcs.begin(), funcs.end(),
                            [](const Function& a, const Function& b) {
                                return a.va == b.va;
                            }),
                funcs.end());

    fill_callers(funcs);
    return funcs;
}

/// Whole-image function recovery. Collects code entries and .pdata, then defers
/// to the reader-driven recover_seeded.
void Cfg::split_at_external_branch_targets(std::vector<Function>& funcs) {
    // Every decoded branch target across the whole recovered image. A target
    // that lands inside another function's block is a cross-function branch
    // (vivisect's incoming REF_CODE xref) that must end that block.
    AddrSet branch_targets;
    for (const auto& fn : funcs) {
        for (const auto& bb : fn.basic_blocks) {
            for (const auto& ins : bb.instructions) {
                if (ins.is_jump && ins.branch_target.has_value()) {
                    branch_targets.insert(*ins.branch_target);
                }
            }
        }
    }

    for (auto& fn : funcs) {
        // Keep the existing block leaders so jump-table splits survive the
        // re-split. A global branch target that lands past a block's first
        // instruction is a new leader.
        AddrSet leaders;
        bool needs_resplit = false;
        for (const auto& bb : fn.basic_blocks) {
            leaders.insert(bb.va);
            for (std::size_t k = 1; k < bb.instructions.size(); ++k) {
                const std::uint64_t va = bb.instructions[k].va;
                if (branch_targets.count(va) != 0) {
                    leaders.insert(va);
                    needs_resplit = true;
                }
            }
        }
        if (!needs_resplit) {
            continue;
        }
        std::vector<DecodedInsn> flat;
        for (auto& bb : fn.basic_blocks) {
            for (auto& ins : bb.instructions) {
                flat.push_back(std::move(ins));
            }
        }
        fn.basic_blocks.clear();
        split_into_basic_blocks(fn, std::move(flat), leaders);
    }
}

Expected<std::vector<Function>> Cfg::recover(
    const pe::PeImage& image, const Disassembler& disasm,
    const NoReturnOracle& is_noreturn) {
    AddrSet code_entries;
    seed_entry_and_exports(image, code_entries);
    seed_tls_callbacks(image, code_entries);

    const auto pdata      = collect_pdata_ranges(image);
    const auto reader     = make_image_reader(image, disasm);
    const auto resolve_jt = make_jump_table_resolver(image, pdata);

    std::vector<std::uint64_t>       entries(code_entries.begin(), code_entries.end());
    const std::vector<std::uint64_t> starts(pdata.starts.begin(), pdata.starts.end());

    auto funcs = recover_seeded(reader, entries, starts, pdata.ranges, resolve_jt,
                                is_noreturn);
    if (!funcs) {
        return funcs;
    }

    // A binary with no .pdata function table (a 32-bit PE) is seeded only from
    // the entry and exports, so recursive descent reaches just that direct-call
    // closure. Recover the rest the way vivisect does, in its pass order:
    // emulate function-pointer targets and seed the ones that behave like
    // functions (pointers + emucode), then emulate each recovered function to
    // seed its runtime-resolved indirect call targets (i386 calling), then
    // prologue-scan the undefined code gaps left over (funcentries).
    if (pdata.starts.empty()) {
        seed_from_emucode_pointers(image, disasm, reader, resolve_jt, entries,
                                   starts, pdata.ranges, funcs.value());
        seed_from_calling_emulation(image, disasm, reader, resolve_jt, entries,
                                    starts, pdata.ranges, funcs.value());
        seed_from_prologue_gaps(image, reader, resolve_jt, entries, starts,
                                pdata.ranges, funcs.value());
    } else if (image.is_64bit()) {
        // x64 with .pdata: the exception table seeds the bulk of the functions,
        // but vivisect also runs the pointers pass on every binary
        // (generic/relocations.py makePointer -> followPointer -> analyzePointer
        // -> isProbablyCode, which for amd64 classifies a target as code via
        // runFunction emulation, since amd64 populates no function-signature
        // tree). Recover the reloc-pointer-referenced functions .pdata omits
        // (e.g. 7z's CRC32 routine at 0x45f224) via that same emulation-
        // validated pointers pass. No prologue gap-scan here: funcentries needs
        // the sigtree that amd64 does not populate.
        seed_from_emucode_pointers(image, disasm, reader, resolve_jt, entries,
                                   starts, pdata.ranges, funcs.value());
    }

    // No-return analysis runs last, over the complete function set, the way
    // vivisect registers noret as a per-function module that fires on every
    // function however it was discovered (entrypoints, pointers/emucode, calling,
    // funcentries). Mark functions that never return (noret.py analyzeFunction)
    // and re-recover so a caller loses the fallthrough after the call. A function
    // whose terminal blocks all end in a no-return call (an exit import or a
    // function already proven no-return) does not return either, so this iterates
    // to a fixpoint. The combined oracle extends the import-based no-return check
    // with direct calls to proven-no-return functions. The re-recovery seeds from
    // the full entry set the passes above have grown, so it keeps every
    // discovered function while pruning the phantom blocks past a no-return call.
    {
        constexpr int kMaxNoretPasses = 8;
        AddrSet         proven_noreturn;
        const NoReturnOracle combined =
            [&is_noreturn, &proven_noreturn](const DecodedInsn& ins) -> bool {
                if (static_cast<bool>(is_noreturn) && is_noreturn(ins)) {
                    return true;
                }
                return ins.is_call && ins.branch_target.has_value() &&
                       proven_noreturn.count(*ins.branch_target) != 0;
            };
        for (int pass = 0; pass < kMaxNoretPasses; ++pass) {
            bool changed = false;
            for (const Function& f : funcs.value()) {
                if (proven_noreturn.count(f.va) != 0) { continue; }
                if (function_is_noreturn(f, combined)) {
                    proven_noreturn.insert(f.va);
                    changed = true;
                }
            }
            if (!changed) { break; }
            auto next = recover_seeded(reader, entries, starts, pdata.ranges,
                                       resolve_jt, combined);
            if (!next) { break; }
            funcs = std::move(next);
        }
    }

    // Final pass over the complete function set: split shared blocks at
    // cross-function branch targets, matching vivisect codeblocks' global
    // getXrefsTo(nextva, REF_CODE) block boundaries. Runs after noret so it
    // sees every function's branches.
    split_at_external_branch_targets(funcs.value());
    return funcs;
}

}  // namespace papa::features::extractors::papa_native
