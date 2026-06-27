#pragma once

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/jump_tables.h"
#include "papa/pe/pe_image.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

// How vivisect's .pdata walk treats one RUNTIME_FUNCTION (parsers/pe.py).
enum class PdataEntryKind {
    kSeed,         // a function entry: add its begin as a seed
    kSkipChained,  // a UNW_FLAG_CHAININFO function block, not an entry: skip it
    kStop,         // a v2 (ver != 1) or unreadable UNWIND_INFO: bail the walk
};

// One straight-line run of instructions with no branches inside
struct BasicBlock {
    std::uint64_t              va{0};
    std::vector<DecodedInsn>   instructions;
    std::vector<std::uint64_t> successors;
    std::vector<std::uint64_t> predecessors;
};

// One function recovered by CFG analysis
struct Function {
    std::uint64_t              va{0};
    std::vector<BasicBlock>    basic_blocks;
    std::vector<std::uint64_t> callers;
    std::vector<std::uint64_t> callees;
    bool                       likely_library{false};
    // Every switch-case target the function's indirect jumps resolved to,
    // whether or not it was folded in here. The orchestrator uses these to fold
    // cases a pointer pass independently seeded back into this dispatcher.
    std::vector<std::uint64_t> jumptable_targets;
};

// Callback returning a decoded instruction at a given VA
// Errors are fatal to the single function being recovered, not to the image
using InsnReader =
    std::function<Expected<DecodedInsn>(std::uint64_t va)>;

// Invoked when recovery reaches an indirect register jump. Given the
// straight-line window of instructions ending at that jump, it returns the
// switch-case targets to continue recovery into, or nullopt when the window is
// not a recognized jump table.
using JumpTableResolver =
    std::function<std::optional<JumpTableTargets>(std::span<const DecodedInsn>)>;

// Predicate: true when the given CALL instruction's resolved target does not
// return, so recovery must not enqueue the fallthrough after it. This mirrors
// vivisect's isNoReturnVa codeflow pruning (the IF_NOFALL bit set after a call
// to an exit/abort style function). An empty oracle treats no call as
// no-return, so recovery behaves exactly as before.
using NoReturnOracle = std::function<bool(const DecodedInsn&)>;

class Cfg {
public:
    // Top-level: seed from entry/exports/TLS/pdata, worklist across new call
    // targets. When is_noreturn is set, a call it flags ends control flow with
    // no fallthrough on the main (pdata) recovery, mirroring vivisect's noret
    // codeflow pruning.
    [[nodiscard]] static Expected<std::vector<Function>>
        recover(const pe::PeImage& image, const Disassembler& disasm,
                const NoReturnOracle& is_noreturn = {});

    // Reader-driven core of whole-image recovery. Seeds from code entries (PE
    // entry, exports, TLS callbacks) and .pdata begins, recovers across the seed
    // worklist, then applies tail-call discrimination so a .pdata begin reached
    // only by intra-procedural flow is absorbed into the function that reaches it
    // rather than standing alone. Exposed so tests can drive it with a span reader.
    [[nodiscard]] static Expected<std::vector<Function>>
        recover_seeded(const InsnReader& read,
                       std::span<const std::uint64_t> code_entries,
                       std::span<const std::uint64_t> pdata_starts,
                       std::span<const std::pair<std::uint64_t, std::uint64_t>> pdata_ranges,
                       const JumpTableResolver& resolve_jt = {},
                       const NoReturnOracle& is_noreturn = {});

    // Recover one function given an instruction reader
    // Shared by production callers and unit tests. When resolve_jt is set,
    // indirect register jumps it recognizes extend recovery into their cases.
    // When is_noreturn is set, a call it flags ends control flow with no
    // fallthrough, the way vivisect stops code flow after a no-return call.
    [[nodiscard]] static Expected<Function>
        recover_one(const InsnReader& read, std::uint64_t start_va,
                    const JumpTableResolver& resolve_jt = {},
                    const NoReturnOracle& is_noreturn = {});

    // Scan undefined code for boundary-anchored function prologues and return
    // candidate function-entry VAs. `covered` is a byte map parallel to `code`
    // (non-zero where a byte already belongs to a recovered function). Mirrors
    // vivisect's funcentries pass, which prologue-scans only the undefined gaps
    // left after call, pointer, and emulation analysis. Used to seed functions
    // in binaries without a .pdata table (32-bit PEs), which would otherwise be
    // reachable only from the entry point's direct-call closure.
    [[nodiscard]] static std::vector<std::uint64_t>
        find_function_prologues(std::span<const std::uint8_t> code,
                                std::uint64_t base_va,
                                std::span<const std::uint8_t> covered);

    // Classify one .pdata RUNTIME_FUNCTION by its UNWIND_INFO VerFlags byte the
    // way vivisect's parsers/pe.py exception walk does: a v2 (ver != 1) or
    // unreadable record bails the whole walk (kStop), a UNW_FLAG_CHAININFO record
    // is a function block rather than an entry and is skipped (kSkipChained), and
    // any other record's begin is a function entry (kSeed). `verflags` is nullopt
    // when the unwind pointer is invalid or the byte cannot be read.
    [[nodiscard]] static PdataEntryKind
        classify_pdata_unwind(std::optional<std::uint8_t> verflags) noexcept;

    // Build an InsnReader that decodes through a PE image
    [[nodiscard]] static InsnReader
        make_image_reader(const pe::PeImage& image, const Disassembler& disasm);

    // Build an InsnReader over a contiguous region starting at base_va
    [[nodiscard]] static InsnReader
        make_span_reader(std::span<const std::byte> region,
                         std::uint64_t base_va,
                         const Disassembler& disasm);

    // Split basic blocks at code addresses branched to from elsewhere in the
    // image. vivisect's codeblocks pass ends a block at any instruction with an
    // incoming REF_CODE xref (getXrefsTo(nextva, REF_CODE)), so a cross-function
    // branch into the middle of a shared block (an SEH funclet reached both by a
    // pointer and by a sibling function's jump) splits it. papa's per-function
    // leader analysis only sees intra-function targets, so this final pass
    // re-splits any block a branch from another recovered function lands inside,
    // keeping basic-block-scope feature grouping faithful to capa.
    static void split_at_external_branch_targets(std::vector<Function>& funcs);
};

}  // namespace papa::features::extractors::papa_native
