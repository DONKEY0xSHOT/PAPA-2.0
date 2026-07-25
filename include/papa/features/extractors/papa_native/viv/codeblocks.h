#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>
#include <vector>

#include "papa/features/extractors/papa_native/viv/location_db.h"
#include "papa/features/extractors/papa_native/viv/xref_db.h"

namespace papa::features::extractors::papa_native::viv {

/// One basic block: the half-open byte range [va, va + size) attributed to
/// function_va
struct CodeBlock {
    std::uint64_t va{0};
    std::uint64_t size{0};
    std::uint64_t function_va{0};
};

/// The two block stores vivisect keeps (base.py _handleADDCODEBLOCK): a
/// multi-owner per-function list (getFunctionBlocks, which capa reads, where one
/// block may belong to several functions) and a single-owner last-writer map
/// keyed by block start (getCodeBlock)
class CodeBlockStore {
public:
    /// Record a block, appending it to its function's list and making it the
    /// current single owner of its start address
    void add_code_block(std::uint64_t va, std::uint64_t size,
                        std::uint64_t function_va);

    /// The blocks attributed to function_va, in registration order, or an empty
    /// list when it has none
    [[nodiscard]] const std::vector<CodeBlock>&
    function_blocks(std::uint64_t function_va) const;

    /// The block that currently owns the start address va, or nullopt
    [[nodiscard]] std::optional<CodeBlock>
    code_block(std::uint64_t va) const;

private:
    std::unordered_map<std::uint64_t, std::vector<CodeBlock>> by_function_;
    std::unordered_map<std::uint64_t, CodeBlock>              by_start_;
};

/// Predicate: true when the instruction at va does not fall through, the envi
/// IF_NOFALL signal, including a no-return call the noret pass marked. Supplied
/// by the driver so codeblocks stays a pure reader of analysis state
using NoFallPredicate = std::function<bool(std::uint64_t va)>;

/// Predicate: true when the bytes at va decode to a valid instruction, the
/// vw.parseOpcode(va) call codeblocks makes for every instruction. It is
/// re-derived from the raw bytes at the walk address, so an address whose
/// containing location says LOC_OP can still fail to parse when a later,
/// overlapping decode left the byte map inconsistent (a FLIRT-created
/// sub-function whose fresh decode overlaps its enclosing function). On failure
/// vivisect breaks the walk without recording the block, so the enclosing
/// function ends with no blocks. Supplied by the driver over its instruction
/// reader
using ParsePredicate = std::function<bool(std::uint64_t va)>;

/// Port of vivisect's generic codeblocks analyzeFunction. Walks the function's
/// flow over the global location and cross-reference state, ending a block at a
/// branch, a join, a no-fall instruction, or an undefined address, and registers
/// the resulting blocks in store. A bad-opcode reparse breaks the walk without
/// recording the block, reproducing vivisect's graph-build failure on an
/// overlapping decode. It reads the shared state and never mutates it, so it can
/// run interleaved at function make-time
void analyze_function(const LocationDb& locations, const XrefDb& xrefs,
                      const NoFallPredicate& is_no_fall,
                      const ParsePredicate& can_parse,
                      std::uint64_t function_va, CodeBlockStore& store);

}  // namespace papa::features::extractors::papa_native::viv
