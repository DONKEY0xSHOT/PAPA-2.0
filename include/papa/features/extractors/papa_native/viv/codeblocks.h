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

/// The two block stores vivisect keeps, a multi-owner per-function list that capa
/// reads and a single-owner last-writer map keyed by block start
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

/// Predicate: true when the instruction at va does not fall through, the envi.
/// IF_NOFALL signal, including a no-return call the noret pass marked
using NoFallPredicate = std::function<bool(std::uint64_t va)>;

/// Predicate: true when the bytes at va decode to a valid instruction, the
/// vw.parseOpcode(va) call codeblocks makes for every instruction
using ParsePredicate = std::function<bool(std::uint64_t va)>;

/// Port of vivisect's generic codeblocks analyzeFunction
void analyze_function(const LocationDb& locations, const XrefDb& xrefs,
                      const NoFallPredicate& is_no_fall,
                      const ParsePredicate& can_parse,
                      std::uint64_t function_va, CodeBlockStore& store);

}  // namespace papa::features::extractors::papa_native::viv
