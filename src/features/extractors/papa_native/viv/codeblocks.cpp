#include "papa/features/extractors/papa_native/viv/codeblocks.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::viv {

void CodeBlockStore::add_code_block(std::uint64_t va, std::uint64_t size,
                                    std::uint64_t function_va) {
    const CodeBlock block{va, size, function_va};
    by_function_[function_va].push_back(block);
    by_start_[va] = block;  // last writer owns the start, matching blockmap
}

const std::vector<CodeBlock>&
CodeBlockStore::function_blocks(std::uint64_t function_va) const {
    static const std::vector<CodeBlock> kEmpty;
    const auto it = by_function_.find(function_va);
    return it == by_function_.end() ? kEmpty : it->second;
}

std::optional<CodeBlock> CodeBlockStore::code_block(std::uint64_t va) const {
    const auto it = by_start_.find(va);
    if (it == by_start_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void analyze_function(const LocationDb& locations, const XrefDb& xrefs,
                      const NoFallPredicate& is_no_fall,
                      const ParsePredicate& can_parse,
                      std::uint64_t function_va, CodeBlockStore& store) {
    // block start -> block size, discovered by the flow walk below
    std::unordered_map<std::uint64_t, std::uint64_t> blocks;
    std::unordered_set<std::uint64_t>                done;
    // (address, is_block_begin) markers, sorted at the end to register blocks in
    // ascending order
    std::vector<std::pair<std::uint64_t, bool>> block_refs;
    std::vector<std::uint64_t>                  todo{function_va};

    while (!todo.empty()) {
        const std::uint64_t start = todo.back();
        todo.pop_back();
        if (!done.insert(start).second) {
            continue;
        }
        blocks[start] = 0;
        block_refs.emplace_back(start, true);

        std::uint64_t va = start;
        while (true) {
            const auto loc = locations.get_location(va);
            // Stop-A: an undefined or non-instruction address ends the block short
            // of it
            if (!loc.has_value() || loc->type != LocType::kOp) {
                blocks[start] = va - start;
                block_refs.emplace_back(va, false);
                break;
            }
            // Bad-opcode reparse: vivisect reparses each instruction and breaks
            // the walk on a decode failure, without recording the block or an end
            // marker, so blocks[start] stays 0 and Skip-D drops it. This fires
            // only where an overlapping decode (a FLIRT sub-function whose fresh
            // decode straddles the enclosing function) left the byte map claiming
            // LOC_OP at an address whose bytes do not decode
            if (can_parse && !can_parse(va)) {
                break;
            }
            const std::uint64_t next_va = va + loc->size;

            // Split-B: every non-procedural, non-deref code edge out of this
            // instruction ends the block and starts a new block at each target.
            // Calls (BR_PROC) and import derefs (BR_DEREF) do not split a block
            bool branch = false;
            for (const CodeXref& xref : xrefs.code_xrefs_from(va)) {
                if ((xref.branch_flags & kBrProc) != 0) {
                    continue;
                }
                if ((xref.branch_flags & kBrDeref) != 0) {
                    continue;
                }
                branch = true;
                todo.push_back(xref.to_va);
            }

            // A no-fall instruction ends the block after it, with no fall-through.
            // vivisect reads IF_NOFALL from the containing location, so query the
            // location start rather than the walk address (they differ only in an
            // overlapping-decode march, where the containing op still governs)
            if (is_no_fall && is_no_fall(loc->va)) {
                blocks[start] = next_va - start;
                block_refs.emplace_back(next_va, false);
                break;
            }
            // A branch ends the block, and its fall-through becomes a new block
            if (branch) {
                blocks[start] = next_va - start;
                todo.push_back(next_va);
                break;
            }
            // Split-C: an inbound edge to the next instruction makes it a block
            // start, so this block ends there
            if (xrefs.has_code_xref_to(next_va)) {
                blocks[start] = next_va - start;
                todo.push_back(next_va);
                break;
            }
            va = next_va;
        }
    }

    // Registration. Sorting then reversing lets pop-from-end visit begins in
    // ascending address order. On a fresh analysis there are no prior blocks, so
    // every nonzero-size begin is simply added (the re-analysis size-change path
    // is deliberately omitted until the oracle shows it moves counts)
    std::sort(block_refs.begin(), block_refs.end());
    std::reverse(block_refs.begin(), block_refs.end());
    while (!block_refs.empty()) {
        const auto [bva, is_begin] = block_refs.back();
        block_refs.pop_back();
        if (!is_begin) {
            continue;
        }
        if (block_refs.empty()) {
            break;
        }
        const std::uint64_t bsize = blocks[bva];
        if (bsize == 0) {  // Skip-D: a begin whose first byte was undefined
            continue;
        }
        store.add_code_block(bva, bsize, function_va);
    }
}

}  // namespace papa::features::extractors::papa_native::viv
