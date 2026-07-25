#pragma once

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace papa::features::extractors::papa_native {

// How vivisect's .pdata walk treats one RUNTIME_FUNCTION (parsers/pe.py)
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
};

// What one analysis run recovers: the functions, plus the library functions
// FLIRT identified along the way with the name it assigned each. Both come from
// the same pass, because FLIRT runs as an analysis module while functions are
// being made, so its naming reflects the state it actually saw
struct RecoveredImage {
    std::vector<Function>                          functions;
    std::unordered_map<std::uint64_t, std::string> library_names;
};

// Callback returning a decoded instruction at a given VA
// Errors are fatal to the single function being recovered, not to the image
using InsnReader = std::function<Expected<DecodedInsn>(std::uint64_t va)>;

namespace cfg {

/// Whole-image function recovery, a faithful port of vivisect's analysis: the
/// ordered discovery passes (entrypoints and .pdata, relocations, emucode, plus
/// calling and funcentries on i386) drive a code-flow engine over a shared
/// location database, with the codeblocks, no-return, and FLIRT modules running
/// inline as each function is made. Block attribution is order-dependent and
/// shared the way vivisect's is. Returns the functions together with the library
/// functions FLIRT named during the same pass
[[nodiscard]] Expected<RecoveredImage>
    recover(const pe::PeImage& image, const Disassembler& disasm);

/// Scan undefined code for boundary-anchored function prologues and return
/// candidate function-entry VAs. `covered` is a byte map parallel to `code`,
/// non-zero where a byte already belongs to a recovered function. Mirrors
/// vivisect's funcentries pass, which prologue-scans only the gaps earlier
/// analysis left undefined
[[nodiscard]] std::vector<std::uint64_t>
    find_function_prologues(std::span<const std::uint8_t> code,
                            std::uint64_t                 base_va,
                            std::span<const std::uint8_t> covered);

/// Classify one .pdata RUNTIME_FUNCTION by its UNWIND_INFO VerFlags byte the way
/// vivisect's parsers/pe.py exception walk does: a v2 or unreadable record bails
/// the whole walk, a UNW_FLAG_CHAININFO record is a function block rather than an
/// entry and is skipped, and any other record's begin is a function entry
[[nodiscard]] PdataEntryKind
    classify_pdata_unwind(std::optional<std::uint8_t> verflags) noexcept;

/// The x64 .pdata RUNTIME_FUNCTION begins that are function entries, ascending.
/// Empty for a 32-bit image or one with no .pdata table
[[nodiscard]] std::vector<std::uint64_t>
    pdata_function_begins(const pe::PeImage& image);

/// Build an InsnReader that decodes through a PE image
[[nodiscard]] InsnReader
    make_image_reader(const pe::PeImage& image, const Disassembler& disasm);

/// Build an InsnReader over a contiguous region starting at base_va
[[nodiscard]] InsnReader
    make_span_reader(std::span<const std::byte> region, std::uint64_t base_va,
                     const Disassembler& disasm);

}  // namespace cfg

}  // namespace papa::features::extractors::papa_native
