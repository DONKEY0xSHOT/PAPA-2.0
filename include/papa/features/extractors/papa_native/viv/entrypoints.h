#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "papa/pe/pe_image.h"

namespace papa::features::extractors::papa_native::viv {

// How vivisect's .pdata walk treats one RUNTIME_FUNCTION (parsers/pe.py)
enum class PdataEntryKind {
    kSeed,         // a function entry: add its begin as a seed
    kSkipChained,  // a UNW_FLAG_CHAININFO function block, not an entry: skip it
    kStop,         // a v2 (ver != 1) or unreadable UNWIND_INFO: bail the walk
};

/// Classify one .pdata RUNTIME_FUNCTION by its UNWIND_INFO VerFlags byte the way
/// vivisect's parsers/pe.py exception walk does
[[nodiscard]] PdataEntryKind
    classify_pdata_unwind(std::optional<std::uint8_t> verflags) noexcept;

/// The x64 .pdata RUNTIME_FUNCTION begins that are function entries, ascending.
/// Empty for a 32-bit image or one with no .pdata table
[[nodiscard]] std::vector<std::uint64_t>
    pdata_function_begins(const pe::PeImage& image);

/// Scan undefined code for boundary-anchored function prologues and return candidate
/// function-entry VAs
[[nodiscard]] std::vector<std::uint64_t>
    find_function_prologues(std::span<const std::uint8_t> code,
                            std::uint64_t                 base_va,
                            std::span<const std::uint8_t> covered);

}  // namespace papa::features::extractors::papa_native::viv
