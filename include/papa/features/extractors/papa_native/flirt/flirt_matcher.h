#pragma once

#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <cstdint>
#include <span>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

/// True when function_bytes match a pattern path whose leaf module's tail
/// CRC16 also verifies. A pattern match alone is insufficient because
/// wildcarded patterns collide, so the tail CRC is the disambiguator. Pure,
/// no allocations, never throws
[[nodiscard]] bool match_flirt(const FlirtTree& tree,
                               std::span<const std::uint8_t> function_bytes) noexcept;

/// Every leaf module whose pattern, tail CRC16, and tail bytes all match
/// function_bytes. The tail bytes are single-byte constraints at
/// function-relative offsets that disambiguate modules sharing a pattern and
/// CRC. Returned pointers are owned by `tree` and valid for its lifetime. The
/// library classifier uses the returned modules' names and references to apply
/// capa's reference-gated decision
[[nodiscard]] std::vector<const FlirtModule*>
match_flirt_modules(const FlirtTree& tree,
                    std::span<const std::uint8_t> function_bytes);

}  // namespace papa::features::extractors::papa_native::flirt
