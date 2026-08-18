#pragma once

#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <cstdint>
#include <span>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

/// True when function_bytes match a pattern path whose leaf module's tail. CRC16 also
/// verifies
[[nodiscard]] bool match_flirt(const FlirtTree& tree,
                               std::span<const std::uint8_t> function_bytes) noexcept;

/// Every leaf module whose pattern, tail CRC16, and tail bytes all match
/// function_bytes
[[nodiscard]] std::vector<const FlirtModule*>
match_flirt_modules(const FlirtTree& tree,
                    std::span<const std::uint8_t> function_bytes);

}  // namespace papa::features::extractors::papa_native::flirt
