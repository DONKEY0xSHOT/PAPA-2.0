#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

namespace papa::features::extractors::papa_native::viv {

/// Drive the discovery engine over a PE image through vivisect's ordered passes,
/// with the codeblocks, no-return and FLIRT modules running inline per function
[[nodiscard]] RecoveredImage
    discover_functions(const pe::PeImage& image, const Disassembler& disasm);

}  // namespace papa::features::extractors::papa_native::viv
