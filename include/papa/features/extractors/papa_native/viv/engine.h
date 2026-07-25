#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

namespace papa::features::extractors::papa_native::viv {

/// Drive the discovery engine over a PE image through vivisect's ordered passes
/// (entrypoints and .pdata, relocations, emucode, plus calling and funcentries
/// on i386). The codeblocks, no-return, and FLIRT modules run inline as each
/// function is made, so shared blocks are attributed the way vivisect's
/// order-dependent analysis attributes them
[[nodiscard]] RecoveredImage
    discover_functions(const pe::PeImage& image, const Disassembler& disasm);

}  // namespace papa::features::extractors::papa_native::viv
