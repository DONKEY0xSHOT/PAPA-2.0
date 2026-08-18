#pragma once

#include "papa/exceptions.h"

#include <cstdint>
#include <span>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

/// Inflate a zlib-formatted DEFLATE stream into a byte vector. Caps the decompressed
/// output at kMaxDecompressedSize to defeat decompression bombs
[[nodiscard]] Expected<std::vector<std::uint8_t>> decompress_inflate(
    std::span<const std::uint8_t> compressed) noexcept;

}  // namespace papa::features::extractors::papa_native::flirt
