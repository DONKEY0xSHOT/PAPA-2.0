#pragma once

#include <cstdint>
#include <span>

namespace papa::features::extractors::papa_native::flirt {

/// FLAIR CRC16 over the given byte range, as stored in IDASGN modules.
///
/// Reflected polynomial 0x8408, initial value 0xFFFF, finished with a
/// one's-complement and a byte swap. The final transform makes the result
/// non-streamable, so the whole range is hashed in a single call
[[nodiscard]] std::uint16_t flirt_crc16(
    std::span<const std::uint8_t> data) noexcept;

}  // namespace papa::features::extractors::papa_native::flirt
