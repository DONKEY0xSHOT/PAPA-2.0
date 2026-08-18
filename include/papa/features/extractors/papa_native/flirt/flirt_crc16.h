#pragma once

#include <cstdint>
#include <span>

namespace papa::features::extractors::papa_native::flirt {

/// FLAIR CRC16 over the given byte range, as stored in IDASGN modules
[[nodiscard]] std::uint16_t flirt_crc16(
    std::span<const std::uint8_t> data) noexcept;

}  // namespace papa::features::extractors::papa_native::flirt
