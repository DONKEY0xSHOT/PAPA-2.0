#include "papa/features/extractors/papa_native/flirt/flirt_crc16.h"

#include "papa/features/extractors/papa_native/flirt/flirt_format.h"

namespace papa::features::extractors::papa_native::flirt {

std::uint16_t flirt_crc16(std::span<const std::uint8_t> data) noexcept {
    std::uint16_t crc = 0xFFFFU;
    for (const std::uint8_t byte : data) {
        crc = static_cast<std::uint16_t>(crc ^ byte);
        for (int bit = 0; bit < 8; ++bit) {
            const bool lsb = (crc & 1U) != 0U;
            crc = static_cast<std::uint16_t>(crc >> 1);
            if (lsb) {
                crc = static_cast<std::uint16_t>(crc ^ kCrc16Polynomial);
            }
        }
    }
    // FLAIR completes the CRC with a one's-complement and a byte swap
    const auto inverted = static_cast<std::uint16_t>(~crc);
    return static_cast<std::uint16_t>((inverted << 8) | (inverted >> 8));
}

}  // namespace papa::features::extractors::papa_native::flirt
