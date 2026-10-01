#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_crc16.h"

#include <cstdint>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

// FLAIR CRC16: reflected polynomial 0x8408, initial value 0xFFFF, finished with a
// one's-complement and a byte swap

TEST_CASE("flirt_crc16: reference vectors") {
    struct Row {
        std::string_view          label;
        std::vector<std::uint8_t> bytes;
        std::uint16_t             crc;
    };
    const std::vector<Row> rows{
        {"empty input is zero", {}, 0x0000U},
        {"a single zero byte", {0x00}, 0x78F0U},
        {"a single 0xFF byte", {0xFF}, 0x00FFU},
        {"the classic 123456789", {'1', '2', '3', '4', '5', '6', '7', '8', '9'}, 0x6E90U},
        {"a 16-byte ASCII slice",
         {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'}, 0x6EB2U},
        {"thirty-two zero bytes", std::vector<std::uint8_t>(32, 0), 0x70CDU},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(flirt::flirt_crc16(row.bytes) == row.crc);
    }
}
