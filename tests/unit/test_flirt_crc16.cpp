#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_crc16.h"

#include <array>
#include <cstdint>

namespace flirt = papa::features::extractors::papa_native::flirt;

// FLAIR CRC16: reflected polynomial 0x8408, initial value 0xFFFF, finished
// with a one's-complement and a byte swap. These vectors are the values FLAIR
// actually stores in real .sig modules, verified against capa's signatures.

TEST_CASE("flirt_crc16: empty input is zero") {
    CHECK(flirt::flirt_crc16({}) == 0x0000U);
}

TEST_CASE("flirt_crc16: single-byte reference vectors") {
    constexpr std::array<std::uint8_t, 1> zero  = {0x00};
    constexpr std::array<std::uint8_t, 1> all_f = {0xFF};
    CHECK(flirt::flirt_crc16(zero)  == 0x78F0U);
    CHECK(flirt::flirt_crc16(all_f) == 0x00FFU);
}

TEST_CASE("flirt_crc16: classic 123456789 reference value") {
    constexpr std::array<std::uint8_t, 9> nine = {
        '1', '2', '3', '4', '5', '6', '7', '8', '9',
    };
    CHECK(flirt::flirt_crc16(nine) == 0x6E90U);
}

TEST_CASE("flirt_crc16: 16-byte ASCII slice") {
    constexpr std::array<std::uint8_t, 16> sixteen = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    };
    CHECK(flirt::flirt_crc16(sixteen) == 0x6EB2U);
}

TEST_CASE("flirt_crc16: thirty-two zero bytes") {
    constexpr std::array<std::uint8_t, 32> zeros{};
    CHECK(flirt::flirt_crc16(zeros) == 0x70CDU);
}
