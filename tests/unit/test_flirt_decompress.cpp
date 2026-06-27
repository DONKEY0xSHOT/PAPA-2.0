#include <ostream>

#include "doctest.h"

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/flirt/flirt_decompress.h"

#include <array>
#include <cstdint>
#include <cstring>

namespace flirt = papa::features::extractors::papa_native::flirt;

TEST_CASE("flirt_decompress: empty input is rejected as truncated") {
    auto result = flirt::decompress_inflate({});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == papa::ErrorKind::kFlirtBadCompressedStream);
}

TEST_CASE("flirt_decompress: round-trip a zlib payload of 13 bytes") {
    // zlib.compress(b"Hello, FLIRT!", 9)
    constexpr std::array<std::uint8_t, 21> compressed = {
        0x78, 0xDA, 0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0xD7,
        0x51, 0x70, 0xF3, 0xF1, 0x0C, 0x0A, 0x51, 0x04,
        0x00, 0x1D, 0x77, 0x03, 0xE3,
    };
    auto out = flirt::decompress_inflate(compressed);
    REQUIRE(out.has_value());
    REQUIRE(out->size() == 13);
    static constexpr char kExpected[] = "Hello, FLIRT!";
    CHECK(std::memcmp(out->data(), kExpected, 13) == 0);
}

TEST_CASE("flirt_decompress: round-trip a 32-byte deterministic payload") {
    // zlib.compress(bytes(range(32)), 9)
    constexpr std::array<std::uint8_t, 40> compressed = {
        0x78, 0xDA, 0x63, 0x60, 0x64, 0x62, 0x66, 0x61, 0x65, 0x63,
        0xE7, 0xE0, 0xE4, 0xE2, 0xE6, 0xE1, 0xE5, 0xE3, 0x17, 0x10,
        0x14, 0x12, 0x16, 0x11, 0x15, 0x13, 0x97, 0x90, 0x94, 0x92,
        0x96, 0x91, 0x95, 0x93, 0x07, 0x00, 0x15, 0x70, 0x01, 0xF1,
    };
    auto out = flirt::decompress_inflate(compressed);
    REQUIRE(out.has_value());
    REQUIRE(out->size() == 32);
    for (std::size_t i = 0; i < 32; ++i) {
        CHECK(static_cast<std::uint8_t>((*out)[i]) == static_cast<std::uint8_t>(i));
    }
}

TEST_CASE("flirt_decompress: malformed stream returns kFlirtBadCompressedStream") {
    constexpr std::array<std::uint8_t, 8> garbage = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    auto out = flirt::decompress_inflate(garbage);
    REQUIRE_FALSE(out.has_value());
    CHECK(out.error().kind == papa::ErrorKind::kFlirtBadCompressedStream);
}

TEST_CASE("flirt_decompress: truncated valid stream returns an error") {
    constexpr std::array<std::uint8_t, 8> truncated = {
        0x78, 0xDA, 0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0xD7,
    };
    auto out = flirt::decompress_inflate(truncated);
    REQUIRE_FALSE(out.has_value());
    CHECK(out.error().kind == papa::ErrorKind::kFlirtBadCompressedStream);
}
