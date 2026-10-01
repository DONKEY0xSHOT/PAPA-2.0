#include <ostream>

#include "doctest.h"

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/flirt/flirt_decompress.h"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

TEST_CASE("flirt_decompress: an empty, malformed or truncated stream is a bad compressed stream") {
    struct Row {
        std::string_view          label;
        std::vector<std::uint8_t> stream;
    };
    const std::vector<Row> rows{
        {"empty input", {}},
        {"a malformed stream", std::vector<std::uint8_t>(8, 0xFF)},
        // The first 8 bytes of the 13-byte payload's zlib stream
        {"a truncated valid stream", {0x78, 0xDA, 0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0xD7}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto out = flirt::decompress_inflate(row.stream);
        CHECK_FALSE(out.has_value());
        if (!out.has_value()) {
            CHECK(out.error().kind == papa::ErrorKind::kFlirtBadCompressedStream);
        }
    }
}

TEST_CASE("flirt_decompress: zlib payloads round-trip byte for byte") {
    std::vector<std::uint8_t> counting(32);
    for (std::size_t i = 0; i < counting.size(); ++i) {
        counting[i] = static_cast<std::uint8_t>(i);
    }
    const std::string_view hello = "Hello, FLIRT!";
    struct Row {
        std::string_view          label;
        std::vector<std::uint8_t> compressed;
        std::vector<std::uint8_t> expected;
    };
    const std::vector<Row> rows{
        // zlib.compress(b"Hello, FLIRT!", 9)
        {"a 13-byte text payload",
         {0x78, 0xDA, 0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0xD7, 0x51, 0x70, 0xF3,
          0xF1, 0x0C, 0x0A, 0x51, 0x04, 0x00, 0x1D, 0x77, 0x03, 0xE3},
         {hello.begin(), hello.end()}},
        // zlib.compress(bytes(range(32)), 9)
        {"a 32-byte deterministic payload",
         {0x78, 0xDA, 0x63, 0x60, 0x64, 0x62, 0x66, 0x61, 0x65, 0x63, 0xE7, 0xE0, 0xE4, 0xE2,
          0xE6, 0xE1, 0xE5, 0xE3, 0x17, 0x10, 0x14, 0x12, 0x16, 0x11, 0x15, 0x13, 0x97, 0x90,
          0x94, 0x92, 0x96, 0x91, 0x95, 0x93, 0x07, 0x00, 0x15, 0x70, 0x01, 0xF1},
         counting},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto out = flirt::decompress_inflate(row.compressed);
        REQUIRE(out.has_value());
        CHECK(out->size() == row.expected.size());
        for (std::size_t i = 0; i < out->size() && i < row.expected.size(); ++i) {
            CAPTURE(i);
            CHECK(static_cast<std::uint8_t>((*out)[i]) == row.expected[i]);
        }
    }
}
