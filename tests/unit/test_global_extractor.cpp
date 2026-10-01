#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/global_.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "pe_builder.h"
#include "test_support.h"

using papa::features::Arch;
using papa::features::Format;
using papa::features::NoAddress;
using papa::features::Os;
using papa::features::extractors::FeatureWithAddress;
using papa::features::extractors::extract_global_features;

TEST_CASE("global_: a PE yields os windows, format pe and its arch, all at no address") {
    struct Row {
        std::string_view label;
        bool             x64;
        std::uint16_t    machine;  // 0 keeps the machine the builder writes
        std::string_view arch;     // empty when no arch is emitted
    };
    const std::array<Row, 3> rows{{
        {"amd64", true, 0, "amd64"},
        {"i386", false, 0, "i386"},
        {"an unsupported machine has no arch", true, 0xAA64, ""},
    }};
    for (const Row& row : rows) {
        CAPTURE(row.label);
        papa_tests::PeBuilder b;
        b.x64  = row.x64;
        b.code = {0xC3};
        auto bytes = b.build();
        if (row.machine != 0) {
            std::memcpy(bytes.data() + b.header_layout().file_header, &row.machine,
                        sizeof row.machine);
        }
        const auto img = papa::pe::PeParser::parse(bytes);
        REQUIRE(img.has_value());

        const NoAddress                 none;
        std::vector<FeatureWithAddress> want{
            {papa_tests::feat<Os>("windows"), none},
            {papa_tests::feat<Format>("pe"), none},
        };
        if (!row.arch.empty()) {
            want.emplace_back(papa_tests::feat<Arch>(std::string(row.arch)), none);
        }
        CHECK(papa_tests::describe(extract_global_features(*img)) == papa_tests::describe(want));
    }
}

TEST_CASE("global_: pe_arch names only the i386 and amd64 machines") {
    using papa::features::extractors::pe_arch;
    CHECK(pe_arch(0x014C) == std::optional<std::string_view>{"i386"});
    CHECK(pe_arch(0x8664) == std::optional<std::string_view>{"amd64"});
    CHECK_FALSE(pe_arch(0xAA64).has_value());
    CHECK_FALSE(pe_arch(0x0000).has_value());
}
