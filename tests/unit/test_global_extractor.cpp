#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/global_.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <string_view>
#include "fixture_paths.h"

using papa::features::Address;
using papa::features::Arch;
using papa::features::FeatureTag;
using papa::features::Format;
using papa::features::NoAddress;
using papa::features::Os;
using papa::features::extractors::FeatureWithAddress;
using papa::features::extractors::extract_global_features;

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");
const auto kChrome = papa_tests::fixture_path("chrome.exe");

[[nodiscard]] const FeatureWithAddress*
find_by_tag(const std::vector<FeatureWithAddress>& v, FeatureTag tag) {
    for (const auto& fa : v) {
        if (fa.first && fa.first->tag() == tag) { return &fa; }
    }
    return nullptr;
}

}  // namespace

TEST_CASE("global_: notepad.exe yields os=windows, format=pe, arch=amd64") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    auto feats = extract_global_features(*res);

    const auto* os = find_by_tag(feats, FeatureTag::kOs);
    REQUIRE(os != nullptr);
    CHECK(static_cast<const Os*>(os->first.get())->value() == "windows");
    CHECK(std::holds_alternative<NoAddress>(os->second));

    const auto* fmt = find_by_tag(feats, FeatureTag::kFormat);
    REQUIRE(fmt != nullptr);
    CHECK(static_cast<const Format*>(fmt->first.get())->value() == "pe");

    const auto* arch = find_by_tag(feats, FeatureTag::kArch);
    REQUIRE(arch != nullptr);
    const std::string& av = static_cast<const Arch*>(arch->first.get())->value();
    // notepad on a modern Windows install is amd64. Tolerate i386 in case the fixture
    // is from a 32-bit machine
    CHECK((av == "amd64" || av == "i386"));
}

TEST_CASE("global_: pe_arch names only the i386 and amd64 machines") {
    using papa::features::extractors::pe_arch;
    CHECK(pe_arch(0x014C) == std::optional<std::string_view>{"i386"});
    CHECK(pe_arch(0x8664) == std::optional<std::string_view>{"amd64"});
    CHECK_FALSE(pe_arch(0xAA64).has_value());
    CHECK_FALSE(pe_arch(0x0000).has_value());
}

TEST_CASE("global_: chrome.exe also yields the standard triple") {
    if (!std::filesystem::exists(kChrome)) {
        MESSAGE("fixture missing: " << kChrome);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kChrome);
    REQUIRE(res.has_value());
    auto feats = extract_global_features(*res);
    CHECK(find_by_tag(feats, FeatureTag::kOs)     != nullptr);
    CHECK(find_by_tag(feats, FeatureTag::kFormat) != nullptr);
    CHECK(find_by_tag(feats, FeatureTag::kArch)   != nullptr);
}
