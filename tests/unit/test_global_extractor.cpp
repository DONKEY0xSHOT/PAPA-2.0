#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/global_.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <filesystem>
#include <string_view>
#include "fixture_paths.h"

using papa::features::Address;
using papa::features::Arch;
using papa::features::FeatureTag;
using papa::features::Format;
using papa::features::NoAddress;
using papa::features::Os;
using papa::features::extractors::papa_native::FeatureWithAddress;
using papa::features::extractors::papa_native::extract_global_features;

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
    // notepad on a modern Windows install is amd64
    // Tolerate i386 in case the
    // fixture is from a 32-bit machine
    CHECK((av == "amd64" || av == "i386"));
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
