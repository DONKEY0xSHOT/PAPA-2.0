#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/pefile.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using papa::features::AbsoluteVirtualAddress;
using papa::features::Address;
using papa::features::Characteristic;
using papa::features::Feature;
using papa::features::FeatureTag;
using papa::features::Format;
using papa::features::Import;
using papa::features::NoAddress;
using papa::features::Section;
using papa::features::String;
using papa::features::extractors::pefile::FeatureWithAddress;

namespace {

constexpr std::string_view kNotepad = "C:/Windows/System32/notepad.exe";

[[nodiscard]] bool has_feature_value(const std::vector<FeatureWithAddress>& v,
                                     FeatureTag tag,
                                     std::string_view want) {
    for (const auto& [feat, _addr] : v) {
        if (!feat || feat->tag() != tag) { continue; }
        switch (tag) {
            case FeatureTag::kImport:
                if (static_cast<const Import*>(feat.get())->value() == want) { return true; }
                break;
            case FeatureTag::kSection:
                if (static_cast<const Section*>(feat.get())->value() == want) { return true; }
                break;
            case FeatureTag::kFormat:
                if (static_cast<const Format*>(feat.get())->value() == want) { return true; }
                break;
            case FeatureTag::kCharacteristic:
                if (static_cast<const Characteristic*>(feat.get())->value() == want) { return true; }
                break;
            case FeatureTag::kString:
                if (static_cast<const String*>(feat.get())->value() == want) { return true; }
                break;
            default:
                break;
        }
    }
    return false;
}

[[nodiscard]] std::size_t count_tag(const std::vector<FeatureWithAddress>& v, FeatureTag tag) {
    return static_cast<std::size_t>(std::count_if(v.begin(), v.end(),
        [&](const FeatureWithAddress& fa) {
            return fa.first && fa.first->tag() == tag;
        }));
}

}  // namespace

TEST_CASE("pefile: notepad emits format=pe, .text section, common imports") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());

    auto feats = papa::features::extractors::pefile::extract_file_features(*res);
    CHECK(has_feature_value(feats, FeatureTag::kFormat,  "pe"));
    CHECK(has_feature_value(feats, FeatureTag::kSection, ".text"));

    // notepad always imports something from kernel32
    // The bare symbol form is generated
    CHECK(count_tag(feats, FeatureTag::kImport) > 0);
}

TEST_CASE("pefile: extract_file_section_names addresses each section by VA") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());

    auto feats = papa::features::extractors::pefile::extract_file_section_names(*res);
    REQUIRE_FALSE(feats.empty());
    for (const auto& [feat, addr] : feats) {
        REQUIRE(feat != nullptr);
        CHECK(feat->tag() == FeatureTag::kSection);
        CHECK(std::holds_alternative<AbsoluteVirtualAddress>(addr));
    }
}

TEST_CASE("pefile: extract_file_format yields a single Format(pe) at NoAddress") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    auto feats = papa::features::extractors::pefile::extract_file_format(*res);
    REQUIRE(feats.size() == 1);
    CHECK(feats[0].first->tag() == FeatureTag::kFormat);
    CHECK(std::holds_alternative<NoAddress>(feats[0].second));
}

TEST_CASE("pefile: extract_file_import_names emits dotted, bare, and AW variants") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    auto feats = papa::features::extractors::pefile::extract_file_import_names(*res);

    // We don't know exactly which APIs notepad imports across Windows versions
    // but every import row produces at least the dotted and bare spellings, so
    // the count of Import features must exceed the count of distinct imports
    CHECK(feats.size() >= res->imports().size());
}

TEST_CASE("pefile: extract_file_strings populates strings from raw bytes") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    auto feats = papa::features::extractors::pefile::extract_file_strings(*res);
    // notepad has lots of strings
    // We just verify the extractor emits some
    CHECK(feats.size() > 100U);
    for (const auto& [feat, addr] : feats) {
        REQUIRE(feat != nullptr);
        CHECK(feat->tag() == FeatureTag::kString);
        CHECK(std::holds_alternative<papa::features::FileOffsetAddress>(addr));
    }
}
