#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/backend.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/insn.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <filesystem>
#include <string_view>
#include <utility>
#include "fixture_paths.h"

using papa::features::extractors::papa_native::PapaNativeBackend;

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");

}  // namespace

TEST_CASE("backend: build returns a populated aggregate for a real PE") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());

    auto backend = PapaNativeBackend::build(*img);
    REQUIRE(backend.has_value());
    CHECK(&backend->image() == &*img);
    CHECK_FALSE(backend->functions().empty());
    CHECK(backend->disassembler().is_64bit() == img->is_64bit());
    CHECK_FALSE(backend->imports().by_iat_va.empty());
}

TEST_CASE("backend: imports are indexed by IAT VA matching the image's row") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());
    auto backend = PapaNativeBackend::build(*img);
    REQUIRE(backend.has_value());

    for (const auto& [va, row] : backend->imports().by_iat_va) {
        REQUIRE(row != nullptr);
        CHECK(row->iat_va == va);
    }
}

TEST_CASE("backend: backend is move-constructible") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());
    auto backend = PapaNativeBackend::build(*img);
    REQUIRE(backend.has_value());

    PapaNativeBackend moved = std::move(*backend);
    CHECK_FALSE(moved.functions().empty());
}
