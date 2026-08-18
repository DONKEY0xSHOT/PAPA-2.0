#include <ostream>

#include "doctest.h"

#include "papa/features/address.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/extractor.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include "fixture_paths.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;
namespace pn = papa::features::extractors::papa_native;

// End-to-end check that the embedded FLIRT signatures match real library functions in a
// compiled binary
TEST_CASE("flirt: embedded signatures classify real library functions") {
    const auto chrome = papa_tests::fixture_path("chrome.exe");
    if (!papa_tests::fixture_available(chrome)) {
        MESSAGE("chrome.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(chrome);
    REQUIRE(img.has_value());
    const auto sigs = flirt::FlirtSignatureSet::make_embedded();
    // The packs are embedded as a Windows resource, so the registry is empty on any
    // other toolchain and there is nothing to classify against
    if (sigs.tree_count() == 0U) {
        MESSAGE("FLIRT signatures are not embedded in this build, skipping");
        return;
    }

    const std::array<std::uint64_t, 5> library_starts = {
        0x14000C4F0ULL, 0x1401940D0ULL, 0x140194EC8ULL, 0x140198910ULL, 0x1401A2A48ULL,
    };
    int matched = 0;
    for (const auto va : library_starts) {
        auto bytes = img->read_at_rva(va - img->image_base(), 512);
        if (!bytes) { continue; }
        std::vector<std::uint8_t> code;
        code.reserve(bytes->size());
        for (const std::byte b : *bytes) { code.push_back(static_cast<std::uint8_t>(b)); }
        if (sigs.classify(code)) { matched += 1; }
    }
    CHECK(matched == static_cast<int>(library_starts.size()));
}

// Per-signature priming resolves a collision the aggregated match cannot, where two
// trees offer differently-named candidates and the function would go unnamed
TEST_CASE("flirt: per-tree priming marks certutil mainCRTStartup library") {
    const auto certutil = papa_tests::fixture_path("corpus/certutil_x64.exe");
    if (!papa_tests::fixture_available(certutil)) {
        MESSAGE("corpus/certutil_x64.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(certutil);
    REQUIRE(img.has_value());
    auto backend = pn::PapaNativeBackend::build(*img);
    REQUIRE(backend);
    const pn::PapaNativeStaticExtractor extractor(std::move(*backend));

    const papa::features::Address mainCRTStartup{
        papa::features::AbsoluteVirtualAddress{0x14011a9d0ULL}};
    CHECK(extractor.is_library_function(mainCRTStartup));
}
