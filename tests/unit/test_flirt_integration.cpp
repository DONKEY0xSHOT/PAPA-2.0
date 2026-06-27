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

// End-to-end check that the embedded FLIRT signatures match real library
// functions in a compiled binary. Before the CRC16 final-transform fix the
// matcher verified zero real functions despite parsing every signature, so a
// pure unit test over synthetic sigs could not catch it. The addresses below
// are library-function starts in
//   chrome.exe sha256 0cac3d17c4f4b83ad936cead2a7e79efcc2e0e39ee030a84477af95cffc2bc84
// the same functions vivisect plus FLIRT mark as library in capa.
TEST_CASE("flirt: embedded signatures classify real library functions") {
    const auto chrome = papa_tests::fixture_path("chrome.exe");
    if (!papa_tests::fixture_available(chrome)) {
        MESSAGE("chrome.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(chrome);
    REQUIRE(img.has_value());
    const auto sigs = flirt::FlirtSignatureSet::make_embedded();

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

// Per-signature priming resolves a collision the aggregated match cannot.
// certutil's mainCRTStartup at 0x14011a9d0 shares the bare 14-byte
// `sub rsp,28; call; add rsp,28; jmp` prologue with the reference-free ?AfxAbort
// signature, which lives in a different tree. Matching all trees at once yields
// two valid, differently-named candidates, so the function goes unnamed and its
// api(exit) produces a spurious terminate-process match. Per-tree matching names
// mainCRTStartup from its earlier tree, marking the function library as capa does
// and closing the false positive.
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
