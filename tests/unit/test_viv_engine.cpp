#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "doctest.h"

#include "fixture_paths.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/emu_discovery.h"
#include "papa/features/extractors/papa_native/viv/engine.h"
#include "papa/pe/pe_parser.h"

namespace pn = papa::features::extractors::papa_native;

TEST_CASE("discovery engine: recovers the entry point and a non-empty function set") {
    const auto path = papa_tests::fixture_path("corpus/hostname_x86.exe");
    if (!papa_tests::fixture_available(path)) {
        MESSAGE("fixture missing: corpus/hostname_x86.exe");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(path);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());

    const std::vector<pn::Function> funcs =
        pn::viv::discover_functions(*img, disasm).functions;

    REQUIRE_FALSE(funcs.empty());
    const std::uint64_t entry = img->image_base() + img->entry_point_rva();
    CHECK(std::any_of(funcs.begin(), funcs.end(),
                      [entry](const pn::Function& f) { return f.va == entry; }));
}
