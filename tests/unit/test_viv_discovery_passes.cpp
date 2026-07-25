#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ostream>
#include <vector>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/viv/discovery.h"
#include "papa/features/extractors/papa_native/viv/discovery_passes.h"

namespace pn = papa::features::extractors::papa_native;
namespace pv = papa::features::extractors::papa_native::viv;

using pn::Disassembler;

namespace {

// A region with a ret at 0x2000 and another at 0x3000, everything else nop
std::array<std::byte, 0x1001> two_ret_region() {
    std::array<std::byte, 0x1001> region{};
    region.fill(std::byte{0x90});
    region[0x000]  = std::byte{0xC3};  // 0x2000: ret
    region[0x1000] = std::byte{0xC3};  // 0x3000: ret
    return region;
}

}  // namespace

TEST_CASE("run_emucode makes undefined code candidates and iterates to a fixpoint") {
    const Disassembler d(/*is_64bit=*/false);
    const auto         region = two_ret_region();
    const auto         reader = pn::cfg::make_span_reader(region, 0x2000, d);
    const pv::Discovery::IsProbablyCode is_code = [](std::uint64_t va) {
        return va == 0x2000 || va == 0x3000;
    };
    pv::Discovery disc(reader, [](std::uint64_t) { return true; }, /*resolve_jt=*/{},
                       is_code);

    // 0x3000 is only exposed as a candidate once 0x2000 has been made, so the
    // pass must iterate to a fixpoint to reach it
    const pv::CandidateSource candidates = [&disc]() -> std::vector<std::uint64_t> {
        if (disc.locations().get_location(0x2000).has_value()) {
            return {0x2000, 0x3000};
        }
        return {0x2000};
    };
    pv::run_emucode(disc, candidates);

    REQUIRE(disc.function_entries().size() == 2);
    CHECK(disc.function_entries()[0] == 0x2000);
    CHECK(disc.function_entries()[1] == 0x3000);
    CHECK(disc.blocks().function_blocks(0x2000).size() == 1);
    CHECK(disc.blocks().function_blocks(0x3000).size() == 1);
}

TEST_CASE("run_emucode leaves an already-defined candidate alone") {
    const Disassembler d(/*is_64bit=*/false);
    const auto         region = two_ret_region();
    const auto         reader = pn::cfg::make_span_reader(region, 0x2000, d);
    pv::Discovery disc(reader, [](std::uint64_t) { return true; }, /*resolve_jt=*/{},
                       [](std::uint64_t) { return true; });

    disc.make_function(0x2000);  // already a function before the pass
    const pv::CandidateSource candidates = []() -> std::vector<std::uint64_t> {
        return {0x2000};
    };
    pv::run_emucode(disc, candidates);

    // The getLocation gate keeps the pass from remaking the existing function
    REQUIRE(disc.function_entries().size() == 1);
    CHECK(disc.function_entries()[0] == 0x2000);
}

TEST_CASE("run_funcentries makes undefined prologue candidates to a fixpoint") {
    const Disassembler d(/*is_64bit=*/false);
    const auto         region = two_ret_region();
    const auto         reader = pn::cfg::make_span_reader(region, 0x2000, d);
    pv::Discovery      disc(reader, [](std::uint64_t) { return true; });

    // As with emucode, 0x3000 is only exposed once 0x2000 has been made
    const pv::CandidateSource prologues = [&disc]() -> std::vector<std::uint64_t> {
        if (disc.locations().get_location(0x2000).has_value()) {
            return {0x2000, 0x3000};
        }
        return {0x2000};
    };
    pv::run_funcentries(disc, prologues);

    REQUIRE(disc.function_entries().size() == 2);
    CHECK(disc.function_entries()[0] == 0x2000);
    CHECK(disc.function_entries()[1] == 0x3000);
}
