#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/viv/discovery.h"

namespace pn = papa::features::extractors::papa_native;
namespace pv = papa::features::extractors::papa_native::viv;

using pn::Disassembler;

namespace {

template <typename... B>
constexpr auto make_bytes(B... bs) {
    return std::array<std::byte, sizeof...(B)>{
        std::byte{static_cast<std::uint8_t>(bs)}...};
}

}  // namespace

TEST_CASE("Discovery make_function defines the function's code and builds its blocks inline") {
    const Disassembler d(/*is_64bit=*/false);
    // 0x1000: 90 nop / 0x1001: 90 nop / 0x1002: c3 ret
    const auto bytes  = make_bytes(0x90, 0x90, 0xC3);
    const auto reader = pn::cfg::make_span_reader(bytes, 0x1000, d);

    pv::Discovery disc(reader, [](std::uint64_t) { return true; });
    disc.make_function(0x1000);

    // The instructions are defined as code locations
    CHECK(disc.locations().location_type(0x1000) == pv::LocType::kOp);
    CHECK(disc.locations().location_type(0x1002) == pv::LocType::kOp);

    // The codeblocks fmod ran inline when the function completed: one block over
    // the whole three-instruction extent
    const auto& blocks = disc.blocks().function_blocks(0x1000);
    REQUIRE(blocks.size() == 1);
    CHECK(blocks[0].va == 0x1000);
    CHECK(blocks[0].size == 3);
    CHECK(blocks[0].function_va == 0x1000);
}

TEST_CASE("Discovery builds inline blocks for a call-discovered function, in post-order") {
    const Disassembler d(/*is_64bit=*/false);
    std::array<std::byte, 0x1001> region{};
    region.fill(std::byte{0x90});
    // 0x1000: e8 fb 0f 00 00   call 0x2000  (rel32 = 0x2000 - 0x1005 = 0xFFB)
    region[0x000] = std::byte{0xE8};
    region[0x001] = std::byte{0xFB};
    region[0x002] = std::byte{0x0F};
    region[0x003] = std::byte{0x00};
    region[0x004] = std::byte{0x00};
    region[0x005] = std::byte{0x90};   // 0x1005: nop
    region[0x006] = std::byte{0xC3};   // 0x1006: ret
    region[0x1000] = std::byte{0xC3};  // 0x2000: ret, the callee
    const auto reader = pn::cfg::make_span_reader(region, 0x1000, d);

    pv::Discovery disc(reader, [](std::uint64_t) { return true; });
    disc.make_function(0x1000);

    // The callee is discovered through the call and completes first (post-order),
    // so both functions exist with their own inline-built blocks
    REQUIRE(disc.function_entries().size() == 2);
    CHECK(disc.function_entries()[0] == 0x2000);
    CHECK(disc.function_entries()[1] == 0x1000);

    const auto& caller = disc.blocks().function_blocks(0x1000);
    REQUIRE(caller.size() == 1);
    CHECK(caller[0].va == 0x1000);
    CHECK(caller[0].size == 7);  // call does not split a block, runs to the ret

    const auto& callee = disc.blocks().function_blocks(0x2000);
    REQUIRE(callee.size() == 1);
    CHECK(callee[0].va == 0x2000);
    CHECK(callee[0].size == 1);
}

TEST_CASE("Discovery's FLIRT fmod creates a sub-function when a function is made") {
    const Disassembler d(/*is_64bit=*/false);
    std::array<std::byte, 0x11> region{};
    region.fill(std::byte{0x90});
    region[0x00] = std::byte{0xC3};  // 0x1000: ret, the enclosing function
    region[0x10] = std::byte{0xC3};  // 0x1010: ret, the helper a signature names
    const auto reader = pn::cfg::make_span_reader(region, 0x1000, d);

    pv::Discovery disc(reader, [](std::uint64_t) { return true; });
    // A stub FLIRT fmod that, when the enclosing function is made, creates the helper
    // at 0x1010, the way viv_utils.flirt.makeFunction creates a local name
    disc.set_flirt_fmod([&disc](std::uint64_t va) {
        if (va == 0x1000 && !disc.is_function(0x1010)) {
            disc.make_function(0x1010);
        }
    });

    disc.make_function(0x1000);

    // The fmod ran at the end of the enclosing function's analysis and re-entered
    // make_function safely, so the helper is a function with its own block
    CHECK(disc.is_function(0x1000));
    CHECK(disc.is_function(0x1010));
    const auto& helper = disc.blocks().function_blocks(0x1010);
    REQUIRE(helper.size() == 1);
    CHECK(helper[0].va == 0x1010);
    CHECK(helper[0].size == 1);
}

TEST_CASE("Discovery make_pointer follows a reloc pointer to make its target a function") {
    const Disassembler d(/*is_64bit=*/false);
    const auto code   = make_bytes(0xC3);  // ret at 0x2000, the pointer's target
    const auto reader = pn::cfg::make_span_reader(code, 0x2000, d);

    const pv::Discovery::ReadPtr read_ptr =
        [](std::uint64_t site) -> std::optional<std::uint64_t> {
        return site == 0x1000 ? std::optional<std::uint64_t>{0x2000} : std::nullopt;
    };
    const pv::Discovery::IsProbablyCode is_code = [](std::uint64_t va) {
        return va == 0x2000;
    };
    pv::Discovery disc(reader, [](std::uint64_t) { return true; },
                       /*resolve_jt=*/{}, is_code, read_ptr, /*ptr_size=*/4);

    disc.make_pointer(0x1000, /*follow=*/true);

    // The reloc site becomes a pointer location, and its stored target becomes a
    // function with its own inline-built blocks
    CHECK(disc.locations().location_type(0x1000) == pv::LocType::kPointer);
    REQUIRE(disc.function_entries().size() == 1);
    CHECK(disc.function_entries()[0] == 0x2000);
    const auto& blocks = disc.blocks().function_blocks(0x2000);
    REQUIRE(blocks.size() == 1);
    CHECK(blocks[0].va == 0x2000);
}
