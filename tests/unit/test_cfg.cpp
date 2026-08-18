// MSVC: <ostream> must precede doctest so std::string pretty-printing compiles
#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <vector>
#include "fixture_paths.h"

namespace cfg = papa::features::extractors::papa_native::cfg;

using papa::features::extractors::papa_native::Disassembler;
using papa::features::extractors::papa_native::Function;
using papa::features::extractors::papa_native::PdataEntryKind;

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");

// Helper to construct a byte array from an integer list
template <typename... B>
constexpr auto make_bytes(B... bs) {
    return std::array<std::byte, sizeof...(B)>{ std::byte{static_cast<std::uint8_t>(bs)}... };
}

}  // namespace

TEST_CASE("classify_pdata_unwind seeds v1, skips chained, stops on v2 or unreadable") {
    // v1 (ver=1), no flags -> a real function entry
    CHECK(cfg::classify_pdata_unwind(std::uint8_t{0x01}) == PdataEntryKind::kSeed);
    // v1 with UNW_FLAG_CHAININFO set (Flags bit 2: VerFlags = 1 | (4 << 3) = 0x21)
    CHECK(cfg::classify_pdata_unwind(std::uint8_t{0x21}) ==
          PdataEntryKind::kSkipChained);
    // v2 UNWIND_INFO (ver=2): vivisect bails on the rest of the .pdata
    CHECK(cfg::classify_pdata_unwind(std::uint8_t{0x02}) == PdataEntryKind::kStop);
    // An unreadable or invalid unwind pointer also bails the walk
    CHECK(cfg::classify_pdata_unwind(std::nullopt) == PdataEntryKind::kStop);
}

TEST_CASE("make_span_reader rejects out-of-range VAs") {
    const auto bytes = make_bytes(0xC3);
    Disassembler d(true);
    const auto reader = cfg::make_span_reader(std::span<const std::byte>(bytes), 0x1000, d);
    CHECK_FALSE(reader(0x0FFFU).has_value());     // below base
    CHECK_FALSE(reader(0x1100U).has_value());     // past end
}

TEST_CASE("find_function_prologues finds vivisect i386 prologues in gaps only") {
    std::vector<std::uint8_t> code(0x70, 0x42u);   // 0x42 filler is not a prologue
    std::vector<std::uint8_t> covered(0x70, 0u);
    // A recovered function already covers [0x00, 0x10)
    for (std::size_t i = 0; i < 0x10; ++i) { covered[i] = 1u; }
    // 0x10 int3 pad, then push ebp / mov ebp, esp at 0x11: boundary + prologue + gap
    code[0x10] = 0xCCu;
    code[0x11] = 0x55u; code[0x12] = 0x8Bu; code[0x13] = 0xECu;
    // 0x20 nop pad, then push ebp / mov ebp, esp at 0x21, but it is covered
    code[0x20] = 0x90u;
    code[0x21] = 0x55u; code[0x22] = 0x8Bu; code[0x23] = 0xECu;
    for (std::size_t i = 0x21; i < 0x24; ++i) { covered[i] = 1u; }
    // 0x31 push ebp prologue but the byte before it (0x42) is not a boundary
    code[0x31] = 0x55u; code[0x32] = 0x8Bu; code[0x33] = 0xECu;
    // 0x40 ret, then mov edi, edi / push ebp / mov ebp, esp at 0x41: hotpatch prologue
    code[0x40] = 0xC3u;
    code[0x41] = 0x8Bu; code[0x42] = 0xFFu; code[0x43] = 0x55u;
    code[0x44] = 0x8Bu; code[0x45] = 0xECu;
    // 0x50 int3 pad, then sub esp, 0x40 at 0x51: not a vivisect signature, ignored
    code[0x50] = 0xCCu;
    code[0x51] = 0x81u; code[0x52] = 0xECu;
    code[0x53] = 0x40u; code[0x54] = 0x00u; code[0x55] = 0x00u; code[0x56] = 0x00u;

    const auto seeds = cfg::find_function_prologues(code, 0x1000u, covered);
    const std::vector<std::uint64_t> want{0x1011u, 0x1041u};
    CHECK(seeds == want);
}

TEST_CASE("recover on notepad.exe seeds at least the entry point and several exports/pdata") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("fixture missing: " << kNotepad);
        return;
    }
    auto res = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(res.has_value());
    Disassembler d(res->is_64bit());

    const auto rec = cfg::recover(*res, d);
    REQUIRE(rec.has_value());
    const std::vector<Function>& funcs = rec->functions;

    // A soft floor
    CHECK(funcs.size() >= 50);

    // The entry point must appear as a recovered function
    const std::uint64_t entry_va = res->image_base() + res->entry_point_rva();
    const bool has_entry = std::any_of(funcs.begin(), funcs.end(),
        [&](const Function& f) { return f.va == entry_va; });
    CHECK(has_entry);

    // Caller backlinks must be filled for at least one recovered function
    const bool any_callers = std::any_of(funcs.begin(), funcs.end(),
        [](const Function& f) { return !f.callers.empty(); });
    CHECK(any_callers);
}
