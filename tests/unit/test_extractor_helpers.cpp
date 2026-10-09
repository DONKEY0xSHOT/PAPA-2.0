#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/helpers.h"
#include "papa/pe/pe_image.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using papa::features::extractors::helpers::carve_pe_files;
using papa::features::extractors::helpers::generate_symbols;
using papa::features::extractors::helpers::import_symbol;
using papa::features::extractors::helpers::reformat_forwarded_export_name;
using papa::features::extractors::helpers::strip_aw_suffix;

namespace {

[[nodiscard]] bool contains(const std::vector<std::string>& v, std::string_view s) {
    return std::any_of(v.begin(), v.end(),
        [&](const std::string& x) { return x == s; });
}

}  // namespace

TEST_CASE("helpers: import_symbol is the import name or its ordinal after a hash") {
    papa::pe::ParsedImport named;
    named.dll  = "kernel32";
    named.name = "CreateFileW";
    CHECK(import_symbol(named) == "CreateFileW");

    papa::pe::ParsedImport by_ordinal;
    by_ordinal.dll        = "ws2_32";
    by_ordinal.ordinal    = 115;
    by_ordinal.by_ordinal = true;
    CHECK(import_symbol(by_ordinal) == "#115");
}

TEST_CASE("helpers: strip_aw_suffix returns the base only when suffix matches") {
    auto a = strip_aw_suffix("CreateFileA");
    REQUIRE(a.has_value());
    CHECK(*a == "CreateFile");

    auto w = strip_aw_suffix("CreateFileW");
    REQUIRE(w.has_value());
    CHECK(*w == "CreateFile");

    // No A/W suffix
    CHECK_FALSE(strip_aw_suffix("CreateFile").has_value());
    // Single-character names cannot have a suffix
    CHECK_FALSE(strip_aw_suffix("A").has_value());
    CHECK_FALSE(strip_aw_suffix("").has_value());
}

TEST_CASE("helpers: generate_symbols emits the dotted and bare names and their AW-stripped forms") {
    struct Row {
        std::string_view              label;
        std::string_view              dll;
        std::string_view              symbol;
        bool                          include_dll;
        std::vector<std::string_view> symbols;
        std::vector<std::string_view> excluded;
    };
    const std::vector<Row> rows{
        {"an AW symbol with the dll prefix", "kernel32", "CreateFileA", true,
         {"kernel32.CreateFileA", "CreateFileA", "kernel32.CreateFile", "CreateFile"}, {}},
        {"an AW symbol without the dll prefix omits the dotted forms", "kernel32", "CreateFileA",
         false, {"CreateFileA", "CreateFile"}, {"kernel32.CreateFileA"}},
        // Ordinals never get an A/W variant
        {"an ordinal symbol", "ws2_32", "#9", true, {"ws2_32.#9", "#9"}, {}},
        {"a plain non-AW symbol", "kernel32", "ExitProcess", true,
         {"kernel32.ExitProcess", "ExitProcess"}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto v = generate_symbols(row.dll, row.symbol, row.include_dll);
        for (const std::string_view sym : row.symbols) {
            CAPTURE(sym);
            CHECK(contains(v, sym));
        }
        for (const std::string_view sym : row.excluded) {
            CAPTURE(sym);
            CHECK_FALSE(contains(v, sym));
        }
        CHECK(v.size() == row.symbols.size());
    }
}

TEST_CASE("helpers: reformat_forwarded_export_name lowercases the module part") {
    CHECK(reformat_forwarded_export_name("NTDLL.RtlAllocateHeap") ==
          "ntdll.RtlAllocateHeap");
    CHECK(reformat_forwarded_export_name("API-MS-Win-Core.SomeFn") ==
          "api-ms-win-core.SomeFn");
    // Without a dot the input passes through untouched
    CHECK(reformat_forwarded_export_name("NoDotHere") == "NoDotHere");
}

namespace {

// Build a buffer with an XOR-encoded MZ/PE header planted at pos
std::vector<std::byte> plant_pe(std::size_t size, std::size_t pos,
                                std::uint8_t key, std::uint32_t lfanew) {
    std::vector<std::byte> buf(size, std::byte{0});
    // Writes past the end are dropped on purpose, so a case can plant an
    // e_lfanew that points outside the buffer without corrupting the test
    auto put = [&](std::size_t off, std::uint8_t v) {
        if (off >= buf.size()) { return; }
        buf[off] = std::byte{static_cast<std::uint8_t>(v ^ key)};
    };
    put(pos + 0, 0x4D);  // M
    put(pos + 1, 0x5A);  // Z
    for (std::size_t i = 0; i < 4; ++i) {
        put(pos + 0x3C + i, static_cast<std::uint8_t>((lfanew >> (8U * i)) & 0xFFU));
    }
    const std::uint32_t sig = 0x00004550U;  // PE\0\0
    for (std::size_t i = 0; i < 4; ++i) {
        put(pos + lfanew + i, static_cast<std::uint8_t>((sig >> (8U * i)) & 0xFFU));
    }
    return buf;
}

}  // namespace

TEST_CASE("helpers: carve_pe_files finds every plain or XOR-encoded PE in ascending order") {
    // Three PEs, at 0x000 plain, at 0x400 under key 0xAB and at 0x800 under key 0x7F
    auto three = plant_pe(0x1000, 0x000, 0x00, 0x80);
    const auto second = plant_pe(0x1000, 0x400, 0xAB, 0x80);
    for (std::size_t i = 0x400; i < 0x600; ++i) { three[i] = second[i]; }
    const auto third = plant_pe(0x1000, 0x800, 0x7F, 0x100);
    for (std::size_t i = 0x800; i < 0xA00; ++i) { three[i] = third[i]; }

    struct Row {
        std::string_view           label;
        std::vector<std::byte>     buf;
        std::vector<std::uint64_t> hits;
    };
    // key 0 is the unencoded case, and every other key exercises the path that derives
    // the key from the first byte instead of trying all 256
    const std::vector<Row> rows{
        {"a minimal unobfuscated PE at offset 0", plant_pe(0x60, 0, 0x00, 0x40), {0}},
        {"a minimal PE XORed with 0x77 at offset 0", plant_pe(0x60, 0, 0x77, 0x40), {0}},
        {"a plain PE at 0x100", plant_pe(0x400, 0x100, 0x00, 0x80), {0x100}},
        {"a PE XORed with 0x01 at 0x100", plant_pe(0x400, 0x100, 0x01, 0x80), {0x100}},
        {"a PE XORed with 0x4D at 0x100", plant_pe(0x400, 0x100, 0x4D, 0x80), {0x100}},
        {"a PE XORed with 0xFF at 0x100", plant_pe(0x400, 0x100, 0xFF, 0x80), {0x100}},
        {"three embedded PEs", three, {0x000, 0x400, 0x800}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto hits = carve_pe_files(row.buf);
        CHECK(hits.size() == row.hits.size());
        for (std::size_t i = 0; i < hits.size() && i < row.hits.size(); ++i) {
            CAPTURE(i);
            CHECK(hits[i] == row.hits[i]);
        }
        CHECK(std::is_sorted(hits.begin(), hits.end()));
    }
}

TEST_CASE("helpers: carve_pe_files reports nothing on noise and near-misses") {
    std::vector<std::byte> ramp(0x80);
    for (std::size_t i = 0; i < ramp.size(); ++i) {
        ramp[i] = std::byte{static_cast<std::uint8_t>(i)};
    }
    // MZ present but the PE signature does not match under the same key
    auto bad_signature = plant_pe(0x400, 0x100, 0x33, 0x80);
    bad_signature[0x100 + 0x80] = std::byte{0x00};

    struct Row {
        std::string_view       label;
        std::vector<std::byte> buf;
    };
    const std::vector<Row> rows{
        {"a deterministic ramp of noise", ramp},
        {"an MZ whose PE signature does not match under the same key", bad_signature},
        {"an e_lfanew that points past the end of the buffer",
         plant_pe(0x200, 0x000, 0x00, 0x10000)},
        {"a buffer too short to hold a DOS header", std::vector<std::byte>(8, std::byte{0x4D})},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(carve_pe_files(row.buf).empty());
    }
}
