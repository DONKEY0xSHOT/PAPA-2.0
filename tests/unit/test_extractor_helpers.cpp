#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/helpers.h"

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
using papa::features::extractors::helpers::normalize_dll_name;
using papa::features::extractors::helpers::reformat_forwarded_export_name;
using papa::features::extractors::helpers::strip_aw_suffix;

namespace {

[[nodiscard]] bool contains(const std::vector<std::string>& v, std::string_view s) {
    return std::any_of(v.begin(), v.end(),
        [&](const std::string& x) { return x == s; });
}

}  // namespace

TEST_CASE("helpers: normalize_dll_name lowercases and strips known extensions") {
    CHECK(normalize_dll_name("KERNEL32.DLL") == "kernel32");
    CHECK(normalize_dll_name("kernel32.dll") == "kernel32");
    CHECK(normalize_dll_name("WS2_32.DLL")   == "ws2_32");
    CHECK(normalize_dll_name("driver.drv")   == "driver");
    CHECK(normalize_dll_name("libc.so")      == "libc");
    // Unknown extension is preserved
    CHECK(normalize_dll_name("Mod.exe")      == "mod.exe");
    // No extension
    CHECK(normalize_dll_name("KERNEL32")     == "kernel32");
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

TEST_CASE("helpers: generate_symbols emits dotted, bare, and AW-stripped variants") {
    auto v = generate_symbols("kernel32", "CreateFileA", true);
    CHECK(contains(v, "kernel32.CreateFileA"));
    CHECK(contains(v, "CreateFileA"));
    CHECK(contains(v, "kernel32.CreateFile"));
    CHECK(contains(v, "CreateFile"));
    CHECK(v.size() == 4);
}

TEST_CASE("helpers: generate_symbols without dll prefix omits the dotted forms") {
    auto v = generate_symbols("kernel32", "CreateFileA", false);
    CHECK_FALSE(contains(v, "kernel32.CreateFileA"));
    CHECK(contains(v, "CreateFileA"));
    CHECK(contains(v, "CreateFile"));
    CHECK(v.size() == 2);
}

TEST_CASE("helpers: generate_symbols treats ordinal symbols specially") {
    auto v = generate_symbols("ws2_32", "#9", true);
    CHECK(contains(v, "ws2_32.#9"));
    CHECK(contains(v, "#9"));
    // Ordinals never get an A/W variant
    CHECK(v.size() == 2);
}

TEST_CASE("helpers: generate_symbols handles plain non-AW symbols") {
    auto v = generate_symbols("kernel32", "ExitProcess", true);
    CHECK(contains(v, "kernel32.ExitProcess"));
    CHECK(contains(v, "ExitProcess"));
    CHECK(v.size() == 2);
}

TEST_CASE("helpers: reformat_forwarded_export_name lowercases the module part") {
    CHECK(reformat_forwarded_export_name("NTDLL.RtlAllocateHeap") ==
          "ntdll.RtlAllocateHeap");
    CHECK(reformat_forwarded_export_name("API-MS-Win-Core.SomeFn") ==
          "api-ms-win-core.SomeFn");
    // Without a dot the input passes through untouched
    CHECK(reformat_forwarded_export_name("NoDotHere") == "NoDotHere");
}

TEST_CASE("helpers: carve_pe_files finds an unobfuscated PE at offset 0") {
    // Synthesize a minimal MZ + lfanew + PE\0\0 buffer
    std::array<std::byte, 0x60> buf{};
    buf[0] = std::byte{'M'};
    buf[1] = std::byte{'Z'};
    // Set lfanew at offset 0x3C to point to 0x40
    buf[0x3C] = std::byte{0x40};
    buf[0x3D] = std::byte{0x00};
    buf[0x3E] = std::byte{0x00};
    buf[0x3F] = std::byte{0x00};
    // Place "PE\0\0" at offset 0x40
    buf[0x40] = std::byte{'P'};
    buf[0x41] = std::byte{'E'};
    buf[0x42] = std::byte{0x00};
    buf[0x43] = std::byte{0x00};

    auto found = carve_pe_files(buf);
    REQUIRE(found.size() == 1);
    CHECK(found[0] == 0);
}

TEST_CASE("helpers: carve_pe_files finds an XOR-obfuscated PE") {
    // Same minimal layout but every byte XORed with 0x77
    std::array<std::byte, 0x60> buf{};
    constexpr std::uint8_t kKey = 0x77;

    auto x = [](std::uint8_t b, std::uint8_t k) -> std::byte {
        return std::byte{static_cast<std::uint8_t>(b ^ k)};
    };

    buf[0]    = x('M', kKey);
    buf[1]    = x('Z', kKey);
    buf[0x3C] = x(0x40, kKey);
    buf[0x3D] = x(0x00, kKey);
    buf[0x3E] = x(0x00, kKey);
    buf[0x3F] = x(0x00, kKey);
    buf[0x40] = x('P', kKey);
    buf[0x41] = x('E', kKey);
    buf[0x42] = x(0x00, kKey);
    buf[0x43] = x(0x00, kKey);

    auto found = carve_pe_files(buf);
    REQUIRE(found.size() == 1);
    CHECK(found[0] == 0);
}

TEST_CASE("helpers: carve_pe_files reports nothing on noise") {
    std::array<std::byte, 0x80> buf{};
    for (std::size_t i = 0; i < buf.size(); ++i) {
        buf[i] = std::byte{static_cast<std::uint8_t>(i)};
    }
    auto found = carve_pe_files(buf);
    // The deterministic ramp can occasionally collide but the check that matters is
    // that no obvious carving false positive at offset 0
    CHECK(std::find(found.begin(), found.end(), 0U) == found.end());
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

TEST_CASE("helpers: carve_pe_files finds a plain and an XOR-encoded PE") {
    // key 0 is the unencoded case, and every other key exercises the derived-key
    // path that replaced the old sweep over all 256 keys
    for (const std::uint8_t key : {std::uint8_t{0x00}, std::uint8_t{0x01},
                                   std::uint8_t{0x4D}, std::uint8_t{0xFF}}) {
        CAPTURE(key);
        const auto buf = plant_pe(0x400, 0x100, key, 0x80);
        const auto hits = carve_pe_files(buf);
        REQUIRE(hits.size() == 1);
        CHECK(hits[0] == 0x100);
    }
}

TEST_CASE("helpers: carve_pe_files reports every embedded PE in ascending order") {
    auto buf = plant_pe(0x1000, 0x000, 0x00, 0x80);
    const auto second = plant_pe(0x1000, 0x400, 0xAB, 0x80);
    for (std::size_t i = 0x400; i < 0x600; ++i) { buf[i] = second[i]; }
    const auto third = plant_pe(0x1000, 0x800, 0x7F, 0x100);
    for (std::size_t i = 0x800; i < 0xA00; ++i) { buf[i] = third[i]; }

    const auto hits = carve_pe_files(buf);
    REQUIRE(hits.size() == 3);
    CHECK(hits[0] == 0x000);
    CHECK(hits[1] == 0x400);
    CHECK(hits[2] == 0x800);
    CHECK(std::is_sorted(hits.begin(), hits.end()));
}

TEST_CASE("helpers: carve_pe_files rejects near-misses") {
    // MZ present but the PE signature does not match under the same key
    auto buf = plant_pe(0x400, 0x100, 0x33, 0x80);
    buf[0x100 + 0x80] = std::byte{0x00};
    CHECK(carve_pe_files(buf).empty());

    // e_lfanew points past the end of the buffer
    const auto past_end = plant_pe(0x200, 0x000, 0x00, 0x10000);
    CHECK(carve_pe_files(past_end).empty());

    // A buffer too short to hold a DOS header carries nothing
    const std::vector<std::byte> tiny(8, std::byte{0x4D});
    CHECK(carve_pe_files(tiny).empty());
}
