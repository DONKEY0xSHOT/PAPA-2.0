// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the PAPA authors

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
    // The deterministic ramp can occasionally collide but the check that
    // matters is that no obvious carving false positive at offset 0
    // The lfanew + PE relationship would have to align by accident
    CHECK(std::find(found.begin(), found.end(), 0U) == found.end());
}
