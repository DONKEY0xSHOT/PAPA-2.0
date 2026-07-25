#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/memory.h"

#include <array>
#include <cstdint>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;

// SandboxMemory is the security-critical core: it models the emulated address
// space as bounds-checked maps over external bytes, routes every write into a
// private capped overlay (the backing bytes are never mutated, so an emulated
// PE can never corrupt papa state), and falls back to a taint fill for
// unmapped reads (vivisect _safe_mem). Faithful to envi/memory.py +
// impemu/emulator.py read/write hooks

namespace {

constexpr std::array<std::uint8_t, 8> kBacking = {
    0x44, 0x33, 0x22, 0x11, 0xAA, 0xBB, 0xCC, 0xDD,
};

}  // namespace

TEST_CASE("emu SandboxMemory: read_value reads a little-endian dword from a map") {
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead, kBacking);
    CHECK(mem.read_value(0x1000, 4) == 0x11223344ULL);
}

TEST_CASE("emu SandboxMemory: read_value reads a single byte") {
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead, kBacking);
    CHECK(mem.read_value(0x1004, 1) == 0xAAULL);
}

TEST_CASE("emu SandboxMemory: an unmapped read returns the taint fill") {
    // vivisect _safe_mem: a read that does not probe returns taintbyte*size
    emu::SandboxMemory mem;
    CHECK(mem.read_value(0x9000, 4) == 0x61616161ULL);
}

TEST_CASE("emu SandboxMemory: probe accepts a range inside one readable map") {
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead, kBacking);
    CHECK(mem.probe(0x1000, 8, emu::kMemRead));
    CHECK(mem.probe(0x1004, 4, emu::kMemRead));
}

TEST_CASE("emu SandboxMemory: probe rejects a range crossing the map end") {
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead, kBacking);  // 8 bytes
    CHECK_FALSE(mem.probe(0x1004, 8, emu::kMemRead));
}

TEST_CASE("emu SandboxMemory: probe rejects a perm the map lacks") {
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead, kBacking);  // read-only
    CHECK_FALSE(mem.probe(0x1000, 4, emu::kMemWrite));
}

TEST_CASE("emu SandboxMemory: probe rejects an unmapped range") {
    emu::SandboxMemory mem;
    CHECK_FALSE(mem.probe(0x9000, 4, emu::kMemRead));
}

TEST_CASE("emu SandboxMemory: is_valid_pointer is true only for mapped addresses") {
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead, kBacking);
    CHECK(mem.is_valid_pointer(0x1000));
    CHECK(mem.is_valid_pointer(0x1007));
    CHECK_FALSE(mem.is_valid_pointer(0x1008));
    CHECK_FALSE(mem.is_valid_pointer(0x4156100FULL));  // a taint-range value
}

TEST_CASE("emu SandboxMemory: the stack reads its fill byte where unwritten") {
    emu::SandboxMemory mem;
    mem.init_stack();
    CHECK(mem.read_value(emu::kStackBase, 1) == 0xFEULL);
    CHECK(mem.is_valid_pointer(emu::kStackBase));
    CHECK(mem.probe(emu::kStackBase, 4, emu::kMemWrite));
}

TEST_CASE("emu SandboxMemory: a stack write reads back through the overlay") {
    emu::SandboxMemory mem;
    mem.init_stack();
    const std::array<std::uint8_t, 4> data = {0xEF, 0xBE, 0xAD, 0xDE};
    mem.write(emu::kStackBase + 0x100, data);
    CHECK(mem.read_value(emu::kStackBase + 0x100, 4) == 0xDEADBEEFULL);
}

TEST_CASE("emu SandboxMemory: a write to a read-only map is dropped") {
    // The backing bytes must never change -- safety property
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead, kBacking);
    const std::array<std::uint8_t, 1> data = {0xFF};
    mem.write(0x1000, data);
    CHECK(mem.read_value(0x1000, 1) == 0x44ULL);  // unchanged
}

TEST_CASE("emu SandboxMemory: a write to a writable map overlays the backing") {
    emu::SandboxMemory mem;
    mem.add_map(0x2000, emu::kMemRead | emu::kMemWrite, kBacking);
    const std::array<std::uint8_t, 1> data = {0x99};
    mem.write(0x2000, data);
    CHECK(mem.read_value(0x2000, 1) == 0x99ULL);     // overlay
    CHECK(mem.read_value(0x2001, 1) == 0x33ULL);     // still backing
}

TEST_CASE("emu SandboxMemory: write_value and read_value round-trip on the stack") {
    emu::SandboxMemory mem;
    mem.init_stack();
    mem.write_value(emu::kStackBase + 0x40, 0xCAFEBABEULL, 4);
    CHECK(mem.read_value(emu::kStackBase + 0x40, 4) == 0xCAFEBABEULL);
}

TEST_CASE("emu SandboxMemory: snapshot and restore roll back overlay writes") {
    emu::SandboxMemory mem;
    mem.init_stack();
    mem.write_value(emu::kStackBase + 0x10, 0x11111111ULL, 4);
    const emu::SandboxMemory::Snapshot snap = mem.snapshot();
    mem.write_value(emu::kStackBase + 0x10, 0x22222222ULL, 4);
    CHECK(mem.read_value(emu::kStackBase + 0x10, 4) == 0x22222222ULL);
    mem.restore(snap);
    CHECK(mem.read_value(emu::kStackBase + 0x10, 4) == 0x11111111ULL);
}

TEST_CASE("emu SandboxMemory: read_code returns mapped bytes clipped to the map end") {
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead | emu::kMemExec, kBacking);  // 8 bytes
    const std::vector<std::uint8_t> got = mem.read_code(0x1004, 15);
    REQUIRE(got.size() == 4);  // only 4 bytes left in the map
    CHECK(got[0] == 0xAA);
    CHECK(got[3] == 0xDD);
}

TEST_CASE("emu SandboxMemory: read_code of an unmapped address is empty") {
    emu::SandboxMemory mem;
    CHECK(mem.read_code(0x9000, 15).empty());
}

TEST_CASE("emu SandboxMemory: the overlay cap drops writes beyond the bound") {
    // DoS guard: the write overlay cannot grow without bound. With a tiny
    // injected cap, writes past it are dropped and read back as the stack fill
    emu::SandboxMemory mem(/*overlay_cap=*/4);
    mem.init_stack();
    const std::array<std::uint8_t, 4> first = {1, 2, 3, 4};
    mem.write(emu::kStackBase, first);
    CHECK(mem.read_value(emu::kStackBase, 1) == 1ULL);
    const std::array<std::uint8_t, 1> overflow = {0x55};
    mem.write(emu::kStackBase + 0x10, overflow);  // would exceed the cap
    CHECK(mem.read_value(emu::kStackBase + 0x10, 1) == 0xFEULL);  // dropped
}
