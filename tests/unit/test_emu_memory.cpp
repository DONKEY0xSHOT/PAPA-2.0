#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/memory.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;

// SandboxMemory is the security-critical core, modelling the emulated address space
// as bounds-checked maps and routing every write into a private capped overlay

namespace {

constexpr std::array<std::uint8_t, 8> kBacking = {
    0x44, 0x33, 0x22, 0x11, 0xAA, 0xBB, 0xCC, 0xDD,
};

// kBacking read-only at 0x1000 and writable at 0x2000, plus the stack
emu::SandboxMemory fixture() {
    emu::SandboxMemory mem;
    mem.add_map(0x1000, emu::kMemRead, kBacking);
    mem.add_map(0x2000, emu::kMemRead | emu::kMemWrite, kBacking);
    mem.init_stack();
    return mem;
}

}  // namespace

TEST_CASE("emu SandboxMemory: a read sees the backing, the fill bytes and every write the maps allow") {
    using Write = void (*)(emu::SandboxMemory&);
    struct Row {
        std::string_view label;
        Write            write;
        std::uint64_t    at;
        std::size_t      size;
        std::uint64_t    expected;
    };
    const Write none = [](emu::SandboxMemory&) {};
    const std::vector<Row> rows{
        {"read_value reads a little-endian dword from a map", none, 0x1000, 4, 0x11223344ULL},
        {"read_value reads a single byte", none, 0x1004, 1, 0xAAULL},
        // vivisect _safe_mem: a read that does not probe returns taintbyte*size
        {"an unmapped read returns the taint fill", none, 0x9000, 4, 0x61616161ULL},
        {"the stack reads its fill byte where unwritten", none, emu::kStackBase, 1, 0xFEULL},
        {"a stack write reads back through the overlay",
         [](emu::SandboxMemory& m) {
             const std::array<std::uint8_t, 4> data = {0xEF, 0xBE, 0xAD, 0xDE};
             m.write(emu::kStackBase + 0x100, data);
         },
         emu::kStackBase + 0x100, 4, 0xDEADBEEFULL},
        {"write_value and read_value round-trip on the stack",
         [](emu::SandboxMemory& m) { m.write_value(emu::kStackBase + 0x40, 0xCAFEBABEULL, 4); },
         emu::kStackBase + 0x40, 4, 0xCAFEBABEULL},
        // The backing bytes must never change, a safety property
        {"a write to a read-only map is dropped",
         [](emu::SandboxMemory& m) {
             const std::array<std::uint8_t, 1> data = {0xFF};
             m.write(0x1000, data);
         },
         0x1000, 1, 0x44ULL},
        {"a write to a writable map overlays the backing",
         [](emu::SandboxMemory& m) {
             const std::array<std::uint8_t, 1> data = {0x99};
             m.write(0x2000, data);
         },
         0x2000, 1, 0x99ULL},
        {"an overlay write leaves the backing bytes beside it",
         [](emu::SandboxMemory& m) {
             const std::array<std::uint8_t, 1> data = {0x99};
             m.write(0x2000, data);
         },
         0x2001, 1, 0x33ULL},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::SandboxMemory mem = fixture();
        row.write(mem);
        CHECK(mem.read_value(row.at, row.size) == row.expected);
    }
}

TEST_CASE("emu SandboxMemory: probe and is_valid_pointer accept only mapped ranges with the perm asked for") {
    struct Row {
        std::string_view label;
        std::uint64_t    at;
        std::size_t      size;
        std::uint32_t    perm;
        bool             probe;
        bool             valid_pointer;
    };
    const std::vector<Row> rows{
        {"a whole readable map", 0x1000, 8, emu::kMemRead, true, true},
        {"a range inside one readable map", 0x1004, 4, emu::kMemRead, true, true},
        {"the last byte of a map", 0x1007, 1, emu::kMemRead, true, true},
        {"a range crossing the map end", 0x1004, 8, emu::kMemRead, false, true},
        {"a perm the map lacks", 0x1000, 4, emu::kMemWrite, false, true},
        {"one past the map end", 0x1008, 1, emu::kMemRead, false, false},
        {"an unmapped range", 0x9000, 4, emu::kMemRead, false, false},
        {"a taint-range value", 0x4156100FULL, 4, emu::kMemRead, false, false},
        {"the stack is writable", emu::kStackBase, 4, emu::kMemWrite, true, true},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::SandboxMemory mem;
        mem.add_map(0x1000, emu::kMemRead, kBacking);
        mem.init_stack();
        CHECK(mem.probe(row.at, row.size, row.perm) == row.probe);
        CHECK(mem.is_valid_pointer(row.at) == row.valid_pointer);
    }
}

TEST_CASE("emu SandboxMemory: read_code returns mapped bytes clipped to the map end") {
    struct Row {
        std::string_view          label;
        std::uint64_t             at;
        std::vector<std::uint8_t> expected;
    };
    const std::vector<Row> rows{
        {"only the 4 bytes left in the map", 0x1004, {0xAA, 0xBB, 0xCC, 0xDD}},
        {"nothing at an unmapped address", 0x9000, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::SandboxMemory mem;
        mem.add_map(0x1000, emu::kMemRead | emu::kMemExec, kBacking);  // 8 bytes
        const std::vector<std::uint8_t> got = mem.read_code(row.at, 15);
        CHECK(got.size() == row.expected.size());
        for (std::size_t i = 0; i < got.size() && i < row.expected.size(); ++i) {
            CAPTURE(i);
            CHECK(got[i] == row.expected[i]);
        }
    }
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
