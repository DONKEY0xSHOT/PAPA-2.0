#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/jump_tables.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace pn = papa::features::extractors::papa_native;

namespace {

// Decode a contiguous byte buffer into a straight-line instruction window at
// ascending VAs. The buffer must outlive the returned window because each
// DecodedInsn keeps a raw_bytes span into it.
std::vector<pn::DecodedInsn> decode_window(std::span<const std::byte> buf,
                                           std::uint64_t base_va,
                                           const pn::Disassembler& dis) {
    std::vector<pn::DecodedInsn> out;
    std::uint64_t va = base_va;
    std::size_t off = 0;
    while (off < buf.size()) {
        auto decoded = dis.decode(buf.subspan(off), va);
        if (!decoded) { break; }
        const std::size_t len = decoded->length;
        out.push_back(std::move(*decoded));
        off += len;
        va += len;
    }
    return out;
}

std::vector<std::byte> to_bytes(std::initializer_list<std::uint8_t> bytes) {
    std::vector<std::byte> out;
    out.reserve(bytes.size());
    for (const std::uint8_t b : bytes) { out.push_back(std::byte{b}); }
    return out;
}

// The real MSVC x64 switch dispatch from capa.exe at 0x14000ac85..0x14000acab:
//   cmp ecx, 0x1f / ja 0x14000c38b / movsxd rax, ecx / lea rdx, [rip-0xac98]
//   lea r11, [rip+0x2ab71] / mov ecx, [rdx+rax*4+0xc3a4] / add rcx, rdx / jmp rcx
const std::initializer_list<std::uint8_t> kIdiomBytes = {
    0x83, 0xf9, 0x1f,
    0x0f, 0x87, 0xfd, 0x16, 0x00, 0x00,
    0x48, 0x63, 0xc1,
    0x48, 0x8d, 0x15, 0x68, 0x53, 0xff, 0xff,
    0x4c, 0x8d, 0x1d, 0x71, 0xab, 0x02, 0x00,
    0x8b, 0x8c, 0x82, 0xa4, 0xc3, 0x00, 0x00,
    0x48, 0x03, 0xca,
    0xff, 0xe1,
};
constexpr std::uint64_t kDispatchVa = 0x14000ac85ULL;
constexpr std::uint64_t kTableVa    = 0x14000c3a4ULL;
constexpr std::uint64_t kFuncLo     = 0x14000ab90ULL;
constexpr std::uint64_t kFuncHi     = 0x14000c424ULL;

}  // namespace

TEST_CASE("jump_tables: resolves the MSVC x64 indexed-jump idiom") {
    const pn::Disassembler dis(true);
    const auto buf = to_bytes(kIdiomBytes);
    const auto window = decode_window(buf, kDispatchVa, dis);
    REQUIRE(window.size() == 8);
    REQUIRE(window.back().is_jump);
    REQUIRE_FALSE(window.back().branch_target.has_value());

    // Synthetic table: entry k is the RVA (0xab90 + k*0x10), so each target is
    // 0x14000ab90 + k*0x10, all inside the function range.
    const auto reader = [](std::uint64_t va) -> std::optional<std::uint32_t> {
        if (va < kTableVa) { return std::nullopt; }
        const std::uint64_t k = (va - kTableVa) / 4U;
        return static_cast<std::uint32_t>(0xab90U + k * 0x10U);
    };

    const auto res = pn::resolve_indexed_jump_table(
        window, /*is_64bit=*/true, kFuncLo, kFuncHi, reader);

    REQUIRE(res.has_value());
    CHECK(res->table_va == kTableVa);
    CHECK(res->targets.size() == 32U);  // cmp ecx, 0x1f + ja => indices 0..0x1f
    CHECK(res->targets.front() == kFuncLo);
    CHECK(res->targets.at(1) == kFuncLo + 0x10ULL);
    CHECK(res->targets.back() == kFuncLo + 31ULL * 0x10ULL);
    CHECK(res->table_size == 32U * 4U);
}

TEST_CASE("jump_tables: stops at the first entry outside the function range") {
    const pn::Disassembler dis(true);
    const auto buf = to_bytes(kIdiomBytes);
    const auto window = decode_window(buf, kDispatchVa, dis);
    REQUIRE(window.size() == 8);

    // Five in-range entries, then an offset that lands outside [lo, hi).
    const auto reader = [](std::uint64_t va) -> std::optional<std::uint32_t> {
        const std::uint64_t k = (va - kTableVa) / 4U;
        return static_cast<std::uint32_t>(k < 5U ? 0xab90U + k * 0x10U : 0x200000U);
    };

    const auto res = pn::resolve_indexed_jump_table(
        window, /*is_64bit=*/true, kFuncLo, kFuncHi, reader);
    REQUIRE(res.has_value());
    CHECK(res->targets.size() == 5U);
}

TEST_CASE("jump_tables: resolves the x86 memory-indirect indexed jump") {
    const pn::Disassembler dis(/*is_64bit=*/false);
    // The real 32-bit MSVC switch dispatch from Everything.exe at 0x44f50e:
    //   jmp dword ptr [eax*4 + 0x00452400]
    const auto buf = to_bytes({0xFF, 0x24, 0x85, 0x00, 0x24, 0x45, 0x00});
    const auto window = decode_window(buf, 0x0044f50eULL, dis);
    REQUIRE(window.size() == 1);
    REQUIRE(window.back().is_jump);
    REQUIRE_FALSE(window.back().branch_target.has_value());
    REQUIRE(window.back().operands[0].kind == pn::OperandKind::kSib);

    constexpr std::uint64_t kTable = 0x00452400ULL;
    // Four in-range case targets, then a dword outside the section range -> stop.
    const auto reader = [](std::uint64_t va) -> std::optional<std::uint32_t> {
        if (va < kTable) { return std::nullopt; }
        const std::uint64_t k = (va - kTable) / 4U;
        if (k < 4U) { return static_cast<std::uint32_t>(0x0044f515U + k * 0x10U); }
        return 0x00000001U;  // outside [lo, hi)
    };
    const auto res = pn::resolve_memory_indirect_jump_table(
        window.back(), /*range_lo=*/0x00401000ULL, /*range_hi=*/0x00550000ULL, reader);

    REQUIRE(res.has_value());
    CHECK(res->table_va == kTable);
    CHECK(res->targets.size() == 4U);
    CHECK(res->targets.front() == 0x0044f515ULL);
    CHECK(res->targets.back() == 0x0044f515ULL + 3ULL * 0x10ULL);
    CHECK(res->table_size == 4U * 4U);
}

TEST_CASE("jump_tables: memory-indirect resolver ignores a register jump") {
    const pn::Disassembler dis(/*is_64bit=*/false);
    const auto buf = to_bytes({0xFF, 0xE0});  // jmp eax
    const auto window = decode_window(buf, 0x00401000ULL, dis);
    REQUIRE(window.size() == 1);
    const auto reader = [](std::uint64_t) -> std::optional<std::uint32_t> {
        return std::nullopt;
    };
    const auto res = pn::resolve_memory_indirect_jump_table(
        window.back(), 0ULL, ~0ULL, reader);
    CHECK_FALSE(res.has_value());
}

TEST_CASE("jump_tables: memory-indirect resolver ignores a base-register table") {
    const pn::Disassembler dis(/*is_64bit=*/false);
    const auto buf = to_bytes({0xFF, 0x24, 0x83});  // jmp [ebx + eax*4]
    const auto window = decode_window(buf, 0x00401000ULL, dis);
    REQUIRE(window.size() == 1);
    const auto reader = [](std::uint64_t) -> std::optional<std::uint32_t> {
        return std::nullopt;
    };
    const auto res = pn::resolve_memory_indirect_jump_table(
        window.back(), 0ULL, ~0ULL, reader);
    CHECK_FALSE(res.has_value());
}

TEST_CASE("jump_tables: returns nullopt when the window is not a jump table") {
    const pn::Disassembler dis(true);
    // mov eax, 1 / ret -- no indirect jump at all.
    const auto buf = to_bytes({0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3});
    const auto window = decode_window(buf, 0x140001000ULL, dis);
    const auto reader = [](std::uint64_t) -> std::optional<std::uint32_t> {
        return std::nullopt;
    };
    const auto res = pn::resolve_indexed_jump_table(
        window, /*is_64bit=*/true, 0ULL, ~0ULL, reader);
    CHECK_FALSE(res.has_value());
}
