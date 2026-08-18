#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/emu_discovery.h"
#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/emu/memory.h"
#include "papa/features/extractors/papa_native/emu/watcher.h"
#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_parser.h"

#include "fixture_paths.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

TEST_CASE("emu discovery: section_perms maps PE characteristics to memory perms") {
    // .text: execute | read
    CHECK(emu::section_perms(0x60000020U) == (emu::kMemExec | emu::kMemRead));
    // .data: read | write
    CHECK(emu::section_perms(0xC0000040U) == (emu::kMemRead | emu::kMemWrite));
    // .rdata: read only
    CHECK(emu::section_perms(0x40000040U) == emu::kMemRead);
}

namespace {

// Build a two-region ImageMaps by hand for the call-target discovery tests:
// region 0 is the function under emulation, region 1 (optional) is the callee
[[nodiscard]] emu::ImageMaps make_maps(
    std::uint64_t caller_base, std::vector<std::uint8_t> caller_code,
    std::uint64_t callee_base = 0, std::vector<std::uint8_t> callee_code = {}) {
    emu::ImageMaps maps;
    maps.bytes.push_back(std::move(caller_code));
    maps.entries.push_back(emu::ImageMaps::Entry{caller_base, emu::kMemRead | emu::kMemExec});
    if (!callee_code.empty()) {
        maps.bytes.push_back(std::move(callee_code));
        maps.entries.push_back(emu::ImageMaps::Entry{callee_base, emu::kMemRead | emu::kMemExec});
    }
    return maps;
}

}  // namespace

TEST_CASE("emu discovery: discover_call_targets collects an executable indirect call target") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    // 0x401000: mov eax, 0x00402000 / call eax / ret    callee 0x402000: ret
    const emu::ImageMaps maps = make_maps(
        0x401000, {0xB8, 0x00, 0x20, 0x40, 0x00, 0xFF, 0xD0, 0xC3},
        0x402000, {0xC3});
    const std::vector<std::uint64_t> seeds =
        emu::discover_call_targets(maps, disasm, 0x401000);
    CHECK(seeds == std::vector<std::uint64_t>{0x402000});
}

TEST_CASE("emu discovery: discover_call_targets ignores a non-executable target") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    // call target 0x402000 is not mapped, so it is not executable code
    const emu::ImageMaps maps = make_maps(
        0x401000, {0xB8, 0x00, 0x20, 0x40, 0x00, 0xFF, 0xD0, 0xC3});
    const std::vector<std::uint64_t> seeds =
        emu::discover_call_targets(maps, disasm, 0x401000);
    CHECK(seeds.empty());
}

TEST_CASE("emu discovery: discover_call_targets ignores a recursive self-call") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    // 0x401000: mov eax, 0x00401000 / call eax / ret  (pc == funcva)
    const emu::ImageMaps maps = make_maps(
        0x401000, {0xB8, 0x00, 0x10, 0x40, 0x00, 0xFF, 0xD0, 0xC3});
    const std::vector<std::uint64_t> seeds =
        emu::discover_call_targets(maps, disasm, 0x401000);
    CHECK(seeds.empty());
}

TEST_CASE("emu discovery: emulate_to_read_register reads a base register set by a lea") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // 0x401000: lea r12, [rip+0xff9]  -> r12 = 0x401007 + 0xff9 = 0x402000
    // 0x401007: ret  (the target address whose register state we read)
    const emu::ImageMaps maps = make_maps(
        0x401000, {0x4c, 0x8d, 0x25, 0xf9, 0x0f, 0x00, 0x00, 0xc3});
    const auto value = emu::emulate_to_read_register(
        maps, disasm, /*funcva=*/0x401000, /*target_va=*/0x401007, ZYDIS_REGISTER_R12);
    REQUIRE(value.has_value());
    CHECK(*value == 0x402000);
}

TEST_CASE("emu discovery: emulate_to_read_register returns nullopt when the target is unreached") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // 0x401000: ret immediately, so 0x401007 is never reached
    const emu::ImageMaps maps = make_maps(0x401000, {0xc3});
    const auto value = emu::emulate_to_read_register(
        maps, disasm, /*funcva=*/0x401000, /*target_va=*/0x401007, ZYDIS_REGISTER_R12);
    CHECK_FALSE(value.has_value());
}

TEST_CASE("emu discovery: find_pointer_candidates surfaces reloc-driven .text pointers") {
    const auto path = papa_tests::fixture_path("Everything.exe");
    if (!papa_tests::fixture_available(path)) {
        MESSAGE("fixture missing: Everything.exe");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(path);
    REQUIRE(img.has_value());

    const std::vector<std::uint64_t> cands = emu::find_pointer_candidates(*img);
    REQUIRE_FALSE(cands.empty());

    // The three socket-island entry functions are referenced only by absolute pointers
    // stored at base-relocation sites inside .text, which a data-only scan never reads
    const auto is_candidate = [&](std::uint64_t va) {
        return std::binary_search(cands.begin(), cands.end(), va);
    };
    CHECK(is_candidate(0x492230u));
    CHECK(is_candidate(0x493d20u));
    CHECK(is_candidate(0x493570u));
}

TEST_CASE("emu discovery: riprel_lea_target computes the lea [rip+disp] pointer") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // lea rdx, [rip + 0xFF8]  (48 8D 15 F8 0F 00 00), length 7.
    // target = va + length + disp
    const std::array<std::byte, 7> bytes{
        std::byte{0x48}, std::byte{0x8D}, std::byte{0x15},
        std::byte{0xF8}, std::byte{0x0F}, std::byte{0x00}, std::byte{0x00}};
    auto lea = disasm.decode(bytes, 0x1000);
    REQUIRE(lea.has_value());
    const auto target = emu::riprel_lea_target(*lea);
    REQUIRE(target.has_value());
    CHECK(*target == 0x1000ULL + 7ULL + 0xFF8ULL);
}

TEST_CASE("emu discovery: riprel_lea_target ignores a non-lea rip-relative load") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // mov rdx, [rip + 0xFF8]  (48 8B 15 ...): a dereference, not an address
    const std::array<std::byte, 7> bytes{
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x15},
        std::byte{0xF8}, std::byte{0x0F}, std::byte{0x00}, std::byte{0x00}};
    auto mov = disasm.decode(bytes, 0x1000);
    REQUIRE(mov.has_value());
    CHECK_FALSE(emu::riprel_lea_target(*mov).has_value());
}

TEST_CASE("emu discovery: riprel_lea_target ignores a lea with a register base") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // lea rdx, [rax + 8]  (48 8D 50 08): runtime-dependent, not a static pointer
    const std::array<std::byte, 4> bytes{
        std::byte{0x48}, std::byte{0x8D}, std::byte{0x50}, std::byte{0x08}};
    auto lea = disasm.decode(bytes, 0x1000);
    REQUIRE(lea.has_value());
    CHECK_FALSE(emu::riprel_lea_target(*lea).has_value());
}

namespace {
[[nodiscard]] std::vector<std::uint64_t> probe_hex_csv(const std::string& s) {
    std::vector<std::uint64_t> out;
    std::size_t i = 0;
    while (i < s.size()) {
        std::size_t j = s.find(',', i);
        if (j == std::string::npos) { j = s.size(); }
        const std::string tok = s.substr(i, j - i);
        if (!tok.empty()) { out.push_back(std::stoull(tok, nullptr, 16)); }
        i = j + 1;
    }
    return out;
}
}  // namespace

TEST_CASE("emu discovery: x64 lea-referenced function is recovered (certutil adler32)") {
    const auto path = papa_tests::fixture_path("corpus/certutil_x64.exe");
    if (!papa_tests::fixture_available(path)) {
        MESSAGE("fixture missing: corpus/certutil_x64.exe");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(path);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());
    auto rec = pn::cfg::recover(*img, disasm);
    REQUIRE(rec.has_value());
    const auto& funcs = rec->functions;
    // adler32 at 0x140109160 is referenced only by `lea rdx, [rip + ...]` at
    // 0x140108161 and is absent from .pdata and the relocations
    const bool recovered = std::any_of(
        funcs.begin(), funcs.end(),
        [](const pn::Function& f) { return f.va == 0x140109160ULL; });
    CHECK(recovered);
}
