#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/emu_discovery.h"
#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/emu/memory.h"
#include "papa/features/extractors/papa_native/emu/watcher.h"
#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/papa_native/imports.h"
#include "papa/features/extractors/papa_native/viv/engine.h"
#include "papa/pe/pe_parser.h"

#include "pe_builder.h"
#include "test_support.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
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

TEST_CASE("emu discovery: find_pointer_candidates keeps the reloc and aligned data pointers that reach code") {
    for (const bool x64 : {false, true}) {
        CAPTURE(x64);
        papa_tests::PeBuilder b;
        b.x64 = x64;
        const std::vector<std::uint8_t> leaf{0x33, 0xC0, 0xC3};  // xor eax, eax / ret
        std::vector<std::uint32_t>      fns;
        for (int i = 0; i < 5; ++i) { fns.push_back(b.add_function(leaf)); }
        // Five pointer slots in .text, each a relocation site, so the block also carries
        // an ABSOLUTE padding entry
        const std::uint32_t slots = b.add_function(std::vector<std::uint8_t>(40, 0));
        const std::size_t   ptr   = x64 ? 8U : 4U;
        for (std::uint32_t i = 0; i < 5U; ++i) {
            b.reloc_code_offsets.push_back(slots + i * 8U);
        }
        b.data.assign(0x40, 0);

        const auto store = [x64](std::vector<std::uint8_t>& buf, std::size_t at,
                                     std::uint64_t value) {
            if (x64) {
                papa_tests::detail::poke(buf, at, value);
            } else {
                papa_tests::detail::poke(buf, at, static_cast<std::uint32_t>(value));
            }
        };
        // Three relocated slots reach code, the fourth points into .data and the fifth past
        // the image
        for (std::uint32_t i = 0; i < 3U; ++i) { store(b.code, slots + i * 8U, b.code_va(fns[i])); }
        store(b.code, slots + 24U, b.data_va(0));
        store(b.code, slots + 32U, b.code_va(0) + 0x00100000U);
        // In .data one aligned slot reaches code, one points past the code and one
        // straddles an alignment boundary
        store(b.data, ptr, b.code_va(fns[3]));
        store(b.data, 2U * ptr, b.code_va(0) + b.code.size());
        store(b.data, 3U * ptr + 1U, b.code_va(fns[4]));

        const auto img = papa::pe::PeParser::parse(b.build());
        REQUIRE(img.has_value());
        const std::vector<std::uint64_t> want{b.code_va(fns[0]), b.code_va(fns[1]),
                                              b.code_va(fns[2]), b.code_va(fns[3])};
        CHECK(emu::find_pointer_candidates(*img) == want);
    }
}

TEST_CASE("emu discovery: riprel_lea_target computes the lea [rip+disp] pointer") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // lea rdx, [rip + 0xFF8]  (48 8D 15 F8 0F 00 00), length 7.
    // target = va + length + disp
    const auto bytes = papa_tests::bytes(0x48, 0x8D, 0x15, 0xF8, 0x0F, 0x00, 0x00);
    auto lea = disasm.decode(bytes, 0x1000);
    REQUIRE(lea.has_value());
    const auto target = emu::riprel_lea_target(*lea);
    REQUIRE(target.has_value());
    CHECK(*target == 0x1000ULL + 7ULL + 0xFF8ULL);
}

TEST_CASE("emu discovery: riprel_lea_target ignores a non-lea rip-relative load") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // mov rdx, [rip + 0xFF8]  (48 8B 15 ...): a dereference, not an address
    const auto bytes = papa_tests::bytes(0x48, 0x8B, 0x15, 0xF8, 0x0F, 0x00, 0x00);
    auto mov = disasm.decode(bytes, 0x1000);
    REQUIRE(mov.has_value());
    CHECK_FALSE(emu::riprel_lea_target(*mov).has_value());
}

TEST_CASE("emu discovery: riprel_lea_target ignores a lea with a register base") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // lea rdx, [rax + 8]  (48 8D 50 08): runtime-dependent, not a static pointer
    const auto bytes = papa_tests::bytes(0x48, 0x8D, 0x50, 0x08);
    auto lea = disasm.decode(bytes, 0x1000);
    REQUIRE(lea.has_value());
    CHECK_FALSE(emu::riprel_lea_target(*lea).has_value());
}

TEST_CASE("emu discovery: an x64 function only a lea [rip+] reaches is recovered") {
    // The target is in neither .pdata nor the relocations
    papa_tests::PeBuilder b;
    const auto user   = b.add_function({0x48, 0x8D, 0x15, 0, 0, 0, 0, 0xC3});  // lea rdx, [rip+] / ret
    const auto target = b.add_function({0x33, 0xC0, 0xC3});                    // xor eax, eax / ret
    b.pdata_functions.pop_back();
    papa_tests::detail::poke(b.code, user + 3U,
                             static_cast<std::int32_t>(b.code_va(target) - b.code_va(user + 7U)));
    const auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());

    const pn::Disassembler             disasm(true);
    const pn::flirt::FlirtSignatureSet no_sigs;
    const auto rec = pn::viv::discover_functions(*img, disasm, pn::build_import_table(*img), no_sigs);
    std::vector<std::uint64_t> got;
    for (const pn::Function& f : rec.functions) { got.push_back(f.va); }
    std::sort(got.begin(), got.end());
    CHECK(got == std::vector<std::uint64_t>{b.code_va(user), b.code_va(target)});
}
