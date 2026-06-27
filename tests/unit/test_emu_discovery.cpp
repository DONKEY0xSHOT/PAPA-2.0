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
// region 0 is the function under emulation, region 1 (optional) is the callee.
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
    // 0x401000: mov eax, 0x00402000 ; call eax ; ret    callee 0x402000: ret
    const emu::ImageMaps maps = make_maps(
        0x401000, {0xB8, 0x00, 0x20, 0x40, 0x00, 0xFF, 0xD0, 0xC3},
        0x402000, {0xC3});
    const std::vector<std::uint64_t> seeds =
        emu::discover_call_targets(maps, disasm, 0x401000);
    CHECK(seeds == std::vector<std::uint64_t>{0x402000});
}

TEST_CASE("emu discovery: discover_call_targets ignores a non-executable target") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    // call target 0x402000 is not mapped, so it is not executable code.
    const emu::ImageMaps maps = make_maps(
        0x401000, {0xB8, 0x00, 0x20, 0x40, 0x00, 0xFF, 0xD0, 0xC3});
    const std::vector<std::uint64_t> seeds =
        emu::discover_call_targets(maps, disasm, 0x401000);
    CHECK(seeds.empty());
}

TEST_CASE("emu discovery: discover_call_targets ignores a recursive self-call") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    // 0x401000: mov eax, 0x00401000 ; call eax ; ret  (pc == funcva)
    const emu::ImageMaps maps = make_maps(
        0x401000, {0xB8, 0x00, 0x10, 0x40, 0x00, 0xFF, 0xD0, 0xC3});
    const std::vector<std::uint64_t> seeds =
        emu::discover_call_targets(maps, disasm, 0x401000);
    CHECK(seeds.empty());
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

    // The three socket-island entry functions are referenced only by absolute
    // pointers stored at base-relocation sites inside .text (site RVAs 0x925f0 /
    // 0x9539c / 0x95b14). A data-only pointer scan never reads .text, so it
    // misses them and the island stays unrecovered. The reloc-driven,
    // section-agnostic scan must surface their targets as candidates.
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
    // target = va + length + disp.
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
    // mov rdx, [rip + 0xFF8]  (48 8B 15 ...): a dereference, not an address.
    const std::array<std::byte, 7> bytes{
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x15},
        std::byte{0xF8}, std::byte{0x0F}, std::byte{0x00}, std::byte{0x00}};
    auto mov = disasm.decode(bytes, 0x1000);
    REQUIRE(mov.has_value());
    CHECK_FALSE(emu::riprel_lea_target(*mov).has_value());
}

TEST_CASE("emu discovery: riprel_lea_target ignores a lea with a register base") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    // lea rdx, [rax + 8]  (48 8D 50 08): runtime-dependent, not a static pointer.
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

// Candidate probe: for each PAPA_DIAG_VAS, report whether the VA is a pointer
// candidate, whether it is already covered by a recovered function, and the
// outcome of emulating it (executable, has_ret, bad_code, insn_count,
// looks_good). Diagnoses why a pointer-referenced function is or is not
// discovered. No-op unless PAPA_DIAG_BIN is set.
TEST_CASE("diag: emu candidate probe") {
    const std::string bin = papa_tests::detail::read_env("PAPA_DIAG_BIN");
    if (bin.empty()) { return; }
    const auto vas = probe_hex_csv(papa_tests::detail::read_env("PAPA_DIAG_VAS"));

    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());
    auto funcs = pn::Cfg::recover(*img, disasm);
    REQUIRE(funcs.has_value());

    std::unordered_set<std::uint64_t> covered;
    for (const auto& f : *funcs) {
        for (const auto& bb : f.basic_blocks) {
            for (const auto& ins : bb.instructions) { covered.insert(ins.va); }
        }
    }
    const std::vector<std::uint64_t> cands = emu::find_pointer_candidates(*img);
    const emu::ImageMaps maps = emu::build_image_maps(*img);

    for (const auto va : vas) {
        const bool is_cand = std::binary_search(cands.begin(), cands.end(), va);
        const bool is_cov = covered.count(va) != 0;
        emu::WorkspaceEmulator we(disasm);
        for (std::size_t i = 0; i < maps.entries.size(); ++i) {
            we.add_map(maps.entries[i].base, maps.entries[i].perms, maps.bytes[i]);
        }
        const bool execok = we.emu().memory().probe(va, 1, emu::kMemExec);
        emu::Watcher w;
        if (execok) {
            we.prepare(va);
            we.run_function(va, &w, /*maxhit=*/1);
        }
        std::printf("VA %llx: candidate=%d covered=%d execok=%d has_ret=%d "
                    "bad_code=%d insns=%zu looks_good=%d\n",
                    static_cast<unsigned long long>(va), is_cand ? 1 : 0,
                    is_cov ? 1 : 0, execok ? 1 : 0, w.has_ret() ? 1 : 0,
                    w.bad_code() ? 1 : 0, w.insn_count(), w.looks_good() ? 1 : 0);
    }
    CHECK(true);
}

TEST_CASE("emu discovery: x64 lea-referenced function is recovered (certutil adler32)") {
    const auto path = papa_tests::fixture_path("corpus/certutil_x64.exe");
    if (!papa_tests::fixture_available(path)) {
        MESSAGE("fixture missing: corpus/certutil_x64.exe");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(path);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());
    auto funcs = pn::Cfg::recover(*img, disasm);
    REQUIRE(funcs.has_value());
    // adler32 at 0x140109160 is referenced only by `lea rdx, [rip + ...]` at
    // 0x140108161 and is absent from .pdata and the relocations. The amd64
    // code-derived REF_PTR (lea-target) emucode candidate source recovers it.
    const bool recovered = std::any_of(
        funcs->begin(), funcs->end(),
        [](const pn::Function& f) { return f.va == 0x140109160ULL; });
    CHECK(recovered);
}

// Fidelity diagnostic: how many of a binary's already-recovered functions does
// the emulator validate as looks_good? A high rate means the opcode coverage is
// good enough to run real 32-bit code to a ret. A low rate reveals opcode gaps
// to fill before discovery integration. No-op unless PAPA_DIAG_BIN is set.
//   PAPA_DIAG_BIN=<path> papa_unit_tests \
//       --test-case="diag: emu looks_good rate over recovered functions"
TEST_CASE("diag: emu looks_good rate over recovered functions") {
    const std::string bin = papa_tests::detail::read_env("PAPA_DIAG_BIN");
    if (bin.empty()) { return; }

    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());
    auto funcs = pn::Cfg::recover(*img, disasm);
    REQUIRE(funcs.has_value());

    const emu::ImageMaps maps = emu::build_image_maps(*img);

    std::size_t good = 0;
    std::size_t total = 0;
    for (const pn::Function& f : *funcs) {
        if (f.basic_blocks.empty()) { continue; }
        ++total;
        if (emu::validate_candidate(maps, disasm, f.va)) {
            ++good;
        }
    }
    const double rate = total > 0 ? 100.0 * static_cast<double>(good) /
                                        static_cast<double>(total)
                                  : 0.0;
    std::printf("emu looks_good: %zu / %zu recovered functions (%.1f%%)\n",
                good, total, rate);
    CHECK(total > 0);
}

// Discovery-yield diagnostic: how many pointer candidates does the image hold,
// how many are not already covered by the recovered functions, and how many of
// those validate as functions? Previews what the emucode pointer pass would
// add before it is wired into recovery. No-op unless PAPA_DIAG_BIN is set.
//   PAPA_DIAG_BIN=<path> papa_unit_tests \
//       --test-case="diag: emu pointer-candidate discovery yield"
TEST_CASE("diag: emu pointer-candidate discovery yield") {
    const std::string bin = papa_tests::detail::read_env("PAPA_DIAG_BIN");
    if (bin.empty()) { return; }

    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());
    auto funcs = pn::Cfg::recover(*img, disasm);
    REQUIRE(funcs.has_value());

    // Every VA already attributed to a recovered function.
    std::unordered_set<std::uint64_t> covered;
    for (const pn::Function& f : *funcs) {
        for (const pn::BasicBlock& bb : f.basic_blocks) {
            for (const pn::DecodedInsn& ins : bb.instructions) {
                covered.insert(ins.va);
            }
        }
    }

    const std::vector<std::uint64_t> cands = emu::find_pointer_candidates(*img);
    const emu::ImageMaps maps = emu::build_image_maps(*img);

    std::size_t uncovered = 0;
    std::size_t validated = 0;
    for (const std::uint64_t va : cands) {
        if (covered.count(va) != 0) { continue; }
        ++uncovered;
        if (emu::validate_candidate(maps, disasm, va)) {
            ++validated;
        }
    }
    std::printf("pointer candidates: %zu total, %zu uncovered, %zu validated as functions\n",
                cands.size(), uncovered, validated);
    CHECK(true);
}

// Opcode-coverage diagnostic: across every instruction of the recovered
// functions, which mnemonics does execute_opcode not yet handle, and how often?
// The top entries are the highest-value opcodes to add next. No-op unless
// PAPA_DIAG_BIN is set.
//   PAPA_DIAG_BIN=<path> papa_unit_tests \
//       --test-case="diag: emu unsupported-opcode histogram"
TEST_CASE("diag: emu unsupported-opcode histogram") {
    const std::string bin = papa_tests::detail::read_env("PAPA_DIAG_BIN");
    if (bin.empty()) { return; }

    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());
    auto funcs = pn::Cfg::recover(*img, disasm);
    REQUIRE(funcs.has_value());

    emu::IntelEmulator scratch;
    std::unordered_map<std::string, std::size_t> unsupported;
    std::size_t insns = 0;
    std::size_t unsupported_total = 0;
    for (const pn::Function& f : *funcs) {
        for (const pn::BasicBlock& bb : f.basic_blocks) {
            for (const pn::DecodedInsn& ins : bb.instructions) {
                ++insns;
                if (scratch.execute_opcode(ins) == emu::ExecResult::kUnsupported) {
                    ++unsupported_total;
                    unsupported[std::string(ins.mnemonic_str)]++;
                }
            }
        }
    }

    std::vector<std::pair<std::string, std::size_t>> ranked(unsupported.begin(),
                                                            unsupported.end());
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    std::printf("unsupported: %zu / %zu instructions (%.1f%%), %zu distinct mnemonics\n",
                unsupported_total, insns,
                insns > 0 ? 100.0 * static_cast<double>(unsupported_total) /
                                static_cast<double>(insns)
                          : 0.0,
                ranked.size());
    for (std::size_t i = 0; i < ranked.size() && i < 30; ++i) {
        std::printf("  %-12s %zu\n", ranked[i].first.c_str(), ranked[i].second);
    }
    CHECK(true);
}
