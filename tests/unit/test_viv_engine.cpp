#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "doctest.h"

#include "fixture_paths.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/emu_discovery.h"
#include "papa/features/extractors/papa_native/viv/engine.h"
#include "papa/pe/pe_parser.h"

namespace pn = papa::features::extractors::papa_native;

TEST_CASE("discovery engine: recovers the entry point and a non-empty function set") {
    const auto path = papa_tests::fixture_path("corpus/hostname_x86.exe");
    if (!papa_tests::fixture_available(path)) {
        MESSAGE("fixture missing: corpus/hostname_x86.exe");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(path);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());

    const std::vector<pn::Function> funcs =
        pn::viv::discover_functions(*img, disasm).functions;

    REQUIRE_FALSE(funcs.empty());
    const std::uint64_t entry = img->image_base() + img->entry_point_rva();
    CHECK(std::any_of(funcs.begin(), funcs.end(),
                      [entry](const pn::Function& f) { return f.va == entry; }));
}

// Dump every recovered function and its basic-block starts for PAPA_BLOCKS_BIN
// to PAPA_BLOCKS_OUT, one "fva bva1 bva2 ..." line per function, so the block
// attribution can be diffed against the vivisect oracle. No-op unless set
TEST_CASE("diag: all function blocks dump") {
    const std::string bin = papa_tests::detail::read_env("PAPA_BLOCKS_BIN");
    if (bin.empty()) {
        return;
    }
    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const pn::Disassembler          disasm(img->is_64bit());
    const std::vector<pn::Function> funcs =
        pn::viv::discover_functions(*img, disasm).functions;

    std::ofstream                    f(papa_tests::detail::read_env("PAPA_BLOCKS_OUT"));
    std::vector<const pn::Function*> ordered;
    ordered.reserve(funcs.size());
    for (const pn::Function& fn : funcs) {
        ordered.push_back(&fn);
    }
    std::sort(ordered.begin(), ordered.end(),
              [](const pn::Function* a, const pn::Function* b) {
                  return a->va < b->va;
              });
    for (const pn::Function* fn : ordered) {
        f << std::hex << fn->va;
        std::vector<std::uint64_t> starts;
        for (const pn::BasicBlock& bb : fn->basic_blocks) {
            starts.push_back(bb.va);
        }
        std::sort(starts.begin(), starts.end());
        for (const std::uint64_t s : starts) {
            f << ' ' << std::hex << s;
        }
        f << '\n';
    }
    CHECK(true);
}

// Print the recovered blocks of each comma-separated hex VA in PAPA_BLOCK_VAS of
// PAPA_BLOCK_BIN, so a match-count divergence can be traced to the function a
// shared block is attributed to. No-op unless PAPA_BLOCK_BIN is set
TEST_CASE("diag: function blocks at a VA") {
    const std::string bin = papa_tests::detail::read_env("PAPA_BLOCK_BIN");
    if (bin.empty()) {
        return;
    }
    std::vector<std::uint64_t> vas;
    std::stringstream          ss(papa_tests::detail::read_env("PAPA_BLOCK_VAS"));
    for (std::string tok; std::getline(ss, tok, ',');) {
        if (!tok.empty()) {
            vas.push_back(std::stoull(tok, nullptr, 16));
        }
    }
    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());
    auto                   rec = pn::cfg::recover(*img, disasm);
    REQUIRE(rec.has_value());
    const auto& funcs = rec->functions;

    for (const std::uint64_t va : vas) {
        const auto it = std::find_if(funcs.begin(), funcs.end(),
                                     [va](const pn::Function& f) { return f.va == va; });
        if (it == funcs.end()) {
            std::printf("VA %llx: NOT a function entry\n",
                        static_cast<unsigned long long>(va));
            continue;
        }
        std::printf("VA %llx: %zu blocks\n", static_cast<unsigned long long>(va),
                    it->basic_blocks.size());
        for (const auto& bb : it->basic_blocks) {
            const std::uint64_t end =
                bb.instructions.empty()
                    ? bb.va
                    : bb.instructions.back().va + bb.instructions.back().length;
            std::printf("  bb %llx..%llx (%zu insns)\n",
                        static_cast<unsigned long long>(bb.va),
                        static_cast<unsigned long long>(end), bb.instructions.size());
        }
    }
    CHECK(true);
}

// Print emu::validate_candidate for each comma-separated hex VA in
// PAPA_VALIDATE_VAS of PAPA_VALIDATE_BIN, to see whether the discovery emulator
// classifies an address as code. No-op unless PAPA_VALIDATE_BIN is set
TEST_CASE("diag: validate_candidate") {
    const std::string bin = papa_tests::detail::read_env("PAPA_VALIDATE_BIN");
    if (bin.empty()) {
        return;
    }
    std::vector<std::uint64_t> vas;
    std::stringstream          ss(papa_tests::detail::read_env("PAPA_VALIDATE_VAS"));
    for (std::string tok; std::getline(ss, tok, ',');) {
        if (!tok.empty()) {
            vas.push_back(std::stoull(tok, nullptr, 16));
        }
    }
    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const pn::Disassembler   disasm(img->is_64bit());
    const pn::emu::ImageMaps maps = pn::emu::build_image_maps(*img);
    for (const std::uint64_t va : vas) {
        const bool ok = pn::emu::validate_candidate(maps, disasm, va);
        std::printf("validate_candidate(%llx) = %d\n",
                    static_cast<unsigned long long>(va), ok ? 1 : 0);
    }
    CHECK(true);
}

// Linearly disassemble PAPA_DISASM_COUNT instructions from PAPA_DISASM_START on
// PAPA_DISASM_BIN, printing branch classification and operand kinds, so a switch
// dispatcher and its table can be identified by eye. No-op unless the bin is set
TEST_CASE("diag: disasm range") {
    const std::string bin = papa_tests::detail::read_env("PAPA_DISASM_BIN");
    if (bin.empty()) {
        return;
    }
    const std::uint64_t start =
        std::stoull(papa_tests::detail::read_env("PAPA_DISASM_START"), nullptr, 16);
    const std::string cnt_s = papa_tests::detail::read_env("PAPA_DISASM_COUNT");
    const int         cnt   = cnt_s.empty() ? 40 : std::stoi(cnt_s);
    auto              img   = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const pn::Disassembler disasm(img->is_64bit());
    const pn::InsnReader   reader = pn::cfg::make_image_reader(*img, disasm);

    std::uint64_t va = start;
    for (int i = 0; i < cnt; ++i) {
        const auto in = reader(va);
        if (!in.has_value()) {
            std::printf("%llx: <decode failed>\n",
                        static_cast<unsigned long long>(va));
            break;
        }
        char flags[32] = "";
        std::snprintf(flags, sizeof(flags), "%s%s%s%s",
                      in->is_call ? "CALL " : "", in->is_jump ? "JMP " : "",
                      in->is_conditional ? "COND " : "",
                      in->is_return ? "RET " : "");
        std::printf("%llx: %-8.*s %s tgt=%llx nop=%zu\n",
                    static_cast<unsigned long long>(va),
                    static_cast<int>(in->mnemonic_str.size()), in->mnemonic_str.data(),
                    flags,
                    static_cast<unsigned long long>(in->branch_target.value_or(0)),
                    in->operand_count);
        va += in->length;
    }
    CHECK(true);
}
