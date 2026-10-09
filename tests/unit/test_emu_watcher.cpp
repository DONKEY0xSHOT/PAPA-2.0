#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/watcher.h"
#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// The watcher decides whether an emulated candidate looks like a real function: a
// faithful port of analysis/generic/emucode.py watcher

TEST_CASE("emu watcher: each candidate's ret, bad code, mnemonic mix and last instruction decide its verdicts") {
    constexpr std::uint64_t kBase = 0x00401000;
    // The rel32 of a jmp at 0x401005 to the unmapped 0x402000
    constexpr std::uint32_t kRel = 0x402000U - (0x401005U + 5U);
    struct Row {
        std::string_view             label;
        std::vector<std::uint8_t>    code;
        std::optional<std::uint32_t> ecx;
        bool                         has_ret;
        bool                         looks_good;
        bool                         bad_code;
        bool                         is_code;
        std::size_t                  insns;
    };
    const std::vector<Row> rows{
        // xor eax, eax / add eax, 1 / ret
        {"a small function that reaches a ret looks good", {0x31, 0xC0, 0x83, 0xC0, 0x01, 0xC3},
         std::nullopt, true, true, false, true, 3},
        // xor eax,eax / add eax,1 / sub eax,1 / or eax,2 / and eax,3 / ret
        {"a varied function of several instructions looks good",
         {0x31, 0xC0, 0x83, 0xC0, 0x01, 0x83, 0xE8, 0x01, 0x83, 0xC8, 0x02, 0x83, 0xE0, 0x03, 0xC3},
         std::nullopt, true, true, false, true, 6},
        // jmp -2, an infinite self-loop that never reaches a ret
        {"a body that never returns does not look good", {0xEB, 0xFE}, std::nullopt, false, false,
         false, false, 1},
        // six nops then ret: nop is 6/7 >= 0.67 of the instructions
        {"a stream dominated by one mnemonic does not look good",
         {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3}, std::nullopt, true, false, false, false, 7},
        // div ecx / ret with ecx forced to 0
        {"a divide by zero marks the candidate as bad code", {0xF7, 0xF1, 0xC3}, 0U, false, false,
         true, false, 1},
        // all-zero bytes: the bad-op signature, not real code
        {"decoding through zero padding stops and does not look good", {0, 0, 0, 0, 0, 0, 0, 0},
         std::nullopt, false, false, false, false, 0},
        // xor eax,eax / add eax,1 / jmp 0x402000, which is unmapped and ends the path
        {"is_code accepts a branch-terminated varied stream",
         {0x31, 0xC0, 0x83, 0xC0, 0x01, 0xE9, static_cast<std::uint8_t>(kRel & 0xFF),
          static_cast<std::uint8_t>((kRel >> 8) & 0xFF),
          static_cast<std::uint8_t>((kRel >> 16) & 0xFF),
          static_cast<std::uint8_t>((kRel >> 24) & 0xFF)},
         std::nullopt, false, false, false, true, 3},
    };
    const pn::Disassembler disasm(false);
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::WorkspaceEmulator we(disasm);
        we.add_map(kBase, emu::kMemRead | emu::kMemExec, row.code);
        we.prepare(kBase);
        if (row.ecx.has_value()) { we.emu().regs().set_register(emu::kRegEcx, *row.ecx); }
        emu::Watcher w;
        we.run_function(kBase, &w);
        CHECK(w.has_ret() == row.has_ret);
        CHECK(w.looks_good() == row.looks_good);
        CHECK(w.bad_code() == row.bad_code);
        CHECK(w.is_code() == row.is_code);
        CHECK(w.insn_count() == row.insns);
    }
}
