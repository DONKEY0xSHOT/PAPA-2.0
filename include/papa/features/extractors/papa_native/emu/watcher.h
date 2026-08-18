#pragma once

#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <unordered_map>

namespace papa::features::extractors::papa_native::emu {

// The discovery monitor that decides whether an emulated candidate looks like a real
// function, a faithful port of the analysis/generic/emucode.py watcher
class Watcher : public EmulationMonitor {
public:
    void prehook(WorkspaceEmulator& emu, const DecodedInsn& insn,
                 std::uint64_t eip) override;
    void log_anomaly(WorkspaceEmulator& emu, std::uint64_t eip) override;

    // A candidate looks like a function: it reached a ret, hit no bad code, and
    // no single mnemonic is >= 67% of instructions (when more than four)
    [[nodiscard]] bool looks_good() const noexcept;

    // A weaker test for greedy code discovery: the last instruction is a ret,
    // branch or call and no single mnemonic is >= 60% of instructions
    [[nodiscard]] bool is_code() const noexcept;

    [[nodiscard]] bool has_ret() const noexcept { return hasret_; }
    [[nodiscard]] bool bad_code() const noexcept { return badcode_; }
    [[nodiscard]] std::size_t insn_count() const noexcept { return insn_count_; }

private:
    bool          hasret_{false};
    bool          badcode_{false};
    std::size_t   insn_count_{0};
    ZydisMnemonic lastop_{ZYDIS_MNEMONIC_INVALID};
    bool          last_is_terminal_{false};
    std::unordered_map<ZydisMnemonic, std::size_t> mndist_;
};

}  // namespace papa::features::extractors::papa_native::emu
