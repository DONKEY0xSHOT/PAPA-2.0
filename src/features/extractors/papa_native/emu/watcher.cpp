#include "papa/features/extractors/papa_native/emu/watcher.h"

#include <cmath>
#include <cstddef>

namespace papa::features::extractors::papa_native::emu {

namespace {

// The all-zero and all-FF byte runs vivisect parses as bad opcodes
// (archGetBadOps): markers of disassembling data as code.
[[nodiscard]] bool is_bad_op_bytes(const DecodedInsn& insn) noexcept {
    if (insn.raw_bytes.size() < 2) {
        return false;
    }
    const auto b0 = std::to_integer<std::uint8_t>(insn.raw_bytes[0]);
    const auto b1 = std::to_integer<std::uint8_t>(insn.raw_bytes[1]);
    return (b0 == 0x00 && b1 == 0x00) || (b0 == 0xFF && b1 == 0xFF);
}

// round(count / total, 3) >= threshold, matching emucode's ratio test.
[[nodiscard]] bool ratio_at_least(std::size_t count, std::size_t total,
                                  double threshold) noexcept {
    if (total == 0) {
        return false;
    }
    const double ratio = static_cast<double>(count) / static_cast<double>(total);
    const double rounded = std::round(ratio * 1000.0) / 1000.0;
    return rounded >= threshold;
}

}  // namespace

void Watcher::prehook(WorkspaceEmulator& emu, const DecodedInsn& insn,
                      std::uint64_t /*eip*/) {
    // Privileged I/O: not a normal function path.
    if (insn.zyd_mnem == ZYDIS_MNEMONIC_OUT) {
        emu.stop_emu();
        return;
    }
    // `int` with eax == 1 is the process-exit pattern: stop, but still count it.
    if (insn.zyd_mnem == ZYDIS_MNEMONIC_INT &&
        emu.emu().regs().get_register(kRegEax) == 1U) {
        emu.stop_emu();
    } else if (is_bad_op_bytes(insn)) {
        emu.stop_emu();
        return;
    }

    if (insn.is_return) {
        hasret_ = true;
        emu.stop_emu();
    }

    lastop_ = insn.zyd_mnem;
    last_is_terminal_ = insn.is_return || insn.is_jump || insn.is_call;
    ++mndist_[insn.zyd_mnem];
    ++insn_count_;
}

void Watcher::log_anomaly(WorkspaceEmulator& emu, std::uint64_t /*eip*/) {
    badcode_ = true;
    emu.stop_emu();
}

bool Watcher::looks_good() const noexcept {
    if (!hasret_ || badcode_) {
        return false;
    }
    if (insn_count_ > 4) {
        for (const auto& [mnem, count] : mndist_) {
            (void)mnem;
            if (ratio_at_least(count, insn_count_, 0.67)) {
                return false;
            }
        }
    }
    return true;
}

bool Watcher::is_code() const noexcept {
    if (lastop_ == ZYDIS_MNEMONIC_INVALID || !last_is_terminal_) {
        return false;
    }
    for (const auto& [mnem, count] : mndist_) {
        (void)mnem;
        if (ratio_at_least(count, insn_count_, 0.60)) {
            return false;
        }
    }
    return true;
}

}  // namespace papa::features::extractors::papa_native::emu
