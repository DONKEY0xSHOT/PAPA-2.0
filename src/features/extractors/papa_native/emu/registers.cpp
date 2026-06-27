#include "papa/features/extractors/papa_native/emu/registers.h"

namespace papa::features::extractors::papa_native::emu {

namespace {

// 2^width - 1 as a 64-bit mask (width in bits, capped at 64).
[[nodiscard]] std::uint64_t width_mask(std::uint32_t width_bits) noexcept {
    if (width_bits >= 64U) {
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    return (1ULL << width_bits) - 1ULL;
}

// A meta-register index whose top half is RMETA_LOW32 is a 32-bit lane at
// offset 0 (width 32 in bits 16..23, offset 0 in bits 24..31). In amd64 mode,
// writing such a lane (eax, r8d, ...) zero-extends into the full parent
// register, so it is redirected to a write of the whole real register
// (envi/archs/amd64/regs.py Amd64RegisterContext.setRegister).
constexpr std::uint32_t kRMetaLow32 = 0x00200000U;

}  // namespace

RegisterFile::RegisterFile(bool is_64bit) noexcept {
    if (is_64bit) {
        real_mask_ = 0xFFFFFFFFFFFFFFFFULL;
        eflags_index_ = kRegEflags64;
        low32_zx_ = true;
    }
}

std::uint64_t RegisterFile::get_register(std::uint32_t index) const noexcept {
    const std::uint32_t ridx = index & 0xFFFFU;
    if (ridx >= kRegSlots) {
        return 0U;
    }
    std::uint64_t value = vals_[ridx];
    if (ridx != index) {
        const std::uint32_t offset = (index >> 24) & 0xFFU;
        const std::uint32_t width  = (index >> 16) & 0xFFU;
        if (offset != 0U) {
            value >>= offset;
        }
        value &= width_mask(width);
    }
    return value;
}

void RegisterFile::set_register(std::uint32_t index, std::uint64_t value) noexcept {
    // amd64 RMETA_LOW32 override: a 32-bit-low lane (eax, r8d, ...) writes the
    // whole real register, zero-extending the value into the upper bits.
    if (low32_zx_ && (index & 0xFFFF0000U) == kRMetaLow32) {
        index &= 0xFFFFU;
    }

    const std::uint32_t ridx = index & 0xFFFFU;
    if (ridx >= kRegSlots) {
        return;
    }
    if (ridx != index) {
        // Meta-register lane: splice the new bits in, preserve the rest
        // (_xlateToNativeReg). 8/16-bit lanes thus keep the upper bits.
        const std::uint32_t offset = (index >> 24) & 0xFFU;
        const std::uint32_t width  = (index >> 16) & 0xFFU;
        const std::uint64_t lane_mask = width_mask(width) << offset;
        const std::uint64_t newbits = (value << offset) & lane_mask;
        vals_[ridx] = ((vals_[ridx] & ~lane_mask) | newbits) & real_mask_;
        return;
    }
    vals_[ridx] = value & real_mask_;
}

bool RegisterFile::get_flag(std::uint32_t which) const noexcept {
    return (vals_[eflags_index_] & which) != 0U;
}

void RegisterFile::set_flag(std::uint32_t which, bool state) noexcept {
    if (state) {
        vals_[eflags_index_] |= which;
    } else {
        vals_[eflags_index_] &= ~static_cast<std::uint64_t>(which);
    }
}

Xmm RegisterFile::get_xmm(std::uint32_t index) const noexcept {
    if (index >= kXmmCount) {
        return Xmm{};
    }
    return xmm_[index];
}

void RegisterFile::set_xmm(std::uint32_t index, const Xmm& value) noexcept {
    if (index < kXmmCount) {
        xmm_[index] = value;
    }
}

bool RegisterFile::is_tainted(std::uint32_t index) const noexcept {
    const std::uint32_t ridx = index & 0xFFFFU;
    return ridx < kRegSlots && taint_[ridx];
}

void RegisterFile::set_taint(std::uint32_t index, bool tainted) noexcept {
    const std::uint32_t ridx = index & 0xFFFFU;
    if (ridx < kRegSlots) {
        taint_[ridx] = tainted;
    }
}

RegisterFile::Snapshot RegisterFile::snapshot() const noexcept {
    return Snapshot{vals_, taint_, xmm_};
}

void RegisterFile::restore(const Snapshot& snap) noexcept {
    vals_ = snap.vals;
    taint_ = snap.taint;
    xmm_ = snap.xmm;
}

}  // namespace papa::features::extractors::papa_native::emu
