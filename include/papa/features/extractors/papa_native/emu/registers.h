#pragma once

#include <array>
#include <cstdint>

namespace papa::features::extractors::papa_native::emu {

// One 128-bit SSE/XMM register, stored as raw bytes. The discovery emulator
// models SSE moves as faithful byte copies, so XMM state is just 16 bytes
using Xmm = std::array<std::uint8_t, 16>;

// The amd64/i386 register file carries 16 XMM registers (xmm0..xmm15)
inline constexpr std::uint32_t kXmmCount = 16;

// i386 general-purpose register indices in envi/archs/i386/regs.py order. The
// values are load-bearing, since the meta-register encoding assumes eax..edi are 0..7
inline constexpr std::uint32_t kRegEax = 0;
inline constexpr std::uint32_t kRegEcx = 1;
inline constexpr std::uint32_t kRegEdx = 2;
inline constexpr std::uint32_t kRegEbx = 3;
inline constexpr std::uint32_t kRegEsp = 4;
inline constexpr std::uint32_t kRegEbp = 5;
inline constexpr std::uint32_t kRegEsi = 6;
inline constexpr std::uint32_t kRegEdi = 7;
inline constexpr std::uint32_t kRegEip = 8;
inline constexpr std::uint32_t kRegEflags = 9;
inline constexpr std::uint32_t kRegCount = 10;

// amd64 layout, sharing the eight low GP slots with i386 and adding r8..r15. Note
// that kRegR8 and kRegR9 reuse the slots i386 gives eip and eflags
inline constexpr std::uint32_t kRegRax = kRegEax;  // 0
inline constexpr std::uint32_t kRegRcx = kRegEcx;  // 1
inline constexpr std::uint32_t kRegRdx = kRegEdx;  // 2
inline constexpr std::uint32_t kRegRbx = kRegEbx;  // 3
inline constexpr std::uint32_t kRegRsp = kRegEsp;  // 4
inline constexpr std::uint32_t kRegRbp = kRegEbp;  // 5
inline constexpr std::uint32_t kRegRsi = kRegEsi;  // 6
inline constexpr std::uint32_t kRegRdi = kRegEdi;  // 7
inline constexpr std::uint32_t kRegR8  = 8;
inline constexpr std::uint32_t kRegR9  = 9;
inline constexpr std::uint32_t kRegR10 = 10;
inline constexpr std::uint32_t kRegR11 = 11;
inline constexpr std::uint32_t kRegR12 = 12;
inline constexpr std::uint32_t kRegR13 = 13;
inline constexpr std::uint32_t kRegR14 = 14;
inline constexpr std::uint32_t kRegR15 = 15;
inline constexpr std::uint32_t kRegRip = 16;
inline constexpr std::uint32_t kRegEflags64 = 17;

// Backing-array size: enough for the amd64 layout (i386 uses indices 0..9)
inline constexpr std::uint32_t kRegSlots = 18;

// Meta-register encoding (registers.py addMetaRegister): a subregister lane is
// (shift_offset << 24) | (width_bits << 16) | real_index
inline constexpr std::uint32_t make_meta_reg(std::uint32_t offset,
                                             std::uint32_t width_bits,
                                             std::uint32_t real_index) noexcept {
    return (offset << 24) | (width_bits << 16) | real_index;
}

// 16-bit lanes
inline constexpr std::uint32_t kRegAx = make_meta_reg(0, 16, kRegEax);
inline constexpr std::uint32_t kRegCx = make_meta_reg(0, 16, kRegEcx);
inline constexpr std::uint32_t kRegDx = make_meta_reg(0, 16, kRegEdx);
inline constexpr std::uint32_t kRegBx = make_meta_reg(0, 16, kRegEbx);
inline constexpr std::uint32_t kRegSp = make_meta_reg(0, 16, kRegEsp);
inline constexpr std::uint32_t kRegBp = make_meta_reg(0, 16, kRegEbp);
inline constexpr std::uint32_t kRegSi = make_meta_reg(0, 16, kRegEsi);
inline constexpr std::uint32_t kRegDi = make_meta_reg(0, 16, kRegEdi);

// 8-bit low lanes
inline constexpr std::uint32_t kRegAl = make_meta_reg(0, 8, kRegEax);
inline constexpr std::uint32_t kRegCl = make_meta_reg(0, 8, kRegEcx);
inline constexpr std::uint32_t kRegDl = make_meta_reg(0, 8, kRegEdx);
inline constexpr std::uint32_t kRegBl = make_meta_reg(0, 8, kRegEbx);

// 8-bit high lanes (shift offset 8 into the parent)
inline constexpr std::uint32_t kRegAh = make_meta_reg(8, 8, kRegEax);
inline constexpr std::uint32_t kRegCh = make_meta_reg(8, 8, kRegEcx);
inline constexpr std::uint32_t kRegDh = make_meta_reg(8, 8, kRegEdx);
inline constexpr std::uint32_t kRegBh = make_meta_reg(8, 8, kRegEbx);

// EFLAGS status bit masks (envi/archs/i386/regs.py statmetas: 1 << offset)
inline constexpr std::uint32_t kEflagsCf = 1U << 0;
inline constexpr std::uint32_t kEflagsPf = 1U << 2;
inline constexpr std::uint32_t kEflagsAf = 1U << 4;
inline constexpr std::uint32_t kEflagsZf = 1U << 6;
inline constexpr std::uint32_t kEflagsSf = 1U << 7;
inline constexpr std::uint32_t kEflagsTf = 1U << 8;
inline constexpr std::uint32_t kEflagsIf = 1U << 9;
inline constexpr std::uint32_t kEflagsDf = 1U << 10;
inline constexpr std::uint32_t kEflagsOf = 1U << 11;

// A faithful port of envi's RegisterContext, reduced to the registers the discovery
// emulator needs, plus a taint bit per register. Every write masks to the width
class RegisterFile {
public:
    // Construct for i386 (32-bit reals) or amd64 (64-bit reals + zero-extend)
    explicit RegisterFile(bool is_64bit = false) noexcept;

    // Bulk register state for the runFunction work-queue (getRegisterSnap)
    struct Snapshot {
        std::array<std::uint64_t, kRegSlots> vals{};
        std::array<bool, kRegSlots>          taint{};
        std::array<Xmm, kXmmCount>           xmm{};
    };

    // Read a register or meta-register lane. Out-of-range indices read 0
    [[nodiscard]] std::uint64_t get_register(std::uint32_t index) const noexcept;

    // Write a register or meta-register lane. The value is masked to the
    // target width (real register) or spliced into the parent (meta lane)
    void set_register(std::uint32_t index, std::uint64_t value) noexcept;

    [[nodiscard]] bool get_flag(std::uint32_t which) const noexcept;
    void set_flag(std::uint32_t which, bool state) noexcept;

    // SSE/XMM register state. Out-of-range indices read zero and ignore writes
    [[nodiscard]] Xmm get_xmm(std::uint32_t index) const noexcept;
    void set_xmm(std::uint32_t index, const Xmm& value) noexcept;

    // Taint tracks whether a register holds an unknown/uninitialized value.
    // Keyed by the real (non-meta) register index of `index`
    [[nodiscard]] bool is_tainted(std::uint32_t index) const noexcept;
    void set_taint(std::uint32_t index, bool tainted) noexcept;

    [[nodiscard]] Snapshot snapshot() const noexcept;
    void restore(const Snapshot& snap) noexcept;

private:
    std::array<std::uint64_t, kRegSlots> vals_{};
    std::array<bool, kRegSlots>          taint_{};
    std::array<Xmm, kXmmCount>           xmm_{};
    // Mask applied to every real-register write (32- or 64-bit), the eflags
    // slot for this arch, and whether the amd64 32-bit-lane zero-extend applies
    std::uint64_t real_mask_{0xFFFFFFFFULL};
    std::uint32_t eflags_index_{kRegEflags};
    bool          low32_zx_{false};
};

}  // namespace papa::features::extractors::papa_native::emu
