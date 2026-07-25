#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

namespace papa::features::extractors::papa_native::emu {

// Memory permission bits (envi/const.py MM_*)
inline constexpr std::uint32_t kMemExec = 0x1;
inline constexpr std::uint32_t kMemWrite = 0x2;
inline constexpr std::uint32_t kMemRead = 0x4;

// The byte returned for reads of unmapped/uninitialized memory under safe-mem
// (vivisect taintbyte = b'a')
inline constexpr std::uint8_t kTaintByte = 0x61;

// vivisect WorkspaceEmulator stack layout (impemu/emulator.py initStackMemory),
// 32-bit: base 0xbfb00000, size 0x8000, fill 0xfe, perms RW
inline constexpr std::uint64_t kStackBase = 0xBFB00000ULL;
inline constexpr std::uint64_t kStackSize = 0x8000ULL;
inline constexpr std::uint64_t kStackTop = kStackBase + kStackSize;
inline constexpr std::uint8_t  kStackFill = 0xFE;

// amd64 stack: impemu sign-extends the 0xbfb00000 base to the 64-bit pointer
// width (initStackMemory, e_bits.sign_extend(0xbfb00000, 4, psize))
inline constexpr std::uint64_t kStackBase64 = 0xFFFFFFFFBFB00000ULL;
inline constexpr std::uint64_t kStackTop64 = kStackBase64 + kStackSize;

// Default cap on the write overlay (DoS backstop, bytes)
inline constexpr std::size_t kDefaultOverlayCap = 1U << 20;

// A bounds-checked model of the emulated address space. Backing maps (PE
// sections, the stack) are read-only views over external bytes. Every write
// lands in a private, capped overlay so an emulated PE can never mutate the
// backing store or grow papa's memory without bound. Reads compose the overlay
// over the backing, and an unmapped read returns a taint fill rather than
// failing. This is the emulator's security boundary
class SandboxMemory {
public:
    // Overlay snapshot for the runFunction work-queue (only mutable state)
    struct Snapshot {
        std::unordered_map<std::uint64_t, std::uint8_t> overlay;
    };

    explicit SandboxMemory(std::size_t overlay_cap = kDefaultOverlayCap) noexcept;

    // Add a backing map over external bytes. The span must outlive this object
    void add_map(std::uint64_t base, std::uint32_t perms,
                 std::span<const std::uint8_t> bytes);

    // Install the standard emulator stack (RW, 0xfe fill, no backing copy) at
    // the given base (the i386 base by default, the sign-extended amd64 base
    // for 64-bit)
    void init_stack(std::uint64_t base = kStackBase);

    // envi probeMemory: the whole [va, va+size) range lies in one map whose
    // perms include `perm`
    [[nodiscard]] bool probe(std::uint64_t va, std::size_t size,
                             std::uint32_t perm) const noexcept;

    // envi isValidPointer: va lies in some map (any perms)
    [[nodiscard]] bool is_valid_pointer(std::uint64_t va) const noexcept;

    // Read `size` bytes: overlay over backing, or a taint fill if not readable
    [[nodiscard]] std::vector<std::uint8_t>
        read_bytes(std::uint64_t va, std::size_t size) const;

    // Read up to `max_len` bytes for instruction fetch: the readable bytes from
    // `va` clipped to the end of the containing map (no taint fill, no
    // cross-map), or empty if `va` is unmapped or unreadable. Mirrors how
    // vivisect parseOpcode fetches from the mapped image bytes
    [[nodiscard]] std::vector<std::uint8_t>
        read_code(std::uint64_t va, std::size_t max_len) const;

    // Little-endian numeric read (emu.py readMemValue). size in {1,2,4,8}
    [[nodiscard]] std::uint64_t
        read_value(std::uint64_t va, std::size_t size) const;

    // Write bytes into the overlay if the range is writable, otherwise drop them
    // (safe-mem). Bounded by the overlay cap
    void write(std::uint64_t va, std::span<const std::uint8_t> bytes);

    // Little-endian numeric write (emu.py writeMemValue)
    void write_value(std::uint64_t va, std::uint64_t value, std::size_t size);

    [[nodiscard]] Snapshot snapshot() const;
    void restore(const Snapshot& snap);

private:
    struct Map {
        std::uint64_t              base{0};
        std::uint64_t              size{0};
        std::uint32_t              perms{0};
        std::span<const std::uint8_t> bytes{};  // empty for the stack fill
        bool                       is_fill{false};
    };

    [[nodiscard]] const Map* find_map(std::uint64_t va) const noexcept;
    [[nodiscard]] std::uint8_t backing_byte(const Map& map,
                                            std::uint64_t va) const noexcept;

    std::vector<Map>                                maps_;
    std::unordered_map<std::uint64_t, std::uint8_t> overlay_;
    std::size_t                                     overlay_cap_;
};

}  // namespace papa::features::extractors::papa_native::emu
