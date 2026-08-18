#pragma once

#include "papa/features/extractors/papa_native/disassembler.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace papa::features::extractors::papa_native {

/// Case targets of an indexed indirect jump plus the extent of the offset table the
/// dispatch reads
struct JumpTableTargets {
    std::vector<std::uint64_t> targets;
    std::uint64_t              table_va{0};
    std::uint64_t              table_size{0};
};

/// Invoked when recovery reaches an indirect register jump
using JumpTableResolver =
    std::function<std::optional<JumpTableTargets>(std::span<const DecodedInsn>)>;

/// Reads a little-endian 32-bit jump-table entry at a virtual address, or
/// nullopt when the address is not mapped
using TableReader = std::function<std::optional<std::uint32_t>(std::uint64_t va)>;

/// Reads a single byte at a virtual address, or nullopt when it is not mapped
using ByteReader = std::function<std::optional<std::uint8_t>(std::uint64_t va)>;

/// Resolve the switch-case targets of the dominant MSVC x64 indexed-jump idiom, whose
/// table holds 32-bit base-relative offsets. Yields nothing when the window does not match
[[nodiscard]] std::optional<JumpTableTargets>
resolve_indexed_jump_table(std::span<const DecodedInsn> window,
                           bool                         is_64bit,
                           std::uint64_t                range_lo,
                           std::uint64_t                range_hi,
                           const TableReader&           read_u32);

/// Resolve the 32-bit memory-indirect indexed jump, the dominant MSVC x86 switch
/// dispatch, whose table address is a constant displacement known without emulation
[[nodiscard]] std::optional<JumpTableTargets>
resolve_memory_indirect_jump_table(const DecodedInsn& jmp_insn,
                                   std::uint64_t      range_lo,
                                   std::uint64_t      range_hi,
                                   const TableReader& read_u32);

/// Recognize the MSVC x64 two-level indexed-jump idiom, which adds a byte index-map
/// remap before the offset-table load, and resolve its distinct case targets
[[nodiscard]] std::optional<JumpTableTargets>
resolve_two_level_indexed_jump_table(std::span<const DecodedInsn> window,
                                     bool                         is_64bit,
                                     std::uint64_t                range_lo,
                                     std::uint64_t                range_hi,
                                     const TableReader&           read_u32,
                                     const ByteReader&            read_u8);

/// The injected environment resolve_switch_jump_table needs: the image base, a table
/// reader, the predicate bounding the walk, and a base-register value from emulation
struct SwitchEnv {
    std::uint64_t image_base{0};
    /// Reads the little-endian 32-bit offset-table entry at a virtual address
    TableReader read_entry;
    /// True when a rebased target is probable code (an executable, decodable
    /// address), the iterJumpTable stop condition
    std::function<bool(std::uint64_t va)> is_probably_code;
    /// The concrete value of the base register at the dispatch, from emulating the
    /// function to the jump, or nullopt when emulation could not reach it
    std::function<std::optional<std::uint64_t>(ZydisRegister reg)> base_reg_value;
};

/// Resolve an MSVC x64 indexed switch dispatch the emulator-driven way vivisect does,
/// reading the register base from the live emulator so a path-sensitive base resolves
[[nodiscard]] std::optional<JumpTableTargets>
resolve_switch_jump_table(std::span<const DecodedInsn> window,
                          bool                         is_64bit,
                          const SwitchEnv&             env);

}  // namespace papa::features::extractors::papa_native
