#pragma once

#include "papa/features/extractors/papa_native/disassembler.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace papa::features::extractors::papa_native {

/// Case targets of an indexed indirect jump plus the extent of the offset table
/// the dispatch reads. The bytes in [table_va, table_va + table_size) are data,
/// not code, so a recovery pass must not disassemble inside that region
struct JumpTableTargets {
    std::vector<std::uint64_t> targets;
    std::uint64_t              table_va{0};
    std::uint64_t              table_size{0};
};

/// Invoked when recovery reaches an indirect register jump. Given the
/// straight-line window of instructions ending at that jump, it returns the
/// switch-case targets to continue recovery into, or nullopt when the window is
/// not a recognized jump table
using JumpTableResolver =
    std::function<std::optional<JumpTableTargets>(std::span<const DecodedInsn>)>;

/// Reads a little-endian 32-bit jump-table entry at a virtual address, or
/// nullopt when the address is not mapped
using TableReader = std::function<std::optional<std::uint32_t>(std::uint64_t va)>;

/// Reads a single byte at a virtual address, or nullopt when it is not mapped
using ByteReader = std::function<std::optional<std::uint8_t>(std::uint64_t va)>;

/// Resolve the switch-case targets of the dominant MSVC x64 indexed-jump idiom:
/// `cmp idx, N` / `lea base, [rip+B]` / `mov off, [base + i*4 + T]` /
/// `add tgt, base` / `jmp tgt`, where the table at base+T holds 32-bit
/// base-relative offsets. The window runs in ascending program order and ends at
/// the indirect jump. Resolution stops at the count bound or the first target
/// outside [range_lo, range_hi), and yields nothing when the window does not
/// match the idiom
[[nodiscard]] std::optional<JumpTableTargets>
resolve_indexed_jump_table(std::span<const DecodedInsn> window,
                           bool                         is_64bit,
                           std::uint64_t                range_lo,
                           std::uint64_t                range_hi,
                           const TableReader&           read_u32);

/// Resolve the 32-bit memory-indirect indexed jump `jmp [index*scale + table]`,
/// the dominant MSVC x86 switch dispatch, directly from the jump instruction.
///
/// The form has no base register, so the table address is the constant
/// displacement and is known without emulation. The table at that address holds
/// absolute case-target pointers, read until one falls outside [range_lo,
/// range_hi) or a DoS cap is reached. Returns nullopt when `jmp_insn` is not an
/// indexed memory-indirect jump with a constant table address
[[nodiscard]] std::optional<JumpTableTargets>
resolve_memory_indirect_jump_table(const DecodedInsn& jmp_insn,
                                   std::uint64_t      range_lo,
                                   std::uint64_t      range_hi,
                                   const TableReader& read_u32);

/// Recognize the MSVC x64 two-level indexed-jump idiom and resolve its distinct
/// case targets. It adds a byte index-map remap before the offset-table load:
///   cmp val, N / ja default / movzx i, byte [base + val + T2] /
///   lea base, [rip+B] / mov off, [base + i*4 + T1] / add tgt, base / jmp tgt
/// where the byte table at base+T2 maps a switch value (0..N) to an offset-table
/// index, and the dword table at base+T1 holds image-base-relative offsets. Each
/// target is base + offset table[index map[value]]. The base register is often
/// set at the prologue, so the window should span the whole function. Targets are
/// accepted only inside [range_lo, range_hi). Returns nullopt when the window does
/// not match the idiom
[[nodiscard]] std::optional<JumpTableTargets>
resolve_two_level_indexed_jump_table(std::span<const DecodedInsn> window,
                                     bool                         is_64bit,
                                     std::uint64_t                range_lo,
                                     std::uint64_t                range_hi,
                                     const TableReader&           read_u32,
                                     const ByteReader&            read_u8);

/// The injected environment resolve_switch_jump_table needs: the image base the
/// offset table is relative to, a reader for the offset table, the predicate that
/// bounds the table walk (isProbablyCode on a rebased target), and the concrete
/// value of a base register evaluated by emulating the enclosing function
struct SwitchEnv {
    std::uint64_t image_base{0};
    /// Reads the little-endian 32-bit offset-table entry at a virtual address
    TableReader read_entry;
    /// True when a rebased target is probable code (an executable, decodable
    /// address), the iterJumpTable stop condition
    std::function<bool(std::uint64_t va)> is_probably_code;
    /// The concrete value of the base register at the dispatch, from emulating
    /// the function to the jump (vivisect getOperValue on the live emulator), or
    /// nullopt when emulation could not reach the dispatch
    std::function<std::optional<std::uint64_t>(ZydisRegister reg)> base_reg_value;
};

/// Resolve an MSVC x64 indexed switch dispatch the faithful, emulator-driven way
/// vivisect does inside its amd64 emulation pass (analysis/generic/switchcase.py
/// getSwitchBase + makeJumpTable). The window ends at the indirect `jmp reg`. The
/// register's base is read from the live emulator (env.base_reg_value), so a
/// path-sensitive base a static scan cannot follow (an imagebase loaded far from
/// the dispatch, past an intervening pop) resolves. The base must equal the image
/// base, and the offset table at image_base + disp is walked sequentially while
/// each rebased entry is probable code. Returns nullopt when the window is not a
/// recognized switch or the base does not resolve to the image base
[[nodiscard]] std::optional<JumpTableTargets>
resolve_switch_jump_table(std::span<const DecodedInsn> window,
                          bool                         is_64bit,
                          const SwitchEnv&             env);

}  // namespace papa::features::extractors::papa_native
