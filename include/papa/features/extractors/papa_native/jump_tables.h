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
/// not code, so a recovery pass must not disassemble inside that region.
struct JumpTableTargets {
    std::vector<std::uint64_t> targets;
    std::uint64_t              table_va{0};
    std::uint64_t              table_size{0};
};

/// Reads a little-endian 32-bit jump-table entry at a virtual address, or
/// nullopt when the address is not mapped.
using TableReader = std::function<std::optional<std::uint32_t>(std::uint64_t va)>;

/// Recognize the dominant MSVC x64 indexed-jump idiom in a straight-line
/// instruction window ending at an indirect `jmp reg`, and resolve its
/// switch-case targets.
///
/// The window is in ascending program order with the indirect jump as its last
/// element. The idiom is
///   cmp idx, N / ja default / movsxd i, idx / lea base, [rip+B] /
///   mov off, [base + i*4 + T] / add tgt, base / jmp tgt
/// where the table at base+T holds 32-bit image-base-relative offsets and each
/// target is base + entry. Targets are accepted only inside [range_lo,
/// range_hi); resolution stops at the count bound N or the first entry outside
/// the range, whichever comes first. Returns nullopt when the window does not
/// match the idiom.
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
/// indexed memory-indirect jump with a constant table address.
[[nodiscard]] std::optional<JumpTableTargets>
resolve_memory_indirect_jump_table(const DecodedInsn& jmp_insn,
                                   std::uint64_t      range_lo,
                                   std::uint64_t      range_hi,
                                   const TableReader& read_u32);

}  // namespace papa::features::extractors::papa_native
