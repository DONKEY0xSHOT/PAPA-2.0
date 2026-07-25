#pragma once

#include <cstdint>

namespace papa::features::extractors::papa_native::viv {

// vivisect envi BR_* branch flags (envi/__init__.py:346-351). They are carried
// on a recorded code cross-reference and consumed by the codeflow and codeblocks
// passes, so they live in one shared place
inline constexpr std::uint16_t kBrProc  = 1U << 0;  // a call target
inline constexpr std::uint16_t kBrCond  = 1U << 1;  // a conditional branch
inline constexpr std::uint16_t kBrDeref = 1U << 2;  // target is dereferenced into PC
inline constexpr std::uint16_t kBrTable = 1U << 3;  // base of a jump-table pointer array
inline constexpr std::uint16_t kBrFall  = 1U << 4;  // fall-through to the next instruction

}  // namespace papa::features::extractors::papa_native::viv
