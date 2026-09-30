#pragma once

#include "papa/features/extractors/papa_native/cfg.h"

namespace papa::features::extractors::papa_native {

/// True when fn is structurally a thunk: a single basic block whose one
/// instruction is an unconditional jmp or call through a memory operand
[[nodiscard]] bool is_thunk(const Function& fn) noexcept;

}  // namespace papa::features::extractors::papa_native
