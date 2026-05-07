#pragma once

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <Zydis/Zydis.h>

#include <cstdint>
#include <optional>

namespace papa::features::extractors::papa_native {

// One step backward in time from a register's eventual use to where it was set
struct Definition {
    std::uint64_t                site_va{0};   // VA of the defining instruction
    std::optional<std::uint64_t> value;        // resolved constant when known
};

// Backward scan within fn for the most recent destructive write to target_reg
// preceding call_va.
//
// Returns nullopt when:
//   - call_va is not contained in any basic block of fn
//   - target_reg is ZYDIS_REGISTER_NONE
//   - no destructive write is found before the BB starts
//
// When a write is found:
//   - mov reg, imm           -> Definition{va, imm}
//   - mov reg, [imm32]       -> Definition{va, imm32}
//   - mov reg, [rip+disp]    -> Definition{va, rip + length + disp}
//   - any other destructive  -> Definition{va, nullopt}
//
// Aliasing of partial-width registers is resolved through
// ZydisRegisterGetLargestEnclosing so eax/ax/al all map to rax on x64.
[[nodiscard]] std::optional<Definition>
find_definition(const Function&     fn,
                std::uint64_t       call_va,
                ZydisRegister       target_reg,
                bool                is_64bit) noexcept;

}  // namespace papa::features::extractors::papa_native
