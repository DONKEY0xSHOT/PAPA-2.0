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

/// The most recent destructive write to target_reg before call_va, found by scanning
/// back through its basic block
[[nodiscard]] std::optional<Definition>
find_definition(const Function&     fn,
                std::uint64_t       call_va,
                ZydisRegister       target_reg,
                bool                is_64bit) noexcept;

}  // namespace papa::features::extractors::papa_native
