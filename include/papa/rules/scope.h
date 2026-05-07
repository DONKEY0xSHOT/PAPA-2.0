#pragma once

#include <cstdint>
#include <string_view>

namespace papa::rules {

// Matching scope
// A rule file may declare a static scope and optionally a dynamic one
enum class Scope : std::uint8_t {
    kFile,
    kFunction,
    kBasicBlock,
    kInstruction,
    kGlobal,
    kProcess,
    kThread,
    kCall,
    kSpanOfCalls,
};

[[nodiscard]] std::string_view to_string(Scope s) noexcept;

}  // namespace papa::rules
