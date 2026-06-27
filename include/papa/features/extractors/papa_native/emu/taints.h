#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>

namespace papa::features::extractors::papa_native::emu {

// Mask applied to taint values on store and lookup (impemu taintmask). A taint
// and any address within its masked page resolve to the same record.
inline constexpr std::uint64_t kTaintMask = 0xFFFFE000ULL;

// The kind of unknown value a taint stands for.
enum class TaintType : std::uint8_t {
    kUninitReg,   // an uninitialized register at function entry
    kFuncStack,   // an uninitialized stack local / argument slot
    kApiCall,     // the return value of a call to another function
    kImport,      // a value read from an import (IAT) slot
    kDynLib,      // a handle from LoadLibrary / GetModuleHandle
    kDynFunc,     // a function pointer from GetProcAddress
    kOther,
};

// One taint record: the sentinel value, its kind, and a type-specific datum
// (a register index, a stack offset, an import slot VA, etc.).
struct TaintInfo {
    std::uint64_t va{0};
    TaintType     type{TaintType::kOther};
    std::uint64_t info{0};
};

// Allocates sentinel "taint" values and recovers their meaning. Faithful to
// impemu/emulator.py: values come from count(0x4156000F, 0x2000) offset by
// 0x1000 and are keyed by value & taintmask, so near-taint lookups resolve.
// The reserved band is chosen so taints read as non-pointers in a normal image.
class TaintRegistry {
public:
    // Allocate a new taint of the given kind and return its sentinel value.
    std::uint64_t allocate(TaintType type, std::uint64_t info = 0);

    // Recover the taint record for a value (masked), or nothing if not a taint.
    [[nodiscard]] std::optional<TaintInfo> lookup(std::uint64_t va) const;

    [[nodiscard]] std::size_t size() const noexcept { return taints_.size(); }

private:
    std::uint64_t counter_{0x4156000FULL};
    std::unordered_map<std::uint64_t, TaintInfo> taints_;
};

}  // namespace papa::features::extractors::papa_native::emu
