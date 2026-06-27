#include "papa/features/extractors/papa_native/emu/taints.h"

namespace papa::features::extractors::papa_native::emu {

std::uint64_t TaintRegistry::allocate(TaintType type, std::uint64_t info) {
    // nextVivTaint: one page into the new taint range.
    const std::uint64_t va = counter_ + 0x1000ULL;
    counter_ += 0x2000ULL;
    taints_[va & kTaintMask] = TaintInfo{va, type, info};
    return va;
}

std::optional<TaintInfo> TaintRegistry::lookup(std::uint64_t va) const {
    const auto it = taints_.find(va & kTaintMask);
    if (it == taints_.end()) {
        return std::nullopt;
    }
    return it->second;
}

}  // namespace papa::features::extractors::papa_native::emu
