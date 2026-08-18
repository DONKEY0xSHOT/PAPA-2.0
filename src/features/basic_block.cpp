#include "papa/features/basic_block.h"

#include "papa/util/hashing.h"

#include <cstddef>
#include <string>
#include <utility>

namespace papa::features {

BasicBlock::BasicBlock(std::string desc)
    : Feature(FeatureTag::kBasicBlock, "basic block", std::move(desc)) {}

std::size_t BasicBlock::hash() const noexcept {
    // Tag-only payload. Multiply the tag by the golden-ratio constant so the resulting
    // seed mixes well when combined with neighboring hashes in a FeatureSet
    return static_cast<std::size_t>(tag_) *
           static_cast<std::size_t>(util::hashing::kGoldenRatio64);
}

bool BasicBlock::equals(const Feature& o) const noexcept {
    return o.tag() == FeatureTag::kBasicBlock;
}

std::string BasicBlock::to_string() const {
    return "basic block";
}

}  // namespace papa::features
