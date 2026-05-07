#pragma once

#include "papa/features/feature.h"

#include <cstddef>
#include <string>

namespace papa::features {

// Zero-arity tag feature
// Extractors inject one per basic block so rules can quantify over basic
// blocks without caring about any specific attribute of the block
// Two BasicBlock instances are always equal because they carry no payload
class BasicBlock : public Feature {
public:
    explicit BasicBlock(std::string desc = {});

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;
};

}  // namespace papa::features
