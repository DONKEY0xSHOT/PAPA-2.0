#include "papa/features/insn.h"

#include "papa/features/common.h"
#include "papa/util/hashing.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <variant>

namespace papa::features {

// Property
Property::Property(std::string value, Access access, std::string desc)
    : Feature(FeatureTag::kProperty, std::move(desc)),
      value_(std::move(value)),
      access_(access) {}

std::size_t Property::hash() const noexcept {
    std::size_t h = std::hash<std::string>{}(value_);
    h = util::hashing::hash_combine(h, static_cast<std::size_t>(access_));
    return mix_tag(tag_, h);
}

bool Property::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kProperty) { return false; }
    const auto& rhs = static_cast<const Property&>(o);
    return access_ == rhs.access_ && value_ == rhs.value_;
}

// OperandNumber
OperandNumber::OperandNumber(std::size_t index, Value value, std::string desc)
    : Feature(FeatureTag::kOperandNumber, std::move(desc)),
      index_(index),
      value_(std::move(value)) {}

std::size_t OperandNumber::hash() const noexcept {
    std::size_t h = std::hash<std::size_t>{}(index_);
    h = util::hashing::hash_combine(h, hash_number_value(value_));
    return mix_tag(tag_, h);
}

bool OperandNumber::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kOperandNumber) { return false; }
    const auto& rhs = static_cast<const OperandNumber&>(o);
    return index_ == rhs.index_ && number_values_equal(value_, rhs.value_);
}

// OperandOffset
OperandOffset::OperandOffset(std::size_t index, std::int64_t value, std::string desc)
    : Feature(FeatureTag::kOperandOffset, std::move(desc)),
      index_(index),
      value_(value) {}

std::size_t OperandOffset::hash() const noexcept {
    std::size_t h = std::hash<std::size_t>{}(index_);
    h = util::hashing::hash_combine(h, std::hash<std::int64_t>{}(value_));
    return mix_tag(tag_, h);
}

bool OperandOffset::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kOperandOffset) { return false; }
    const auto& rhs = static_cast<const OperandOffset&>(o);
    return index_ == rhs.index_ && value_ == rhs.value_;
}

}  // namespace papa::features
