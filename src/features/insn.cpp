#include "papa/features/insn.h"

#include "papa/util/hashing.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace papa::features {

namespace {

// Shared tag-mix used by every hash() override in this translation unit
std::size_t mix_tag(FeatureTag t, std::size_t h) noexcept {
    return util::hashing::hash_combine(static_cast<std::size_t>(t), h);
}

// Hash an OperandNumber::Value variant and fold in its active alternative
// index so the distinct zero values 0u64, 0i64, and 0.0 hash apart
std::size_t hash_number_variant(const OperandNumber::Value& v) noexcept {
    const std::size_t payload = std::visit([](auto x) noexcept -> std::size_t {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, double>) {
            return util::hashing::hash_double_bits(x);
        } else {
            return std::hash<T>{}(x);
        }
    }, v);
    return util::hashing::hash_combine(payload, v.index());
}

}  // namespace

// Api
Api::Api(std::string value, std::string desc)
    : Feature(FeatureTag::kApi, std::move(desc)),
      value_(std::move(value)) {}

std::size_t Api::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Api::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kApi) { return false; }
    const auto& rhs = static_cast<const Api&>(o);
    return value_ == rhs.value_;
}

// Mnemonic
Mnemonic::Mnemonic(std::string value, std::string desc)
    : Feature(FeatureTag::kMnemonic, std::move(desc)),
      value_(std::move(value)) {}

std::size_t Mnemonic::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Mnemonic::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kMnemonic) { return false; }
    const auto& rhs = static_cast<const Mnemonic&>(o);
    return value_ == rhs.value_;
}

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
    h = util::hashing::hash_combine(h, hash_number_variant(value_));
    return mix_tag(tag_, h);
}

bool OperandNumber::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kOperandNumber) { return false; }
    const auto& rhs = static_cast<const OperandNumber&>(o);
    return index_ == rhs.index_ && value_ == rhs.value_;
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
