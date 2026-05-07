#include "papa/features/insn.h"

#include "papa/util/hashing.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <sstream>
#include <string>
#include <string_view>
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
    : Feature(FeatureTag::kApi, "api", std::move(desc)),
      value_(std::move(value)) {}

std::size_t Api::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Api::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kApi) { return false; }
    const auto& rhs = static_cast<const Api&>(o);
    return value_ == rhs.value_;
}

std::string Api::to_string() const {
    return "api(" + value_ + ")";
}

// Mnemonic
Mnemonic::Mnemonic(std::string value, std::string desc)
    : Feature(FeatureTag::kMnemonic, "mnemonic", std::move(desc)),
      value_(std::move(value)) {}

std::size_t Mnemonic::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Mnemonic::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kMnemonic) { return false; }
    const auto& rhs = static_cast<const Mnemonic&>(o);
    return value_ == rhs.value_;
}

std::string Mnemonic::to_string() const {
    return "mnemonic(" + value_ + ")";
}

// Property
std::string_view to_string(Property::Access a) noexcept {
    switch (a) {
        case Property::Access::kNone:  return "none";
        case Property::Access::kRead:  return "read";
        case Property::Access::kWrite: return "write";
    }
    return "unknown";
}

Property::Property(std::string value, Access access, std::string desc)
    : Feature(FeatureTag::kProperty, "property", std::move(desc)),
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

std::string Property::to_string() const {
    std::string out;
    out.reserve(value_.size() + 16);
    out.append("property/");
    // Fully qualify to reach the free function overload
    // The unqualified name resolves to this very member and would be a
    // no-argument ambiguity at the call site
    out.append(::papa::features::to_string(access_));
    out.append("(");
    out.append(value_);
    out.append(")");
    return out;
}

// OperandNumber
OperandNumber::OperandNumber(std::size_t index, Value value, std::string desc)
    : Feature(FeatureTag::kOperandNumber, "operand.number", std::move(desc)),
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

std::string OperandNumber::to_string() const {
    std::ostringstream os;
    os << "operand[" << index_ << "].number(";
    std::visit([&os](auto v) { os << v; }, value_);
    os << ')';
    return os.str();
}

// OperandOffset
OperandOffset::OperandOffset(std::size_t index, std::int64_t value, std::string desc)
    : Feature(FeatureTag::kOperandOffset, "operand.offset", std::move(desc)),
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

std::string OperandOffset::to_string() const {
    std::ostringstream os;
    os << "operand[" << index_ << "].offset(" << value_ << ')';
    return os.str();
}

}  // namespace papa::features
