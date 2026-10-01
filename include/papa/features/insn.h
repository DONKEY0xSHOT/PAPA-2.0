#pragma once

#include "papa/features/feature.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace papa::features {

// API call or reference
class Api : public ValueFeature {
public:
    explicit Api(std::string value, std::string desc = {})
        : ValueFeature(FeatureTag::kApi, std::move(value), std::move(desc)) {}
};

// Decoded instruction mnemonic stored as its lowercase spelling
class Mnemonic : public ValueFeature {
public:
    explicit Mnemonic(std::string value, std::string desc = {})
        : ValueFeature(FeatureTag::kMnemonic, std::move(value), std::move(desc)) {}
};

// Managed-language property access kind. kNone is reserved for implementations that
// cannot distinguish read from write and therefore must match both
class Property : public Feature {
public:
    enum class Access : std::uint8_t { kNone, kRead, kWrite };

    Property(std::string value, Access access, std::string desc = {});

    [[nodiscard]] const std::string& value()  const noexcept { return value_; }
    [[nodiscard]] Access              access() const noexcept { return access_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;

private:
    std::string value_;
    Access      access_{Access::kNone};
};

// operand[i].number is a Number feature scoped to a specific operand index
class OperandNumber : public Feature {
public:
    using Value = std::variant<std::uint64_t, std::int64_t, double>;

    OperandNumber(std::size_t index, Value value, std::string desc = {});

    [[nodiscard]] std::size_t     index() const noexcept { return index_; }
    [[nodiscard]] const Value&    value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;

private:
    std::size_t index_{0};
    Value       value_;
};

// operand[i].offset uses the same indexed-equality contract as OperandNumber
class OperandOffset : public Feature {
public:
    OperandOffset(std::size_t index, std::int64_t value, std::string desc = {});

    [[nodiscard]] std::size_t   index() const noexcept { return index_; }
    [[nodiscard]] std::int64_t  value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;

private:
    std::size_t  index_{0};
    std::int64_t value_{0};
};

}  // namespace papa::features
