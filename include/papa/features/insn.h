#pragma once

#include "papa/features/feature.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

namespace papa::features {

// API call or reference
// Default evaluate (structural membership) is sufficient because the extractor
// emits every spelling variant CAPA rules use, including bare and dll-qualified
class Api : public Feature {
public:
    explicit Api(std::string value, std::string desc = {});

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

// Decoded instruction mnemonic stored as its lowercase spelling
class Mnemonic : public Feature {
public:
    explicit Mnemonic(std::string value, std::string desc = {});

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

// Managed-language property access kind
// kNone is reserved for implementations that cannot distinguish read from
// write and therefore must match both
class Property : public Feature {
public:
    enum class Access : std::uint8_t { kNone, kRead, kWrite };

    Property(std::string value, Access access, std::string desc = {});

    [[nodiscard]] const std::string& value()  const noexcept { return value_; }
    [[nodiscard]] Access              access() const noexcept { return access_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
    Access      access_;
};

[[nodiscard]] std::string_view to_string(Property::Access a) noexcept;

// operand[i].number is a Number feature scoped to a specific operand index
// Equality includes the operand index because the same literal value at
// different operand positions represents different feature occurrences
class OperandNumber : public Feature {
public:
    using Value = std::variant<std::uint64_t, std::int64_t, double>;

    OperandNumber(std::size_t index, Value value, std::string desc = {});

    [[nodiscard]] std::size_t     index() const noexcept { return index_; }
    [[nodiscard]] const Value&    value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::size_t index_;
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
    [[nodiscard]] std::string to_string() const override;

private:
    std::size_t  index_;
    std::int64_t value_;
};

}  // namespace papa::features
