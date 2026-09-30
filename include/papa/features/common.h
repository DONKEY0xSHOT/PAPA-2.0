#pragma once

#include "papa/features/feature.h"

#include <cstddef>
#include <cstdint>
#include <regex>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace papa::features {

// Plain string match
// The default evaluate does direct FeatureSet lookup by structural equality
class String : public ValueFeature {
public:
    explicit String(std::string value, std::string desc = {})
        : ValueFeature(FeatureTag::kString, std::move(value), std::move(desc)) {}
};

// Substring scans every String feature in fs and tests find()
class Substring : public ValueFeature {
public:
    explicit Substring(std::string value, std::string desc = {})
        : ValueFeature(FeatureTag::kSubstring, std::move(value), std::move(desc)) {}
    [[nodiscard]] engine::Result evaluate(const FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool matches(const FeatureSet& fs) const override;
};

// Regex runs std::regex_search on every String feature that holds its required literal
class Regex : public ValueFeature {
public:
    explicit Regex(std::string literal, std::string desc = {});
    [[nodiscard]] engine::Result evaluate(const FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool matches(const FeatureSet& fs) const override;

    [[nodiscard]] const std::string& pattern() const noexcept { return pattern_; }
    [[nodiscard]] bool case_insensitive() const noexcept { return case_insensitive_; }

private:
    std::regex  compiled_;
    std::string pattern_;           // pattern body without surrounding slashes or flags
    bool        case_insensitive_{false};
    // CAPA rules are linted against Python's re module which supports a few constructs
    // std::regex does not (named groups, inline flags, possessive quantifiers)
    bool        compiled_ok_{true};
    // A literal every match contains, lowercased when case-insensitive, or empty
    std::string required_;
};

// Bytes matches when self.value is a prefix of any Bytes feature's value
class Bytes : public Feature {
public:
    explicit Bytes(std::vector<std::byte> value, std::string desc = {});

    [[nodiscard]] std::span<const std::byte> value() const noexcept { return value_; }

    [[nodiscard]] engine::Result evaluate(const FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool matches(const FeatureSet& fs) const override;
    [[nodiscard]] std::size_t    hash()   const noexcept override;
    [[nodiscard]] bool           equals(const Feature& o) const noexcept override;

private:
    std::vector<std::byte> value_;
};

// Number supports three literal kinds
// Equality compares the active variant alternative, so 1u64 and 1i64 differ
class Number : public Feature {
public:
    using Value = std::variant<std::uint64_t, std::int64_t, double>;

    explicit Number(Value v, std::string desc = {});

    [[nodiscard]] const Value& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;

protected:
    Number(FeatureTag t, Value v, std::string desc);

    Value value_;
};

// Offset is stored signed because negative struct offsets are valid inputs
class Offset : public Feature {
public:
    explicit Offset(std::int64_t v, std::string desc = {});

    [[nodiscard]] std::int64_t value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;

protected:
    Offset(FeatureTag t, std::int64_t v, std::string desc);

    std::int64_t value_;
};

// MatchedRule is injected into FeatureSet after a rule matches
// The default evaluate suffices because later rules reference the name directly
class MatchedRule : public ValueFeature {
public:
    explicit MatchedRule(std::string name, std::string desc = {})
        : ValueFeature(FeatureTag::kMatchedRule, std::move(name), std::move(desc)) {}
    [[nodiscard]] const std::string& rule_name() const noexcept { return value(); }
};

// Characteristic is a named string tag such as "loop" or "stack string"
class Characteristic : public ValueFeature {
public:
    explicit Characteristic(std::string v, std::string desc = {})
        : ValueFeature(FeatureTag::kCharacteristic, std::move(v), std::move(desc)) {}
};

// Class and Namespace are value-typed like Characteristic
// Default evaluate suffices because the extractor emits the exact rule spelling
class Class : public ValueFeature {
public:
    explicit Class(std::string v, std::string desc = {})
        : ValueFeature(FeatureTag::kClass, std::move(v), std::move(desc)) {}
};

class Namespace : public ValueFeature {
public:
    explicit Namespace(std::string v, std::string desc = {})
        : ValueFeature(FeatureTag::kNamespace, std::move(v), std::move(desc)) {}
};

// Os treats "any" as a wildcard in either the rule or the feature set, as capa does
class Os : public ValueFeature {
public:
    explicit Os(std::string v, std::string desc = {})
        : ValueFeature(FeatureTag::kOs, std::move(v), std::move(desc)) {}
    [[nodiscard]] engine::Result evaluate(const FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool matches(const FeatureSet& fs) const override;
};

// Arch matches only an equal value, so arch: any matches only a literal any, as in capa
class Arch : public ValueFeature {
public:
    explicit Arch(std::string v, std::string desc = {})
        : ValueFeature(FeatureTag::kArch, std::move(v), std::move(desc)) {}
};

class Format : public ValueFeature {
public:
    explicit Format(std::string v, std::string desc = {})
        : ValueFeature(FeatureTag::kFormat, std::move(v), std::move(desc)) {}
};

}  // namespace papa::features
