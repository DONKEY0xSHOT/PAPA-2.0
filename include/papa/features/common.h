#pragma once

#include "papa/features/feature.h"

#include <cstddef>
#include <cstdint>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace papa::features {

// Plain string match
// The default evaluate does direct FeatureSet lookup by structural equality
class String : public Feature {
public:
    explicit String(std::string value, std::string desc = {});

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

protected:
    // Constructor used by Substring and Regex so subclasses share value_
    // without redeclaring the same field in every derived class
    String(FeatureTag t, std::string_view tname, std::string value, std::string desc);

    std::string value_;
};

// Substring scans every String feature in fs and tests find()
class Substring : public String {
public:
    explicit Substring(std::string value, std::string desc = {});
    [[nodiscard]] engine::Result evaluate(const FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool matches(const FeatureSet& fs) const override;
};

// Regex scans every String feature in fs via std::regex_search
class Regex : public String {
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
    [[nodiscard]] std::string    to_string() const override;

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
    [[nodiscard]] std::string to_string() const override;

protected:
    Number(FeatureTag t, std::string_view tname, Value v, std::string desc);

    Value value_;
};

// Offset is stored signed because negative struct offsets are valid inputs
class Offset : public Feature {
public:
    explicit Offset(std::int64_t v, std::string desc = {});

    [[nodiscard]] std::int64_t value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

protected:
    Offset(FeatureTag t, std::string_view tname, std::int64_t v, std::string desc);

    std::int64_t value_;
};

// MatchedRule is injected into FeatureSet after a rule matches
// The default evaluate suffices because later rules reference the name directly
class MatchedRule : public Feature {
public:
    explicit MatchedRule(std::string name, std::string desc = {});
    [[nodiscard]] const std::string& rule_name() const noexcept { return name_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string name_;
};

// Characteristic is a named string tag such as "loop" or "stack string"
class Characteristic : public Feature {
public:
    explicit Characteristic(std::string v, std::string desc = {});
    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

// Class and Namespace are value-typed like Characteristic
// Default evaluate suffices because the extractor emits the exact rule spelling
class Class : public Feature {
public:
    explicit Class(std::string v, std::string desc = {});
    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

class Namespace : public Feature {
public:
    explicit Namespace(std::string v, std::string desc = {});
    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

// Os, Arch, and Format support "any" as a wildcard in either the rule
// or the feature set, mirroring CAPA's bidirectional wildcard semantics
class Os : public Feature {
public:
    explicit Os(std::string v, std::string desc = {});
    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] engine::Result evaluate(const FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool matches(const FeatureSet& fs) const override;
    [[nodiscard]] std::size_t    hash()   const noexcept override;
    [[nodiscard]] bool           equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string    to_string() const override;

private:
    std::string value_;
};

class Arch : public Feature {
public:
    explicit Arch(std::string v, std::string desc = {});
    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] engine::Result evaluate(const FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool matches(const FeatureSet& fs) const override;
    [[nodiscard]] std::size_t    hash()   const noexcept override;
    [[nodiscard]] bool           equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string    to_string() const override;

private:
    std::string value_;
};

class Format : public Feature {
public:
    explicit Format(std::string v, std::string desc = {});
    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

}  // namespace papa::features
