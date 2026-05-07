#pragma once

#include "papa/features/feature.h"

#include <cstddef>
#include <string>

namespace papa::features {

// File-scope features
// Default evaluate (structural membership) is correct for all of them because
// the extractor emits the exact spelling a rule references

// Imported symbol name
// By CAPA convention this is "<dll>.<symbol>" with dll lowercased and extension
// stripped, or "<dll>.#<ordinal>" for by-ordinal imports
class Import : public Feature {
public:
    explicit Import(std::string value, std::string desc = {});

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

// Exported symbol name
class Export : public Feature {
public:
    explicit Export(std::string value, std::string desc = {});

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

// PE section name stored as the null-trimmed UTF-8 form of the 8-byte field
class Section : public Feature {
public:
    explicit Section(std::string value, std::string desc = {});

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

// Function name known from symbols, PDB, or generator heuristics
class FunctionName : public Feature {
public:
    explicit FunctionName(std::string value, std::string desc = {});

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;
    [[nodiscard]] std::string to_string() const override;

private:
    std::string value_;
};

}  // namespace papa::features
