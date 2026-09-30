#pragma once

#include "papa/features/feature.h"

#include <string>
#include <utility>

namespace papa::features {

// File-scope features. Default evaluate (structural membership) is correct for all of
// them because the extractor emits the exact spelling a rule references

// Imported symbol name. By CAPA convention this is "<dll>.<symbol>" with dll lowercased
// and extension stripped, or "<dll>.#<ordinal>" for by-ordinal imports
class Import : public ValueFeature {
public:
    explicit Import(std::string value, std::string desc = {})
        : ValueFeature(FeatureTag::kImport, std::move(value), std::move(desc)) {}
};

// Exported symbol name
class Export : public ValueFeature {
public:
    explicit Export(std::string value, std::string desc = {})
        : ValueFeature(FeatureTag::kExport, std::move(value), std::move(desc)) {}
};

// PE section name stored as the null-trimmed UTF-8 form of the 8-byte field
class Section : public ValueFeature {
public:
    explicit Section(std::string value, std::string desc = {})
        : ValueFeature(FeatureTag::kSection, std::move(value), std::move(desc)) {}
};

// Function name known from symbols, PDB, or generator heuristics
class FunctionName : public ValueFeature {
public:
    explicit FunctionName(std::string value, std::string desc = {})
        : ValueFeature(FeatureTag::kFunctionName, std::move(value), std::move(desc)) {}
};

}  // namespace papa::features
