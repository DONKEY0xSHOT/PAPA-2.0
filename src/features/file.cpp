#include "papa/features/file.h"

#include "papa/util/hashing.h"

#include <cstddef>
#include <functional>
#include <string>
#include <utility>

namespace papa::features {

namespace {

// Shared tag-mix so features of different kinds but matching payload bytes
// never alias into the same FeatureSet bucket
std::size_t mix_tag(FeatureTag t, std::size_t h) noexcept {
    return util::hashing::hash_combine(static_cast<std::size_t>(t), h);
}

}  // namespace

// Import
Import::Import(std::string value, std::string desc)
    : Feature(FeatureTag::kImport, "import", std::move(desc)),
      value_(std::move(value)) {}

std::size_t Import::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Import::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kImport) { return false; }
    const auto& rhs = static_cast<const Import&>(o);
    return value_ == rhs.value_;
}

std::string Import::to_string() const {
    return "import(" + value_ + ")";
}

// Export
Export::Export(std::string value, std::string desc)
    : Feature(FeatureTag::kExport, "export", std::move(desc)),
      value_(std::move(value)) {}

std::size_t Export::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Export::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kExport) { return false; }
    const auto& rhs = static_cast<const Export&>(o);
    return value_ == rhs.value_;
}

std::string Export::to_string() const {
    return "export(" + value_ + ")";
}

// Section
Section::Section(std::string value, std::string desc)
    : Feature(FeatureTag::kSection, "section", std::move(desc)),
      value_(std::move(value)) {}

std::size_t Section::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Section::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kSection) { return false; }
    const auto& rhs = static_cast<const Section&>(o);
    return value_ == rhs.value_;
}

std::string Section::to_string() const {
    return "section(" + value_ + ")";
}

// FunctionName
FunctionName::FunctionName(std::string value, std::string desc)
    : Feature(FeatureTag::kFunctionName, "function-name", std::move(desc)),
      value_(std::move(value)) {}

std::size_t FunctionName::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool FunctionName::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kFunctionName) { return false; }
    const auto& rhs = static_cast<const FunctionName&>(o);
    return value_ == rhs.value_;
}

std::string FunctionName::to_string() const {
    return "function-name(" + value_ + ")";
}

}  // namespace papa::features
