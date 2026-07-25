#pragma once

#include "papa/features/address.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Forward-declare engine::Result to break the cycle with engine.h
namespace papa::engine {
struct Result;
}  // namespace papa::engine

namespace papa::features {

// Identifier for every feature kind
// Enables O(1) typing without dynamic_cast or RTTI
enum class FeatureTag : std::uint8_t {
    kString,
    kSubstring,
    kRegex,
    kBytes,
    kNumber,
    kOffset,
    kMnemonic,
    kApi,
    kImport,
    kExport,
    kSection,
    kFunctionName,
    kClass,
    kNamespace,
    kProperty,
    kCharacteristic,
    kMatchedRule,
    kOs,
    kArch,
    kFormat,
    kOperandNumber,
    kOperandOffset,
    kBasicBlock,
};

[[nodiscard]] std::string_view to_string(FeatureTag t) noexcept;

// Forward declarations so FeatureSet can be defined before Feature
class Feature;
using FeaturePtr = std::shared_ptr<const Feature>;

// Functor bodies are out-of-line in feature.cpp because they deref Feature
struct FeatureHashKey {
    std::size_t operator()(const FeaturePtr& p) const noexcept;
};

struct FeatureEqKey {
    bool operator()(const FeaturePtr& a, const FeaturePtr& b) const noexcept;
};

/// Map from a structurally-identified feature to the set of locations where
/// it occurred, with auxiliary indices that let scanning evaluators (Substring,
/// Regex, Bytes) iterate just the relevant tag without traversing the whole map
class FeatureSet
    : public std::unordered_map<FeaturePtr,
                                std::unordered_set<Address>,
                                FeatureHashKey,
                                FeatureEqKey> {
public:
    using base = std::unordered_map<FeaturePtr,
                                    std::unordered_set<Address>,
                                    FeatureHashKey,
                                    FeatureEqKey>;
    using base::base;

    void add(FeaturePtr f, const Address& a);
    void merge_in(const FeatureSet& other);

    /// Snapshot of all String features ever inserted into this set
    /// Maintained as add() runs so substring and regex evaluators can iterate
    /// just the strings instead of every feature in the map
    [[nodiscard]] const std::vector<FeaturePtr>& strings() const noexcept {
        return strings_;
    }

    /// Snapshot of all Bytes features ever inserted (used by Bytes::evaluate)
    [[nodiscard]] const std::vector<FeaturePtr>& bytes_features() const noexcept {
        return bytes_;
    }

private:
    std::vector<FeaturePtr> strings_;
    std::vector<FeaturePtr> bytes_;
};

// Abstract base for every concrete feature type
// Subclasses must implement hash, equals, and to_string
// They may override evaluate to add scanning or wildcard semantics
class Feature {
public:
    virtual ~Feature() = default;

    [[nodiscard]] FeatureTag         tag()         const noexcept { return tag_; }
    [[nodiscard]] std::string_view   type_name()   const noexcept { return type_name_; }
    [[nodiscard]] const std::string& description() const noexcept { return description_; }

    // Membership check plus subclass-specific semantic matching
    // Default implementation looks self up in the FeatureSet by structural equality
    // Subclasses override when they must scan the set (substring, regex, bytes, wildcards)
    [[nodiscard]] virtual engine::Result evaluate(const FeatureSet& fs,
                                                  bool short_circuit) const;

    // Structural hash
    // Implementations must guarantee that equal features always hash equal
    [[nodiscard]] virtual std::size_t hash() const noexcept = 0;

    // Structural equality ignoring description field
    [[nodiscard]] virtual bool equals(const Feature& other) const noexcept = 0;

    // Display form used by renderers and diagnostics
    [[nodiscard]] virtual std::string to_string() const = 0;

protected:
    Feature(FeatureTag t, std::string_view tname, std::string desc)
        : tag_(t), type_name_(tname), description_(std::move(desc)) {}

    FeatureTag       tag_;
    std::string_view type_name_;        // points at a static literal, never owned
    std::string      description_;
};

}  // namespace papa::features
