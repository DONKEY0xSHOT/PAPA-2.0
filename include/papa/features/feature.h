#pragma once

#include "papa/features/address.h"
#include "papa/util/hashing.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
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

/// Map from a structurally-identified feature to the locations where it occurred,
/// with indices that let scanning evaluators iterate just the relevant tag
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

    /// Add every (feature, address) pair, sharing the feature objects with the caller
    void add_all(std::span<const std::pair<FeaturePtr, Address>> batch);

    /// Add every pair of a batch the caller hands over, moving its feature pointers
    void add_all(std::vector<std::pair<FeaturePtr, Address>>&& batch);

    /// Snapshot of all String features ever inserted into this set
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

// Abstract base for every concrete feature type. Subclasses must implement hash
// and equals
class Feature {
public:
    virtual ~Feature() = default;

    [[nodiscard]] FeatureTag         tag()         const noexcept { return tag_; }
    [[nodiscard]] const std::string& description() const noexcept { return description_; }

    // Membership check plus subclass-specific semantic matching. Default implementation
    // looks self up in the FeatureSet by structural equality
    [[nodiscard]] virtual engine::Result evaluate(const FeatureSet& fs,
                                                  bool short_circuit) const;

    // Boolean form of evaluate for the probe pass
    [[nodiscard]] virtual bool matches(const FeatureSet& fs) const;

    // Structural hash
    // Implementations must guarantee that equal features always hash equal
    [[nodiscard]] virtual std::size_t hash() const noexcept = 0;

    // Structural equality ignoring description field
    [[nodiscard]] virtual bool equals(const Feature& other) const noexcept = 0;

protected:
    Feature(FeatureTag t, std::string desc) : tag_(t), description_(std::move(desc)) {}

    // Fold the tag into a payload hash so kinds with identical payloads hash apart
    [[nodiscard]] static constexpr std::size_t mix_tag(FeatureTag  t,
                                                       std::size_t h) noexcept {
        return util::hashing::hash_combine(static_cast<std::size_t>(t), h);
    }

    FeatureTag  tag_;
    std::string description_;
};

/// A feature whose payload is one string, equal when both tag and value match
class ValueFeature : public Feature {
public:
    [[nodiscard]] const std::string& value() const noexcept { return value_; }

    [[nodiscard]] std::size_t hash()   const noexcept override;
    [[nodiscard]] bool        equals(const Feature& o) const noexcept override;

protected:
    ValueFeature(FeatureTag t, std::string value, std::string desc)
        : Feature(t, std::move(desc)), value_(std::move(value)) {}

    std::string value_;
};

}  // namespace papa::features
