#pragma once

#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

namespace embedded {

/// One compile-time-embedded signature blob. Defined by the generated
/// embedded_sigs.cpp (added in the sig-embedding task)
struct EmbeddedSig {
    std::string_view    name;
    const std::uint8_t* data;
    std::size_t         size;
};

/// The compile-time set of embedded signature blobs
[[nodiscard]] std::span<const EmbeddedSig> registry() noexcept;

}  // namespace embedded

/// A collection of parsed FLIRT trees. The production constructor is
/// make_embedded() and add_from_buffer exists for tests
class FlirtSignatureSet {
public:
    FlirtSignatureSet()                                        = default;
    FlirtSignatureSet(FlirtSignatureSet&&) noexcept            = default;
    FlirtSignatureSet& operator=(FlirtSignatureSet&&) noexcept = default;
    FlirtSignatureSet(const FlirtSignatureSet&)                = delete;
    FlirtSignatureSet& operator=(const FlirtSignatureSet&)     = delete;

    /// Build a set from the compile-time embedded signature registry
    [[nodiscard]] static FlirtSignatureSet make_embedded();

    /// Parse one raw .sig buffer and append its tree. Returns false and logs
    /// once to stderr on any parse failure. Never throws
    [[nodiscard]] bool add_from_buffer(std::span<const std::uint8_t> sig_bytes) noexcept;

    /// True when function_bytes match any loaded tree
    [[nodiscard]] bool classify(std::span<const std::uint8_t> function_bytes) const noexcept;

    /// Every leaf module across all loaded trees that matches function_bytes by pattern
    /// and tail CRC
    [[nodiscard]] std::vector<const FlirtModule*>
    match(std::span<const std::uint8_t> function_bytes) const;

    /// The number of parsed trees currently held
    [[nodiscard]] std::size_t tree_count() const noexcept { return trees_.size(); }

    /// The parsed trees, for diagnostics and introspection
    [[nodiscard]] const std::vector<FlirtTree>& trees() const noexcept { return trees_; }

private:
    std::vector<FlirtTree> trees_;
};

}  // namespace papa::features::extractors::papa_native::flirt
