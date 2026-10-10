#pragma once

#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

namespace embedded {

/// One signature pack compiled into the binary as consecutive chunks of its bytes
struct EmbeddedSig {
    std::string_view                  path{};
    std::span<const std::string_view> chunks{};
};

/// The signature packs compiled into the binary, in registry order
[[nodiscard]] std::span<const EmbeddedSig> registry() noexcept;

/// The pack's chunks joined into one buffer
[[nodiscard]] std::vector<std::uint8_t> join(const EmbeddedSig& sig);

}  // namespace embedded

/// A collection of parsed FLIRT trees. make_embedded() returns a fresh set the caller owns
/// and add_from_buffer exists for tests
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

    /// The number of parsed trees currently held
    [[nodiscard]] std::size_t tree_count() const noexcept { return trees_.size(); }

    /// The parsed trees, for diagnostics and introspection
    [[nodiscard]] const std::vector<FlirtTree>& trees() const noexcept { return trees_; }

private:
    std::vector<FlirtTree> trees_;
};

}  // namespace papa::features::extractors::papa_native::flirt
