#pragma once

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace papa::features::extractors::papa_native {

/// Library-function detector matching CAPA's inputs: a structural thunk check
/// plus FLIRT signature matching over the embedded IDASGN set.
class LibrarySignatureSet {
public:
    /// Build a detector populated with the embedded FLIRT signatures.
    [[nodiscard]] static LibrarySignatureSet make_default();

    /// True when fn is structurally a thunk: a single basic block whose one
    /// instruction is an unconditional jmp or call through a memory operand.
    [[nodiscard]] static bool is_thunk(const Function& fn) noexcept;

    /// True when fn should be treated as library code. function_bytes are the
    /// contiguous bytes starting at fn.va (pattern plus CRC tail window).
    [[nodiscard]] bool classify_as_library(
        const Function& fn,
        std::span<const std::uint8_t> function_bytes) const noexcept;

    /// The number of parsed FLIRT trees backing this detector.
    [[nodiscard]] std::size_t flirt_tree_count() const noexcept {
        return flirt_.tree_count();
    }

    /// The FLIRT signature set, for the reference-validating library classifier.
    [[nodiscard]] const flirt::FlirtSignatureSet& flirt() const noexcept {
        return flirt_;
    }

private:
    flirt::FlirtSignatureSet flirt_;
};

}  // namespace papa::features::extractors::papa_native
