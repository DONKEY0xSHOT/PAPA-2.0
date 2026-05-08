#pragma once

#include "papa/features/extractors/papa_native/cfg.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace papa::features::extractors::papa_native {

/// One pattern entry in the prologue signature table.
/// bytes[i] holds either the required byte value or std::nullopt for a wildcard.
struct PrologueSignature {
    std::string                                 name;
    std::vector<std::optional<std::uint8_t>>    bytes;
};

/// Lightweight library-function detector.
///
/// Two complementary mechanisms run for every function:
///   1. A structural thunk check that flags single-block functions whose
///      single instruction is an unconditional JMP or CALL through an IAT
///      slot. Such functions are forwarders by construction.
///   2. A prologue-pattern matcher driven by hand-curated signatures for
///      well-known MSVC CRT helpers. Each signature is a sequence of bytes
///      with wildcards on positions that hold relocation-affected displacements.
///
/// This is a pragmatic subset of FLIRT (no CRC tail, no symbol tables).
/// It closes the false-positive cases CAPA's FLIRT integration suppresses
/// for typical MSVC PE samples without dragging in the full FLIRT runtime.
class LibrarySignatureSet {
public:
    /// Build a detector populated with the bundled MSVC CRT signature subset.
    [[nodiscard]] static LibrarySignatureSet make_default();

    /// Replace the signature table with caller-supplied entries.
    /// Useful for tests and for users who want a custom signature pack.
    void set_signatures(std::vector<PrologueSignature> sigs) noexcept;

    [[nodiscard]] std::span<const PrologueSignature>
    signatures() const noexcept { return signatures_; }

    /// True when fn is structurally a thunk: one basic block whose single
    /// instruction is an unconditional jmp or call through a memory operand.
    [[nodiscard]] static bool is_thunk(const Function& fn) noexcept;

    /// True when fn's prologue bytes match any signature in the table.
    /// prologue_bytes should hold the contiguous bytes starting at fn.va.
    [[nodiscard]] bool
    matches_signature(std::span<const std::uint8_t> prologue_bytes) const noexcept;

    /// Combined entry point used by PapaNativeStaticExtractor.
    /// Returns true when the function should be treated as library code.
    [[nodiscard]] bool
    classify_as_library(const Function&                fn,
                        std::span<const std::uint8_t>  prologue_bytes) const noexcept;

private:
    std::vector<PrologueSignature>  signatures_;
};

/// Parse a single signature entry from the textual format used by the
/// bundled signature table. Each entry has the shape:
///   name: <human-readable name>
///   bytes: AA BB ?? CC DD ??
/// Bytes are space-separated two-character hex pairs; "??" denotes a wildcard.
/// Returns nullopt when the input is malformed.
[[nodiscard]] std::optional<PrologueSignature>
parse_signature_entry(std::string_view name, std::string_view byte_pattern);

}  // namespace papa::features::extractors::papa_native
