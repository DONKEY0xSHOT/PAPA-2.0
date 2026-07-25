#pragma once

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/flirt/flirt_format.h"
#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace papa::features::extractors::papa_native::flirt {

/// Returns the on-disk header size in bytes for a supported version,
/// counted up to but not including the variable-length library name
[[nodiscard]] std::size_t header_size_for_version(std::uint8_t version) noexcept;

/// Parse the IDASGN header from the start of `data`.
///
/// Validates magic and version range. Reads optional v9+ and v10+
/// fields conditionally on the version byte. Consumes the variable-
/// length library_name when library_name_len > 0.
///
/// Returns:
///   kFlirtTruncated         when the buffer is shorter than required
///   kFlirtBadMagic          when the first 6 bytes are not "IDASGN"
///   kFlirtUnsupportedVersion when the version is outside [v8, v10]
[[nodiscard]] Expected<FlirtHeader> parse_header(
    std::span<const std::uint8_t> data) noexcept;

/// Parse a complete .sig buffer (header + body) into a FlirtTree.
/// Decompresses the body when the header compression bit is set.
/// Returns kFlirtTruncated / kFlirtBadNode / kFlirtTooDeep on malformed
/// input. Never throws
[[nodiscard]] Expected<FlirtTree> parse_sig_buffer(
    std::span<const std::uint8_t> sig) noexcept;

}  // namespace papa::features::extractors::papa_native::flirt
