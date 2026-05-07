#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace papa::features::extractors::helpers {

// Lowercase the DLL name and strip a trailing .dll, .drv, or .so suffix
// Used to canonicalize import names so rule lookups match every common spelling
[[nodiscard]] std::string normalize_dll_name(std::string_view dll);

// Strip a trailing 'A' or 'W' from an exported symbol name when one exists
// Returns the stripped base name when the suffix was present, std::nullopt otherwise
// CAPA uses this to expose both ANSI and wide variants of common Win32 APIs
[[nodiscard]] std::optional<std::string_view> strip_aw_suffix(std::string_view symbol);

// Generate every symbol spelling a rule may reference for one (dll, symbol) pair
// The output list always contains symbol itself and, when include_dll is true,
// the dotted "<dll>.<symbol>" form. Names ending in 'A' or 'W' contribute a
// stripped variant so a single rule line can match both PostMessage and PostMessageA
[[nodiscard]] std::vector<std::string>
generate_symbols(std::string_view dll, std::string_view symbol, bool include_dll);

// Reformat a forwarded export string from "MODULE.Func" to "module.Func"
// The module portion is lowercased and the symbol is preserved
// When the input lacks a dot the original is returned unchanged
[[nodiscard]] std::string reformat_forwarded_export_name(std::string_view forwarder);

// Search buf for embedded PE files
// Both plain and single-byte XOR-keyed PE images are detected by re-applying
// the candidate key to the lfanew field and the NT signature
// Returns the absolute byte offsets of every match in increasing order
[[nodiscard]] std::vector<std::uint64_t>
carve_pe_files(std::span<const std::byte> buf);

}  // namespace papa::features::extractors::helpers
