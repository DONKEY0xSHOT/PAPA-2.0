#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace papa::pe {

/// Resolve an ordinal-imported symbol to its name for the DLLs that are
/// frequently linked by ordinal without symbol info, the way vivisect's
/// ordlookup database does (ws2_32 / wsock32 / oleaut32). `dll` is the
/// normalized module name (lowercased, extension stripped). Returns nullopt
/// when the DLL or ordinal is unknown, leaving the import addressed by ordinal.
[[nodiscard]] std::optional<std::string_view>
    lookup_ordinal_name(std::string_view dll, std::uint32_t ordinal) noexcept;

}  // namespace papa::pe
