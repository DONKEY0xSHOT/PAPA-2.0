#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace papa::pe {

/// Resolve an ordinal-imported symbol to its name for the DLLs frequently linked by
/// ordinal, the way vivisect's ordlookup database does
[[nodiscard]] std::optional<std::string_view>
    lookup_ordinal_name(std::string_view dll, std::uint32_t ordinal) noexcept;

}  // namespace papa::pe
