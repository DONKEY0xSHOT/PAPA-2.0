#pragma once

#include <cstdint>
#include <string_view>

namespace papa::version {

inline constexpr std::uint32_t kMajor = 0;
inline constexpr std::uint32_t kMinor = 1;
inline constexpr std::uint32_t kPatch = 0;

inline constexpr std::string_view kVersionString = "0.1.0";
inline constexpr std::string_view kProductName   = "PAPA";

/// The capa release whose report format and rules PAPA reproduces
inline constexpr std::string_view kCapaVersion = "9.4.0";

// "PAPA X.Y.Z"
[[nodiscard]] std::string_view banner() noexcept;

}  // namespace papa::version
