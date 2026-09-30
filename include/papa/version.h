#pragma once

#include <string_view>

namespace papa::version {

/// The capa release whose report format and rules PAPA reproduces
inline constexpr std::string_view kCapaVersion = "9.4.0";

/// PAPA's own release version, stamped into the binary by the build
[[nodiscard]] std::string_view version() noexcept;

}  // namespace papa::version
