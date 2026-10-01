#pragma once

#include "test_support.h"

#include <filesystem>
#include <string>
#include <string_view>

/// Helpers used by unit tests to locate optional sample-PE fixtures at runtime,
/// resolved from PAPA_TEST_FIXTURES. Missing fixtures skip rather than fail
namespace papa_tests {

/// Resolve a fixture file path under the directory pointed to by
/// PAPA_TEST_FIXTURES. Returns an empty path when the variable is unset
[[nodiscard]] inline std::filesystem::path
fixture_path(std::string_view name) {
    const std::string root = read_env("PAPA_TEST_FIXTURES");
    if (root.empty()) { return {}; }
    return std::filesystem::path(root) / std::filesystem::path(name);
}

/// True when the fixture exists on disk and can be opened
[[nodiscard]] inline bool fixture_available(const std::filesystem::path& p) {
    return !p.empty() && std::filesystem::exists(p);
}

}  // namespace papa_tests
