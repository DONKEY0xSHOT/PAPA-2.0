#pragma once

#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>

/// Helpers used by unit tests to locate optional sample-PE fixtures
/// (notepad.exe, chrome.exe, capa.exe, "CFF Explorer.exe") at runtime.
///
/// The fixtures live outside the repository because they are real Windows
/// binaries the project does not redistribute. Their location is resolved
/// from the PAPA_TEST_FIXTURES environment variable; when the variable is
/// unset or the requested file is absent, fixture-dependent test cases
/// emit a MESSAGE and return without failing so the suite stays runnable
/// on machines that do not have the fixtures available.
namespace papa_tests::detail {

/// Portable env-var read; MSVC rejects std::getenv under /W4 /WX.
[[nodiscard]] inline std::string read_env(const char* name) {
#if defined(_MSC_VER)
    std::size_t required = 0;
    if (getenv_s(&required, nullptr, 0, name) != 0 || required == 0) {
        return {};
    }
    std::string buf(required, '\0');
    if (getenv_s(&required, buf.data(), buf.size(), name) != 0) {
        return {};
    }
    // getenv_s writes a trailing NUL inside the buffer
    if (!buf.empty() && buf.back() == '\0') { buf.pop_back(); }
    return buf;
#else
    const char* v = std::getenv(name);
    return v != nullptr ? std::string(v) : std::string{};
#endif
}

}  // namespace papa_tests::detail

namespace papa_tests {

/// Resolve a fixture file path under the directory pointed to by
/// PAPA_TEST_FIXTURES. Returns an empty path when the variable is unset.
[[nodiscard]] inline std::filesystem::path
fixture_path(std::string_view name) {
    const std::string root = detail::read_env("PAPA_TEST_FIXTURES");
    if (root.empty()) { return {}; }
    return std::filesystem::path(root) / std::filesystem::path(name);
}

/// True when the fixture exists on disk and can be opened.
[[nodiscard]] inline bool fixture_available(const std::filesystem::path& p) {
    return !p.empty() && std::filesystem::exists(p);
}

}  // namespace papa_tests
