#include "papa/features/extractors/papa_native/flirt/flirt.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#if defined(_WIN32) && defined(_MSC_VER)
#  pragma warning(push, 0)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  pragma warning(pop)
#  include "flirt_sigs_resources.h"
#  include <vector>
#endif

namespace papa::features::extractors::papa_native::flirt::embedded {

#if defined(_WIN32) && defined(_MSC_VER)
namespace {
/// Locks one RCDATA resource and returns it as an EmbeddedSig, or nullopt.
[[nodiscard]] std::optional<EmbeddedSig> lock_sig(std::string_view name, int id) noexcept {
    const HMODULE module = GetModuleHandleW(nullptr);
    // RT_RCDATA expands to the ANSI MAKEINTRESOURCE when UNICODE is undefined,
    // so spell the type out with the wide form to match FindResourceW.
    const LPCWSTR rcdata_type = MAKEINTRESOURCEW(10);
    const HRSRC found = FindResourceW(module, MAKEINTRESOURCEW(id), rcdata_type);
    if (found == nullptr) { return std::nullopt; }
    const HGLOBAL loaded = LoadResource(module, found);
    if (loaded == nullptr) { return std::nullopt; }
    const void* data = LockResource(loaded);
    const DWORD size = SizeofResource(module, found);
    if (data == nullptr || size == 0U) { return std::nullopt; }
    return EmbeddedSig{name, static_cast<const std::uint8_t*>(data), size};
}
}  // namespace

std::span<const EmbeddedSig> registry() noexcept {
    static const std::vector<EmbeddedSig> sigs = [] {
        std::vector<EmbeddedSig> out;
        struct Entry { std::string_view name; int id; };
        const Entry entries[] = {
            {"1_flare_msvc_rtf_32_64", PAPA_FLIRT_RTF},
            {"2_flare_msvc_atlmfc_32_64", PAPA_FLIRT_ATLMFC},
            {"3_flare_common_libs", PAPA_FLIRT_COMMON},
        };
        for (const Entry& e : entries) {
            if (auto sig = lock_sig(e.name, e.id)) { out.push_back(*sig); }
        }
        return out;
    }();
    return sigs;
}
#else
// FLIRT signatures are embedded only on MSVC (via an .rc resource). On other
// toolchains the registry is empty and FLIRT classification is inactive.
std::span<const EmbeddedSig> registry() noexcept { return {}; }
#endif

}  // namespace papa::features::extractors::papa_native::flirt::embedded
