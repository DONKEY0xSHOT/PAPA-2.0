#include "papa/rules/com_lookup.h"

#include <algorithm>
#include <array>
#include <span>
#include <string_view>

namespace papa::rules {

namespace {

// Both tables must stay sorted by name, because lookup_com runs a binary search over them
constexpr std::array<ComEntry, 9> kClasses = {{
    {"BackgroundCopyManager", "{4991d34b-80a1-4291-83b6-3328366b9097}"},
    {"CVidCapClassManager",   "{860bb310-5d01-11d0-bd3b-00a0c911ce86}"},
    {"CWaveinClassManager",   "{33d9a762-90c8-11d0-bd43-00a0c911ce86}"},
    {"ShellDesktop",          "{00021400-0000-0000-c000-000000000046}"},
    {"ShellLink",             "{00021401-0000-0000-c000-000000000046}"},
    {"SystemDeviceEnum",      "{62be5d10-60eb-11d0-bd3b-00a0c911ce86}"},
    {"TaskScheduler",         "{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}"},
    {"WbemLocator",           "{4590f811-1d3a-11d0-891f-00aa004b2e24}"},
    {"WshShell",              "{72c24dd5-d70a-438b-8a42-98424b88afb8}"},
}};

constexpr std::array<ComEntry, 7> kInterfaces = {{
    {"IBackgroundCopyManager", "{5ce34c0d-0dc9-4c1f-897c-daa1b78cee7c}"},
    {"ICreateDevEnum",         "{29840822-5b84-11d0-bd3b-00a0c911ce86}"},
    {"IDispatch",              "{00020400-0000-0000-c000-000000000046}"},
    {"IShellLinkA",            "{000214ee-0000-0000-c000-000000000046}"},
    {"IShellLinkW",            "{000214f9-0000-0000-c000-000000000046}"},
    {"IUnknown",               "{00000000-0000-0000-c000-000000000046}"},
    {"IWbemLocator",           "{dc12a687-737f-11cf-884d-00aa004b2e24}"},
}};

}  // namespace

std::span<const ComEntry> com_class_table() noexcept {
    return kClasses;
}

std::span<const ComEntry> com_interface_table() noexcept {
    return kInterfaces;
}

const ComEntry* lookup_com(ComKind kind, std::string_view name) noexcept {
    const std::span<const ComEntry> table =
        (kind == ComKind::kClass) ? com_class_table() : com_interface_table();

    // Tables are sorted by name so binary search keeps lookup logarithmic
    // even when future generations grow each table to thousands of entries
    const auto it = std::lower_bound(table.begin(), table.end(), name,
        [](const ComEntry& entry, std::string_view target) {
            return entry.name < target;
        });
    if (it == table.end() || it->name != name) {
        return nullptr;
    }
    return &(*it);
}

}  // namespace papa::rules
