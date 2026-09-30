#include "papa/rules/com_lookup.h"

#include <array>
#include <span>
#include <string_view>

namespace papa::rules {

namespace {

// Names must stay sorted alphabetically, because lookup_com runs a binary search over them
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

}  // namespace

std::span<const ComEntry> com_class_table() noexcept {
    return kClasses;
}

}  // namespace papa::rules
