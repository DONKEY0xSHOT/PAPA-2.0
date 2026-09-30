#include "papa/rules/com_lookup.h"

#include <array>
#include <span>
#include <string_view>

namespace papa::rules {

namespace {

// Names must remain sorted alphabetically because lookup_com runs a binary search
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

std::span<const ComEntry> com_interface_table() noexcept {
    return kInterfaces;
}

}  // namespace papa::rules
