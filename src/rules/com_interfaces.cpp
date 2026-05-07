#include "papa/rules/com_lookup.h"

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

namespace papa::rules {

namespace {

// Names must remain sorted alphabetically because lookup_com runs a binary search
constexpr std::array<ComEntry, 7> kInterfaces = {{
    { "IBackgroundCopyManager",
      "{5ce34c0d-0dc9-4c1f-897c-daa1b78cee7c}",
      { std::byte{0x0D}, std::byte{0x4C}, std::byte{0xE3}, std::byte{0x5C},
        std::byte{0xC9}, std::byte{0x0D},
        std::byte{0x1F}, std::byte{0x4C},
        std::byte{0x89}, std::byte{0x7C}, std::byte{0xDA}, std::byte{0xA1},
        std::byte{0xB7}, std::byte{0x8C}, std::byte{0xEE}, std::byte{0x7C} } },
    { "ICreateDevEnum",
      "{29840822-5b84-11d0-bd3b-00a0c911ce86}",
      { std::byte{0x22}, std::byte{0x08}, std::byte{0x84}, std::byte{0x29},
        std::byte{0x84}, std::byte{0x5B},
        std::byte{0xD0}, std::byte{0x11},
        std::byte{0xBD}, std::byte{0x3B}, std::byte{0x00}, std::byte{0xA0},
        std::byte{0xC9}, std::byte{0x11}, std::byte{0xCE}, std::byte{0x86} } },
    { "IDispatch",
      "{00020400-0000-0000-c000-000000000046}",
      { std::byte{0x00}, std::byte{0x04}, std::byte{0x02}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x46} } },
    { "IShellLinkA",
      "{000214ee-0000-0000-c000-000000000046}",
      { std::byte{0xEE}, std::byte{0x14}, std::byte{0x02}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x46} } },
    { "IShellLinkW",
      "{000214f9-0000-0000-c000-000000000046}",
      { std::byte{0xF9}, std::byte{0x14}, std::byte{0x02}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x46} } },
    { "IUnknown",
      "{00000000-0000-0000-c000-000000000046}",
      { std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x46} } },
    { "IWbemLocator",
      "{dc12a687-737f-11cf-884d-00aa004b2e24}",
      { std::byte{0x87}, std::byte{0xA6}, std::byte{0x12}, std::byte{0xDC},
        std::byte{0x7F}, std::byte{0x73},
        std::byte{0xCF}, std::byte{0x11},
        std::byte{0x88}, std::byte{0x4D}, std::byte{0x00}, std::byte{0xAA},
        std::byte{0x00}, std::byte{0x4B}, std::byte{0x2E}, std::byte{0x24} } },
}};

}  // namespace

std::span<const ComEntry> com_interface_table() noexcept {
    return kInterfaces;
}

}  // namespace papa::rules
