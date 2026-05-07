#include "papa/rules/com_lookup.h"

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

namespace papa::rules {

namespace {

// Each row encodes the 16-byte little-endian GUID layout:
//   bytes[0..4]  reversed Data1 (DWORD)
//   bytes[4..6]  reversed Data2 (WORD)
//   bytes[6..8]  reversed Data3 (WORD)
//   bytes[8..16] Data4 in source order
// Names must remain sorted alphabetically because lookup_com runs a binary search
// New entries should be inserted in their lexicographic position
constexpr std::array<ComEntry, 9> kClasses = {{
    { "BackgroundCopyManager",
      "{4991d34b-80a1-4291-83b6-3328366b9097}",
      { std::byte{0x4B}, std::byte{0xD3}, std::byte{0x91}, std::byte{0x49},
        std::byte{0xA1}, std::byte{0x80},
        std::byte{0x91}, std::byte{0x42},
        std::byte{0x83}, std::byte{0xB6}, std::byte{0x33}, std::byte{0x28},
        std::byte{0x36}, std::byte{0x6B}, std::byte{0x90}, std::byte{0x97} } },
    { "CVidCapClassManager",
      "{860bb310-5d01-11d0-bd3b-00a0c911ce86}",
      { std::byte{0x10}, std::byte{0xB3}, std::byte{0x0B}, std::byte{0x86},
        std::byte{0x01}, std::byte{0x5D},
        std::byte{0xD0}, std::byte{0x11},
        std::byte{0xBD}, std::byte{0x3B}, std::byte{0x00}, std::byte{0xA0},
        std::byte{0xC9}, std::byte{0x11}, std::byte{0xCE}, std::byte{0x86} } },
    { "CWaveinClassManager",
      "{33d9a762-90c8-11d0-bd43-00a0c911ce86}",
      { std::byte{0x62}, std::byte{0xA7}, std::byte{0xD9}, std::byte{0x33},
        std::byte{0xC8}, std::byte{0x90},
        std::byte{0xD0}, std::byte{0x11},
        std::byte{0xBD}, std::byte{0x43}, std::byte{0x00}, std::byte{0xA0},
        std::byte{0xC9}, std::byte{0x11}, std::byte{0xCE}, std::byte{0x86} } },
    { "ShellDesktop",
      "{00021400-0000-0000-c000-000000000046}",
      { std::byte{0x00}, std::byte{0x14}, std::byte{0x02}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x46} } },
    { "ShellLink",
      "{00021401-0000-0000-c000-000000000046}",
      { std::byte{0x01}, std::byte{0x14}, std::byte{0x02}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x46} } },
    { "SystemDeviceEnum",
      "{62be5d10-60eb-11d0-bd3b-00a0c911ce86}",
      { std::byte{0x10}, std::byte{0x5D}, std::byte{0xBE}, std::byte{0x62},
        std::byte{0xEB}, std::byte{0x60},
        std::byte{0xD0}, std::byte{0x11},
        std::byte{0xBD}, std::byte{0x3B}, std::byte{0x00}, std::byte{0xA0},
        std::byte{0xC9}, std::byte{0x11}, std::byte{0xCE}, std::byte{0x86} } },
    { "TaskScheduler",
      "{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}",
      { std::byte{0x9F}, std::byte{0x36}, std::byte{0x87}, std::byte{0x0F},
        std::byte{0xE5}, std::byte{0xA4},
        std::byte{0xFC}, std::byte{0x4C},
        std::byte{0xBD}, std::byte{0x3E}, std::byte{0x73}, std::byte{0xE6},
        std::byte{0x15}, std::byte{0x45}, std::byte{0x72}, std::byte{0xDD} } },
    { "WbemLocator",
      "{4590f811-1d3a-11d0-891f-00aa004b2e24}",
      { std::byte{0x11}, std::byte{0xF8}, std::byte{0x90}, std::byte{0x45},
        std::byte{0x3A}, std::byte{0x1D},
        std::byte{0xD0}, std::byte{0x11},
        std::byte{0x89}, std::byte{0x1F}, std::byte{0x00}, std::byte{0xAA},
        std::byte{0x00}, std::byte{0x4B}, std::byte{0x2E}, std::byte{0x24} } },
    { "WshShell",
      "{72c24dd5-d70a-438b-8a42-98424b88afb8}",
      { std::byte{0xD5}, std::byte{0x4D}, std::byte{0xC2}, std::byte{0x72},
        std::byte{0x0A}, std::byte{0xD7},
        std::byte{0x8B}, std::byte{0x43},
        std::byte{0x8A}, std::byte{0x42}, std::byte{0x98}, std::byte{0x42},
        std::byte{0x4B}, std::byte{0x88}, std::byte{0xAF}, std::byte{0xB8} } },
}};

}  // namespace

std::span<const ComEntry> com_class_table() noexcept {
    return kClasses;
}

}  // namespace papa::rules
