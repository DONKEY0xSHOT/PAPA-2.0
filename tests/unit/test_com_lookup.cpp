// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the PAPA authors

#include <ostream>

#include "doctest.h"

#include "papa/rules/com_lookup.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

using papa::rules::ComEntry;
using papa::rules::ComKind;
using papa::rules::com_class_table;
using papa::rules::com_interface_table;
using papa::rules::lookup_com;

TEST_CASE("com_lookup: ShellDesktop class resolves to its CLSID") {
    const ComEntry* e = lookup_com(ComKind::kClass, "ShellDesktop");
    REQUIRE(e != nullptr);
    CHECK(e->name == "ShellDesktop");
    CHECK(e->guid_string == "{00021400-0000-0000-c000-000000000046}");

    // First DWORD encoded little-endian: 0x00 0x14 0x02 0x00
    CHECK(static_cast<std::uint8_t>(e->guid_bytes[0]) == 0x00);
    CHECK(static_cast<std::uint8_t>(e->guid_bytes[1]) == 0x14);
    CHECK(static_cast<std::uint8_t>(e->guid_bytes[2]) == 0x02);
    CHECK(static_cast<std::uint8_t>(e->guid_bytes[3]) == 0x00);
    // Last byte is the trailing 0x46 from Data4
    CHECK(static_cast<std::uint8_t>(e->guid_bytes[15]) == 0x46);
}

TEST_CASE("com_lookup: IUnknown interface resolves") {
    const ComEntry* e = lookup_com(ComKind::kInterface, "IUnknown");
    REQUIRE(e != nullptr);
    CHECK(e->guid_string == "{00000000-0000-0000-c000-000000000046}");
}

TEST_CASE("com_lookup: classes and interfaces share namespaces but lookup is segregated") {
    // IUnknown is in the interface table only
    CHECK(lookup_com(ComKind::kClass,     "IUnknown") == nullptr);
    CHECK(lookup_com(ComKind::kInterface, "IUnknown") != nullptr);
    // ShellDesktop is in the class table only
    CHECK(lookup_com(ComKind::kClass,     "ShellDesktop") != nullptr);
    CHECK(lookup_com(ComKind::kInterface, "ShellDesktop") == nullptr);
}

TEST_CASE("com_lookup: unknown name returns nullptr") {
    CHECK(lookup_com(ComKind::kClass,     "DefinitelyNotARealCom") == nullptr);
    CHECK(lookup_com(ComKind::kInterface, "AlsoNotReal")           == nullptr);
}

TEST_CASE("com_lookup: SystemDeviceEnum and WbemLocator resolve correctly") {
    // These two CLSIDs unblock CAPA rules in the host-interaction/hardware
    // and host-interaction/wmi namespaces
    // The GUID encodings are spot-checked because byte-swapping the first
    // three GUID fields is easy to get wrong
    const ComEntry* sde = lookup_com(ComKind::kClass, "SystemDeviceEnum");
    REQUIRE(sde != nullptr);
    CHECK(sde->guid_string == "{62be5d10-60eb-11d0-bd3b-00a0c911ce86}");
    // First DWORD 0x62be5d10 stored little-endian as 10 5d be 62
    CHECK(static_cast<std::uint8_t>(sde->guid_bytes[0]) == 0x10);
    CHECK(static_cast<std::uint8_t>(sde->guid_bytes[3]) == 0x62);

    const ComEntry* wl = lookup_com(ComKind::kClass, "WbemLocator");
    REQUIRE(wl != nullptr);
    CHECK(wl->guid_string == "{4590f811-1d3a-11d0-891f-00aa004b2e24}");
    CHECK(static_cast<std::uint8_t>(wl->guid_bytes[0]) == 0x11);
    CHECK(static_cast<std::uint8_t>(wl->guid_bytes[3]) == 0x45);
}

TEST_CASE("com_lookup: tables are sorted alphabetically by name") {
    const auto check_sorted = [](std::span<const ComEntry> t) {
        return std::is_sorted(t.begin(), t.end(),
            [](const ComEntry& a, const ComEntry& b) { return a.name < b.name; });
    };
    CHECK(check_sorted(com_class_table()));
    CHECK(check_sorted(com_interface_table()));
}

TEST_CASE("com_lookup: every entry has a 16-byte GUID and brace-wrapped string") {
    const auto validate = [](std::span<const ComEntry> t) {
        for (const ComEntry& e : t) {
            REQUIRE_FALSE(e.name.empty());
            REQUIRE(e.guid_string.size() == 38);
            REQUIRE(e.guid_string.front() == '{');
            REQUIRE(e.guid_string.back() == '}');
            REQUIRE(e.guid_bytes.size() == 16);
        }
    };
    validate(com_class_table());
    validate(com_interface_table());
}
