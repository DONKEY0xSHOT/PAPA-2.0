#include <ostream>

#include "doctest.h"

#include "papa/exceptions.h"
#include "papa/rules/com_lookup.h"
#include "papa/util/hash.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

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
    // These two CLSIDs unblock CAPA rules in the host-interaction/hardware and host-
    // interaction/wmi namespaces
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

TEST_CASE("com_lookup: every entry keeps the little-endian bytes of its GUID") {
    struct Row {
        ComKind     kind;
        const char* name;
        const char* bytes_hex;
    };
    constexpr std::array<Row, 16> kRows = {{
        {ComKind::kClass,     "BackgroundCopyManager",  "4bd39149a180914283b63328366b9097"},
        {ComKind::kClass,     "CVidCapClassManager",    "10b30b86015dd011bd3b00a0c911ce86"},
        {ComKind::kClass,     "CWaveinClassManager",    "62a7d933c890d011bd4300a0c911ce86"},
        {ComKind::kClass,     "ShellDesktop",           "0014020000000000c000000000000046"},
        {ComKind::kClass,     "ShellLink",              "0114020000000000c000000000000046"},
        {ComKind::kClass,     "SystemDeviceEnum",       "105dbe62eb60d011bd3b00a0c911ce86"},
        {ComKind::kClass,     "TaskScheduler",          "9f36870fe5a4fc4cbd3e73e6154572dd"},
        {ComKind::kClass,     "WbemLocator",            "11f890453a1dd011891f00aa004b2e24"},
        {ComKind::kClass,     "WshShell",               "d54dc2720ad78b438a4298424b88afb8"},
        {ComKind::kInterface, "IBackgroundCopyManager", "0d4ce35cc90d1f4c897cdaa1b78cee7c"},
        {ComKind::kInterface, "ICreateDevEnum",         "22088429845bd011bd3b00a0c911ce86"},
        {ComKind::kInterface, "IDispatch",              "0004020000000000c000000000000046"},
        {ComKind::kInterface, "IShellLinkA",            "ee14020000000000c000000000000046"},
        {ComKind::kInterface, "IShellLinkW",            "f914020000000000c000000000000046"},
        {ComKind::kInterface, "IUnknown",               "0000000000000000c000000000000046"},
        {ComKind::kInterface, "IWbemLocator",           "87a612dc7f73cf11884d00aa004b2e24"},
    }};
    CHECK(com_class_table().size() + com_interface_table().size() == kRows.size());
    for (const Row& row : kRows) {
        CAPTURE(row.name);
        const ComEntry* e = lookup_com(row.kind, row.name);
        REQUIRE(e != nullptr);
        CHECK(papa::util::hex_digest(e->guid_bytes) == std::string{row.bytes_hex});
    }
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

TEST_CASE("com_lookup: bytes_le reads either hex case and rejects malformed strings") {
    using papa::rules::bytes_le;
    static_assert(bytes_le("{00000000-0000-0000-c000-000000000046}")[8] == std::byte{0xC0});
    CHECK(bytes_le("{DC12A687-737F-11CF-884D-00AA004B2E24}") ==
          bytes_le("{dc12a687-737f-11cf-884d-00aa004b2e24}"));

    constexpr std::array<const char*, 5> kMalformed = {{
        "dc12a687-737f-11cf-884d-00aa004b2e24",
        "(dc12a687-737f-11cf-884d-00aa004b2e24)",
        "{dc12a687-737f-11cf-884d-00aa004b2e2}",
        "{dc12a687+737f-11cf-884d-00aa004b2e24}",
        "{dc12a687-737f-11cf-884d-00aa004b2e2g}",
    }};
    for (const char* guid : kMalformed) {
        CAPTURE(guid);
        CHECK_THROWS_AS((void)bytes_le(guid), papa::PapaInvariantError);
    }
}
