#include <ostream>

#include "doctest.h"

#include "papa/exceptions.h"
#include "papa/rules/com_lookup.h"
#include "papa/util/hash.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using papa::rules::ComEntry;
using papa::rules::ComKind;
using papa::rules::com_class_table;
using papa::rules::com_interface_table;
using papa::rules::lookup_com;

TEST_CASE("com_lookup: a name resolves to its GUID in its own table only") {
    // SystemDeviceEnum and WbemLocator unblock capa rules in the host-interaction/hardware
    // and host-interaction/wmi namespaces
    struct Row {
        std::string_view                label;
        ComKind                         kind;
        std::string_view                name;
        std::optional<std::string_view> guid;
        std::string_view                bytes_hex;
    };
    const std::vector<Row> rows{
        // The first DWORD is little-endian, and the last byte is the trailing 0x46 of Data4
        {"the ShellDesktop class", ComKind::kClass, "ShellDesktop",
         "{00021400-0000-0000-c000-000000000046}", "0014020000000000c000000000000046"},
        {"the IUnknown interface", ComKind::kInterface, "IUnknown",
         "{00000000-0000-0000-c000-000000000046}", "0000000000000000c000000000000046"},
        {"the SystemDeviceEnum class", ComKind::kClass, "SystemDeviceEnum",
         "{62be5d10-60eb-11d0-bd3b-00a0c911ce86}", "105dbe62eb60d011bd3b00a0c911ce86"},
        {"the WbemLocator class", ComKind::kClass, "WbemLocator",
         "{4590f811-1d3a-11d0-891f-00aa004b2e24}", "11f890453a1dd011891f00aa004b2e24"},
        {"IUnknown is not a class", ComKind::kClass, "IUnknown", std::nullopt, ""},
        {"ShellDesktop is not an interface", ComKind::kInterface, "ShellDesktop", std::nullopt, ""},
        {"an unknown class name", ComKind::kClass, "DefinitelyNotARealCom", std::nullopt, ""},
        {"an unknown interface name", ComKind::kInterface, "AlsoNotReal", std::nullopt, ""},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const ComEntry* e = lookup_com(row.kind, row.name);
        CHECK((e != nullptr) == row.guid.has_value());
        if (e == nullptr || !row.guid.has_value()) { continue; }
        CHECK(e->name == row.name);
        CHECK(e->guid_string == *row.guid);
        CHECK(papa::util::hex_digest(e->guid_bytes) == row.bytes_hex);
        // The same name is absent from the other table
        const ComKind other = row.kind == ComKind::kClass ? ComKind::kInterface : ComKind::kClass;
        CHECK(lookup_com(other, row.name) == nullptr);
    }
}

TEST_CASE("com_lookup: every entry keeps the little-endian bytes of its GUID") {
    struct Row {
        ComKind          kind;
        std::string_view name;
        std::string_view bytes_hex;
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
        CHECK(papa::util::hex_digest(e->guid_bytes) == row.bytes_hex);
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

    constexpr std::array<std::string_view, 5> kMalformed = {{
        "dc12a687-737f-11cf-884d-00aa004b2e24",
        "(dc12a687-737f-11cf-884d-00aa004b2e24)",
        "{dc12a687-737f-11cf-884d-00aa004b2e2}",
        "{dc12a687+737f-11cf-884d-00aa004b2e24}",
        "{dc12a687-737f-11cf-884d-00aa004b2e2g}",
    }};
    for (const std::string_view guid : kMalformed) {
        CAPTURE(guid);
        CHECK_THROWS_AS((void)bytes_le(guid), papa::PapaInvariantError);
    }
}
