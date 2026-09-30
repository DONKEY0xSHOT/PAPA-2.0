#include <ostream>

#include "doctest.h"

#include "papa/features/address.h"

#include <unordered_set>
#include <variant>

using namespace papa::features;

TEST_SUITE("address") {

TEST_CASE("NoAddress instances compare equal") {
    const Address a = NoAddress{};
    const Address b = NoAddress{};
    CHECK(a == b);
}

TEST_CASE("Concrete addresses compare by payload") {
    Address a = AbsoluteVirtualAddress{0x401000};
    Address b = AbsoluteVirtualAddress{0x401000};
    Address c = AbsoluteVirtualAddress{0x401004};
    CHECK(a == b);
    CHECK_FALSE(a == c);
}

TEST_CASE("Different variant alternatives are not equal even when payload matches") {
    // AbsoluteVirtualAddress{0x10} vs FileOffsetAddress{0x10} share a payload but live
    // in different variant slots, and std::variant operator== is index-aware
    Address a = AbsoluteVirtualAddress{0x10};
    Address b = FileOffsetAddress{0x10};
    CHECK_FALSE(a == b);
}

TEST_CASE("linearize yields distinct values for distinct tag and payload") {
    const auto va_1   = linearize(Address{AbsoluteVirtualAddress{0x401000}});
    const auto va_2   = linearize(Address{AbsoluteVirtualAddress{0x402000}});
    const auto rva_1  = linearize(Address{RelativeVirtualAddress{0x401000}});
    const auto file_1 = linearize(Address{FileOffsetAddress{0x401000}});

    // Same tag, different payload
    CHECK(va_1 != va_2);
    // Different tag, same payload
    // The tag mix in the high bits separates them
    CHECK(va_1 != rva_1);
    CHECK(va_1 != file_1);
    CHECK(rva_1 != file_1);
}

TEST_CASE("Each variant alternative keeps its payload") {
    CHECK(std::holds_alternative<NoAddress>(Address{NoAddress{}}));
    CHECK(std::get<AbsoluteVirtualAddress>(Address{AbsoluteVirtualAddress{0x401000}}).v == 0x401000U);
    CHECK(std::get<RelativeVirtualAddress>(Address{RelativeVirtualAddress{0x1000}}).v == 0x1000U);
    CHECK(std::get<FileOffsetAddress>(Address{FileOffsetAddress{0x200}}).v == 0x200U);
    CHECK(std::get<DnTokenAddress>(Address{DnTokenAddress{0x06000001}}).token == 0x06000001U);
}

TEST_CASE("Address can be stored in std::unordered_set") {
    // Confirms the std::hash specialization is wired and comparable
    std::unordered_set<Address> s;
    s.insert(Address{AbsoluteVirtualAddress{0x1}});
    s.insert(Address{AbsoluteVirtualAddress{0x1}});   // duplicate collapses
    s.insert(Address{AbsoluteVirtualAddress{0x2}});
    s.insert(Address{FileOffsetAddress{0x1}});        // different variant slot
    CHECK(s.size() == 3);
}

}  // TEST_SUITE
