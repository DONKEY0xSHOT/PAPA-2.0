#include <ostream>

#include "doctest.h"

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/features/basic_block.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/features/insn.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace papa::features;

namespace {

// Convenience factory
// Shared_ptr<const T> is the storage type in FeatureSet
template <typename T, typename... Args>
FeaturePtr make(Args&&... args) {
    return std::make_shared<const T>(std::forward<Args>(args)...);
}

Address va(std::uint64_t v) {
    return Address{AbsoluteVirtualAddress{v}};
}

std::vector<std::byte> bytes_of(std::initializer_list<std::uint8_t> ilist) {
    std::vector<std::byte> out;
    out.reserve(ilist.size());
    for (auto b : ilist) { out.emplace_back(std::byte{b}); }
    return out;
}

}  // namespace

TEST_SUITE("feature_semantics") {

TEST_CASE("Structural equality compares tag and payload") {
    auto s1 = make<String>(std::string("foo"));
    auto s2 = make<String>(std::string("foo"));
    auto s3 = make<String>(std::string("bar"));
    CHECK(s1->equals(*s2));
    CHECK_FALSE(s1->equals(*s3));
    CHECK(s1->hash() == s2->hash());
}

TEST_CASE("FeatureSet deduplicates structurally equal features") {
    FeatureSet fs;
    fs.add(make<String>(std::string("foo")), va(0x1));
    fs.add(make<String>(std::string("foo")), va(0x2));
    fs.add(make<String>(std::string("bar")), va(0x3));
    CHECK(fs.size() == 2);
    // The first entry still keyed by "foo" now holds both locations
    auto probe = make<String>(std::string("foo"));
    auto it = fs.find(probe);
    REQUIRE(it != fs.end());
    CHECK(it->second.size() == 2);
}

TEST_CASE("Default evaluate is structural membership") {
    FeatureSet fs;
    fs.add(make<Api>(std::string("kernel32.CreateFileA")), va(0x401000));
    fs.add(make<Api>(std::string("kernel32.CreateFileA")), va(0x401020));

    Api probe{"kernel32.CreateFileA"};
    auto r = probe.evaluate(fs, /*sc=*/false);
    CHECK(r.success);
    CHECK(r.locations.size() == 2);

    Api missing{"kernel32.WriteFile"};
    auto r2 = missing.evaluate(fs, /*sc=*/false);
    CHECK_FALSE(r2.success);
    CHECK(r2.locations.empty());
}

TEST_CASE("Substring scans String features and reports all hits") {
    FeatureSet fs;
    fs.add(make<String>(std::string("hello world")), va(0x1));
    fs.add(make<String>(std::string("world peace")), va(0x2));
    fs.add(make<String>(std::string("goodbye")),     va(0x3));
    // A Bytes feature containing the needle must not match
    // Substring only scans String
    fs.add(make<Bytes>(bytes_of({'w','o','r','l','d'})), va(0x4));

    Substring needle{"world"};
    auto r = needle.evaluate(fs, /*sc=*/false);
    CHECK(r.success);
    CHECK(r.locations.size() == 2);
    CHECK(r.locations.count(va(0x1)) == 1);
    CHECK(r.locations.count(va(0x2)) == 1);
}

TEST_CASE("Substring short-circuits on first hit") {
    FeatureSet fs;
    fs.add(make<String>(std::string("foo")), va(0x1));
    fs.add(make<String>(std::string("foobar")), va(0x2));

    Substring s{"foo"};
    auto r = s.evaluate(fs, /*sc=*/true);
    CHECK(r.success);
    // Under short-circuit we return as soon as any match is found
    // Locations
    // must be non-empty but may cover only one of the matching entries
    CHECK(r.locations.size() >= 1);
    CHECK(r.locations.size() <= 2);
}

TEST_CASE("Regex literal forms parse slashes and case-insensitive suffix") {
    FeatureSet fs;
    fs.add(make<String>(std::string("HelloWorld")), va(0x1));
    fs.add(make<String>(std::string("goodbye")),   va(0x2));

    Regex r_ci{"/hello/i"};
    auto ci_result = r_ci.evaluate(fs, false);
    CHECK(ci_result.success);
    CHECK(ci_result.locations.count(va(0x1)) == 1);

    Regex r_sensitive{"/hello/"};
    auto cs_result = r_sensitive.evaluate(fs, false);
    CHECK_FALSE(cs_result.success);  // "Hello" != "hello" without /i

    Regex r_anchored{"/^good/"};
    auto r_anch = r_anchored.evaluate(fs, false);
    CHECK(r_anch.success);
    CHECK(r_anch.locations.count(va(0x2)) == 1);
}

TEST_CASE("Bytes matches when self is a prefix of a candidate") {
    FeatureSet fs;
    fs.add(make<Bytes>(bytes_of({0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE})), va(0x100));
    fs.add(make<Bytes>(bytes_of({0x90, 0x90, 0x90})),                   va(0x200));

    Bytes short_prefix{bytes_of({0xDE, 0xAD})};
    auto r = short_prefix.evaluate(fs, false);
    CHECK(r.success);
    CHECK(r.locations.count(va(0x100)) == 1);
    CHECK_FALSE(r.locations.count(va(0x200)) == 1);

    // A pattern longer than any candidate cannot match
    Bytes too_long{bytes_of({0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00})};
    auto r2 = too_long.evaluate(fs, false);
    CHECK_FALSE(r2.success);

    // Exact match is just a prefix of equal length
    Bytes exact{bytes_of({0x90, 0x90, 0x90})};
    auto r3 = exact.evaluate(fs, false);
    CHECK(r3.success);
    CHECK(r3.locations.count(va(0x200)) == 1);
}

TEST_CASE("Bytes non-prefix middle occurrence does not match") {
    // The candidate contains the pattern but not at offset 0
    // Prefix-only
    FeatureSet fs;
    fs.add(make<Bytes>(bytes_of({0x00, 0xDE, 0xAD})), va(0x1));

    Bytes pat{bytes_of({0xDE, 0xAD})};
    auto r = pat.evaluate(fs, false);
    CHECK_FALSE(r.success);
}

TEST_CASE("Os rule side any matches any concrete Os in fs") {
    FeatureSet fs;
    fs.add(make<Os>(std::string("windows")), va(0x0));

    Os any_rule{"any"};
    auto r = any_rule.evaluate(fs, false);
    CHECK(r.success);

    Os concrete_match{"windows"};
    auto r2 = concrete_match.evaluate(fs, false);
    CHECK(r2.success);

    Os mismatch{"linux"};
    auto r3 = mismatch.evaluate(fs, false);
    CHECK_FALSE(r3.success);
}

TEST_CASE("Os fs side any matches any concrete rule") {
    FeatureSet fs;
    fs.add(make<Os>(std::string("any")), va(0x0));

    Os concrete{"windows"};
    auto r = concrete.evaluate(fs, false);
    CHECK(r.success);
}

TEST_CASE("Arch wildcard behaves like Os wildcard") {
    FeatureSet fs;
    fs.add(make<Arch>(std::string("amd64")), va(0x0));

    Arch any_rule{"any"};
    auto r = any_rule.evaluate(fs, false);
    CHECK(r.success);

    Arch mismatch{"i386"};
    CHECK_FALSE(mismatch.evaluate(fs, false).success);
}

TEST_CASE("Property equality requires both name and access to match") {
    auto p1 = make<Property>(std::string("MyProp"), Property::Access::kRead);
    auto p2 = make<Property>(std::string("MyProp"), Property::Access::kRead);
    auto p3 = make<Property>(std::string("MyProp"), Property::Access::kWrite);
    auto p4 = make<Property>(std::string("Other"),  Property::Access::kRead);

    CHECK(p1->equals(*p2));
    CHECK_FALSE(p1->equals(*p3));
    CHECK_FALSE(p1->equals(*p4));
}

TEST_CASE("OperandNumber equality discriminates on index") {
    auto a = make<OperandNumber>(0u, OperandNumber::Value{std::uint64_t{0x10}});
    auto b = make<OperandNumber>(0u, OperandNumber::Value{std::uint64_t{0x10}});
    auto c = make<OperandNumber>(1u, OperandNumber::Value{std::uint64_t{0x10}});

    CHECK(a->equals(*b));
    CHECK_FALSE(a->equals(*c));
    CHECK(a->hash() == b->hash());
}

TEST_CASE("Number variant alternatives with same payload are not equal") {
    auto u = make<Number>(Number::Value{std::uint64_t{0}});
    auto i = make<Number>(Number::Value{std::int64_t{0}});
    auto d = make<Number>(Number::Value{0.0});

    // Different active alternatives of std::variant compare unequal even if
    // their stored values would compare equal as their underlying numeric types
    CHECK_FALSE(u->equals(*i));
    CHECK_FALSE(u->equals(*d));
    CHECK_FALSE(i->equals(*d));
}

TEST_CASE("BasicBlock instances are all structurally equal") {
    auto b1 = make<BasicBlock>();
    auto b2 = make<BasicBlock>();
    CHECK(b1->equals(*b2));
    CHECK(b1->hash() == b2->hash());
}

TEST_CASE("Different feature kinds never collide in a FeatureSet") {
    // Each feature has a distinct tag so fs.size() must equal the insertion count
    FeatureSet fs;
    fs.add(make<String>(std::string("foo")),                           va(0x1));
    fs.add(make<Api>(std::string("foo")),                              va(0x2));
    fs.add(make<Import>(std::string("foo")),                           va(0x3));
    fs.add(make<Export>(std::string("foo")),                           va(0x4));
    fs.add(make<Section>(std::string("foo")),                          va(0x5));
    fs.add(make<FunctionName>(std::string("foo")),                     va(0x6));
    fs.add(make<Mnemonic>(std::string("foo")),                         va(0x7));
    fs.add(make<Characteristic>(std::string("foo")),                   va(0x8));
    fs.add(make<Class>(std::string("foo")),                            va(0x9));
    fs.add(make<Namespace>(std::string("foo")),                        va(0xA));
    fs.add(make<MatchedRule>(std::string("foo")),                      va(0xB));
    fs.add(make<Os>(std::string("foo")),                               va(0xC));
    fs.add(make<Arch>(std::string("foo")),                             va(0xD));
    fs.add(make<Format>(std::string("foo")),                           va(0xE));
    CHECK(fs.size() == 14);
}

}  // TEST_SUITE
