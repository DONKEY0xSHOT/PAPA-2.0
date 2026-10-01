#include <ostream>

#include "doctest.h"

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/features/basic_block.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/features/insn.h"
#include "papa/util/hashing.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <unordered_set>
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

TEST_CASE("FeatureSet add_all copies or moves a batch and keeps the string index in order") {
    const std::vector<std::pair<FeaturePtr, Address>> shared = {
        {make<String>(std::string("foo")), va(0x1)},
        {make<Section>(std::string(".text")), va(0x2)},
    };
    std::vector<std::pair<FeaturePtr, Address>> handed_over = {
        {make<String>(std::string("bar")), va(0x3)},
        {make<String>(std::string("foo")), va(0x4)},
    };

    FeatureSet fs;
    fs.add_all(shared);
    fs.add_all(std::move(handed_over));
    CHECK(shared[0].first != nullptr);
    CHECK(fs.size() == 3);
    CHECK(fs.find(make<String>(std::string("foo")))->second.size() == 2);
    REQUIRE(fs.strings().size() == 2);
    CHECK(fs.strings()[0].get() == shared[0].first.get());
    CHECK(fs.strings()[1]->equals(String{"bar"}));
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
    // Under short-circuit we return as soon as any match is found. Locations must be
    // non-empty but may cover only one of the matching entries
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

TEST_CASE("Regex: a required literal never hides a case-insensitive match") {
    FeatureSet fs;
    fs.add(make<String>(std::string("C:\\Program Files\\VirtualBox Guest Additions")), va(0x1000));
    CHECK(Regex("/virtualbox guest/i").matches(fs));
    CHECK(Regex("/virtualbox guest/i").evaluate(fs, false).locations.count(va(0x1000)) == 1);
    CHECK(Regex("/VirtualBox/").matches(fs));
    CHECK_FALSE(Regex("/vmware tools/i").matches(fs));
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

TEST_CASE("Arch has no wildcard, so any matches only a literal any") {
    FeatureSet fs;
    fs.add(make<Arch>(std::string("amd64")), va(0x0));

    Arch any_rule{"any"};
    CHECK_FALSE(any_rule.evaluate(fs, false).success);

    Arch exact{"amd64"};
    CHECK(exact.evaluate(fs, false).success);

    Arch mismatch{"i386"};
    CHECK_FALSE(mismatch.evaluate(fs, false).success);

    FeatureSet literal_any;
    literal_any.add(make<Arch>(std::string("any")), va(0x0));
    CHECK(any_rule.evaluate(literal_any, false).success);
}

TEST_CASE("Os and Arch: only os treats any as a wildcard, in both directions") {
    const Address a = va(0x1000);

    FeatureSet any_os;
    any_os.add(make<Os>(std::string("any")), a);
    CHECK(Os("windows").matches(any_os));
    const auto r = Os("windows").evaluate(any_os, false);
    CHECK(r.success);
    CHECK(r.locations.size() == 1U);

    FeatureSet windows;
    windows.add(make<Os>(std::string("windows")), a);
    CHECK(Os("any").matches(windows));
    CHECK_FALSE(Os("linux").matches(windows));

    FeatureSet i386;
    i386.add(make<Arch>(std::string("i386")), a);
    CHECK_FALSE(Arch("amd64").matches(i386));
    CHECK_FALSE(Arch("any").matches(i386));
    FeatureSet any_arch;
    any_arch.add(make<Arch>(std::string("any")), a);
    CHECK_FALSE(Arch("amd64").matches(any_arch));
}

TEST_CASE("Os: only the set side any contributes locations to a concrete rule") {
    const Address a = va(0x1000);
    const Address b = va(0x2000);
    FeatureSet    fs;
    fs.add(make<Os>(std::string("windows")), a);
    fs.add(make<Os>(std::string("any")), b);

    const auto r = Os("linux").evaluate(fs, false);
    CHECK(r.success);
    CHECK(r.locations == std::unordered_set<Address>{b});
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

TEST_CASE("Single-string features hash the tag mixed into the value hash") {
    // One shared value, a regex literal so Regex must hash the literal, not its pattern
    const std::string v = "/foo/i";
    const std::pair<FeaturePtr, FeatureTag> rows[] = {
        {make<String>(v), FeatureTag::kString},
        {make<Substring>(v), FeatureTag::kSubstring},
        {make<Regex>(v), FeatureTag::kRegex},
        {make<MatchedRule>(v), FeatureTag::kMatchedRule},
        {make<Characteristic>(v), FeatureTag::kCharacteristic},
        {make<Class>(v), FeatureTag::kClass},
        {make<Namespace>(v), FeatureTag::kNamespace},
        {make<Os>(v), FeatureTag::kOs},
        {make<Arch>(v), FeatureTag::kArch},
        {make<Format>(v), FeatureTag::kFormat},
        {make<Import>(v), FeatureTag::kImport},
        {make<Export>(v), FeatureTag::kExport},
        {make<Section>(v), FeatureTag::kSection},
        {make<FunctionName>(v), FeatureTag::kFunctionName},
        {make<Api>(v), FeatureTag::kApi},
        {make<Mnemonic>(v), FeatureTag::kMnemonic},
    };
    for (const auto& [f, tag] : rows) {
        CAPTURE(static_cast<int>(tag));
        CHECK(f->tag() == tag);
        CHECK(f->hash() == papa::util::hashing::hash_combine(static_cast<std::size_t>(tag),
                                                             std::hash<std::string>{}(v)));
        for (const auto& [other, other_tag] : rows) {
            if (other_tag != tag) { CHECK_FALSE(f->equals(*other)); }
        }
    }
}

}  // TEST_SUITE

TEST_CASE("feature semantics: matches agrees with evaluate success for every kind") {
    // The probe pass calls matches while the reporting pass calls evaluate
    FeatureSet fs;
    fs.add(make<String>("hello world"), va(0x1000));
    fs.add(make<String>("GetProcAddress"), va(0x1004));
    fs.add(make<Bytes>(bytes_of({0xDE, 0xAD, 0xBE, 0xEF})), va(0x1008));
    fs.add(make<Number>(0x40), va(0x100C));
    fs.add(make<Number>(0x40), va(0x1010));
    fs.add(make<Os>("windows"), va(0x1014));
    fs.add(make<Arch>("amd64"), va(0x1018));
    fs.add(make<Api>("CreateFileA"), va(0x101C));

    std::vector<FeaturePtr> probes;
    probes.push_back(make<String>("hello world"));
    probes.push_back(make<String>("absent"));
    probes.push_back(make<Substring>("lo wo"));
    probes.push_back(make<Substring>("nope"));
    probes.push_back(make<Regex>("/Get.*Address/"));
    probes.push_back(make<Regex>("/^nomatch$/"));
    probes.push_back(make<Bytes>(bytes_of({0xDE, 0xAD})));
    probes.push_back(make<Bytes>(bytes_of({0xAA, 0xBB})));
    probes.push_back(make<Number>(0x40));
    probes.push_back(make<Number>(0x41));
    probes.push_back(make<Os>("windows"));
    probes.push_back(make<Os>("linux"));
    probes.push_back(make<Os>("any"));
    probes.push_back(make<Arch>("amd64"));
    probes.push_back(make<Arch>("i386"));
    probes.push_back(make<Arch>("any"));
    probes.push_back(make<Api>("CreateFileA"));
    probes.push_back(make<Api>("NotPresent"));

    for (std::size_t i = 0; i < probes.size(); ++i) {
        CAPTURE(i);
        CHECK(probes[i]->matches(fs) == probes[i]->evaluate(fs, true).success);
    }

    // The empty set must agree too
    const FeatureSet empty;
    for (std::size_t i = 0; i < probes.size(); ++i) {
        CAPTURE(i);
        CHECK(probes[i]->matches(empty) == probes[i]->evaluate(empty, true).success);
    }
}

TEST_CASE("engine: Range evaluate_quick agrees with evaluate success") {
    FeatureSet fs;
    fs.add(make<Number>(7), va(0x2000));
    fs.add(make<Number>(7), va(0x2004));
    fs.add(make<Number>(7), va(0x2008));

    struct Bound { std::size_t min; std::size_t max; };
    const Bound bounds[] = {
        {0, 0}, {0, 2}, {0, 3}, {1, 3}, {3, 3}, {4, 10},
        {0, std::numeric_limits<std::size_t>::max()},
    };
    for (const auto& b : bounds) {
        CAPTURE(b.min);
        CAPTURE(b.max);
        const papa::engine::Range present(make<Number>(7), b.min, b.max);
        CHECK(present.evaluate_quick(fs) == present.evaluate(fs, true).success);
        const papa::engine::Range absent(make<Number>(99), b.min, b.max);
        CHECK(absent.evaluate_quick(fs) == absent.evaluate(fs, true).success);
    }
}
