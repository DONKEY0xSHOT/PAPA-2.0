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

#include "test_support.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace papa::features;

using papa_tests::feat;
using papa_tests::va;

TEST_SUITE("feature_semantics") {

TEST_CASE("Structural equality compares tag and every part of the payload, and equal features hash equal") {
    using Access = Property::Access;
    struct Row {
        std::string_view label;
        FeaturePtr       a;
        FeaturePtr       b;
        bool             equal;
    };
    const auto opnum = [](std::size_t index) {
        return feat<OperandNumber>(index, OperandNumber::Value{std::uint64_t{0x10}});
    };
    const std::vector<Row> rows{
        {"two strings with one value", feat<String>(std::string("foo")),
         feat<String>(std::string("foo")), true},
        {"two strings with different values", feat<String>(std::string("foo")),
         feat<String>(std::string("bar")), false},
        {"properties with one name and access", feat<Property>(std::string("MyProp"), Access::kRead),
         feat<Property>(std::string("MyProp"), Access::kRead), true},
        {"properties differing in access", feat<Property>(std::string("MyProp"), Access::kRead),
         feat<Property>(std::string("MyProp"), Access::kWrite), false},
        {"properties differing in name", feat<Property>(std::string("MyProp"), Access::kRead),
         feat<Property>(std::string("Other"), Access::kRead), false},
        {"operand numbers on one index", opnum(0), opnum(0), true},
        {"operand numbers on different indices", opnum(0), opnum(1), false},
        // Different active alternatives of std::variant compare unequal even if their
        // stored values would compare equal as their underlying numeric types
        {"an unsigned and a signed zero", feat<Number>(Number::Value{std::uint64_t{0}}),
         feat<Number>(Number::Value{std::int64_t{0}}), false},
        {"an unsigned and a floating zero", feat<Number>(Number::Value{std::uint64_t{0}}),
         feat<Number>(Number::Value{0.0}), false},
        {"a signed and a floating zero", feat<Number>(Number::Value{std::int64_t{0}}),
         feat<Number>(Number::Value{0.0}), false},
        {"two equal unsigned numbers", feat<Number>(Number::Value{std::uint64_t{5}}),
         feat<Number>(Number::Value{std::uint64_t{5}}), true},
        {"two different unsigned numbers", feat<Number>(Number::Value{std::uint64_t{5}}),
         feat<Number>(Number::Value{std::uint64_t{6}}), false},
        {"two equal signed numbers", feat<Number>(Number::Value{std::int64_t{-1}}),
         feat<Number>(Number::Value{std::int64_t{-1}}), true},
        {"two different signed numbers", feat<Number>(Number::Value{std::int64_t{-1}}),
         feat<Number>(Number::Value{std::int64_t{-2}}), false},
        {"two equal floating numbers", feat<Number>(Number::Value{1.5}),
         feat<Number>(Number::Value{1.5}), true},
        {"two not-a-number values", feat<Number>(Number::Value{std::numeric_limits<double>::quiet_NaN()}),
         feat<Number>(Number::Value{std::numeric_limits<double>::quiet_NaN()}), false},
        {"operand numbers with different values",
         feat<OperandNumber>(std::size_t{0}, OperandNumber::Value{std::uint64_t{0x10}}),
         feat<OperandNumber>(std::size_t{0}, OperandNumber::Value{std::uint64_t{0x20}}), false},
        {"two basic blocks", feat<BasicBlock>(), feat<BasicBlock>(), true},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(row.a->equals(*row.b) == row.equal);
        if (row.equal) { CHECK(row.a->hash() == row.b->hash()); }
    }
}

TEST_CASE("FeatureSet deduplicates structurally equal features") {
    FeatureSet fs;
    fs.add(feat<String>(std::string("foo")), va(0x1));
    fs.add(feat<String>(std::string("foo")), va(0x2));
    fs.add(feat<String>(std::string("bar")), va(0x3));
    CHECK(fs.size() == 2);
    // The first entry still keyed by "foo" now holds both locations
    auto probe = feat<String>(std::string("foo"));
    auto it = fs.find(probe);
    REQUIRE(it != fs.end());
    CHECK(it->second.size() == 2);
}

TEST_CASE("FeatureSet add_all copies or moves a batch and keeps the string index in order") {
    const std::vector<std::pair<FeaturePtr, Address>> shared = {
        {feat<String>(std::string("foo")), va(0x1)},
        {feat<Section>(std::string(".text")), va(0x2)},
    };
    std::vector<std::pair<FeaturePtr, Address>> handed_over = {
        {feat<String>(std::string("bar")), va(0x3)},
        {feat<String>(std::string("foo")), va(0x4)},
    };

    FeatureSet fs;
    fs.add_all(shared);
    fs.add_all(std::move(handed_over));
    CHECK(shared[0].first != nullptr);
    CHECK(fs.size() == 3);
    CHECK(fs.find(feat<String>(std::string("foo")))->second.size() == 2);
    REQUIRE(fs.strings().size() == 2);
    CHECK(fs.strings()[0].get() == shared[0].first.get());
    CHECK(fs.strings()[1]->equals(String{"bar"}));
}

TEST_CASE("Default evaluate is structural membership") {
    FeatureSet fs;
    fs.add(feat<Api>(std::string("kernel32.CreateFileA")), va(0x401000));
    fs.add(feat<Api>(std::string("kernel32.CreateFileA")), va(0x401020));

    Api probe{"kernel32.CreateFileA"};
    auto r = probe.evaluate(fs, /*sc=*/false);
    CHECK(r.success);
    CHECK(r.locations.size() == 2);

    Api missing{"kernel32.WriteFile"};
    auto r2 = missing.evaluate(fs, /*sc=*/false);
    CHECK_FALSE(r2.success);
    CHECK(r2.locations.empty());
}

TEST_CASE("Substring scans only String features, reporting every hit unless it short-circuits") {
    FeatureSet worlds;
    worlds.add(feat<String>(std::string("hello world")), va(0x1));
    worlds.add(feat<String>(std::string("world peace")), va(0x2));
    worlds.add(feat<String>(std::string("goodbye")), va(0x3));
    // A Bytes feature containing the needle must not match, since Substring scans String
    worlds.add(feat<Bytes>(papa_tests::byte_vec({'w', 'o', 'r', 'l', 'd'})), va(0x4));
    FeatureSet foos;
    foos.add(feat<String>(std::string("foo")), va(0x1));
    foos.add(feat<String>(std::string("foobar")), va(0x2));

    struct Row {
        std::string_view     label;
        const FeatureSet*    fs;
        std::string_view     needle;
        bool                 sc;
        std::size_t          min_locations;
        std::size_t          max_locations;
        std::vector<Address> must_include;
    };
    const std::vector<Row> rows{
        {"every string holding the needle", &worlds, "world", false, 2, 2, {va(0x1), va(0x2)}},
        // Under short-circuit the scan returns at the first hit, so the locations are
        // non-empty but may cover only one of the matching strings
        {"a short-circuited scan", &foos, "foo", true, 1, 2, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = Substring{std::string(row.needle)}.evaluate(*row.fs, row.sc);
        CHECK(r.success);
        CHECK(r.locations.size() >= row.min_locations);
        CHECK(r.locations.size() <= row.max_locations);
        for (const Address& at : row.must_include) { CHECK(r.locations.count(at) == 1); }
    }
}

TEST_CASE("Regex reads the /.../ literal and its i suffix and matches anywhere in a string") {
    FeatureSet hello;
    hello.add(feat<String>(std::string("HelloWorld")), va(0x1));
    hello.add(feat<String>(std::string("goodbye")), va(0x2));
    // A required literal must never hide a case-insensitive match
    FeatureSet vbox;
    vbox.add(feat<String>(std::string("C:\\Program Files\\VirtualBox Guest Additions")), va(0x1000));

    struct Row {
        std::string_view       label;
        const FeatureSet*      fs;
        std::string_view       literal;
        bool                   success;
        std::optional<Address> location;
    };
    const std::vector<Row> rows{
        {"/i ignores case", &hello, "/hello/i", true, va(0x1)},
        {"without /i case matters", &hello, "/hello/", false, std::nullopt},
        {"an anchored pattern", &hello, "/^good/", true, va(0x2)},
        {"a case-insensitive match with a required literal", &vbox, "/virtualbox guest/i", true,
         va(0x1000)},
        {"a case-sensitive literal", &vbox, "/VirtualBox/", true, std::nullopt},
        {"a case-insensitive miss", &vbox, "/vmware tools/i", false, std::nullopt},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const Regex re{std::string(row.literal)};
        const auto  r = re.evaluate(*row.fs, false);
        CHECK(r.success == row.success);
        CHECK(re.matches(*row.fs) == row.success);
        if (row.location.has_value()) { CHECK(r.locations.count(*row.location) == 1); }
    }
}

TEST_CASE("Bytes matches a candidate it is a prefix of, never a shorter one or a middle occurrence") {
    FeatureSet two;
    two.add(feat<Bytes>(papa_tests::byte_vec({0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE})), va(0x100));
    two.add(feat<Bytes>(papa_tests::byte_vec({0x90, 0x90, 0x90})), va(0x200));
    // The candidate contains the pattern, but not at offset 0
    FeatureSet middle;
    middle.add(feat<Bytes>(papa_tests::byte_vec({0x00, 0xDE, 0xAD})), va(0x1));

    struct Row {
        std::string_view       label;
        const FeatureSet*      fs;
        std::vector<std::byte> pattern;
        bool                   success;
        std::vector<Address>   hit;
        std::vector<Address>   missed;
    };
    const std::vector<Row> rows{
        {"a short prefix", &two, papa_tests::byte_vec({0xDE, 0xAD}), true, {va(0x100)}, {va(0x200)}},
        {"a pattern longer than any candidate", &two,
         papa_tests::byte_vec({0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00}), false, {}, {}},
        {"an exact match is a prefix of equal length", &two, papa_tests::byte_vec({0x90, 0x90, 0x90}),
         true, {va(0x200)}, {}},
        {"a middle occurrence", &middle, papa_tests::byte_vec({0xDE, 0xAD}), false, {}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = Bytes{row.pattern}.evaluate(*row.fs, false);
        CHECK(r.success == row.success);
        for (const Address& at : row.hit) { CHECK(r.locations.count(at) == 1); }
        for (const Address& at : row.missed) { CHECK(r.locations.count(at) == 0); }
    }
}

TEST_CASE("Os and Arch: only os treats any as a wildcard, in both directions") {
    // Each set holds its features at the given addresses
    using Entries = std::vector<std::pair<FeaturePtr, Address>>;
    const Address a = va(0x1000);
    const Address b = va(0x2000);
    const auto os   = [](std::string v) { return feat<Os>(std::move(v)); };
    const auto arch = [](std::string v) { return feat<Arch>(std::move(v)); };
    struct Row {
        std::string_view                           label;
        Entries                                    set;
        FeaturePtr                                 probe;
        bool                                       success;
        std::optional<std::unordered_set<Address>> locations;
    };
    const std::vector<Row> rows{
        {"os any in a rule matches a concrete os", {{os("windows"), a}}, os("any"), true, {}},
        {"os windows matches windows", {{os("windows"), a}}, os("windows"), true, {}},
        {"os linux does not match windows", {{os("windows"), a}}, os("linux"), false, {}},
        {"os any in the set matches a concrete rule", {{os("any"), a}}, os("windows"), true,
         std::unordered_set<Address>{a}},
        {"arch any in a rule does not match amd64", {{arch("amd64"), a}}, arch("any"), false, {}},
        {"arch amd64 matches amd64", {{arch("amd64"), a}}, arch("amd64"), true, {}},
        {"arch i386 does not match amd64", {{arch("amd64"), a}}, arch("i386"), false, {}},
        {"arch any matches only a literal any", {{arch("any"), a}}, arch("any"), true, {}},
        {"arch amd64 does not match i386", {{arch("i386"), a}}, arch("amd64"), false, {}},
        {"arch any does not match i386", {{arch("i386"), a}}, arch("any"), false, {}},
        {"arch any in the set does not match amd64", {{arch("any"), a}}, arch("amd64"), false, {}},
        // Only the set side any contributes locations to a concrete rule
        {"a concrete os takes its locations from the set's any", {{os("windows"), a}, {os("any"), b}},
         os("linux"), true, std::unordered_set<Address>{b}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        FeatureSet fs;
        for (const auto& [f, at] : row.set) { fs.add(f, at); }
        const auto r = row.probe->evaluate(fs, false);
        CHECK(r.success == row.success);
        CHECK(row.probe->matches(fs) == row.success);
        if (row.locations.has_value()) { CHECK(r.locations == *row.locations); }
    }
}

TEST_CASE("Different feature kinds never collide in a FeatureSet") {
    // Each feature has a distinct tag so fs.size() must equal the insertion count
    FeatureSet fs;
    fs.add(feat<String>(std::string("foo")),                           va(0x1));
    fs.add(feat<Api>(std::string("foo")),                              va(0x2));
    fs.add(feat<Import>(std::string("foo")),                           va(0x3));
    fs.add(feat<Export>(std::string("foo")),                           va(0x4));
    fs.add(feat<Section>(std::string("foo")),                          va(0x5));
    fs.add(feat<FunctionName>(std::string("foo")),                     va(0x6));
    fs.add(feat<Mnemonic>(std::string("foo")),                         va(0x7));
    fs.add(feat<Characteristic>(std::string("foo")),                   va(0x8));
    fs.add(feat<Class>(std::string("foo")),                            va(0x9));
    fs.add(feat<Namespace>(std::string("foo")),                        va(0xA));
    fs.add(feat<MatchedRule>(std::string("foo")),                      va(0xB));
    fs.add(feat<Os>(std::string("foo")),                               va(0xC));
    fs.add(feat<Arch>(std::string("foo")),                             va(0xD));
    fs.add(feat<Format>(std::string("foo")),                           va(0xE));
    CHECK(fs.size() == 14);
}

TEST_CASE("Single-string features hash the tag mixed into the value hash") {
    // One shared value, a regex literal so Regex must hash the literal, not its pattern
    const std::string v = "/foo/i";
    const std::pair<FeaturePtr, FeatureTag> rows[] = {
        {feat<String>(v), FeatureTag::kString},
        {feat<Substring>(v), FeatureTag::kSubstring},
        {feat<Regex>(v), FeatureTag::kRegex},
        {feat<MatchedRule>(v), FeatureTag::kMatchedRule},
        {feat<Characteristic>(v), FeatureTag::kCharacteristic},
        {feat<Class>(v), FeatureTag::kClass},
        {feat<Namespace>(v), FeatureTag::kNamespace},
        {feat<Os>(v), FeatureTag::kOs},
        {feat<Arch>(v), FeatureTag::kArch},
        {feat<Format>(v), FeatureTag::kFormat},
        {feat<Import>(v), FeatureTag::kImport},
        {feat<Export>(v), FeatureTag::kExport},
        {feat<Section>(v), FeatureTag::kSection},
        {feat<FunctionName>(v), FeatureTag::kFunctionName},
        {feat<Api>(v), FeatureTag::kApi},
        {feat<Mnemonic>(v), FeatureTag::kMnemonic},
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

TEST_CASE("Number and OperandNumber hash the payload with its alternative index folded in") {
    using papa::util::hashing::hash_combine;
    // One value per alternative, each paired with the hash of its payload alone
    const std::pair<Number::Value, std::size_t> rows[] = {
        {Number::Value{std::uint64_t{0x40}}, std::hash<std::uint64_t>{}(0x40)},
        {Number::Value{std::int64_t{-8}}, std::hash<std::int64_t>{}(-8)},
        {Number::Value{2.5}, papa::util::hashing::hash_double_bits(2.5)},
    };
    for (const auto& [v, payload] : rows) {
        CAPTURE(v.index());
        const std::size_t value_hash = hash_combine(payload, v.index());
        CHECK(feat<Number>(v)->hash() ==
              hash_combine(static_cast<std::size_t>(FeatureTag::kNumber), value_hash));
        CHECK(feat<OperandNumber>(std::size_t{1}, v)->hash() ==
              hash_combine(static_cast<std::size_t>(FeatureTag::kOperandNumber),
                           hash_combine(std::hash<std::size_t>{}(1), value_hash)));
    }
}

}  // TEST_SUITE

TEST_CASE("feature semantics: matches agrees with evaluate success for every kind") {
    // The probe pass calls matches while the reporting pass calls evaluate
    FeatureSet fs;
    fs.add(feat<String>("hello world"), va(0x1000));
    fs.add(feat<String>("GetProcAddress"), va(0x1004));
    fs.add(feat<Bytes>(papa_tests::byte_vec({0xDE, 0xAD, 0xBE, 0xEF})), va(0x1008));
    fs.add(feat<Number>(0x40), va(0x100C));
    fs.add(feat<Number>(0x40), va(0x1010));
    fs.add(feat<Os>("windows"), va(0x1014));
    fs.add(feat<Arch>("amd64"), va(0x1018));
    fs.add(feat<Api>("CreateFileA"), va(0x101C));

    std::vector<FeaturePtr> probes;
    probes.push_back(feat<String>("hello world"));
    probes.push_back(feat<String>("absent"));
    probes.push_back(feat<Substring>("lo wo"));
    probes.push_back(feat<Substring>("nope"));
    probes.push_back(feat<Regex>("/Get.*Address/"));
    probes.push_back(feat<Regex>("/^nomatch$/"));
    probes.push_back(feat<Bytes>(papa_tests::byte_vec({0xDE, 0xAD})));
    probes.push_back(feat<Bytes>(papa_tests::byte_vec({0xAA, 0xBB})));
    probes.push_back(feat<Number>(0x40));
    probes.push_back(feat<Number>(0x41));
    probes.push_back(feat<Os>("windows"));
    probes.push_back(feat<Os>("linux"));
    probes.push_back(feat<Os>("any"));
    probes.push_back(feat<Arch>("amd64"));
    probes.push_back(feat<Arch>("i386"));
    probes.push_back(feat<Arch>("any"));
    probes.push_back(feat<Api>("CreateFileA"));
    probes.push_back(feat<Api>("NotPresent"));

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
