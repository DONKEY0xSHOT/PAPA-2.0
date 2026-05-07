#include <ostream>

#include "doctest.h"

#include "papa/rules/parser.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/basic_block.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/features/insn.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <variant>

using papa::ErrorKind;
using papa::engine::And;
using papa::engine::FeatureStatement;
using papa::engine::Not;
using papa::engine::Or;
using papa::engine::Range;
using papa::engine::Some;
using papa::engine::Statement;
using papa::engine::Subscope;
using papa::features::Api;
using papa::features::BasicBlock;
using papa::features::Bytes;
using papa::features::Characteristic;
using papa::features::Export;
using papa::features::Feature;
using papa::features::FeatureTag;
using papa::features::Format;
using papa::features::FunctionName;
using papa::features::Import;
using papa::features::MatchedRule;
using papa::features::Mnemonic;
using papa::features::Number;
using papa::features::Offset;
using papa::features::OperandNumber;
using papa::features::OperandOffset;
using papa::features::Os;
using papa::features::Property;
using papa::features::Regex;
using papa::features::Section;
using papa::features::String;
using papa::features::Substring;
using papa::rules::CountRange;
using papa::rules::NumberValue;
using papa::rules::Rule;
using papa::rules::RuleParser;
using papa::rules::Scope;

namespace {

// Helper: pull a leaf feature out of a FeatureStatement-and-only-child wrapper
const Feature& feat_of(const Statement& st) {
    const auto* fs = dynamic_cast<const FeatureStatement*>(&st);
    REQUIRE(fs != nullptr);
    REQUIRE(fs->feature() != nullptr);
    return *fs->feature();
}

// Cast helper that fails the test rather than returning null
template <typename T>
const T& must_be(const Feature& f) {
    const auto* p = dynamic_cast<const T*>(&f);
    REQUIRE(p != nullptr);
    return *p;
}

template <typename T>
const T& must_be(const Statement& s) {
    const auto* p = dynamic_cast<const T*>(&s);
    REQUIRE(p != nullptr);
    return *p;
}

}  // namespace

// --- helper functions ---------------------------------------------------

TEST_CASE("rules: split_inline_description splits on unquoted ' = '") {
    const auto [v, d] = RuleParser::split_inline_description("0x10 = MAGIC_CONST");
    CHECK(v == "0x10");
    REQUIRE(d.has_value());
    CHECK(*d == "MAGIC_CONST");
}

TEST_CASE("rules: split_inline_description leaves quoted strings alone") {
    const auto [v, d] = RuleParser::split_inline_description("\"a = b\"");
    CHECK(v == "\"a = b\"");
    CHECK_FALSE(d.has_value());
}

TEST_CASE("rules: parse_number_literal hex unsigned") {
    auto r = RuleParser::parse_number_literal("0x10");
    REQUIRE(r);
    REQUIRE(std::holds_alternative<std::uint64_t>(*r));
    CHECK(std::get<std::uint64_t>(*r) == 16U);
}

TEST_CASE("rules: parse_number_literal decimal unsigned") {
    auto r = RuleParser::parse_number_literal("42");
    REQUIRE(r);
    REQUIRE(std::holds_alternative<std::uint64_t>(*r));
    CHECK(std::get<std::uint64_t>(*r) == 42U);
}

TEST_CASE("rules: parse_number_literal negative") {
    auto r = RuleParser::parse_number_literal("-1");
    REQUIRE(r);
    REQUIRE(std::holds_alternative<std::int64_t>(*r));
    CHECK(std::get<std::int64_t>(*r) == -1);
}

TEST_CASE("rules: parse_number_literal floating point") {
    auto r = RuleParser::parse_number_literal("1.5");
    REQUIRE(r);
    REQUIRE(std::holds_alternative<double>(*r));
    CHECK(std::get<double>(*r) == doctest::Approx(1.5));
}

TEST_CASE("rules: parse_count_range integer") {
    auto r = RuleParser::parse_count_range("3");
    REQUIRE(r);
    CHECK(r->min == 3);
    CHECK(r->max == 3);
}

TEST_CASE("rules: parse_count_range or-more") {
    auto r = RuleParser::parse_count_range("2 or more");
    REQUIRE(r);
    CHECK(r->min == 2);
    CHECK(r->max == SIZE_MAX);
}

TEST_CASE("rules: parse_count_range zero or more") {
    auto r = RuleParser::parse_count_range("0 or more");
    REQUIRE(r);
    CHECK(r->min == 0);
    CHECK(r->max == SIZE_MAX);
}

TEST_CASE("rules: parse_count_range pair tuple") {
    auto r = RuleParser::parse_count_range("(1, 3)");
    REQUIRE(r);
    CHECK(r->min == 1);
    CHECK(r->max == 3);
}

TEST_CASE("rules: parse_bytes_literal hex bytes") {
    auto r = RuleParser::parse_bytes_literal("DE AD BE EF");
    REQUIRE(r);
    CHECK_FALSE(r->has_wildcards);
    REQUIRE(r->pattern.size() == 4);
    REQUIRE(r->pattern[0].has_value());
    CHECK(static_cast<std::uint8_t>(*r->pattern[0]) == 0xDE);
    CHECK(static_cast<std::uint8_t>(*r->pattern[3]) == 0xEF);
}

TEST_CASE("rules: parse_bytes_literal with wildcards") {
    auto r = RuleParser::parse_bytes_literal("01 02 ?? 04");
    REQUIRE(r);
    CHECK(r->has_wildcards);
    REQUIRE(r->pattern.size() == 4);
    CHECK_FALSE(r->pattern[2].has_value());
}

// --- whole-rule parsing -------------------------------------------------

TEST_CASE("rules: minimal rule with single api leaf parses") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: simple rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: kernel32.CreateFileA\n";
    auto r = RuleParser::parse(text, "simple.yml");
    REQUIRE(r);
    const Rule& rule = **r;
    CHECK(rule.meta().name == "simple rule");
    CHECK(rule.scope() == Scope::kFunction);
    CHECK(rule.meta().source_path == "simple.yml");
    const auto& api = must_be<Api>(feat_of(rule.statement()));
    CHECK(api.value() == "kernel32.CreateFileA");
}

TEST_CASE("rules: rule with namespace, authors, and description in meta") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: anti-vm probe\n"
        "    namespace: anti-analysis/vm\n"
        "    authors:\n"
        "      - alice@example.com\n"
        "      - bob@example.com\n"
        "    scope: file\n"
        "    description: detects VM probing\n"
        "  features:\n"
        "    - import: kernel32.IsDebuggerPresent\n";
    auto r = RuleParser::parse(text, "anti-vm.yml");
    REQUIRE(r);
    const auto& m = (*r)->meta();
    CHECK(m.namespace_.value_or("") == "anti-analysis/vm");
    REQUIRE(m.authors.size() == 2);
    CHECK(m.authors[0] == "alice@example.com");
    CHECK(m.authors[1] == "bob@example.com");
    REQUIRE(m.description.has_value());
    CHECK(*m.description == "detects VM probing");
    CHECK((*r)->scope() == Scope::kFile);
}

TEST_CASE("rules: scopes block accepts static and dynamic") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: scoped rule\n"
        "    scopes:\n"
        "      static: basic block\n"
        "      dynamic: process\n"
        "  features:\n"
        "    - mnemonic: xor\n";
    auto r = RuleParser::parse(text, "scoped.yml");
    REQUIRE(r);
    const auto& s = (*r)->meta().scopes;
    REQUIRE(s.static_scope.has_value());
    CHECK(*s.static_scope == Scope::kBasicBlock);
    REQUIRE(s.dynamic_scope.has_value());
    CHECK(*s.dynamic_scope == Scope::kProcess);
}

TEST_CASE("rules: missing name is rejected") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    scope: file\n"
        "  features:\n"
        "    - api: foo\n";
    auto r = RuleParser::parse(text, "noname.yml");
    REQUIRE_FALSE(r);
    CHECK(r.error().kind == ErrorKind::kInvalidRule);
}

TEST_CASE("rules: top-level and statement parses children") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: and-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - and:\n"
        "      - api: kernel32.CreateFileA\n"
        "      - api: kernel32.WriteFile\n";
    auto r = RuleParser::parse(text, "and.yml");
    REQUIRE(r);
    const auto& and_st = must_be<And>((*r)->statement());
    REQUIRE(and_st.children().size() == 2);
}

TEST_CASE("rules: or statement parses children") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: or-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - or:\n"
        "      - api: foo\n"
        "      - api: bar\n";
    auto r = RuleParser::parse(text, "or.yml");
    REQUIRE(r);
    must_be<Or>((*r)->statement());
}

TEST_CASE("rules: not wraps exactly one child") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: not-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - not:\n"
        "      - api: foo\n";
    auto r = RuleParser::parse(text, "not.yml");
    REQUIRE(r);
    const auto& n = must_be<Not>((*r)->statement());
    REQUIRE(n.children().size() == 1);
}

TEST_CASE("rules: optional statement maps to Some(0, ...)") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: opt-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - optional:\n"
        "      - api: foo\n";
    auto r = RuleParser::parse(text, "opt.yml");
    REQUIRE(r);
    const auto& s = must_be<Some>((*r)->statement());
    CHECK(s.count() == 0);
}

TEST_CASE("rules: N or more statement parses count") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: nm-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - 3 or more:\n"
        "      - api: foo\n"
        "      - api: bar\n"
        "      - api: baz\n"
        "      - api: qux\n";
    auto r = RuleParser::parse(text, "nm.yml");
    REQUIRE(r);
    const auto& s = must_be<Some>((*r)->statement());
    CHECK(s.count() == 3);
}

TEST_CASE("rules: count(...) becomes Range with parsed bounds") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: range-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - count(api(kernel32.CreateFileA)): 2 or more\n";
    auto r = RuleParser::parse(text, "range.yml");
    REQUIRE(r);
    const auto& rg = must_be<Range>((*r)->statement());
    CHECK(rg.min() == 2);
    CHECK(rg.max() == SIZE_MAX);
    REQUIRE(rg.feature() != nullptr);
    CHECK(rg.feature()->tag() == FeatureTag::kApi);
}

TEST_CASE("rules: leaf features cover every common spelling") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: zoo\n"
        "    scope: function\n"
        "  features:\n"
        "    - and:\n"
        "      - number: 0x10\n"
        "      - offset: 0x20\n"
        "      - mnemonic: xor\n"
        "      - string: \"hello\"\n"
        "      - substring: world\n"
        "      - bytes: DE AD BE EF\n"
        "      - characteristic: nzxor\n"
        "      - operand[0].number: 0x100\n"
        "      - operand[1].offset: 8\n";
    auto r = RuleParser::parse(text, "zoo.yml");
    REQUIRE(r);
    const auto& and_st = must_be<And>((*r)->statement());
    REQUIRE(and_st.children().size() == 9);

    must_be<Number>(feat_of(*and_st.children()[0]));
    must_be<Offset>(feat_of(*and_st.children()[1]));
    must_be<Mnemonic>(feat_of(*and_st.children()[2]));
    must_be<String>(feat_of(*and_st.children()[3]));
    must_be<Substring>(feat_of(*and_st.children()[4]));
    must_be<Bytes>(feat_of(*and_st.children()[5]));
    must_be<Characteristic>(feat_of(*and_st.children()[6]));
    const auto& opn = must_be<OperandNumber>(feat_of(*and_st.children()[7]));
    CHECK(opn.index() == 0);
    const auto& opo = must_be<OperandOffset>(feat_of(*and_st.children()[8]));
    CHECK(opo.index() == 1);
    CHECK(opo.value() == 8);
}

TEST_CASE("rules: regex literal becomes Regex feature") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: regex-rule\n"
        "    scope: file\n"
        "  features:\n"
        "    - string: /he.*o/i\n";
    auto r = RuleParser::parse(text, "regex.yml");
    REQUIRE(r);
    const auto& re = must_be<Regex>(feat_of((*r)->statement()));
    CHECK(re.case_insensitive());
    CHECK(re.pattern() == "he.*o");
}

TEST_CASE("rules: number with inline description retains description") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: inline-desc\n"
        "    scope: function\n"
        "  features:\n"
        "    - number: 0x10 = SECTOR_SIZE\n";
    auto r = RuleParser::parse(text, "inline.yml");
    REQUIRE(r);
    const auto& num = must_be<Number>(feat_of((*r)->statement()));
    CHECK(num.description() == "SECTOR_SIZE");
}

TEST_CASE("rules: import, export, section, function-name leaves work at file scope") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: file-zoo\n"
        "    scope: file\n"
        "  features:\n"
        "    - and:\n"
        "      - import: kernel32.CreateFileA\n"
        "      - export: DllRegisterServer\n"
        "      - section: .text\n"
        "      - function-name: my_main\n";
    auto r = RuleParser::parse(text, "file-zoo.yml");
    REQUIRE(r);
    const auto& and_st = must_be<And>((*r)->statement());
    REQUIRE(and_st.children().size() == 4);
    must_be<Import>(feat_of(*and_st.children()[0]));
    must_be<Export>(feat_of(*and_st.children()[1]));
    must_be<Section>(feat_of(*and_st.children()[2]));
    must_be<FunctionName>(feat_of(*and_st.children()[3]));
}

TEST_CASE("rules: property/read and property/write produce Property with access") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: prop-rule\n"
        "    scope: instruction\n"
        "  features:\n"
        "    - and:\n"
        "      - property/read: System.IO.File::Exists\n"
        "      - property/write: System.IO.File::Length\n";
    auto r = RuleParser::parse(text, "prop.yml");
    REQUIRE(r);
    const auto& and_st = must_be<And>((*r)->statement());
    REQUIRE(and_st.children().size() == 2);
    const auto& pread = must_be<Property>(feat_of(*and_st.children()[0]));
    CHECK(pread.access() == Property::Access::kRead);
    const auto& pwrite = must_be<Property>(feat_of(*and_st.children()[1]));
    CHECK(pwrite.access() == Property::Access::kWrite);
}

TEST_CASE("rules: match injects MatchedRule feature") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: composite\n"
        "    scope: file\n"
        "  features:\n"
        "    - match: get-system-info\n";
    auto r = RuleParser::parse(text, "composite.yml");
    REQUIRE(r);
    const auto& mr = must_be<MatchedRule>(feat_of((*r)->statement()));
    CHECK(mr.rule_name() == "get-system-info");
}

TEST_CASE("rules: os, arch, format leaves work everywhere") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: triple\n"
        "    scope: function\n"
        "  features:\n"
        "    - and:\n"
        "      - os: windows\n"
        "      - format: pe\n";
    auto r = RuleParser::parse(text, "triple.yml");
    REQUIRE(r);
    const auto& and_st = must_be<And>((*r)->statement());
    REQUIRE(and_st.children().size() == 2);
    must_be<Os>(feat_of(*and_st.children()[0]));
    must_be<Format>(feat_of(*and_st.children()[1]));
}

TEST_CASE("rules: subscope basic block emits a Subscope statement") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: sub-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - basic block:\n"
        "      - and:\n"
        "        - characteristic: nzxor\n"
        "        - mnemonic: xor\n";
    auto r = RuleParser::parse(text, "sub.yml");
    REQUIRE(r);
    const auto& sub = must_be<Subscope>((*r)->statement());
    CHECK(sub.scope() == Scope::kBasicBlock);
}

TEST_CASE("rules: feature in incompatible scope is rejected") {
    // section is a file-only feature, must not appear at function scope
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: bad-scope\n"
        "    scope: function\n"
        "  features:\n"
        "    - section: .text\n";
    auto r = RuleParser::parse(text, "bad.yml");
    REQUIRE_FALSE(r);
    CHECK(r.error().kind == ErrorKind::kInvalidRule);
}

TEST_CASE("rules: anchored regex flag propagates") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: re-noflag\n"
        "    scope: file\n"
        "  features:\n"
        "    - string: /abc/\n";
    auto r = RuleParser::parse(text, "rn.yml");
    REQUIRE(r);
    const auto& re = must_be<Regex>(feat_of((*r)->statement()));
    CHECK_FALSE(re.case_insensitive());
}

TEST_CASE("rules: lib flag in meta sets RuleMeta::lib") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: lib-rule\n"
        "    scope: function\n"
        "    lib: true\n"
        "  features:\n"
        "    - api: kernel32.CreateFileA\n";
    auto r = RuleParser::parse(text, "lib.yml");
    REQUIRE(r);
    CHECK((*r)->is_lib());
}

TEST_CASE("rules: com/class expands to Or(Bytes, String)") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: com-class-rule\n"
        "    scope: instruction\n"
        "  features:\n"
        "    - com/class: ShellDesktop\n";
    auto r = RuleParser::parse(text, "com.yml");
    REQUIRE(r);
    const auto& or_st = must_be<Or>((*r)->statement());
    REQUIRE(or_st.children().size() == 2);
    const Feature& a = feat_of(*or_st.children()[0]);
    const Feature& b = feat_of(*or_st.children()[1]);
    // The two children expand to one Bytes (binary GUID) and one String (canonical form)
    const bool bytes_then_string = (a.tag() == FeatureTag::kBytes && b.tag() == FeatureTag::kString);
    const bool string_then_bytes = (a.tag() == FeatureTag::kString && b.tag() == FeatureTag::kBytes);
    CHECK((bytes_then_string || string_then_bytes));
}

TEST_CASE("rules: com/interface uses the IID table") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: com-iface-rule\n"
        "    scope: instruction\n"
        "  features:\n"
        "    - com/interface: IUnknown\n";
    auto r = RuleParser::parse(text, "iface.yml");
    REQUIRE(r);
    must_be<Or>((*r)->statement());
}

TEST_CASE("rules: unknown com/class name is rejected") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: bad-com\n"
        "    scope: instruction\n"
        "  features:\n"
        "    - com/class: NotARealClass\n";
    auto r = RuleParser::parse(text, "bad.yml");
    REQUIRE_FALSE(r);
    CHECK(r.error().kind == ErrorKind::kInvalidRule);
}

TEST_CASE("rules: att&ck and mbc lists collect strings") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: tagged\n"
        "    scope: function\n"
        "    att&ck:\n"
        "      - Discovery::System Information Discovery [T1082]\n"
        "    mbc:\n"
        "      - OS::Environment Variable [B0029]\n"
        "  features:\n"
        "    - api: kernel32.GetSystemInfo\n";
    auto r = RuleParser::parse(text, "tagged.yml");
    REQUIRE(r);
    const auto& m = (*r)->meta();
    REQUIRE(m.att_and_ck.size() == 1);
    CHECK(m.att_and_ck[0] == "Discovery::System Information Discovery [T1082]");
    REQUIRE(m.mbc.size() == 1);
    CHECK(m.mbc[0] == "OS::Environment Variable [B0029]");
}
