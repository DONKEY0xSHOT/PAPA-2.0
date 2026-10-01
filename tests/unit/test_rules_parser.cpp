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

#include "test_support.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

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

TEST_CASE("rules: split_inline_description splits on an unquoted ' = ' only") {
    struct Row {
        std::string_view                label;
        std::string_view                text;
        std::string_view                value;
        std::optional<std::string_view> description;
    };
    const std::vector<Row> rows{
        {"a value and its description", "0x10 = MAGIC_CONST", "0x10", "MAGIC_CONST"},
        {"a quoted string is left alone", "\"a = b\"", "\"a = b\"", std::nullopt},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto [v, d] = RuleParser::split_inline_description(row.text);
        CHECK(v == row.value);
        CHECK(d.has_value() == row.description.has_value());
        if (d.has_value() && row.description.has_value()) { CHECK(*d == *row.description); }
    }
}

TEST_CASE("rules: parse_number_literal reads hex, decimal, negative and floating point literals") {
    struct Row {
        std::string_view label;
        std::string_view text;
        NumberValue      expected;
    };
    const std::vector<Row> rows{
        {"hex unsigned", "0x10", std::uint64_t{16}},
        {"decimal unsigned", "42", std::uint64_t{42}},
        {"negative", "-1", std::int64_t{-1}},
        {"floating point", "1.5", 1.5},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = RuleParser::parse_number_literal(row.text);
        REQUIRE(r);
        CHECK(r->index() == row.expected.index());
        if (r->index() != row.expected.index()) { continue; }
        if (const auto* d = std::get_if<double>(&row.expected)) {
            CHECK(std::get<double>(*r) == doctest::Approx(*d));
        } else {
            CHECK((*r == row.expected));
        }
    }
}

TEST_CASE("rules: parse_count_range reads an exact count, N or more and a (min, max) pair") {
    struct Row {
        std::string_view label;
        std::string_view text;
        std::size_t      min;
        std::size_t      max;
    };
    const std::vector<Row> rows{
        {"an integer", "3", 3, 3},
        {"or more", "2 or more", 2, SIZE_MAX},
        {"zero or more", "0 or more", 0, SIZE_MAX},
        {"a pair tuple", "(1, 3)", 1, 3},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = RuleParser::parse_count_range(row.text);
        REQUIRE(r);
        CHECK(r->min == row.min);
        CHECK(r->max == row.max);
    }
}

TEST_CASE("rules: parse_bytes_literal reads hex bytes and ?? wildcards") {
    // A negative entry is a wildcard
    struct Row {
        std::string_view label;
        std::string_view text;
        bool             wildcards;
        std::vector<int> pattern;
    };
    const std::vector<Row> rows{
        {"hex bytes", "DE AD BE EF", false, {0xDE, 0xAD, 0xBE, 0xEF}},
        {"a wildcard", "01 02 ?? 04", true, {0x01, 0x02, -1, 0x04}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = RuleParser::parse_bytes_literal(row.text);
        REQUIRE(r);
        CHECK(r->has_wildcards == row.wildcards);
        CHECK(r->pattern.size() == row.pattern.size());
        for (std::size_t i = 0; i < r->pattern.size() && i < row.pattern.size(); ++i) {
            CAPTURE(i);
            CHECK(r->pattern[i].has_value() == (row.pattern[i] >= 0));
            if (r->pattern[i].has_value() && row.pattern[i] >= 0) {
                CHECK(std::to_integer<int>(*r->pattern[i]) == row.pattern[i]);
            }
        }
    }
}

// Whole-rule parsing
// Whole-rule parsing

TEST_CASE("rules: the meta block sets the name, scopes, namespace, authors, description, lib flag and tags") {
    struct Meta {
        std::string_view           name;
        Scope                      scope = Scope::kFunction;
        std::optional<Scope>       dynamic;
        std::optional<std::string> namespace_;
        std::vector<std::string>   authors;
        std::optional<std::string> description;
        bool                       lib = false;
        std::vector<std::string>   att_and_ck;
        std::vector<std::string>   mbc;
    };
    struct Row {
        std::string_view label;
        std::string      text;
        Meta             meta;
    };
    const std::vector<Row> rows{
        {"a minimal rule",
         "rule:\n"
         "  meta:\n"
         "    name: simple rule\n"
         "    scope: function\n"
         "  features:\n"
         "    - api: kernel32.CreateFileA\n",
         {.name = "simple rule"}},
        {"a namespace, authors and a description",
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
         "    - import: kernel32.IsDebuggerPresent\n",
         {.name        = "anti-vm probe",
          .scope       = Scope::kFile,
          .namespace_  = "anti-analysis/vm",
          .authors     = {"alice@example.com", "bob@example.com"},
          .description = "detects VM probing"}},
        {"a scopes block with static and dynamic scopes",
         "rule:\n"
         "  meta:\n"
         "    name: scoped rule\n"
         "    scopes:\n"
         "      static: basic block\n"
         "      dynamic: process\n"
         "  features:\n"
         "    - mnemonic: xor\n",
         {.name = "scoped rule", .scope = Scope::kBasicBlock, .dynamic = Scope::kProcess}},
        {"the lib flag",
         "rule:\n"
         "  meta:\n"
         "    name: lib-rule\n"
         "    scope: function\n"
         "    lib: true\n"
         "  features:\n"
         "    - api: kernel32.CreateFileA\n",
         {.name = "lib-rule", .lib = true}},
        {"att&ck and mbc lists",
         "rule:\n"
         "  meta:\n"
         "    name: tagged\n"
         "    scope: function\n"
         "    att&ck:\n"
         "      - Discovery::System Information Discovery [T1082]\n"
         "    mbc:\n"
         "      - OS::Environment Variable [B0029]\n"
         "  features:\n"
         "    - api: kernel32.GetSystemInfo\n",
         {.name       = "tagged",
          .att_and_ck = {"Discovery::System Information Discovery [T1082]"},
          .mbc        = {"OS::Environment Variable [B0029]"}}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = RuleParser::parse(row.text, "rule.yml");
        REQUIRE(r);
        const auto& m = (*r)->meta();
        CHECK(m.name == row.meta.name);
        CHECK(m.source_path == "rule.yml");
        CHECK((*r)->scope() == row.meta.scope);
        CHECK(m.scopes.static_scope == row.meta.scope);
        CHECK(m.scopes.dynamic_scope == row.meta.dynamic);
        CHECK(m.namespace_ == row.meta.namespace_);
        CHECK(m.authors == row.meta.authors);
        CHECK(m.description == row.meta.description);
        CHECK((*r)->is_lib() == row.meta.lib);
        CHECK(m.att_and_ck == row.meta.att_and_ck);
        CHECK(m.mbc == row.meta.mbc);
    }
}

TEST_CASE("rules: api leaf trims the dll part like capa") {
    auto api_value = [](std::string_view api_line) -> std::string {
        const auto r = papa_tests::rule(
            papa_tests::rule_yaml("r", "function", {"api: " + std::string(api_line)}));
        return must_be<Api>(feat_of(r->statement())).value();
    };
    // single-dot native names drop the dll
    CHECK(api_value("kernel32.GetTickCount") == "GetTickCount");
    CHECK(api_value("ntdll.NtTerminateProcess") == "NtTerminateProcess");
    // already-bare names are unchanged
    CHECK(api_value("exit") == "exit");
    // ordinal imports keep the dll
    CHECK(api_value("ws2_32.#1") == "ws2_32.#1");
    // dotnet names with :: keep their full form
    CHECK(api_value("System.Convert::FromBase64String") == "System.Convert::FromBase64String");
}

TEST_CASE("rules: and, or, not, optional and N or more parse into their statements with every child") {
    struct Row {
        std::string_view           label;
        std::string                block;
        std::string_view           name;
        std::size_t                children;
        std::optional<std::size_t> some_count;
    };
    const std::vector<Row> rows{
        {"and", "and:\n      - api: kernel32.CreateFileA\n      - api: kernel32.WriteFile", "and",
         2, std::nullopt},
        {"or", "or:\n      - api: foo\n      - api: bar", "or", 2, std::nullopt},
        {"not wraps exactly one child", "not:\n      - api: foo", "not", 1, std::nullopt},
        {"optional maps to Some(0, ...)", "optional:\n      - api: foo", "optional", 1, 0},
        {"3 or more keeps its count",
         "3 or more:\n      - api: foo\n      - api: bar\n      - api: baz\n      - api: qux",
         "some", 4, 3},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = RuleParser::parse(papa_tests::rule_yaml("r", "function", {row.block}),
                                         "rule.yml");
        REQUIRE(r);
        const Statement& st = (*r)->statement();
        CHECK(st.name() == row.name);
        CHECK(st.children().size() == row.children);
        if (row.some_count.has_value()) { CHECK(must_be<Some>(st).count() == *row.some_count); }
    }
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

TEST_CASE("rules: each leaf key parses into its feature with its value, index, access and flags") {
    // rendered is the feature's tag and value, as papa_tests::describe spells them, and
    // a regex also names its pattern and whether it ignores case
    struct RegexSpec {
        std::string_view pattern;
        bool             case_insensitive;
    };
    struct Row {
        std::string_view                label;
        std::string_view                scope;
        std::string                     line;
        std::string_view                rendered;
        std::optional<RegexSpec>        regex;
        std::optional<std::string_view> description;
    };
    const std::vector<Row> rows{
        // api matching is dll-agnostic since capa v7, so the dll part is trimmed
        {"api", "function", "api: kernel32.CreateFileA", "api CreateFileA", {}, {}},
        {"number", "function", "number: 0x10", "number 0x10", {}, {}},
        {"offset", "function", "offset: 0x20", "offset 32", {}, {}},
        {"mnemonic", "function", "mnemonic: xor", "mnemonic xor", {}, {}},
        {"string", "function", "string: \"hello\"", "string hello", {}, {}},
        {"substring", "function", "substring: world", "substring world", {}, {}},
        {"bytes", "function", "bytes: DE AD BE EF", "bytes deadbeef", {}, {}},
        {"characteristic", "function", "characteristic: nzxor", "characteristic nzxor", {}, {}},
        {"operand[0].number", "function", "operand[0].number: 0x100", "operand number 0 0x100", {},
         {}},
        {"operand[1].offset", "function", "operand[1].offset: 8", "operand offset 1 8", {}, {}},
        {"a case-insensitive regex literal", "file", "string: /he.*o/i", "regex /he.*o/i",
         RegexSpec{"he.*o", true}, {}},
        {"a regex literal without flags", "file", "string: /abc/", "regex /abc/",
         RegexSpec{"abc", false}, {}},
        {"a number with an inline description", "function", "number: 0x10 = SECTOR_SIZE",
         "number 0x10", {}, "SECTOR_SIZE"},
        {"import", "file", "import: kernel32.CreateFileA", "import kernel32.CreateFileA", {}, {}},
        {"export", "file", "export: DllRegisterServer", "export DllRegisterServer", {}, {}},
        {"section", "file", "section: .text", "section .text", {}, {}},
        {"function-name", "file", "function-name: my_main", "function-name my_main", {}, {}},
        {"property/read", "instruction", "property/read: System.IO.File::Exists",
         "property System.IO.File::Exists 1", {}, {}},
        {"property/write", "instruction", "property/write: System.IO.File::Length",
         "property System.IO.File::Length 2", {}, {}},
        {"match", "file", "match: get-system-info", "match get-system-info", {}, {}},
        {"os", "function", "os: windows", "os windows", {}, {}},
        {"format", "function", "format: pe", "format pe", {}, {}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = RuleParser::parse(papa_tests::rule_yaml("r", row.scope, {row.line}),
                                         "rule.yml");
        REQUIRE(r);
        const auto* leaf = dynamic_cast<const FeatureStatement*>(&(*r)->statement());
        REQUIRE(leaf != nullptr);
        std::string rendered = papa_tests::describe(papa::features::extractors::FeatureWithAddress{
            leaf->feature(), papa::features::NoAddress{}});
        rendered.erase(rendered.rfind(" @ "));
        CHECK(rendered == row.rendered);
        if (row.regex.has_value()) {
            const auto& re = must_be<Regex>(*leaf->feature());
            CHECK(re.pattern() == row.regex->pattern);
            CHECK(re.case_insensitive() == row.regex->case_insensitive);
        }
        if (row.description.has_value()) {
            CHECK(leaf->feature()->description() == *row.description);
        }
    }
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

TEST_CASE("rules: com/class and com/interface expand to Or(Bytes, String)") {
    struct Row {
        std::string_view label;
        std::string_view line;
    };
    const std::vector<Row> rows{
        {"a class from the CLSID table", "com/class: ShellDesktop"},
        {"an interface from the IID table", "com/interface: IUnknown"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = RuleParser::parse(
            papa_tests::rule_yaml("r", "instruction", {std::string(row.line)}), "rule.yml");
        REQUIRE(r);
        const Statement& st = (*r)->statement();
        CHECK(st.name() == "or");
        REQUIRE(st.children().size() == 2);
        // One Bytes child for the binary GUID and one String child for its canonical form
        const FeatureTag a = feat_of(*st.children()[0]).tag();
        const FeatureTag b = feat_of(*st.children()[1]).tag();
        CHECK(((a == FeatureTag::kBytes && b == FeatureTag::kString) ||
               (a == FeatureTag::kString && b == FeatureTag::kBytes)));
    }
}

TEST_CASE("rules: a rule missing its name, a feature outside its scope or an unknown COM name is rejected") {
    struct Row {
        std::string_view label;
        std::string      text;
        std::string_view detail;
    };
    const std::vector<Row> rows{
        {"a missing name",
         "rule:\n"
         "  meta:\n"
         "    scope: file\n"
         "  features:\n"
         "    - api: foo\n",
         "missing 'meta.name'"},
        // section is a file-only feature, so it must not appear at function scope
        {"a feature in an incompatible scope",
         papa_tests::rule_yaml("bad-scope", "function", {"section: .text"}),
         "feature 'section' not allowed at scope function"},
        {"an unknown com/class name",
         papa_tests::rule_yaml("bad-com", "instruction", {"com/class: NotARealClass"}),
         "unknown COM class name: NotARealClass"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = RuleParser::parse(row.text, "bad.yml");
        CHECK_FALSE(r);
        if (r) { continue; }
        CHECK(r.error().kind == ErrorKind::kInvalidRule);
        CHECK(r.error().detail.find(row.detail) != std::string::npos);
    }
}
