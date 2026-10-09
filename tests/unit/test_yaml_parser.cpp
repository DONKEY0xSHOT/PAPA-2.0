#include <ostream>

#include "doctest.h"

#include "papa/exceptions.h"
#include "papa/util/yaml.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using papa::util::yaml::Node;
using papa::util::yaml::NodeKind;
using papa::util::yaml::parse;

namespace {

// Convenience helpers used by tests
[[nodiscard]] const Node& must_get(const Node& parent, std::string_view key) {
    const Node* n = parent.find(key);
    REQUIRE(n != nullptr);
    return *n;
}

}  // namespace

TEST_CASE("yaml: empty input parses to default scalar") {
    auto r = parse("");
    REQUIRE(r);
    CHECK(r->kind() == NodeKind::kScalar);
    CHECK(r->scalar().empty());
}

TEST_CASE("yaml: a block mapping keeps every key and value in insertion order") {
    using Entry = std::pair<std::string_view, std::string_view>;
    struct Row {
        std::string_view   label;
        std::string_view   text;
        std::vector<Entry> entries;
    };
    const std::vector<Row> rows{
        {"a simple mapping with three keys", "name: PAPA\nscope: file\nlib: true\n",
         {{"name", "PAPA"}, {"scope", "file"}, {"lib", "true"}}},
        {"keys out of alphabetical order", "z: 1\na: 2\nm: 3\n",
         {{"z", "1"}, {"a", "2"}, {"m", "3"}}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = parse(row.text);
        REQUIRE(r);
        CHECK(r->kind() == NodeKind::kMapping);
        CHECK(r->mapping().size() == row.entries.size());
        for (std::size_t i = 0; i < r->mapping().size() && i < row.entries.size(); ++i) {
            CAPTURE(i);
            CHECK(r->mapping()[i].first == row.entries[i].first);
            CHECK(r->mapping()[i].second.scalar() == row.entries[i].second);
        }
    }
}

TEST_CASE("yaml: nested mapping") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: foo\n"
        "    scope: function\n"
        "  features:\n"
        "    - api: kernel32.CreateFileA\n";
    auto r = parse(text);
    REQUIRE(r);
    REQUIRE(r->kind() == NodeKind::kMapping);
    const Node& rule = must_get(*r, "rule");
    REQUIRE(rule.kind() == NodeKind::kMapping);
    const Node& meta = must_get(rule, "meta");
    REQUIRE(meta.kind() == NodeKind::kMapping);
    CHECK(must_get(meta, "name").scalar()  == "foo");
    CHECK(must_get(meta, "scope").scalar() == "function");
    const Node& feats = must_get(rule, "features");
    REQUIRE(feats.kind() == NodeKind::kSequence);
    REQUIRE(feats.sequence().size() == 1);
    const Node& item = feats.sequence()[0];
    REQUIRE(item.kind() == NodeKind::kMapping);
    CHECK(must_get(item, "api").scalar() == "kernel32.CreateFileA");
}

TEST_CASE("yaml: sequence of scalars") {
    constexpr std::string_view text =
        "authors:\n"
        "  - alice\n"
        "  - bob\n"
        "  - carol\n";
    auto r = parse(text);
    REQUIRE(r);
    const Node& a = must_get(*r, "authors");
    REQUIRE(a.kind() == NodeKind::kSequence);
    REQUIRE(a.sequence().size() == 3);
    CHECK(a.sequence()[0].scalar() == "alice");
    CHECK(a.sequence()[1].scalar() == "bob");
    CHECK(a.sequence()[2].scalar() == "carol");
}

TEST_CASE("yaml: quoted scalars decode their escapes") {
    struct Row {
        std::string_view label;
        std::string_view text;
        std::string      expected;
    };
    const std::vector<Row> rows{
        {"a double-quoted \\n", "a: \"line1\\nline2\"\n", "line1\nline2"},
        {"a double-quoted \\t", "b: \"tab\\there\"\n", "tab\there"},
        {"a double-quoted \\x escape", "c: \"hex\\x41\"\n", "hexA"},
        // U+00E9 is encoded as 0xC3 0xA9 in UTF-8
        {"a double-quoted \\u escape", "d: \"unicode\\u00e9\"\n", "unicode\xC3\xA9"},
        {"a single-quoted '' is one quote", "msg: 'it''s fine'\n", "it's fine"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = parse(row.text);
        REQUIRE(r);
        REQUIRE(r->kind() == NodeKind::kMapping);
        CHECK(r->mapping().front().second.scalar() == row.expected);
    }
}

TEST_CASE("yaml: comments are ignored") {
    constexpr std::string_view text =
        "# leading comment\n"
        "name: foo  # trailing comment\n"
        "# between\n"
        "value: 42\n";
    auto r = parse(text);
    REQUIRE(r);
    CHECK(must_get(*r, "name").scalar()  == "foo");
    CHECK(must_get(*r, "value").scalar() == "42");
}

TEST_CASE("yaml: a literal block scalar keeps its newlines unless chomped, and the mapping continues after it") {
    struct Row {
        std::string_view label;
        std::string_view text;
        std::string_view desc;
    };
    const std::vector<Row> rows{
        {"| preserves newlines", "desc: |\n  line one\n  line two\nname: foo\n",
         "line one\nline two\n"},
        {"|- strips the final newline", "desc: |-\n  hi\nname: foo\n", "hi"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = parse(row.text);
        REQUIRE(r);
        const Node& d = must_get(*r, "desc");
        CHECK(d.kind() == NodeKind::kScalar);
        CHECK(d.scalar() == row.desc);
        CHECK(must_get(*r, "name").scalar() == "foo");
    }
}

TEST_CASE("yaml: each malformed document is a parse error that names its fault, and a wrong-kind accessor throws") {
    // Parse expects a parse error, and the others parse and then call that accessor on the root
    enum class Call { kParse, kScalar, kSequence, kMapping };
    struct Row {
        std::string_view label;
        std::string_view text;
        std::string_view detail;
        Call             call = Call::kParse;
    };
    constexpr std::string_view kUnsupported =
        "anchors, aliases, tags, and flow collections are not supported";
    const std::vector<Row> rows{
        {"a tab in indentation", "a:\n\tb: 1\n", "tab in indentation is not allowed"},
        {"an anchor and an alias", "a: &x foo\nb: *x\n", kUnsupported},
        {"a flow sequence", "a: [1, 2, 3]\n", kUnsupported},
        {"a flow mapping", "a: {x: 1}\n", kUnsupported},
        {"an unterminated double-quoted string", "a: \"unterminated\n",
         "unterminated double-quoted string"},
        {"an unterminated single-quoted string", "a: 'unterminated\n",
         "unterminated single-quoted string"},
        {"an invalid hex escape", "a: \"bad\\xZZ\"\n", "invalid hex digit in \\xNN escape"},
        {"a truncated hex escape", "a: \"\\x4\"\n", "truncated \\xNN escape in double-quoted string"},
        {"a truncated unicode escape", "a: \"\\u12\"\n",
         "truncated \\uNNNN escape in double-quoted string"},
        {"an invalid unicode escape digit", "a: \"\\u12G4\"\n", "invalid hex digit in \\uNNNN escape"},
        {"a surrogate unicode escape", "a: \"\\uD800\"\n", "surrogate code point in \\uNNNN escape"},
        {"an unknown escape", "a: \"\\q\"\n", "unknown escape in double-quoted string"},
        {"a value that is no sequence, mapping or scalar", "a:\n  @x\n",
         "expected a sequence, mapping, or scalar value"},
        {"a mapping indented under a sequence item", "a:\n  - x\n    b: c\n",
         "unexpected indent inside sequence"},
        {"a key indented under a mapping value", "a: 1\n  b: 2\n", "unexpected indent inside mapping"},
        {"text after a double-quoted key", "\"ab\"c: v\n", "unterminated double-quoted key"},
        {"text after a single-quoted key", "'ab'c: v\n", "unterminated single-quoted key"},
        {"a sequence item after the root mapping", "a: 1\n- b\n", "extra content after document end"},
        {"a second document", "a: 1\n---\nb: 2\n", "extra content after document end"},
        {"scalar() on a mapping", "a: 1\n", "scalar called on non-scalar node", Call::kScalar},
        {"sequence() on a mapping", "a: 1\n", "sequence called on non-sequence node",
         Call::kSequence},
        {"mapping() on a scalar", "", "mapping called on non-mapping node", Call::kMapping},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = parse(row.text);
        if (row.call == Call::kParse) {
            CHECK_FALSE(r);
            if (r) { continue; }
            CHECK(r.error().kind == papa::ErrorKind::kYamlParseError);
            CHECK(r.error().detail.find(row.detail) != std::string::npos);
            continue;
        }
        REQUIRE(r);
        std::string thrown;
        try {
            switch (row.call) {
                case Call::kScalar:   (void)r->scalar();   break;
                case Call::kSequence: (void)r->sequence(); break;
                case Call::kMapping:  (void)r->mapping();  break;
                case Call::kParse:    break;
            }
        } catch (const papa::PapaInvariantError& e) {
            thrown = e.what();
        }
        CHECK(thrown.find(row.detail) != std::string::npos);
    }
}

TEST_CASE("yaml: dash item with inline mapping") {
    constexpr std::string_view text =
        "rules:\n"
        "  - name: foo\n"
        "    scope: function\n"
        "  - name: bar\n"
        "    scope: file\n";
    auto r = parse(text);
    REQUIRE(r);
    const Node& seq = must_get(*r, "rules");
    REQUIRE(seq.kind() == NodeKind::kSequence);
    REQUIRE(seq.sequence().size() == 2);
    const Node& a = seq.sequence()[0];
    REQUIRE(a.kind() == NodeKind::kMapping);
    CHECK(must_get(a, "name").scalar()  == "foo");
    CHECK(must_get(a, "scope").scalar() == "function");
    const Node& b = seq.sequence()[1];
    REQUIRE(b.kind() == NodeKind::kMapping);
    CHECK(must_get(b, "name").scalar()  == "bar");
    CHECK(must_get(b, "scope").scalar() == "file");
}

TEST_CASE("yaml: capa-style nested rule layout") {
    constexpr std::string_view text =
        "rule:\n"
        "  meta:\n"
        "    name: extract embedded PE\n"
        "    namespace: anti-analysis/packer\n"
        "    authors:\n"
        "      - william.ballenthin@mandiant.com\n"
        "    scope: file\n"
        "  features:\n"
        "    - and:\n"
        "      - characteristic: embedded pe\n"
        "      - count(string(MZ)): 2 or more\n";
    auto r = parse(text);
    REQUIRE(r);
    const Node& rule = must_get(*r, "rule");
    const Node& meta = must_get(rule, "meta");
    CHECK(must_get(meta, "name").scalar()      == "extract embedded PE");
    CHECK(must_get(meta, "namespace").scalar() == "anti-analysis/packer");
    CHECK(must_get(meta, "scope").scalar()     == "file");
    const Node& feats = must_get(rule, "features");
    REQUIRE(feats.sequence().size() == 1);
    const Node& and_item = feats.sequence()[0];
    REQUIRE(and_item.kind() == NodeKind::kMapping);
    const Node& and_seq = must_get(and_item, "and");
    REQUIRE(and_seq.kind() == NodeKind::kSequence);
    REQUIRE(and_seq.sequence().size() == 2);
}

TEST_CASE("yaml: document separator is allowed at start and end") {
    constexpr std::string_view text =
        "---\n"
        "name: foo\n"
        "---\n";
    auto r = parse(text);
    REQUIRE(r);
    CHECK(must_get(*r, "name").scalar() == "foo");
}

TEST_CASE("yaml: nesting is bounded so a crafted document cannot overflow the stack") {
    // Parsing is recursive and the rules directory is untrusted input. On Windows a
    // stack overflow raises an exception the CLI's catch cannot intercept
    const auto nested = [](std::size_t depth) {
        std::string doc = "root:\n";
        for (std::size_t i = 0; i < depth; ++i) {
            doc.append(std::string(i + 2U, ' ')).append("-\n");
        }
        doc.append(std::string(depth + 2U, ' ')).append("leaf: v\n");
        return doc;
    };

    SUBCASE("nesting a real rule could plausibly use still parses") {
        // Well inside the limit. The exact cost per visual level is an implementation
        // detail, so this checks the property rather than the precise boundary
        auto ok = papa::util::yaml::parse(nested(20U));
        CHECK(ok.has_value());
    }

    SUBCASE("past the limit is rejected rather than fatal") {
        auto deep = papa::util::yaml::parse(nested(papa::util::yaml::kMaxNestingDepth * 4U));
        REQUIRE_FALSE(deep.has_value());
        CHECK(deep.error().kind == papa::ErrorKind::kYamlParseError);
    }

    SUBCASE("far past the limit is still just an error") {
        auto absurd = papa::util::yaml::parse(nested(5000U));
        REQUIRE_FALSE(absurd.has_value());
        CHECK(absurd.error().kind == papa::ErrorKind::kYamlParseError);
    }
}
