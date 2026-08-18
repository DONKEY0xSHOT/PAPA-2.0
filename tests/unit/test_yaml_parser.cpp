#include <ostream>

#include "doctest.h"

#include "papa/util/yaml.h"

#include <string>
#include <string_view>

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

TEST_CASE("yaml: simple mapping with three keys") {
    constexpr std::string_view text =
        "name: PAPA\n"
        "scope: file\n"
        "lib: true\n";
    auto r = parse(text);
    REQUIRE(r);
    REQUIRE(r->kind() == NodeKind::kMapping);
    CHECK(must_get(*r, "name").scalar()  == "PAPA");
    CHECK(must_get(*r, "scope").scalar() == "file");
    CHECK(must_get(*r, "lib").scalar()   == "true");
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

TEST_CASE("yaml: double-quoted scalars decode escapes") {
    constexpr std::string_view text =
        "a: \"line1\\nline2\"\n"
        "b: \"tab\\there\"\n"
        "c: \"hex\\x41\"\n"
        "d: \"unicode\\u00e9\"\n";
    auto r = parse(text);
    REQUIRE(r);
    CHECK(must_get(*r, "a").scalar() == "line1\nline2");
    CHECK(must_get(*r, "b").scalar() == "tab\there");
    CHECK(must_get(*r, "c").scalar() == "hexA");
    // U+00E9 is encoded as 0xC3 0xA9 in UTF-8
    CHECK(must_get(*r, "d").scalar() == std::string("unicode\xC3\xA9"));
}

TEST_CASE("yaml: single-quoted scalars decode '' as one quote") {
    constexpr std::string_view text =
        "msg: 'it''s fine'\n";
    auto r = parse(text);
    REQUIRE(r);
    CHECK(must_get(*r, "msg").scalar() == "it's fine");
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

TEST_CASE("yaml: literal block scalar | preserves newlines") {
    constexpr std::string_view text =
        "desc: |\n"
        "  line one\n"
        "  line two\n"
        "name: foo\n";
    auto r = parse(text);
    REQUIRE(r);
    const Node& d = must_get(*r, "desc");
    CHECK(d.kind() == NodeKind::kScalar);
    CHECK(d.scalar() == "line one\nline two\n");
    CHECK(must_get(*r, "name").scalar() == "foo");
}

TEST_CASE("yaml: literal block with chomp strip") {
    constexpr std::string_view text =
        "desc: |-\n"
        "  hi\n"
        "name: foo\n";
    auto r = parse(text);
    REQUIRE(r);
    CHECK(must_get(*r, "desc").scalar() == "hi");
    CHECK(must_get(*r, "name").scalar() == "foo");
}

TEST_CASE("yaml: tabs in indentation are rejected") {
    constexpr std::string_view text =
        "a:\n"
        "\tb: 1\n";
    auto r = parse(text);
    REQUIRE_FALSE(r);
    CHECK(r.error().kind == papa::ErrorKind::kYamlParseError);
}

TEST_CASE("yaml: anchors and aliases are rejected") {
    constexpr std::string_view text_anchor =
        "a: &x foo\n"
        "b: *x\n";
    auto r1 = parse(text_anchor);
    REQUIRE_FALSE(r1);
    CHECK(r1.error().kind == papa::ErrorKind::kYamlParseError);
}

TEST_CASE("yaml: flow collections are rejected") {
    constexpr std::string_view text_seq =
        "a: [1, 2, 3]\n";
    auto r1 = parse(text_seq);
    REQUIRE_FALSE(r1);
    constexpr std::string_view text_map =
        "a: {x: 1}\n";
    auto r2 = parse(text_map);
    REQUIRE_FALSE(r2);
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

TEST_CASE("yaml: mapping insertion order is preserved") {
    constexpr std::string_view text =
        "z: 1\n"
        "a: 2\n"
        "m: 3\n";
    auto r = parse(text);
    REQUIRE(r);
    REQUIRE(r->mapping().size() == 3);
    CHECK(r->mapping()[0].first == "z");
    CHECK(r->mapping()[1].first == "a");
    CHECK(r->mapping()[2].first == "m");
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

TEST_CASE("yaml: unterminated quoted string is rejected") {
    constexpr std::string_view t1 =
        "a: \"unterminated\n";
    auto r1 = parse(t1);
    REQUIRE_FALSE(r1);
    constexpr std::string_view t2 =
        "a: 'unterminated\n";
    auto r2 = parse(t2);
    REQUIRE_FALSE(r2);
}

TEST_CASE("yaml: invalid hex escape rejected") {
    constexpr std::string_view text =
        "a: \"bad\\xZZ\"\n";
    auto r = parse(text);
    REQUIRE_FALSE(r);
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
