#include <ostream>

#include "doctest.h"

#include "papa/util/regex_prefilter.h"

#include <regex>
#include <string>

using papa::util::contains_literal;
using papa::util::required_literal;

TEST_CASE("regex_prefilter: required_literal picks the longest mandatory run") {
    struct Row {
        const char* pattern{""};
        bool        icase{false};
        const char* literal{""};
    };
    const Row rows[] = {
        {"GetProcAddress",        false, "GetProcAddress"},
        {"Get.*Address",          false, "Address"},
        {"^https?://",            false, "http"},
        {"VBox",                  true,  "vbox"},
        {"(foo|bar)baz",          false, "baz"},
        {"foo|bar",               false, ""},
        {"a+bc",                  false, "bc"},
        {"ab{2,}c",               false, "ab"},
        {"x{0,3}yz",              false, "yz"},
        {"\\.exe$",               true,  ".exe"},
        {"[a-z]+\\.dll",          false, ".dll"},
        {"abc\\d+def",            false, "abc"},
        {"\\x41BC",               false, ""},
        {"(abc)\\1",              false, ""},
        {"{default}",             false, ""},
        {"a[]b",                  false, ""},
        {"[[:alpha:]abcd[e]f",    false, ""},
        {"[[.a.]bcde[x]f",        false, ""},
        {"[[=a=]bcde[x]f",        false, ""},
        {"([[:alpha:])abcd(e]x)", false, ""},
        {"[[]abc",                false, "abc"},
        {"[\\]]abc",              false, "abc"},
        {"([a-z]|q)xyz",          false, "xyz"},
    };
    for (const Row& r : rows) {
        CAPTURE(r.pattern);
        CHECK(required_literal(r.pattern, r.icase) == r.literal);
    }
}

TEST_CASE("regex_prefilter: contains_literal folds ASCII case only when asked") {
    CHECK(contains_literal("xxGetProcAddress", "ProcAddress", false));
    CHECK_FALSE(contains_literal("xxGETPROCADDRESS", "ProcAddress", false));
    CHECK(contains_literal("xxGETPROCADDRESS", "procaddress", true));
    CHECK(contains_literal("anything", "", false));
    CHECK(contains_literal("", "", true));
    CHECK_FALSE(contains_literal("ab", "abc", true));
}

TEST_CASE("regex_prefilter: every match contains the required literal") {
    struct Row {
        const char* pattern{""};
        bool        icase{false};
        const char* subject{""};
    };
    const Row rows[] = {
        {"Get.*Address",          false, "xxGetProcAddressyy"},
        {"^https?://",            false, "https://example"},
        {"VBox",                  true,  "c:\\vboxguest"},
        {"a+bc",                  false, "aaabc"},
        {"ab{2,}c",               false, "abbbc"},
        {"x{0,3}yz",              false, "yz"},
        {"(foo|bar)baz",          false, "barbaz"},
        {"abc\\d+def",            false, "abc123def"},
        {"[[:alpha:]abcd[e]f",    false, "Xf"},
        {"([[:alpha:])abcd(e]x)", false, "Xx"},
        {"[[]abc",                false, "[abc"},
        {"[\\]]abc",              false, "]abc"},
        {"([a-z]|q)xyz",          false, "qxyz"},
    };
    for (const Row& r : rows) {
        CAPTURE(r.pattern);
        auto flags = std::regex::ECMAScript;
        if (r.icase) { flags |= std::regex::icase; }
        REQUIRE(std::regex_search(r.subject, std::regex(r.pattern, flags)));
        CHECK(contains_literal(r.subject, required_literal(r.pattern, r.icase), r.icase));
    }
}
