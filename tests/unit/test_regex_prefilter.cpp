#include <ostream>

#include "doctest.h"

#include "papa/util/regex_prefilter.h"

#include <cstddef>
#include <iterator>
#include <random>
#include <regex>
#include <string>
#include <string_view>

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
        {"abc{0,2}de",            false, "ab"},
        {"ab+?cd",                false, "ab"},
        {"ab*?cd",                false, "cd"},
        {"(ab)|cd",               false, ""},
        {"[|]abc",                false, "abc"},
        {"\\|abc",                false, "|abc"},
        {"abc\\",                 false, ""},
        {"(abc",                  false, ""},
    };
    for (const Row& r : rows) {
        const std::string_view pattern{r.pattern};
        CAPTURE(pattern);
        CHECK(required_literal(r.pattern, r.icase) == r.literal);
    }
}

TEST_CASE("regex_prefilter: contains_literal folds ASCII case only when asked") {
    CHECK(contains_literal("xxGetProcAddress", "ProcAddress", false));
    CHECK_FALSE(contains_literal("xxGETPROCADDRESS", "ProcAddress", false));
    CHECK(contains_literal("xxGETPROCADDRESS", "procaddress", true));
    CHECK(contains_literal("xxgetprocaddress", "ProcAddress", true));
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
        const std::string_view pattern{r.pattern};
        CAPTURE(pattern);
        auto flags = std::regex::ECMAScript;
        if (r.icase) { flags |= std::regex::icase; }
        REQUIRE(std::regex_search(r.subject, std::regex(r.pattern, flags)));
        CHECK(contains_literal(r.subject, required_literal(r.pattern, r.icase), r.icase));
    }
}

TEST_CASE("regex_prefilter: random patterns never match a subject that lacks the literal") {
    constexpr std::string_view kAtoms[] = {
        "a", "ab", ".", "\\.", "\\d", "\\b", "\\x41", "\\cJ", "A", "\\0", "\\1", "[ab]", "[^a]",
        "[[:alpha:]", "[[.a.]", "[[=a=]", "[]", "(a)", "(?:ab|b)", "(?=a)", "|", ")", "]", "[",
        "{", "}", "\\|", "[|]",
    };
    constexpr std::string_view kQuantifiers[] = {
        "", "*", "+", "?", "{0}", "{1}", "{2,}", "{0,2}", "*?", "+?",
    };
    constexpr std::string_view kSubjectChars = "abAB:.=[]|\n";

    // Fixed seeds and raw modulo give every standard library the same patterns
    // Subjects use their own engine so a pattern one library rejects cannot shift the patterns
    std::mt19937 pattern_rng(20260927U);
    std::mt19937 subject_rng(20260928U);
    std::string  bad_pattern;
    std::string  bad_subject;
    for (int n = 0; n < 2000 && bad_pattern.empty(); ++n) {
        std::string pattern;
        const std::size_t pairs = 1 + (pattern_rng() % 5);
        for (std::size_t k = 0; k < pairs; ++k) {
            pattern += kAtoms[pattern_rng() % std::size(kAtoms)];
            pattern += kQuantifiers[pattern_rng() % std::size(kQuantifiers)];
        }
        const bool icase = (pattern_rng() % 2) == 1U;
        auto flags = std::regex::ECMAScript;
        if (icase) { flags |= std::regex::icase; }
        std::regex re;
        try {
            re = std::regex(pattern, flags);
        } catch (const std::regex_error&) {
            continue;
        }
        const std::string literal  = required_literal(pattern, icase);
        const std::string alphabet = std::string(kSubjectChars) + pattern;
        for (int s = 0; s < 20; ++s) {
            std::string subject;
            const std::size_t len = subject_rng() % 12;
            for (std::size_t c = 0; c < len; ++c) {
                subject += alphabet[subject_rng() % alphabet.size()];
            }
            if (std::regex_search(subject, re) && !contains_literal(subject, literal, icase)) {
                bad_pattern = pattern;
                bad_subject = subject;
                break;
            }
        }
    }
    CAPTURE(bad_pattern);
    CAPTURE(bad_subject);
    CHECK(bad_pattern.empty());
}
