#include "papa/util/regex_prefilter.h"

#include <algorithm>
#include <cstddef>
#include <optional>

namespace papa::util {

namespace {

constexpr std::size_t      kNone       = std::string_view::npos;
constexpr std::string_view kBraceChars = "0123456789,";

[[nodiscard]] constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

[[nodiscard]] constexpr bool is_alnum(char c) noexcept {
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

[[nodiscard]] constexpr char fold(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Index just past the class that opens at i, or kNone when it is empty, never closes, or
// holds a [:name:], [.name.] or [=name=] element whose inner ']' would end it early
[[nodiscard]] std::size_t class_end(std::string_view p, std::size_t i) noexcept {
    std::size_t k = i + 1;
    if (k < p.size() && p[k] == '^') { ++k; }
    if (k < p.size() && p[k] == ']') { return kNone; }
    for (; k < p.size(); ++k) {
        if (p[k] == '\\') { ++k; continue; }
        if (p[k] == '[' && k + 1 < p.size() && std::string_view(":.=").find(p[k + 1]) != kNone) {
            return kNone;
        }
        if (p[k] == ']') { return k + 1; }
    }
    return kNone;
}

// Index just past the group or class that opens at i, or kNone when it never closes or
// holds a class the scanner cannot delimit
[[nodiscard]] std::size_t skip_bracketed(std::string_view p, std::size_t i) noexcept {
    if (p[i] == '[') { return class_end(p, i); }
    int depth = 0;
    for (std::size_t k = i; k < p.size(); ++k) {
        const char c = p[k];
        if (c == '\\') { ++k; continue; }
        if (c == '[') {
            const std::size_t end = class_end(p, k);
            if (end == kNone) { return kNone; }
            k = end - 1;
        } else if (c == '(') {
            ++depth;
        } else if (c == ')' && --depth == 0) {
            return k + 1;
        }
    }
    return kNone;
}

// A parsed quantifier: the index just past it and whether it allows zero repeats
struct Quantifier {
    std::size_t end{0};
    bool        optional{false};
};

// Parses the quantifier at i, if any, keeping i as the end when there is none
// Returns nullopt for a malformed brace quantifier
[[nodiscard]] std::optional<Quantifier> parse_quantifier(std::string_view p,
                                                         std::size_t      i) noexcept {
    Quantifier q{i, false};
    if (i >= p.size()) { return q; }
    const char c = p[i];
    if (c == '*' || c == '?') {
        q = Quantifier{i + 1, true};
    } else if (c == '+') {
        q.end = i + 1;
    } else if (c == '{') {
        const std::size_t close = p.find('}', i);
        if (close == kNone) { return std::nullopt; }
        std::string_view body = p;
        body.remove_suffix(p.size() - close);
        body.remove_prefix(i + 1);
        const std::size_t min_len = std::min(body.find(','), body.size());
        if (min_len == 0 || body.find_first_not_of(kBraceChars) != kNone) { return std::nullopt; }
        q.optional = body.find_first_not_of('0') >= min_len;
        q.end      = close + 1;
    } else {
        return q;
    }
    if (q.end < p.size() && p[q.end] == '?') { ++q.end; }   // lazy form
    return q;
}

}  // namespace

std::string required_literal(std::string_view pattern, bool icase) {
    std::string best;
    std::string run;
    const auto flush = [&best, &run] {
        if (run.size() > best.size()) { best = run; }
        run.clear();
    };
    std::size_t i = 0;
    while (i < pattern.size()) {
        const char          c = pattern[i];
        std::optional<char> literal;
        std::size_t         next = i + 1;
        if (c == '(' || c == '[') {
            next = skip_bracketed(pattern, i);
            if (next == kNone) { return {}; }
        } else if (c == '\\') {
            if (i + 1 >= pattern.size()) { return {}; }
            const char e = pattern[i + 1];
            next = i + 2;
            if (!is_alnum(e)) {
                literal = e;
            } else if (std::string_view("dDwWsSbB").find(e) == kNone) {
                return {};   // hex, unicode, control and back-reference escapes are not modelled
            }
        } else if (std::string_view("|)]}*+?{").find(c) != kNone) {
            return {};
        } else if (c != '.' && c != '^' && c != '$') {
            literal = c;
        }
        const auto q = parse_quantifier(pattern, next);
        if (!q.has_value()) { return {}; }
        // Only printable ASCII, since std::regex folds case by locale and fold covers ASCII only
        const bool printable = literal.has_value() && *literal >= 0x20 && *literal <= 0x7E;
        if (printable && !q->optional) { run.push_back(icase ? fold(*literal) : *literal); }
        // Any repetition, and any non-literal atom, breaks contiguity with what follows
        if (!printable || q->end != next) { flush(); }
        i = q->end;
    }
    flush();
    return best;
}

bool contains_literal(std::string_view haystack, std::string_view literal, bool icase) noexcept {
    if (literal.empty()) { return true; }
    if (!icase) { return haystack.find(literal) != kNone; }
    return std::search(haystack.begin(), haystack.end(), literal.begin(), literal.end(),
                       [](char h, char l) { return fold(h) == fold(l); }) != haystack.end();
}

}  // namespace papa::util
