#include "papa/util/regex_prefilter.h"

#include <algorithm>
#include <cstddef>
#include <optional>

namespace papa::util {

namespace {

constexpr std::size_t kNone = std::string_view::npos;

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

// True when the pattern has an alternation outside every group and class, or a class
// the scanner cannot delimit
[[nodiscard]] bool has_top_level_alternation(std::string_view p) noexcept {
    int depth = 0;
    for (std::size_t i = 0; i < p.size(); ++i) {
        const char c = p[i];
        if (c == '\\') { ++i; continue; }
        if (c == '[') {
            const std::size_t end = class_end(p, i);
            if (end == kNone) { return true; }
            i = end - 1;
        } else if (c == '(') {
            ++depth;
        } else if (c == ')') {
            --depth;
        } else if (c == '|' && depth == 0) {
            return true;
        }
    }
    return false;
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

// Parses a quantifier at i into its minimum repeat count and the index past it
// Returns nullopt for a malformed brace quantifier
struct Quantifier {
    std::size_t min_count{1};
    std::size_t end{0};
    bool        present{false};
};

[[nodiscard]] std::optional<Quantifier> parse_quantifier(std::string_view p, std::size_t i) {
    Quantifier q;
    q.end = i;
    if (i >= p.size()) { return q; }
    const char c = p[i];
    if (c == '*' || c == '?') { q.min_count = 0; q.end = i + 1; }
    else if (c == '+') { q.end = i + 1; }
    else if (c == '{') {
        std::size_t k = i + 1;
        std::size_t n = 0;
        const std::size_t digits_start = k;
        while (k < p.size() && is_digit(p[k])) {
            n = (n * 10) + static_cast<std::size_t>(p[k] - '0');
            ++k;
        }
        if (k == digits_start) { return std::nullopt; }
        while (k < p.size() && (p[k] == ',' || is_digit(p[k]))) { ++k; }
        if (k >= p.size() || p[k] != '}') { return std::nullopt; }
        q.min_count = n;
        q.end       = k + 1;
    } else {
        return q;
    }
    q.present = true;
    if (q.end < p.size() && p[q.end] == '?') { ++q.end; }   // lazy form
    return q;
}

}  // namespace

std::string required_literal(std::string_view p, bool icase) {
    if (has_top_level_alternation(p)) { return {}; }
    std::string best;
    std::string run;
    const auto flush = [&best, &run] {
        if (run.size() > best.size()) { best = run; }
        run.clear();
    };
    std::size_t i = 0;
    while (i < p.size()) {
        const char          c = p[i];
        std::optional<char> literal;
        std::size_t         next = i + 1;
        if (c == '(' || c == '[') {
            next = skip_bracketed(p, i);
            if (next == kNone) { return {}; }
        } else if (c == '\\') {
            if (i + 1 >= p.size()) { return {}; }
            const char e = p[i + 1];
            next = i + 2;
            if (!is_alnum(e)) {
                literal = e;
            } else if (std::string_view("dDwWsSbB").find(e) == kNone) {
                return {};   // hex, unicode, control and back-reference escapes are not modelled
            }
        } else if (std::string_view(")]}*+?{").find(c) != kNone) {
            return {};
        } else if (c != '.' && c != '^' && c != '$') {
            literal = c;
        }
        const auto q = parse_quantifier(p, next);
        if (!q.has_value()) { return {}; }
        const bool printable = literal.has_value() && *literal >= 0x20 && *literal <= 0x7E;
        if (printable && q->min_count >= 1) { run.push_back(icase ? fold(*literal) : *literal); }
        // Any repetition, and any non-literal atom, breaks contiguity with what follows
        if (!printable || q->present) { flush(); }
        i = q->end;
    }
    flush();
    return best;
}

bool contains_literal(std::string_view haystack, std::string_view literal, bool icase) noexcept {
    if (literal.empty()) { return true; }
    if (!icase) { return haystack.find(literal) != kNone; }
    return std::search(haystack.begin(), haystack.end(), literal.begin(), literal.end(),
                       [](char h, char l) { return fold(h) == l; }) != haystack.end();
}

}  // namespace papa::util
