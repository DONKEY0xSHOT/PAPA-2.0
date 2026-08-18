#include "papa/util/yaml.h"

#include "papa/exceptions.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace papa::util::yaml {

// Node

Node::Node() noexcept = default;

Node::Node(std::string scalar, std::size_t line, std::size_t column) noexcept
    : kind_(NodeKind::kScalar), line_(line), column_(column),
      scalar_(std::move(scalar)) {}

Node::Node(std::vector<Node> sequence, std::size_t line, std::size_t column) noexcept
    : kind_(NodeKind::kSequence), line_(line), column_(column),
      sequence_(std::move(sequence)) {}

Node::Node(std::vector<MappingEntry> mapping, std::size_t line, std::size_t column) noexcept
    : kind_(NodeKind::kMapping), line_(line), column_(column),
      mapping_(std::move(mapping)) {}

Node::Node(Node&&) noexcept            = default;
Node& Node::operator=(Node&&) noexcept = default;
Node::~Node()                          = default;

std::string_view Node::scalar() const {
    if (kind_ != NodeKind::kScalar) {
        throw PapaInvariantError("yaml::Node::scalar called on non-scalar node");
    }
    return scalar_;
}

std::span<const Node> Node::sequence() const {
    if (kind_ != NodeKind::kSequence) {
        throw PapaInvariantError("yaml::Node::sequence called on non-sequence node");
    }
    return std::span<const Node>(sequence_.data(), sequence_.size());
}

std::span<const MappingEntry> Node::mapping() const {
    if (kind_ != NodeKind::kMapping) {
        throw PapaInvariantError("yaml::Node::mapping called on non-mapping node");
    }
    return std::span<const MappingEntry>(mapping_.data(), mapping_.size());
}

const Node* Node::find(std::string_view key) const noexcept {
    if (kind_ != NodeKind::kMapping) {
        return nullptr;
    }
    for (const auto& entry : mapping_) {
        if (entry.first == key) {
            return &entry.second;
        }
    }
    return nullptr;
}

// Parser

namespace {

// Indices into the source text always carry their 1-based line and column
struct Pos {
    std::size_t line   { 1 };
    std::size_t column { 1 };
};

// One physical line, pre-stripped of trailing CR indent is the column of the first non-
// space byte payload is the substring from indent to end excluding trailing CR
struct Line {
    std::size_t       line_no { 0 };
    std::size_t       indent  { 0 };
    std::string_view  payload;
    bool              is_blank   { false };
    bool              is_comment { false };
};

// Tab handling: CAPA rules never use tabs for indentation
// Reject early with a clear error rather than silently treating tabs as one space
[[nodiscard]] bool contains_indent_tab(std::string_view raw) noexcept {
    for (char c : raw) {
        if (c == '\t') {
            return true;
        }
        if (c != ' ') {
            return false;
        }
    }
    return false;
}

[[nodiscard]] PapaError yaml_err(std::size_t line, std::size_t column,
                                 std::string_view what) {
    std::string detail;
    detail.reserve(what.size() + 24);
    detail.append("line ");
    detail.append(std::to_string(line));
    detail.append(":");
    detail.append(std::to_string(column));
    detail.append(": ");
    detail.append(what);
    return make_error(ErrorKind::kYamlParseError, std::move(detail));
}

// Split text into lines, preserving indent as a column count
// CR is stripped from CRLF input so payload comparisons stay simple
[[nodiscard]] Expected<std::vector<Line>> tokenize_lines(std::string_view text) {
    std::vector<Line> out;
    out.reserve(64);
    std::size_t line_no = 1;
    std::size_t i       = 0;
    const std::size_t n = text.size();
    while (i <= n) {
        std::size_t start = i;
        while (i < n && text[i] != '\n') {
            ++i;
        }
        std::string_view raw = text.substr(start, i - start);
        if (!raw.empty() && raw.back() == '\r') {
            raw.remove_suffix(1);
        }
        if (contains_indent_tab(raw)) {
            return Unexpected{yaml_err(line_no, 1, "tab in indentation is not allowed")};
        }
        std::size_t indent = 0;
        while (indent < raw.size() && raw[indent] == ' ') {
            ++indent;
        }
        Line ln;
        ln.line_no = line_no;
        ln.indent  = indent;
        ln.payload = raw.substr(indent);
        ln.is_blank   = ln.payload.empty();
        ln.is_comment = !ln.is_blank && ln.payload.front() == '#';
        out.push_back(ln);
        if (i == n) {
            break;
        }
        ++i;
        ++line_no;
    }
    return out;
}

// Strip a trailing comment from a plain scalar payload
// A comment marker must be preceded by whitespace to start a comment
[[nodiscard]] std::string_view strip_inline_comment(std::string_view s) noexcept {
    bool in_single = false;
    bool in_double = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '\\' && in_double && i + 1 < s.size()) {
            ++i;
            continue;
        }
        if (c == '\'' && !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' && !in_single) {
            in_double = !in_double;
            continue;
        }
        if (in_single || in_double) {
            continue;
        }
        if (c == '#' && (i == 0 || s[i - 1] == ' ')) {
            std::size_t end = i;
            while (end > 0 && s[end - 1] == ' ') {
                --end;
            }
            return s.substr(0, end);
        }
    }
    while (!s.empty() && s.back() == ' ') {
        s.remove_suffix(1);
    }
    return s;
}

[[nodiscard]] std::string_view rtrim(std::string_view s) noexcept {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

// Decode a double-quoted YAML scalar
// We accept the escapes CAPA rules use: \n \t \r \\ \" \0 \xNN \uNNNN
[[nodiscard]] Expected<std::string> decode_double_quoted(
    std::string_view body, std::size_t line, std::size_t column) {
    std::string out;
    out.reserve(body.size());
    for (std::size_t i = 0; i < body.size(); ++i) {
        const char c = body[i];
        if (c != '\\') {
            out.push_back(c);
            continue;
        }
        if (i + 1 >= body.size()) {
            return Unexpected{yaml_err(line, column,
                "trailing backslash in double-quoted string")};
        }
        const char n = body[++i];
        switch (n) {
            case 'n':  out.push_back('\n'); break;
            case 't':  out.push_back('\t'); break;
            case 'r':  out.push_back('\r'); break;
            case '\\': out.push_back('\\'); break;
            case '"':  out.push_back('"');  break;
            case '/':  out.push_back('/');  break;
            case '0':  out.push_back('\0'); break;
            case 'a':  out.push_back('\a'); break;
            case 'b':  out.push_back('\b'); break;
            case 'f':  out.push_back('\f'); break;
            case 'v':  out.push_back('\v'); break;
            case 'x': {
                if (i + 2 >= body.size()) {
                    return Unexpected{yaml_err(line, column,
                        "truncated \\xNN escape in double-quoted string")};
                }
                auto hex = [](char d) -> int {
                    if (d >= '0' && d <= '9') return d - '0';
                    if (d >= 'a' && d <= 'f') return 10 + (d - 'a');
                    if (d >= 'A' && d <= 'F') return 10 + (d - 'A');
                    return -1;
                };
                const int hi = hex(body[i + 1]);
                const int lo = hex(body[i + 2]);
                if (hi < 0 || lo < 0) {
                    return Unexpected{yaml_err(line, column,
                        "invalid hex digit in \\xNN escape")};
                }
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                break;
            }
            case 'u': {
                if (i + 4 >= body.size()) {
                    return Unexpected{yaml_err(line, column,
                        "truncated \\uNNNN escape in double-quoted string")};
                }
                auto hex = [](char d) -> int {
                    if (d >= '0' && d <= '9') return d - '0';
                    if (d >= 'a' && d <= 'f') return 10 + (d - 'a');
                    if (d >= 'A' && d <= 'F') return 10 + (d - 'A');
                    return -1;
                };
                int code = 0;
                for (std::size_t k = 1; k <= 4; ++k) {
                    const int v = hex(body[i + k]);
                    if (v < 0) {
                        return Unexpected{yaml_err(line, column,
                            "invalid hex digit in \\uNNNN escape")};
                    }
                    code = (code << 4) | v;
                }
                i += 4;
                // UTF-8 encode the code point
                // Surrogate halves are rejected to avoid producing invalid UTF-8
                if (code >= 0xD800 && code <= 0xDFFF) {
                    return Unexpected{yaml_err(line, column,
                        "surrogate code point in \\uNNNN escape")};
                }
                if (code < 0x80) {
                    out.push_back(static_cast<char>(code));
                } else if (code < 0x800) {
                    out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                } else {
                    out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                    out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                }
                break;
            }
            default:
                return Unexpected{yaml_err(line, column,
                    "unknown escape in double-quoted string")};
        }
    }
    return out;
}

// Decode a single-quoted YAML scalar
// In YAML single quotes, "''" is the only escape and stands for one quote
[[nodiscard]] std::string decode_single_quoted(std::string_view body) {
    std::string out;
    out.reserve(body.size());
    for (std::size_t i = 0; i < body.size(); ++i) {
        if (body[i] == '\'' && i + 1 < body.size() && body[i + 1] == '\'') {
            out.push_back('\'');
            ++i;
            continue;
        }
        out.push_back(body[i]);
    }
    return out;
}

// Recognize forbidden YAML constructs early so we never produce a wrong AST
[[nodiscard]] bool is_forbidden_lead(std::string_view s) noexcept {
    if (s.empty()) {
        return false;
    }
    const char c = s.front();
    return c == '&' || c == '*' || c == '!' || c == '[' || c == '{';
}

// Restores the nesting depth on every exit path, of which parse_value has many
class DepthGuard {
public:
    explicit DepthGuard(std::size_t& depth) noexcept : depth_(depth) { ++depth_; }
    ~DepthGuard() { --depth_; }

    DepthGuard(const DepthGuard&)            = delete;
    DepthGuard& operator=(const DepthGuard&) = delete;
    DepthGuard(DepthGuard&&)                 = delete;
    DepthGuard& operator=(DepthGuard&&)      = delete;

private:
    std::size_t& depth_;
};

class Parser {
public:
    Parser(std::span<const Line> lines) noexcept : lines_(lines) {}

    [[nodiscard]] Expected<Node> parse_document();

private:
    [[nodiscard]] bool at_end() const noexcept {
        return cursor_ >= lines_.size();
    }
    [[nodiscard]] const Line& peek() const noexcept { return lines_[cursor_]; }

    void skip_blank_and_comment() noexcept {
        while (!at_end() && (peek().is_blank || peek().is_comment)) {
            ++cursor_;
        }
    }

    // Parse a value that begins at `indent`
    // Caller has positioned cursor_ at the first content line at or past `indent`
    [[nodiscard]] Expected<Node> parse_value(std::size_t indent);

    // Block sequence: every line at `indent` starts with "- "
    [[nodiscard]] Expected<Node> parse_sequence(std::size_t indent);

    // Block mapping: every key starts at `indent`
    [[nodiscard]] Expected<Node> parse_mapping(std::size_t indent);

    // Inline scalar appearing on the same line as a "- " or "key:" prefix
    [[nodiscard]] Expected<Node> parse_inline_scalar(
        std::string_view body, std::size_t line, std::size_t column);

    // Block scalar starting with | or >
    [[nodiscard]] Expected<Node> parse_block_scalar(
        char style, std::size_t indent,
        std::size_t line, std::size_t column);

    // Helper: split "key: value" into the key portion and the remainder
    // Returns nullopt when no top-level colon-space is found
    [[nodiscard]] static std::optional<std::pair<std::string_view, std::string_view>>
        split_key(std::string_view payload);

    std::span<const Line> lines_;
    std::size_t           cursor_ { 0 };
    std::size_t           depth_  { 0 };
};

std::optional<std::pair<std::string_view, std::string_view>>
Parser::split_key(std::string_view payload) {
    bool in_single = false;
    bool in_double = false;
    for (std::size_t i = 0; i < payload.size(); ++i) {
        const char c = payload[i];
        if (c == '\\' && in_double && i + 1 < payload.size()) {
            ++i;
            continue;
        }
        if (c == '\'' && !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' && !in_single) {
            in_double = !in_double;
            continue;
        }
        if (in_single || in_double) {
            continue;
        }
        if (c == ':') {
            const bool followed_by_ws = (i + 1 == payload.size()) ||
                                        payload[i + 1] == ' ';
            if (followed_by_ws) {
                std::string_view k = payload.substr(0, i);
                std::string_view v = (i + 1 < payload.size())
                    ? payload.substr(i + 1)
                    : std::string_view{};
                while (!v.empty() && v.front() == ' ') {
                    v.remove_prefix(1);
                }
                return std::make_pair(k, v);
            }
        }
    }
    return std::nullopt;
}

Expected<Node> Parser::parse_inline_scalar(
    std::string_view body, std::size_t line, std::size_t column) {
    std::string_view trimmed = rtrim(body);
    if (trimmed.empty()) {
        return Node{std::string{}, line, column};
    }

    // For quoted scalars, find the actual closing quote first so trailing inline
    // comments do not look like an unterminated string
    if (trimmed.front() == '"') {
        std::size_t end = std::string_view::npos;
        for (std::size_t i = 1; i < trimmed.size(); ++i) {
            const char c = trimmed[i];
            if (c == '\\' && i + 1 < trimmed.size()) { ++i; continue; }
            if (c == '"') { end = i; break; }
        }
        if (end == std::string_view::npos) {
            return Unexpected{yaml_err(line, column,
                "unterminated double-quoted string")};
        }
        std::string_view body2 = trimmed.substr(1, end - 1);
        auto decoded = decode_double_quoted(body2, line, column);
        if (!decoded) { return Unexpected{decoded.error()}; }
        return Node{std::move(*decoded), line, column};
    }
    if (trimmed.front() == '\'') {
        // Single-quote escape is doubled '' which is not a string terminator
        std::size_t end = std::string_view::npos;
        for (std::size_t i = 1; i < trimmed.size(); ++i) {
            if (trimmed[i] != '\'') { continue; }
            if (i + 1 < trimmed.size() && trimmed[i + 1] == '\'') { ++i; continue; }
            end = i;
            break;
        }
        if (end == std::string_view::npos) {
            return Unexpected{yaml_err(line, column,
                "unterminated single-quoted string")};
        }
        std::string_view body2 = trimmed.substr(1, end - 1);
        return Node{decode_single_quoted(body2), line, column};
    }
    if (is_forbidden_lead(trimmed)) {
        return Unexpected{yaml_err(line, column,
            "anchors, aliases, tags, and flow collections are not supported")};
    }
    std::string_view stripped = strip_inline_comment(trimmed);
    return Node{std::string{stripped}, line, column};
}

Expected<Node> Parser::parse_block_scalar(
    char style, std::size_t indent,
    std::size_t line, std::size_t column) {
    // The | and > headers may carry a chomp indicator. All six combinations are
    // accepted, with | keeping newlines and > folding them to spaces
    char chomp = '\0';
    if (cursor_ > 0) {
        std::string_view header = lines_[cursor_ - 1].payload;
        for (char c : header) {
            if (c == '-' || c == '+') {
                chomp = c;
                break;
            }
        }
    }

    std::vector<std::string_view> raw_lines;
    std::size_t block_indent = 0;
    bool block_indent_set = false;
    while (!at_end()) {
        const Line& ln = peek();
        if (ln.is_blank) {
            raw_lines.emplace_back();
            ++cursor_;
            continue;
        }
        if (ln.indent <= indent) {
            break;
        }
        if (!block_indent_set) {
            block_indent     = ln.indent;
            block_indent_set = true;
        }
        if (ln.indent < block_indent) {
            break;
        }
        // Relative indent within the block is ignored, which matches CAPA rule usage
        // where every line of a block scalar shares the same indent
        raw_lines.push_back(ln.payload);
        ++cursor_;
    }

    std::string out;
    if (style == '|') {
        for (std::size_t i = 0; i < raw_lines.size(); ++i) {
            out.append(raw_lines[i]);
            out.push_back('\n');
        }
    } else {
        // Folded: blank line keeps a newline, run of non-blank lines folds with single spaces
        for (std::size_t i = 0; i < raw_lines.size(); ++i) {
            const bool is_blank = raw_lines[i].empty();
            if (is_blank) {
                // A pending fold space becomes the newline, otherwise the
                // newline is appended
                if (!out.empty() && out.back() == ' ') {
                    out.back() = '\n';
                } else {
                    out.push_back('\n');
                }
            } else {
                out.append(raw_lines[i]);
                out.push_back(' ');
            }
        }
        if (!out.empty() && out.back() == ' ') {
            out.back() = '\n';
        }
    }

    if (chomp == '-') {
        while (!out.empty() && out.back() == '\n') {
            out.pop_back();
        }
    } else if (chomp == '+') {
        // Keep all trailing newlines as-is
    } else {
        // Default: single trailing newline at most
        while (out.size() >= 2 && out[out.size() - 1] == '\n' && out[out.size() - 2] == '\n') {
            out.pop_back();
        }
    }

    return Node{std::move(out), line, column};
}

Expected<Node> Parser::parse_value(std::size_t indent) {
    // Nesting recurses through here, so one bound covers the whole cycle
    if (depth_ >= kMaxNestingDepth) {
        const std::size_t line_no = at_end() ? 0U : peek().line_no;
        return Unexpected{yaml_err(line_no, 1U, "nesting is too deep")};
    }
    const DepthGuard guard(depth_);

    skip_blank_and_comment();
    if (at_end()) {
        return Node{};
    }
    const Line& ln = peek();
    // YAML allows a block sequence value to share its parent key's column i.e. a "- "
    // line dedented by one space relative to other value content
    if (!ln.payload.empty() && ln.payload.front() == '-' &&
        (ln.payload.size() == 1 || ln.payload[1] == ' ') &&
        ln.indent + 1 >= indent) {
        return parse_sequence(ln.indent);
    }
    if (ln.indent < indent) {
        return Node{};
    }
    if (ln.payload.empty()) {
        ++cursor_;
        return Node{};
    }
    if (split_key(ln.payload).has_value()) {
        return parse_mapping(ln.indent);
    }
    return Unexpected{yaml_err(ln.line_no, ln.indent + 1,
        "expected a sequence, mapping, or scalar value")};
}

Expected<Node> Parser::parse_sequence(std::size_t indent) {
    std::vector<Node> items;
    const std::size_t start_line = peek().line_no;
    const std::size_t start_col  = indent + 1;
    while (!at_end()) {
        skip_blank_and_comment();
        if (at_end()) {
            break;
        }
        const Line& ln = peek();
        if (ln.indent < indent) {
            break;
        }
        if (ln.indent > indent) {
            return Unexpected{yaml_err(ln.line_no, ln.indent + 1,
                "unexpected indent inside sequence")};
        }
        if (ln.payload.empty() || ln.payload.front() != '-') {
            break;
        }
        const bool dash_alone = (ln.payload.size() == 1) || (ln.payload[1] == ' ');
        if (!dash_alone) {
            break;
        }
        const std::size_t item_line = ln.line_no;
        const std::size_t item_col  = ln.indent + 1;
        const std::string_view rest = (ln.payload.size() == 1)
            ? std::string_view{}
            : ln.payload.substr(2);
        ++cursor_;
        if (rest.empty()) {
            // Item content lives on subsequent lines indented past indent
            auto v = parse_value(indent + 1);
            if (!v) {
                return Unexpected{v.error()};
            }
            items.push_back(std::move(*v));
            continue;
        }
        // Inline content after "- "
        if (auto kv = split_key(rest); kv.has_value()) {
            // The dash introduces a single-key mapping inline
            // Subsequent keys at indent + 2 (the column after "- ") continue this mapping
            std::vector<MappingEntry> entries;
            // First entry from the dash line
            std::string_view k0 = kv->first;
            std::string_view v0 = kv->second;
            std::size_t map_indent = ln.indent + 2;
            Node value;
            // Comment-only inline values must defer to a block sequence on the
            // following lines, e.g. "- or: # explanation"
            const bool v0_is_comment_only =
                !v0.empty() && (v0.front() == '#' ||
                                strip_inline_comment(rtrim(v0)).empty());
            if (!v0.empty() && !v0_is_comment_only) {
                auto parsed = parse_inline_scalar(v0, item_line, map_indent + 1 + k0.size() + 2);
                if (!parsed) {
                    return Unexpected{parsed.error()};
                }
                value = std::move(*parsed);
            } else {
                auto v = parse_value(map_indent + 1);
                if (!v) {
                    return Unexpected{v.error()};
                }
                value = std::move(*v);
            }
            entries.emplace_back(std::string{k0}, std::move(value));

            // Continue collecting keys at map_indent
            while (!at_end()) {
                skip_blank_and_comment();
                if (at_end()) {
                    break;
                }
                const Line& nx = peek();
                if (nx.indent != map_indent) {
                    break;
                }
                if (nx.payload.empty() || nx.payload.front() == '-') {
                    break;
                }
                auto kv2 = split_key(nx.payload);
                if (!kv2.has_value()) {
                    break;
                }
                const std::size_t kline = nx.line_no;
                const std::size_t kcol  = nx.indent + 1;
                std::string_view kk = kv2->first;
                std::string_view vv = kv2->second;
                ++cursor_;
                Node nval;
                const bool vv_is_comment_only =
                    !vv.empty() && (vv.front() == '#' ||
                                    strip_inline_comment(rtrim(vv)).empty());
                if (vv.empty() || vv_is_comment_only) {
                    auto v2 = parse_value(map_indent + 1);
                    if (!v2) {
                        return Unexpected{v2.error()};
                    }
                    nval = std::move(*v2);
                } else if (vv == "|" || vv == ">" || vv == "|-" || vv == "|+" ||
                           vv == ">-" || vv == ">+") {
                    auto v2 = parse_block_scalar(vv.front(), map_indent, kline, kcol);
                    if (!v2) {
                        return Unexpected{v2.error()};
                    }
                    nval = std::move(*v2);
                } else {
                    auto parsed = parse_inline_scalar(vv, kline, kcol + kk.size() + 2);
                    if (!parsed) {
                        return Unexpected{parsed.error()};
                    }
                    nval = std::move(*parsed);
                }
                entries.emplace_back(std::string{kk}, std::move(nval));
            }
            items.emplace_back(std::move(entries), item_line, item_col);
            continue;
        }
        // Plain scalar after "- "
        auto sv = parse_inline_scalar(rest, item_line, item_col + 2);
        if (!sv) {
            return Unexpected{sv.error()};
        }
        items.push_back(std::move(*sv));
    }
    return Node{std::move(items), start_line, start_col};
}

Expected<Node> Parser::parse_mapping(std::size_t indent) {
    std::vector<MappingEntry> entries;
    const std::size_t start_line = peek().line_no;
    const std::size_t start_col  = indent + 1;
    while (!at_end()) {
        skip_blank_and_comment();
        if (at_end()) {
            break;
        }
        const Line& ln = peek();
        if (ln.indent < indent) {
            break;
        }
        if (ln.indent > indent) {
            return Unexpected{yaml_err(ln.line_no, ln.indent + 1,
                "unexpected indent inside mapping")};
        }
        if (ln.payload.empty() || ln.payload.front() == '-') {
            break;
        }
        auto kv = split_key(ln.payload);
        if (!kv.has_value()) {
            break;
        }
        const std::size_t kline = ln.line_no;
        const std::size_t kcol  = ln.indent + 1;
        // Quoted keys get unquoted (CAPA rules also use plain keys interchangeably)
        std::string key;
        std::string_view kraw = kv->first;
        if (!kraw.empty() && kraw.front() == '"') {
            if (kraw.size() < 2 || kraw.back() != '"') {
                return Unexpected{yaml_err(kline, kcol, "unterminated double-quoted key")};
            }
            auto decoded = decode_double_quoted(kraw.substr(1, kraw.size() - 2),
                                                kline, kcol);
            if (!decoded) {
                return Unexpected{decoded.error()};
            }
            key = std::move(*decoded);
        } else if (!kraw.empty() && kraw.front() == '\'') {
            if (kraw.size() < 2 || kraw.back() != '\'') {
                return Unexpected{yaml_err(kline, kcol, "unterminated single-quoted key")};
            }
            key = decode_single_quoted(kraw.substr(1, kraw.size() - 2));
        } else {
            key = std::string{rtrim(kraw)};
        }
        std::string_view vraw = kv->second;
        ++cursor_;
        Node value;
        // Treat comment-only inline values the same as an empty value
        const bool inline_value_is_comment_only =
            !vraw.empty() && (vraw.front() == '#' ||
                              strip_inline_comment(rtrim(vraw)).empty());
        if (vraw.empty() || inline_value_is_comment_only) {
            // Block mapping value or block sequence on subsequent lines
            auto v = parse_value(indent + 1);
            if (!v) {
                return Unexpected{v.error()};
            }
            value = std::move(*v);
        } else if (vraw == "|" || vraw == ">" || vraw == "|-" || vraw == "|+" ||
                   vraw == ">-" || vraw == ">+") {
            auto v = parse_block_scalar(vraw.front(), indent, kline, kcol);
            if (!v) {
                return Unexpected{v.error()};
            }
            value = std::move(*v);
        } else {
            auto sv = parse_inline_scalar(vraw, kline, kcol + key.size() + 2);
            if (!sv) {
                return Unexpected{sv.error()};
            }
            value = std::move(*sv);
        }
        entries.emplace_back(std::move(key), std::move(value));
    }
    return Node{std::move(entries), start_line, start_col};
}

Expected<Node> Parser::parse_document() {
    skip_blank_and_comment();
    // Optional document separator
    while (!at_end() && peek().payload == "---") {
        ++cursor_;
        skip_blank_and_comment();
    }
    if (at_end()) {
        return Node{};
    }
    const std::size_t indent = peek().indent;
    auto root = parse_value(indent);
    if (!root) {
        return Unexpected{root.error()};
    }
    skip_blank_and_comment();
    while (!at_end() && peek().payload == "---") {
        ++cursor_;
        skip_blank_and_comment();
    }
    if (!at_end()) {
        const Line& ln = peek();
        return Unexpected{yaml_err(ln.line_no, ln.indent + 1,
            "extra content after document end")};
    }
    return root;
}

}  // namespace

Expected<Node> parse(std::string_view text) {
    auto lines = tokenize_lines(text);
    if (!lines) {
        return Unexpected{lines.error()};
    }
    Parser p{*lines};
    return p.parse_document();
}

}  // namespace papa::util::yaml
