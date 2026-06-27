#include "papa/render/table.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace papa::render::table {

namespace {

// SQUARE box glyphs as raw UTF-8 bytes so the source stays ASCII-only.
// These are the same characters rich substitutes for its HEAVY_HEAD default
// box on Windows, which is what capa.exe emits.
constexpr std::string_view kHorizontal = "\xE2\x94\x80";  // U+2500
constexpr std::string_view kVertical   = "\xE2\x94\x82";  // U+2502
constexpr std::string_view kTopLeft    = "\xE2\x94\x8C";  // U+250C
constexpr std::string_view kTopCross   = "\xE2\x94\xAC";  // U+252C
constexpr std::string_view kTopRight   = "\xE2\x94\x90";  // U+2510
constexpr std::string_view kMidLeft    = "\xE2\x94\x9C";  // U+251C
constexpr std::string_view kMidCross   = "\xE2\x94\xBC";  // U+253C
constexpr std::string_view kMidRight   = "\xE2\x94\xA4";  // U+2524
constexpr std::string_view kBotLeft    = "\xE2\x94\x94";  // U+2514
constexpr std::string_view kBotCross   = "\xE2\x94\xB4";  // U+2534
constexpr std::string_view kBotRight   = "\xE2\x94\x98";  // U+2518
constexpr std::string_view kEllipsis   = "\xE2\x80\xA6";  // U+2026

// ANSI SGR escapes for capa's cyan styling (rich's [cyan] markup).
constexpr std::string_view kCyanOn  = "\x1b[36m";
constexpr std::string_view kReset   = "\x1b[0m";

// Horizontal padding rich applies inside every cell, one space each side.
constexpr int kCellPadding = 2;

// Whitespace per Python's regex \s for the ASCII text capa renders.
[[nodiscard]] bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

// Cell length in terminal columns, which equals the byte count for ASCII text.
[[nodiscard]] int cell_len(std::string_view s) noexcept {
    return static_cast<int>(s.size());
}

[[nodiscard]] int sum(const std::vector<int>& v) noexcept {
    int total = 0;
    for (const int x : v) { total += x; }
    return total;
}

// The plain text of a cell, used for all width and wrap calculations.
[[nodiscard]] std::string cell_plain(const Cell& cell) {
    std::string out;
    for (const Run& run : cell.runs) { out.append(run.text); }
    return out;
}

// The style of each character of a cell's plain text, parallel to cell_plain.
[[nodiscard]] std::vector<Style> cell_styles(const Cell& cell) {
    std::vector<Style> out;
    for (const Run& run : cell.runs) {
        out.insert(out.end(), run.text.size(), run.style);
    }
    return out;
}

// Length of the longest newline-delimited line, which is rich's max measurement.
[[nodiscard]] int longest_line(std::string_view cell) noexcept {
    int best = 0;
    std::size_t start = 0;
    while (start <= cell.size()) {
        const std::size_t nl = cell.find('\n', start);
        const std::size_t stop = (nl == std::string_view::npos) ? cell.size() : nl;
        best = std::max(best, cell_len(cell.substr(start, stop - start)));
        if (nl == std::string_view::npos) { break; }
        start = nl + 1;
    }
    return best;
}

// Round num/den to the nearest integer with ties to even, as Python's round does.
// Both arguments are non-negative and den is positive at every call site.
[[nodiscard]] long long round_half_even(long long num, long long den) noexcept {
    const long long quotient = num / den;
    const long long twice_remainder = 2 * (num % den);
    if (twice_remainder < den) { return quotient; }
    if (twice_remainder > den) { return quotient + 1; }
    return (quotient % 2 == 0) ? quotient : quotient + 1;
}

// Smallest integer not less than num/den for non-negative num and positive den.
[[nodiscard]] long long ceil_div(long long num, long long den) noexcept {
    return (num + den - 1) / den;
}

// Coalesce per-character styles over [begin, end) of plain into styled runs.
[[nodiscard]] std::vector<Run> runs_from(const std::string& plain,
                                         const std::vector<Style>& styles,
                                         std::size_t begin, std::size_t end) {
    std::vector<Run> out;
    for (std::size_t i = begin; i < end;) {
        const Style style = styles[i];
        std::size_t j = i;
        while (j < end && styles[j] == style) { ++j; }
        out.push_back({plain.substr(i, j - i), style});
        i = j;
    }
    return out;
}

// One whitespace-delimited word with the offset where it begins in the source.
struct Word {
    int         start;
    std::string text;
};

// Drop trailing whitespace, matching rich's per-line rstrip before padding.
[[nodiscard]] std::string rstrip(std::string_view s) {
    std::size_t end = s.size();
    while (end > 0 && is_space(s[end - 1])) { --end; }
    return std::string(s.substr(0, end));
}

// Split text into rich's words: each is one run of non-space plus trailing space.
[[nodiscard]] std::vector<Word> words(const std::string& s) {
    std::vector<Word> out;
    const int n = static_cast<int>(s.size());
    int p = 0;
    while (p < n) {
        const int start = p;
        while (p < n && is_space(s[static_cast<std::size_t>(p)])) { ++p; }
        if (p >= n) { break; }
        while (p < n && !is_space(s[static_cast<std::size_t>(p)])) { ++p; }
        while (p < n && is_space(s[static_cast<std::size_t>(p)])) { ++p; }
        const auto len = static_cast<std::size_t>(p - start);
        out.push_back({start, s.substr(static_cast<std::size_t>(start), len)});
    }
    return out;
}

// Build a styled line of exactly width cells from [begin, end) of one wrapped
// piece: trailing whitespace is dropped, then the line is ellipsis-truncated if
// it overflows or right-padded with spaces if it is short.
[[nodiscard]] std::vector<Run> make_line(const std::string& plain,
                                         const std::vector<Style>& styles,
                                         std::size_t begin, std::size_t end, int width) {
    while (end > begin && is_space(plain[end - 1])) { --end; }
    const int len = static_cast<int>(end - begin);

    if (len > width) {
        const std::size_t keep = static_cast<std::size_t>(std::max(0, width - 1));
        std::vector<Run> runs = runs_from(plain, styles, begin, begin + keep);
        runs.push_back({std::string(kEllipsis), Style::kNone});
        return runs;
    }
    std::vector<Run> runs = runs_from(plain, styles, begin, end);
    if (width - len > 0) {
        runs.push_back({std::string(static_cast<std::size_t>(width - len), ' '), Style::kNone});
    }
    return runs;
}

// Wrap a cell to width columns, returning styled lines each width cells wide.
// A token longer than width is truncated with an ellipsis, matching rich's
// default "ellipsis" overflow rather than folding.
[[nodiscard]] std::vector<std::vector<Run>> wrap_cell(const Cell& cell, int width) {
    const std::string plain = cell_plain(cell);
    const std::vector<Style> styles = cell_styles(cell);

    std::vector<std::vector<Run>> out;
    std::size_t start = 0;
    while (start <= plain.size()) {
        const std::size_t nl = plain.find('\n', start);
        const std::size_t stop = (nl == std::string::npos) ? plain.size() : nl;
        const std::string line = plain.substr(start, stop - start);

        std::size_t cursor = start;
        const auto offsets = detail::divide_line(line, width);
        std::size_t prev = 0;
        for (const int off : offsets) {
            out.push_back(make_line(plain, styles, cursor + prev,
                                    start + static_cast<std::size_t>(off), width));
            prev = static_cast<std::size_t>(off);
        }
        out.push_back(make_line(plain, styles, cursor + prev, stop, width));

        if (nl == std::string::npos) { break; }
        start = nl + 1;
    }
    return out;
}

// Build one horizontal box rule spanning the column widths.
[[nodiscard]] std::string border(const std::vector<int>& widths,
                                 std::string_view left, std::string_view cross,
                                 std::string_view right) {
    std::string s(left);
    for (std::size_t i = 0; i < widths.size(); ++i) {
        for (int k = 0; k < widths[i]; ++k) { s.append(kHorizontal); }
        if (i + 1 < widths.size()) { s.append(cross); }
    }
    s.append(right);
    s.push_back('\n');
    return s;
}

// Emit one styled line, wrapping cyan runs in ANSI escapes when color is set.
void emit_runs(std::string& out, const std::vector<Run>& runs, bool color) {
    for (const Run& run : runs) {
        if (color && run.style == Style::kCyan) {
            out.append(kCyanOn);
            out.append(run.text);
            out.append(kReset);
        } else {
            out.append(run.text);
        }
    }
}

// Emit one logical row, wrapping cells and padding short cells with blank lines.
void emit_row(std::string& out, const std::vector<Cell>& cells,
              const std::vector<int>& widths, bool color) {
    const std::size_t ncols = widths.size();
    std::vector<std::vector<std::vector<Run>>> lines(ncols);
    std::size_t height = 1;
    for (std::size_t c = 0; c < ncols; ++c) {
        lines[c] = wrap_cell(cells[c], widths[c] - kCellPadding);
        height = std::max(height, lines[c].size());
    }
    for (std::size_t ln = 0; ln < height; ++ln) {
        out.append(kVertical);
        for (std::size_t c = 0; c < ncols; ++c) {
            out.push_back(' ');
            if (ln < lines[c].size()) {
                emit_runs(out, lines[c][ln], color);
            } else {
                out.append(static_cast<std::size_t>(widths[c] - kCellPadding), ' ');
            }
            out.push_back(' ');
            out.append(kVertical);
        }
        out.push_back('\n');
    }
}

}  // namespace

namespace detail {

std::vector<int> ratio_distribute(int total, const std::vector<int>& ratios) {
    long long total_ratio = 0;
    for (const int r : ratios) { total_ratio += r; }

    std::vector<int> out;
    out.reserve(ratios.size());
    long long total_remaining = total;
    for (const int ratio : ratios) {
        long long distributed = total_remaining;
        if (total_ratio > 0) {
            distributed = ceil_div(static_cast<long long>(ratio) * total_remaining, total_ratio);
        }
        out.push_back(static_cast<int>(distributed));
        total_ratio -= ratio;
        total_remaining -= distributed;
    }
    return out;
}

std::vector<int> ratio_reduce(int total, std::vector<int> ratios,
                              const std::vector<int>& maximums,
                              const std::vector<int>& values) {
    for (std::size_t i = 0; i < ratios.size(); ++i) {
        if (maximums[i] == 0) { ratios[i] = 0; }
    }
    long long total_ratio = 0;
    for (const int r : ratios) { total_ratio += r; }
    if (total_ratio == 0) { return values; }

    std::vector<int> result;
    result.reserve(values.size());
    long long total_remaining = total;
    for (std::size_t i = 0; i < ratios.size(); ++i) {
        const int ratio = ratios[i];
        if (ratio != 0 && total_ratio > 0) {
            const long long share =
                round_half_even(static_cast<long long>(ratio) * total_remaining, total_ratio);
            const long long distributed = std::min(static_cast<long long>(maximums[i]), share);
            result.push_back(values[i] - static_cast<int>(distributed));
            total_remaining -= distributed;
            total_ratio -= ratio;
        } else {
            result.push_back(values[i]);
        }
    }
    return result;
}

std::vector<int> divide_line(const std::string& text, int width) {
    std::vector<int> breaks;
    int cell_offset = 0;
    for (const auto& w : words(text)) {
        const int word_length = cell_len(rstrip(w.text));
        const int remaining = width - cell_offset;
        if (remaining >= word_length) {
            cell_offset += cell_len(w.text);
        } else if (word_length > width) {
            // Folding is disabled, so the over-long word stays put to be truncated.
            if (w.start != 0) { breaks.push_back(w.start); }
            cell_offset = cell_len(w.text);
        } else if (cell_offset != 0 && w.start != 0) {
            breaks.push_back(w.start);
            cell_offset = cell_len(w.text);
        }
    }
    return breaks;
}

std::vector<int> compute_column_widths(const Table& table, int available_width) {
    const std::size_t ncols = table.columns.size();
    const int extra_width = 2 + static_cast<int>(ncols) - 1;
    const int max_width = available_width - extra_width;

    // Natural width of each column is its widest line plus padding.
    std::vector<int> widths(ncols);
    for (std::size_t c = 0; c < ncols; ++c) {
        int measured = 0;
        if (table.show_header) {
            measured = std::max(measured, longest_line(table.columns[c].header));
        }
        for (const auto& row : table.rows) {
            measured = std::max(measured, longest_line(cell_plain(row[c])));
        }
        widths[c] = measured + kCellPadding;
    }

    int table_width = sum(widths);
    if (table_width > max_width) {
        // Over budget: shrink the widest columns, then re-measuring is a no-op
        // because every width is now at most its natural maximum.
        int total = table_width;
        int excess = total - max_width;
        while (total > 0 && excess > 0) {
            const int max_col = *std::max_element(widths.begin(), widths.end());
            int second_max = 0;
            for (const int w : widths) {
                if (w != max_col) { second_max = std::max(second_max, w); }
            }
            const int col_diff = max_col - second_max;
            std::vector<int> ratios(ncols);
            bool any = false;
            for (std::size_t c = 0; c < ncols; ++c) {
                ratios[c] = (widths[c] == max_col) ? 1 : 0;
                any = any || ratios[c] != 0;
            }
            if (!any || col_diff == 0) { break; }
            const std::vector<int> max_reduce(ncols, std::min(excess, col_diff));
            widths = ratio_reduce(excess, ratios, max_reduce, widths);
            total = sum(widths);
            excess = total - max_width;
        }
        table_width = sum(widths);
        if (table_width > max_width) {
            const std::vector<int> ones(ncols, 1);
            widths = ratio_reduce(table_width - max_width, ones, widths, widths);
            table_width = sum(widths);
        }
    }

    if (table.min_width != 0 && table_width < (table.min_width - extra_width)) {
        const int target = std::min(table.min_width - extra_width, max_width);
        const std::vector<int> pad = ratio_distribute(target - table_width, widths);
        for (std::size_t c = 0; c < ncols; ++c) { widths[c] += pad[c]; }
    }
    return widths;
}

}  // namespace detail

std::string render(const Table& table, int available_width, bool color) {
    if (table.columns.empty()) { return "\n"; }

    const std::vector<int> widths = detail::compute_column_widths(table, available_width);

    std::string out = border(widths, kTopLeft, kTopCross, kTopRight);
    if (table.show_header) {
        std::vector<Cell> headers;
        headers.reserve(table.columns.size());
        for (const auto& col : table.columns) { headers.emplace_back(col.header); }
        emit_row(out, headers, widths, color);
        out += border(widths, kMidLeft, kMidCross, kMidRight);
    }
    for (const auto& row : table.rows) { emit_row(out, row, widths, color); }
    out += border(widths, kBotLeft, kBotCross, kBotRight);
    return out;
}

}  // namespace papa::render::table
