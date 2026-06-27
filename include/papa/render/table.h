#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace papa::render::table {

// Visual style of a run of cell text. capa colors a few cells cyan in an
// interactive terminal (rich markup) and strips the color when redirected.
enum class Style : std::uint8_t {
    kNone,
    kCyan,
};

// A run of cell text sharing one style. A cell is a sequence of runs so part of
// it can be colored (e.g. a capability name) while the rest stays default.
struct Run {
    std::string text;
    Style       style{Style::kNone};
};

// One column of a Table, identified by the label shown in the header row.
struct Column {
    std::string header;
};

// A cell of a Table, built from styled runs. A plain string converts implicitly,
// which keeps unstyled call sites (the meta table, namespaces) terse.
struct Cell {
    std::vector<Run> runs;

    Cell() = default;
    Cell(std::string text) { runs.push_back({std::move(text), Style::kNone}); }  // NOLINT(*-explicit-*)
    Cell(const char* text) : Cell(std::string(text)) {}                          // NOLINT(*-explicit-*)
    explicit Cell(std::vector<Run> r) : runs(std::move(r)) {}

    // Append a run, returning *this so cells can be built fluently.
    Cell& add(std::string text, Style style) {
        runs.push_back({std::move(text), style});
        return *this;
    }
};

// A box table whose layout and glyphs match the rich library capa renders with.
// A cell's text may embed newline characters to force hard line breaks inside one
// logical row. Every row carries exactly one cell per column.
struct Table {
    std::vector<Column>             columns;
    std::vector<std::vector<Cell>>  rows;
    bool                            show_header{true};
    int                             min_width{0};
};

// Render the table to a string. Layout (column widths, wrapping) is computed on
// the plain text, so it is identical whether or not styling is emitted. When
// color is true, cyan runs are wrapped in ANSI escapes, matching capa's
// interactive output; when false the output is plain and byte-identical to capa's
// redirected output. available_width is the usable console width.
[[nodiscard]] std::string render(const Table& table, int available_width, bool color);

// Layout primitives ported verbatim from rich, exposed for direct testing.
// Callers outside the renderer should prefer render() above.
namespace detail {

// Distribute total across slots in proportion to ratios, rounding up.
// Port of rich._ratio.ratio_distribute (no per-slot minimums).
[[nodiscard]] std::vector<int> ratio_distribute(int total,
                                                const std::vector<int>& ratios);

// Reduce values by total in proportion to ratios, capped per slot by maximums.
// Port of rich._ratio.ratio_reduce, including Python round-half-to-even.
[[nodiscard]] std::vector<int> ratio_reduce(int total,
                                            std::vector<int> ratios,
                                            const std::vector<int>& maximums,
                                            const std::vector<int>& values);

// Offsets at which to break text so each line fits within width cells.
// Port of rich._wrap.divide_line with folding disabled (ellipsis overflow).
[[nodiscard]] std::vector<int> divide_line(const std::string& text, int width);

// Final per-column widths including padding, excluding the box borders.
// Port of rich.table.Table._calculate_column_widths for capa's configuration.
[[nodiscard]] std::vector<int> compute_column_widths(const Table& table,
                                                     int available_width);

}  // namespace detail

}  // namespace papa::render::table
