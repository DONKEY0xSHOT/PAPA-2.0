#include <ostream>

#include "doctest.h"

#include "papa/render/table.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tbl = papa::render::table;

namespace {

// SQUARE box glyphs, mirrored from table.cpp so expected output stays ASCII source.
constexpr std::string_view kH  = "\xE2\x94\x80";  // horizontal
constexpr std::string_view kV  = "\xE2\x94\x82";  // vertical
constexpr std::string_view kTL = "\xE2\x94\x8C";
constexpr std::string_view kTC = "\xE2\x94\xAC";
constexpr std::string_view kTR = "\xE2\x94\x90";
constexpr std::string_view kML = "\xE2\x94\x9C";
constexpr std::string_view kMC = "\xE2\x94\xBC";
constexpr std::string_view kMR = "\xE2\x94\xA4";
constexpr std::string_view kBL = "\xE2\x94\x94";
constexpr std::string_view kBC = "\xE2\x94\xB4";
constexpr std::string_view kBR = "\xE2\x94\x98";
constexpr std::string_view kEll = "\xE2\x80\xA6";

[[nodiscard]] std::string rep(std::string_view s, int n) {
    std::string out;
    for (int i = 0; i < n; ++i) { out.append(s); }
    return out;
}

}  // namespace

TEST_CASE("table: ratio_distribute spreads spare width like rich") {
    // capa's capabilities table expands [31,36] by 9 columns into [+5,+4].
    CHECK(tbl::detail::ratio_distribute(9, {31, 36}) == std::vector<int>{5, 4});
    // capa's ATT&CK table expands [22,38] by 16 into [+6,+10].
    CHECK(tbl::detail::ratio_distribute(16, {22, 38}) == std::vector<int>{6, 10});
    // Nothing to distribute leaves the columns untouched.
    CHECK(tbl::detail::ratio_distribute(0, {10, 66}) == std::vector<int>{0, 0});
}

TEST_CASE("table: ratio_reduce shrinks columns with banker's rounding") {
    // Second collapse step of a 61/47 capability row reduces [49,49] to [38,38].
    CHECK(tbl::detail::ratio_reduce(22, {1, 1}, {22, 22}, {49, 49}) ==
          std::vector<int>{38, 38});
    // A half share rounds to even (0), matching Python's round().
    CHECK(tbl::detail::ratio_reduce(1, {1, 1}, {5, 5}, {10, 10}) ==
          std::vector<int>{10, 9});
}

TEST_CASE("table: divide_line breaks on words and never folds") {
    // A phrase wraps at the last word that fits.
    CHECK(tbl::detail::divide_line("check for time delay via GetTickCount", 36) ==
          std::vector<int>{25});
    // A single token longer than the column is left whole for ellipsis truncation.
    CHECK(tbl::detail::divide_line("anti-analysis/anti-debugging/debugger-detection", 36)
              .empty());
    // A long behavior wraps across three lines at word boundaries.
    CHECK(tbl::detail::divide_line(
              "Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]",
              48) == std::vector<int>{20, 61});
}

TEST_CASE("table: compute_column_widths matches capa's observed layouts") {
    // Meta table: short keys, a 64-char sha256 value, no header, width 79.
    tbl::Table meta;
    meta.columns = {{""}, {""}};
    meta.show_header = false;
    meta.min_width = 100;
    meta.rows = {{"analysis", std::string(64, 'a')}};
    CHECK(tbl::detail::compute_column_widths(meta, 79) == std::vector<int>{10, 66});

    // ATT&CK table: first header padded to 20, longest technique 36 chars.
    tbl::Table attack;
    attack.columns = {{"ATT&CK Tactic       "}, {"ATT&CK Technique"}};
    attack.min_width = 100;
    attack.rows = {{"PRIVILEGE ESCALATION", "File and Directory Discovery [T1083]"}};
    CHECK(tbl::detail::compute_column_widths(attack, 79) == std::vector<int>{28, 48});

    // Over-budget capabilities row (61 + 47 content) collapses to even halves.
    tbl::Table caps;
    caps.columns = {{"Capability          "}, {"Namespace"}};
    caps.min_width = 100;
    caps.rows = {{std::string(61, 'c'), std::string(47, 'n')}};
    CHECK(tbl::detail::compute_column_widths(caps, 79) == std::vector<int>{38, 38});
}

TEST_CASE("table: render draws a full box with wrap, ellipsis and multi-line cells") {
    tbl::Table t;
    t.columns = {{"AB"}, {"CD"}};
    t.rows = {{"hello world foo", "abcdefghijklmnop"}};

    const std::string out = tbl::render(t, 25, /*color=*/false);

    // Columns collapse to width 11 each (content width 9).
    std::string expected;
    expected += std::string(kTL) + rep(kH, 11) + std::string(kTC) + rep(kH, 11) +
                std::string(kTR) + "\n";
    expected += std::string(kV) + " AB        " + std::string(kV) + " CD        " +
                std::string(kV) + "\n";
    expected += std::string(kML) + rep(kH, 11) + std::string(kMC) + rep(kH, 11) +
                std::string(kMR) + "\n";
    expected += std::string(kV) + " hello     " + std::string(kV) + " abcdefgh" +
                std::string(kEll) + " " + std::string(kV) + "\n";
    expected += std::string(kV) + " world foo " + std::string(kV) + "           " +
                std::string(kV) + "\n";
    expected += std::string(kBL) + rep(kH, 11) + std::string(kBC) + rep(kH, 11) +
                std::string(kBR) + "\n";

    CHECK(out == expected);
}

TEST_CASE("table: render returns a newline for an empty table") {
    tbl::Table t;
    CHECK(tbl::render(t, 79, false) == "\n");
}

TEST_CASE("table: cyan runs are styled only when color is enabled") {
    tbl::Table t;
    t.columns = {{"H1"}, {"H2"}};
    tbl::Cell name;
    name.add("alpha", tbl::Style::kCyan).add(" beta", tbl::Style::kNone);
    t.rows.push_back({std::move(name), tbl::Cell{"plainns"}});

    const std::string colored = tbl::render(t, 79, /*color=*/true);
    const std::string plain   = tbl::render(t, 79, /*color=*/false);

    // Color mode wraps the cyan run in SGR escapes, leaving the rest default.
    CHECK(colored.find("\x1b[36malpha\x1b[0m beta") != std::string::npos);
    // Plain mode emits no escape sequences at all.
    CHECK(plain.find('\x1b') == std::string::npos);
    CHECK(plain.find("alpha beta") != std::string::npos);
    // Styling must not change the layout: stripping escapes yields the plain form.
    std::string stripped;
    for (std::size_t i = 0; i < colored.size();) {
        if (colored[i] == '\x1b') {
            i = colored.find('m', i);
            i = (i == std::string::npos) ? colored.size() : i + 1;
        } else {
            stripped.push_back(colored[i]);
            ++i;
        }
    }
    CHECK(stripped == plain);
}
