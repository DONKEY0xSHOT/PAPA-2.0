#include "papa/render/text.h"

#include "papa/features/address.h"
#include "papa/loader.h"
#include "papa/render/result_document.h"
#include "papa/render/spec.h"
#include "papa/render/table.h"
#include "papa/rules/rule.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <map>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace papa::render::text {

namespace {

constexpr std::string_view kNoNamespace = "(no namespace)";

[[nodiscard]] std::string format_address(const features::Address& a) {
    using namespace ::papa::features;
    std::ostringstream oss;
    if (const auto* abs_va = std::get_if<AbsoluteVirtualAddress>(&a)) {
        oss << "0x" << std::hex << std::uppercase << abs_va->v;
    } else if (const auto* rel_va = std::get_if<RelativeVirtualAddress>(&a)) {
        oss << "rva 0x" << std::hex << std::uppercase << rel_va->v;
    } else if (const auto* fo = std::get_if<FileOffsetAddress>(&a)) {
        oss << "file 0x" << std::hex << std::uppercase << fo->v;
    } else {
        oss << "(none)";
    }
    return oss.str();
}

// Pad a string to at least twenty cells, matching capa's width() header helper
[[nodiscard]] std::string pad20(std::string_view s) {
    std::string out(s);
    if (out.size() < 20) { out.append(20 - out.size(), ' '); }
    return out;
}

[[nodiscard]] std::string to_upper_ascii(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        if (c >= 'a' && c <= 'z') { c = static_cast<char>(c - 'a' + 'A'); }
    }
    return out;
}

[[nodiscard]] std::string join_newline(const std::vector<std::string>& lines) {
    std::string out;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (i != 0) { out.push_back('\n'); }
        out.append(lines[i]);
    }
    return out;
}

// Usable console width capa renders against: COLUMNS if set, else 80, less one
[[nodiscard]] int default_console_width() {
    int columns = 80;
    std::string value;
#ifdef _MSC_VER
    std::size_t needed = 0;
    char buf[32] = {};
    if (getenv_s(&needed, buf, sizeof(buf), "COLUMNS") == 0 && needed > 1) {
        value.assign(buf);
    }
#else
    if (const char* env = std::getenv("COLUMNS")) { value.assign(env); }
#endif
    if (!value.empty()) {
        int parsed = 0;
        const char* first = value.data();
        const char* last = first + value.size();
        if (auto [ptr, ec] = std::from_chars(first, last, parsed);
            ec == std::errc() && parsed > 0) {
            columns = parsed;
        }
    }
    return columns - 1;
}

// Capability rules in capa's (namespace, name) order, excluding building blocks
[[nodiscard]] std::vector<const RuleReport*>
capability_rules(const ResultDocument& doc) {
    std::vector<const RuleReport*> out;
    for (const auto& [_name, rep] : doc.rules) {
        const auto& m = rep.meta;
        if (m.lib || m.is_subscope_rule) { continue; }
        if (m.namespace_.has_value() && m.namespace_->starts_with("internal/")) {
            continue;
        }
        out.push_back(&rep);
    }
    std::sort(out.begin(), out.end(), [](const RuleReport* a, const RuleReport* b) {
        const std::string na = a->meta.namespace_.value_or(std::string{});
        const std::string nb = b->meta.namespace_.value_or(std::string{});
        return std::tie(na, a->meta.name) < std::tie(nb, b->meta.name);
    });
    return out;
}

[[nodiscard]] std::string render_meta(const ResultDocument& doc, int width, bool color) {
    table::Table t;
    t.columns = {table::Column{}, table::Column{}};
    t.show_header = false;
    t.min_width = 100;
    t.rows = {
        {"md5", doc.meta.hashes.md5},
        {"sha1", doc.meta.hashes.sha1},
        {"sha256", doc.meta.hashes.sha256},
        {"analysis", "static"},
        {"os", doc.meta.analysis.os},
        {"format", doc.meta.analysis.format},
        {"arch", doc.meta.analysis.arch},
        {"path", posix_path(doc.meta.sample_path)},
    };
    return table::render(t, width, color);
}

// Group parsed specs by their leading part (tactic/objective), then render rows.
// capa colors the group and the detail name cyan, leaving the id default
[[nodiscard]] std::string
render_spec_table(const std::vector<const RuleReport*>& caps,
                  std::vector<std::string> rules::RuleMeta::* field,
                  std::string_view group_header, std::string_view detail_header,
                  int width, bool color) {
    // ATT&CK and MBC share the same parse shape, so one parser serves both:
    // parts[0] is the group, parts[1] and parts[2] the detail and sub-detail
    std::map<std::string, std::set<std::tuple<std::string, std::string, std::string>>> groups;
    for (const auto* rep : caps) {
        for (const auto& spec : rep->meta.*field) {
            const AttackSpec parsed = attack_from_string(spec);
            groups[parsed.tactic].insert(
                {parsed.technique, parsed.subtechnique, parsed.id});
        }
    }
    if (groups.empty()) { return {}; }

    table::Table t;
    t.columns = {table::Column{pad20(group_header)}, table::Column{std::string(detail_header)}};
    t.min_width = 100;
    for (const auto& [group, details] : groups) {
        table::Cell detail;
        bool first = true;
        for (const auto& [name, sub, id] : details) {
            if (!first) { detail.add("\n", table::Style::kNone); }
            first = false;
            detail.add(name, table::Style::kCyan);
            detail.add(sub.empty() ? " [" + id + "]" : "::" + sub + " [" + id + "]",
                       table::Style::kNone);
        }
        table::Cell head;
        head.add(to_upper_ascii(group), table::Style::kCyan);
        t.rows.push_back({std::move(head), std::move(detail)});
    }
    return table::render(t, width, color);
}

// capa colors the capability name cyan, leaving the namespace and any "(N
// matches)" suffix default
[[nodiscard]] std::string
render_capabilities(const ResultDocument& doc,
                    const std::vector<const RuleReport*>& caps, int width, bool color) {
    table::Table t;
    t.columns = {table::Column{pad20("Capability")}, table::Column{"Namespace"}};
    t.min_width = 100;
    for (const auto* rep : caps) {
        // A rule pulled in by another capability rule is not listed on its own
        if (doc.matched_subrules.count(rep->meta.name) != 0) { continue; }
        table::Cell capability;
        capability.add(rep->meta.name, table::Style::kCyan);
        if (rep->match_count != 1) {
            capability.add(" (" + std::to_string(rep->match_count) + " matches)",
                           table::Style::kNone);
        }
        t.rows.push_back({std::move(capability),
                          table::Cell{rep->meta.namespace_.value_or(std::string{})}});
    }
    if (t.rows.empty()) { return "no capabilities found\n"; }
    return table::render(t, width, color);
}

// Default report: the meta, ATT&CK, MBC and capability tables capa prints
void emit_default(const ResultDocument& doc, std::ostream& out, bool color) {
    const int width = default_console_width();
    const std::vector<const RuleReport*> caps = capability_rules(doc);

    std::string report = render_meta(doc, width, color);
    report += render_spec_table(caps, &rules::RuleMeta::att_and_ck, "ATT&CK Tactic",
                                "ATT&CK Technique", width, color);
    report += render_spec_table(caps, &rules::RuleMeta::mbc, "MBC Objective",
                                "MBC Behavior", width, color);
    report += render_capabilities(doc, caps, width, color);

    // capa prints render_default()'s value, which adds one trailing newline
    report.push_back('\n');
    out << report;
}

// Plain header used by the verbose modes, which keep PAPA's own layout
void emit_header(const ResultDocument& doc, std::ostream& out) {
    out << "PAPA " << doc.meta.version << '\n';
    out << "sample: " << doc.meta.sample_path.string() << '\n';
    out << "size:   " << doc.meta.sample_size_bytes << " bytes\n";
    out << "md5:    " << doc.meta.hashes.md5    << '\n';
    out << "sha1:   " << doc.meta.hashes.sha1   << '\n';
    out << "sha256: " << doc.meta.hashes.sha256 << '\n';
    out << "os:     " << doc.meta.analysis.os << ' '
                       << doc.meta.analysis.arch << ' '
                       << doc.meta.analysis.format << '\n';
    out << '\n';
}

// Group rules by their (possibly empty) namespace
// std::map sort makes the namespace listing alphabetical, matching CAPA's
// default output ordering
[[nodiscard]] std::map<std::string, std::vector<const RuleReport*>>
group_by_namespace(const ResultDocument& doc) {
    std::map<std::string, std::vector<const RuleReport*>> groups;
    for (const auto& [_name, rep] : doc.rules) {
        // Library rules are building blocks for other rules, not capabilities.
        // capa matches them and keeps them in --json but never lists them in its
        // text report, so the text renderer skips them to match that output
        if (rep.meta.lib) { continue; }
        const std::string ns =
            rep.meta.namespace_.value_or(std::string(kNoNamespace));
        groups[ns].push_back(&rep);
    }
    return groups;
}

void emit_verbose(const ResultDocument& doc, std::ostream& out) {
    emit_header(doc, out);
    if (doc.rules.empty()) {
        out << "no capabilities matched\n";
        return;
    }
    auto groups = group_by_namespace(doc);
    for (const auto& [ns, reports] : groups) {
        out << ns << '\n';
        for (const auto* rep : reports) {
            out << "  " << rep->meta.name << '\n';
            if (rep->meta.description.has_value() &&
                !rep->meta.description->empty()) {
                out << "    description: " << *rep->meta.description << '\n';
            }
            if (!rep->addresses.empty()) {
                out << "    matches:";
                for (const auto& a : rep->addresses) {
                    out << ' ' << format_address(a);
                }
                out << '\n';
            }
        }
        out << '\n';
    }
}

void emit_vverbose(const ResultDocument& doc, std::ostream& out) {
    // vverbose is verbose plus the embedded rule YAML
    // A future revision may surface a per-match feature tree
    // v1 keeps the output stable and human-readable without that level of detail
    emit_verbose(doc, out);
    out << "----- rule sources -----\n\n";
    for (const auto& [_name, rep] : doc.rules) {
        if (rep.meta.lib) { continue; }
        if (rep.source_yaml.empty()) { continue; }
        out << "# " << rep.meta.name << "\n";
        out << rep.source_yaml << "\n\n";
    }
}

}  // namespace

void render(const ResultDocument& doc, std::ostream& out, Verbosity v, bool color) {
    switch (v) {
        case Verbosity::kDefault:  emit_default(doc, out, color);  break;
        case Verbosity::kVerbose:  emit_verbose(doc, out);  break;
        case Verbosity::kVverbose: emit_vverbose(doc, out); break;
    }
}

std::string render_to_string(const ResultDocument& doc, Verbosity v) {
    std::ostringstream oss;
    render(doc, oss, v, /*color=*/false);
    return oss.str();
}

}  // namespace papa::render::text
