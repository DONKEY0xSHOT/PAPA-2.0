#include "papa/render/text.h"

#include "papa/features/address.h"
#include "papa/loader.h"
#include "papa/render/result_document.h"
#include "papa/rules/rule.h"

#include <iomanip>
#include <map>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
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
        const std::string ns =
            rep.meta.namespace_.value_or(std::string(kNoNamespace));
        groups[ns].push_back(&rep);
    }
    return groups;
}

void emit_default(const ResultDocument& doc, std::ostream& out) {
    emit_header(doc, out);
    if (doc.rules.empty()) {
        out << "no capabilities matched\n";
        return;
    }
    auto groups = group_by_namespace(doc);
    for (const auto& [ns, reports] : groups) {
        out << ns << '\n';
        for (const auto* rep : reports) {
            out << "  " << rep->meta.name;
            const auto count = rep->addresses.size();
            if (count > 0) {
                out << "  [" << count
                    << (count == 1U ? " match]" : " matches]");
            }
            out << '\n';
        }
        out << '\n';
    }
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
    // A future revision may surface a per-match feature tree; v1 keeps the
    // output stable and human-readable without that level of detail
    emit_verbose(doc, out);
    out << "----- rule sources -----\n\n";
    for (const auto& [_name, rep] : doc.rules) {
        if (rep.source_yaml.empty()) { continue; }
        out << "# " << rep.meta.name << "\n";
        out << rep.source_yaml << "\n\n";
    }
}

}  // namespace

void render(const ResultDocument& doc, std::ostream& out, Verbosity v) {
    switch (v) {
        case Verbosity::kDefault:  emit_default(doc, out);  break;
        case Verbosity::kVerbose:  emit_verbose(doc, out);  break;
        case Verbosity::kVverbose: emit_vverbose(doc, out); break;
    }
}

std::string render_to_string(const ResultDocument& doc, Verbosity v) {
    std::ostringstream oss;
    render(doc, oss, v);
    return oss.str();
}

}  // namespace papa::render::text
