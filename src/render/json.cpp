#include "papa/render/json.h"

#include "papa/features/address.h"
#include "papa/loader.h"
#include "papa/render/result_document.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"
#include "papa/util/json_writer.h"

#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>

namespace papa::render::json {

namespace {

// Emit one Address as a small object
// CAPA expresses every address as { "type": <kind>, "value": <number> } so we
// preserve the same shape for byte-level diffability against capa.exe output
void emit_address(::papa::util::json::Writer& w, const features::Address& a) {
    using namespace ::papa::features;
    w.begin_object();
    if (const auto* abs_va = std::get_if<AbsoluteVirtualAddress>(&a)) {
        w.key("type");  w.value_string("absolute");
        w.key("value"); w.value_uint(abs_va->v);
    } else if (const auto* rel_va = std::get_if<RelativeVirtualAddress>(&a)) {
        w.key("type");  w.value_string("relative");
        w.key("value"); w.value_uint(rel_va->v);
    } else if (const auto* fo = std::get_if<FileOffsetAddress>(&a)) {
        w.key("type");  w.value_string("file");
        w.key("value"); w.value_uint(fo->v);
    } else if (const auto* tok = std::get_if<DnTokenAddress>(&a)) {
        w.key("type");  w.value_string("dn_token");
        w.key("value"); w.value_uint(tok->token);
    } else if (const auto* toff = std::get_if<DnTokenOffsetAddress>(&a)) {
        w.key("type");   w.value_string("dn_token_offset");
        w.key("token");  w.value_uint(toff->token);
        w.key("offset"); w.value_uint(toff->offset);
    } else {
        w.key("type");  w.value_string("none");
        w.key("value"); w.value_null();
    }
    w.end_object();
}

void emit_string_array(::papa::util::json::Writer& w,
                       std::span<const std::string>  items) {
    w.begin_array();
    for (const auto& s : items) { w.value_string(s); }
    w.end_array();
}

// Map a Scope enum to its JSON tag
[[nodiscard]] std::string_view scope_to_string(::papa::rules::Scope s) noexcept {
    return ::papa::rules::to_string(s);
}

void emit_meta(::papa::util::json::Writer& w, const Metadata& m) {
    w.key("meta");
    w.begin_object();
    w.key("timestamp"); w.value_string(m.timestamp);
    w.key("version");   w.value_string(m.version);
    w.key("argv");      w.value_string(m.argv);

    w.key("sample");
    w.begin_object();
    w.key("path");      w.value_string(m.sample_path.string());
    w.key("size");      w.value_uint(m.sample_size_bytes);
    w.key("md5");       w.value_string(m.hashes.md5);
    w.key("sha1");      w.value_string(m.hashes.sha1);
    w.key("sha256");    w.value_string(m.hashes.sha256);
    w.end_object();

    w.key("analysis");
    w.begin_object();
    w.key("os");        w.value_string(m.analysis.os);
    w.key("arch");      w.value_string(m.analysis.arch);
    w.key("format");    w.value_string(m.analysis.format);
    w.key("extractor"); w.value_string(m.analysis.extractor);
    w.key("rules");     emit_string_array(w, m.analysis.rules_paths);
    w.key("feature_count_file");
    w.value_uint(static_cast<std::uint64_t>(m.analysis.feature_count_file));

    w.key("feature_counts_functions");
    w.begin_array();
    for (auto v : m.analysis.feature_counts_functions) {
        w.value_uint(static_cast<std::uint64_t>(v));
    }
    w.end_array();

    w.key("library_functions");
    w.begin_array();
    for (const auto& a : m.analysis.library_functions) {
        emit_address(w, a);
    }
    w.end_array();

    w.end_object();    // analysis
    w.end_object();    // meta
}

void emit_rule_meta(::papa::util::json::Writer&     w,
                    const ::papa::rules::RuleMeta&  rm) {
    w.key("name");      w.value_string(rm.name);
    if (rm.namespace_.has_value()) {
        w.key("namespace"); w.value_string(*rm.namespace_);
    }
    w.key("scopes");
    w.begin_object();
    if (rm.scopes.static_scope.has_value()) {
        w.key("static"); w.value_string(scope_to_string(*rm.scopes.static_scope));
    }
    if (rm.scopes.dynamic_scope.has_value()) {
        w.key("dynamic"); w.value_string(scope_to_string(*rm.scopes.dynamic_scope));
    }
    w.end_object();
    w.key("authors");    emit_string_array(w, rm.authors);
    w.key("att&ck");     emit_string_array(w, rm.att_and_ck);
    w.key("mbc");        emit_string_array(w, rm.mbc);
    w.key("examples");   emit_string_array(w, rm.examples);
    w.key("references"); emit_string_array(w, rm.references);
    if (rm.description.has_value()) {
        w.key("description"); w.value_string(*rm.description);
    }
    w.key("lib"); w.value_bool(rm.lib);
}

void emit_rules(::papa::util::json::Writer& w, const ResultDocument& doc) {
    w.key("rules");
    w.begin_object();
    for (const auto& [name, rep] : doc.rules) {
        w.key(name);
        w.begin_object();
        w.key("meta");
        w.begin_object();
        emit_rule_meta(w, rep.meta);
        w.end_object();

        w.key("source"); w.value_string(rep.source_yaml);

        w.key("matches");
        w.begin_array();
        for (const auto& a : rep.addresses) {
            emit_address(w, a);
        }
        w.end_array();
        w.end_object();
    }
    w.end_object();
}

}  // namespace

void render(const ResultDocument& doc, std::ostream& out, bool pretty) {
    ::papa::util::json::Writer w(out, pretty);
    w.begin_object();
    emit_meta(w, doc.meta);
    emit_rules(w, doc);
    w.end_object();
}

std::string render_to_string(const ResultDocument& doc, bool pretty) {
    std::ostringstream oss;
    render(doc, oss, pretty);
    return oss.str();
}

}  // namespace papa::render::json
