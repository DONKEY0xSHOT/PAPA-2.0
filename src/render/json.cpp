#include "papa/render/json.h"

#include "papa/features/address.h"
#include "papa/features/basic_block.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/features/insn.h"
#include "papa/loader.h"
#include "papa/render/result_document.h"
#include "papa/render/spec.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"
#include "papa/util/json_writer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

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

// Emit a bare image-base or similar value as capa's absolute address object
void emit_absolute(::papa::util::json::Writer& w, std::uint64_t value) {
    emit_address(w,
                 ::papa::features::Address{::papa::features::AbsoluteVirtualAddress{value}});
}

// Field order and nesting mirror capa's StaticMetadata / StaticAnalysis so the
// document round-trips through capa's own loader
void emit_meta(::papa::util::json::Writer& w, const Metadata& m) {
    w.key("meta");
    w.begin_object();
    w.key("timestamp"); w.value_string(m.timestamp);
    w.key("version");   w.value_string(m.version);
    w.key("argv");      emit_string_array(w, m.argv);

    w.key("sample");
    w.begin_object();
    w.key("md5");    w.value_string(m.hashes.md5);
    w.key("sha1");   w.value_string(m.hashes.sha1);
    w.key("sha256"); w.value_string(m.hashes.sha256);
    w.key("path");   w.value_string(::papa::render::posix_path(m.sample_path));
    w.end_object();

    w.key("flavor"); w.value_string("static");

    w.key("analysis");
    w.begin_object();
    w.key("format");       w.value_string(m.analysis.format);
    w.key("arch");         w.value_string(m.analysis.arch);
    w.key("os");           w.value_string(m.analysis.os);
    w.key("extractor");    w.value_string(m.analysis.extractor);
    w.key("rules");        emit_string_array(w, m.analysis.rules_paths);
    w.key("base_address"); emit_absolute(w, m.analysis.base_address);

    // layout links each function to the basic blocks within it that matched
    w.key("layout");
    w.begin_object();
    w.key("functions");
    w.begin_array();
    for (const auto& fn : m.analysis.layout) {
        w.begin_object();
        w.key("address"); emit_address(w, fn.address);
        w.key("matched_basic_blocks");
        w.begin_array();
        for (const auto& bb : fn.matched_basic_blocks) {
            w.begin_object();
            w.key("address"); emit_address(w, bb);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
    w.end_array();
    w.end_object();

    w.key("feature_counts");
    w.begin_object();
    w.key("file");
    w.value_uint(static_cast<std::uint64_t>(m.analysis.feature_count_file));
    w.key("functions");
    w.begin_array();
    for (const auto& fc : m.analysis.feature_counts_functions) {
        w.begin_object();
        w.key("address"); emit_address(w, fc.address);
        w.key("count");   w.value_uint(static_cast<std::uint64_t>(fc.count));
        w.end_object();
    }
    w.end_array();
    w.end_object();

    w.key("library_functions");
    w.begin_array();
    for (const auto& lf : m.analysis.library_functions) {
        w.begin_object();
        w.key("address"); emit_address(w, lf.address);
        w.key("name");    w.value_string(lf.name);
        w.end_object();
    }
    w.end_array();

    w.end_object();    // analysis
    w.end_object();    // meta
}

// Emit the parsed ATT&CK entries as capa's AttackSpec objects
void emit_attack_array(::papa::util::json::Writer&         w,
                       const std::vector<std::string>&    raw) {
    w.begin_array();
    for (const auto& s : raw) {
        const ::papa::render::AttackSpec spec = ::papa::render::attack_from_string(s);
        w.begin_object();
        w.key("parts");        emit_string_array(w, spec.parts);
        w.key("tactic");       w.value_string(spec.tactic);
        w.key("technique");    w.value_string(spec.technique);
        w.key("subtechnique"); w.value_string(spec.subtechnique);
        w.key("id");           w.value_string(spec.id);
        w.end_object();
    }
    w.end_array();
}

// Emit the parsed MBC entries as capa's MBCSpec objects
void emit_mbc_array(::papa::util::json::Writer&         w,
                    const std::vector<std::string>&    raw) {
    w.begin_array();
    for (const auto& s : raw) {
        const ::papa::render::MbcSpec spec = ::papa::render::mbc_from_string(s);
        w.begin_object();
        w.key("parts");     emit_string_array(w, spec.parts);
        w.key("objective"); w.value_string(spec.objective);
        w.key("behavior");  w.value_string(spec.behavior);
        w.key("method");    w.value_string(spec.method);
        w.key("id");        w.value_string(spec.id);
        w.end_object();
    }
    w.end_array();
}

// Field order and shapes mirror capa's RuleMetadata so the JSON round-trips
// through capa's own loader. maec is always emitted, empty when absent
void emit_rule_meta(::papa::util::json::Writer&     w,
                    const ::papa::rules::RuleMeta&  rm) {
    w.key("name");      w.value_string(rm.name);
    if (rm.namespace_.has_value()) {
        w.key("namespace"); w.value_string(*rm.namespace_);
    }
    w.key("authors");   emit_string_array(w, rm.authors);

    w.key("scopes");
    w.begin_object();
    if (rm.scopes.static_scope.has_value()) {
        w.key("static"); w.value_string(scope_to_string(*rm.scopes.static_scope));
    }
    if (rm.scopes.dynamic_scope.has_value()) {
        w.key("dynamic"); w.value_string(scope_to_string(*rm.scopes.dynamic_scope));
    }
    w.end_object();

    w.key("attack");     emit_attack_array(w, rm.att_and_ck);
    w.key("mbc");        emit_mbc_array(w, rm.mbc);
    w.key("references"); emit_string_array(w, rm.references);
    w.key("examples");   emit_string_array(w, rm.examples);
    w.key("description"); w.value_string(rm.description.value_or(std::string{}));
    w.key("lib");              w.value_bool(rm.lib);
    w.key("is_subscope_rule"); w.value_bool(rm.is_subscope_rule);

    // PAPA does not parse maec metadata, so the object is always empty, which
    // matches capa's exclude_none output for the benign rules in scope
    w.key("maec");
    w.begin_object();
    w.end_object();
}

// Encode a Number/OperandNumber value as capa's int-or-float JSON number
void emit_number_value(::papa::util::json::Writer&                                 w,
                       const std::variant<std::uint64_t, std::int64_t, double>&    v) {
    if (const auto* u = std::get_if<std::uint64_t>(&v))      { w.value_uint(*u); }
    else if (const auto* i = std::get_if<std::int64_t>(&v))  { w.value_int(*i); }
    else if (const auto* d = std::get_if<double>(&v))        { w.value_double(*d); }
}

void emit_hex_bytes(::papa::util::json::Writer& w, std::span<const std::byte> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (const std::byte b : bytes) {
        const auto v = static_cast<unsigned char>(b);
        s.push_back(kHex[v >> 4]);
        s.push_back(kHex[v & 0x0F]);
    }
    w.value_string(s);
}

// Serialize one feature in capa's freeze format: {type, <value field>, description?}.
// Field names follow capa's FeatureModel attribute names (operand_offset, etc.)
void emit_feature(::papa::util::json::Writer& w, const features::Feature& f) {
    using namespace ::papa::features;
    w.begin_object();
    switch (f.tag()) {
        case FeatureTag::kOs:
            w.key("type"); w.value_string("os");
            w.key("os");   w.value_string(static_cast<const Os&>(f).value());
            break;
        case FeatureTag::kArch:
            w.key("type"); w.value_string("arch");
            w.key("arch"); w.value_string(static_cast<const Arch&>(f).value());
            break;
        case FeatureTag::kFormat:
            w.key("type");   w.value_string("format");
            w.key("format"); w.value_string(static_cast<const Format&>(f).value());
            break;
        case FeatureTag::kMatchedRule:
            w.key("type");  w.value_string("match");
            w.key("match"); w.value_string(static_cast<const MatchedRule&>(f).rule_name());
            break;
        case FeatureTag::kCharacteristic:
            w.key("type");           w.value_string("characteristic");
            w.key("characteristic"); w.value_string(static_cast<const Characteristic&>(f).value());
            break;
        case FeatureTag::kExport:
            w.key("type");   w.value_string("export");
            w.key("export"); w.value_string(static_cast<const Export&>(f).value());
            break;
        case FeatureTag::kImport:
            w.key("type");    w.value_string("import");
            w.key("import_"); w.value_string(static_cast<const Import&>(f).value());
            break;
        case FeatureTag::kSection:
            w.key("type");    w.value_string("section");
            w.key("section"); w.value_string(static_cast<const Section&>(f).value());
            break;
        case FeatureTag::kFunctionName:
            w.key("type");          w.value_string("function name");
            w.key("function_name"); w.value_string(static_cast<const FunctionName&>(f).value());
            break;
        case FeatureTag::kSubstring:
            w.key("type");      w.value_string("substring");
            w.key("substring"); w.value_string(static_cast<const Substring&>(f).value());
            break;
        case FeatureTag::kRegex:
            w.key("type");  w.value_string("regex");
            w.key("regex"); w.value_string(static_cast<const Regex&>(f).value());
            break;
        case FeatureTag::kString:
            w.key("type");   w.value_string("string");
            w.key("string"); w.value_string(static_cast<const String&>(f).value());
            break;
        case FeatureTag::kClass:
            w.key("type");   w.value_string("class");
            w.key("class_"); w.value_string(static_cast<const Class&>(f).value());
            break;
        case FeatureTag::kNamespace:
            w.key("type");      w.value_string("namespace");
            w.key("namespace"); w.value_string(static_cast<const Namespace&>(f).value());
            break;
        case FeatureTag::kApi:
            w.key("type"); w.value_string("api");
            w.key("api");  w.value_string(static_cast<const Api&>(f).value());
            break;
        case FeatureTag::kProperty: {
            const auto& p = static_cast<const Property&>(f);
            w.key("type"); w.value_string("property");
            if (p.access() == Property::Access::kRead) {
                w.key("access"); w.value_string("read");
            } else if (p.access() == Property::Access::kWrite) {
                w.key("access"); w.value_string("write");
            }
            w.key("property"); w.value_string(p.value());
            break;
        }
        case FeatureTag::kNumber:
            w.key("type");   w.value_string("number");
            w.key("number"); emit_number_value(w, static_cast<const Number&>(f).value());
            break;
        case FeatureTag::kBytes:
            w.key("type");  w.value_string("bytes");
            w.key("bytes"); emit_hex_bytes(w, static_cast<const Bytes&>(f).value());
            break;
        case FeatureTag::kOffset:
            w.key("type");   w.value_string("offset");
            w.key("offset"); w.value_int(static_cast<const Offset&>(f).value());
            break;
        case FeatureTag::kMnemonic:
            w.key("type");     w.value_string("mnemonic");
            w.key("mnemonic"); w.value_string(static_cast<const Mnemonic&>(f).value());
            break;
        case FeatureTag::kOperandNumber: {
            const auto& o = static_cast<const OperandNumber&>(f);
            w.key("type");           w.value_string("operand number");
            w.key("index");          w.value_uint(static_cast<std::uint64_t>(o.index()));
            w.key("operand_number"); emit_number_value(w, o.value());
            break;
        }
        case FeatureTag::kOperandOffset: {
            const auto& o = static_cast<const OperandOffset&>(f);
            w.key("type");           w.value_string("operand offset");
            w.key("index");          w.value_uint(static_cast<std::uint64_t>(o.index()));
            w.key("operand_offset"); w.value_int(o.value());
            break;
        }
        case FeatureTag::kBasicBlock:
            w.key("type"); w.value_string("basic block");
            break;
    }
    if (!f.description().empty()) {
        w.key("description"); w.value_string(f.description());
    }
    w.end_object();
}

// Serialize one match-tree node: {success, node, children, locations, captures}.
// captures is always empty because PAPA does not retain regex capture groups
void emit_match_node(::papa::util::json::Writer& w, const render::MatchNode& node) {
    w.begin_object();
    w.key("success"); w.value_bool(node.success);

    w.key("node");
    w.begin_object();
    if (node.is_feature) {
        w.key("type");    w.value_string("feature");
        w.key("feature"); emit_feature(w, *node.feature);
    } else {
        w.key("type"); w.value_string("statement");
        w.key("statement");
        w.begin_object();
        w.key("type"); w.value_string(node.statement_type);
        if (node.statement_type == "some" && node.count.has_value()) {
            w.key("count"); w.value_int(*node.count);
        } else if (node.statement_type == "range") {
            w.key("min");   w.value_int(node.range_min.value_or(0));
            w.key("max");   w.value_int(node.range_max.value_or(0));
            w.key("child"); emit_feature(w, *node.range_child);
        } else if (node.statement_type == "subscope" && node.subscope.has_value()) {
            w.key("scope"); w.value_string(scope_to_string(*node.subscope));
        }
        w.end_object();
    }
    w.end_object();    // node

    w.key("children");
    w.begin_array();
    for (const auto& child : node.children) { emit_match_node(w, child); }
    w.end_array();

    w.key("locations");
    w.begin_array();
    for (const auto& loc : node.locations) { emit_address(w, loc); }
    w.end_array();

    w.key("captures");
    w.begin_object();
    w.end_object();

    w.end_object();
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

        // capa pairs each match address with the full match tree at that address
        w.key("matches");
        w.begin_array();
        for (const auto& [addr, node] : rep.matches) {
            w.begin_array();
            emit_address(w, addr);
            emit_match_node(w, node);
            w.end_array();
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
