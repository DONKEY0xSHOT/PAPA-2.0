#include "papa/rules/parser.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/basic_block.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/features/insn.h"
#include "papa/rules/com_lookup.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"
#include "papa/util/yaml.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace papa::rules {

namespace {

// Reusable pull of the Expected alias that the helper functions return
// papa::util::Expected is a 2-arg template so the bare alias would shadow papa::Expected
template <typename T>
using Expected = ::papa::Expected<T>;

using ::papa::ErrorKind;
using ::papa::PapaError;
using ::papa::Unexpected;
using ::papa::engine::And;
using ::papa::engine::FeatureStatement;
using ::papa::engine::Not;
using ::papa::engine::Or;
using ::papa::engine::Range;
using ::papa::engine::Some;
using ::papa::engine::Statement;
using ::papa::engine::Subscope;
using ::papa::features::Api;
using ::papa::features::Arch;
using ::papa::features::Bytes;
using ::papa::features::Characteristic;
using ::papa::features::Class;
using ::papa::features::Export;
using ::papa::features::Feature;
using ::papa::features::FeaturePtr;
using ::papa::features::FeatureTag;
using ::papa::features::Format;
using ::papa::features::FunctionName;
using ::papa::features::Import;
using ::papa::features::MatchedRule;
using ::papa::features::Mnemonic;
using ::papa::features::Namespace;
using ::papa::features::Number;
using ::papa::features::Offset;
using ::papa::features::OperandNumber;
using ::papa::features::OperandOffset;
using ::papa::features::Os;
using ::papa::features::Property;
using ::papa::features::Regex;
using ::papa::features::Section;
using ::papa::features::String;
using ::papa::features::Substring;

namespace yaml = ::papa::util::yaml;

// string helpers
constexpr std::string_view kInlineDescSep = " = ";

[[nodiscard]] bool is_ws(char c) noexcept {
    return c == ' ' || c == '\t';
}

[[nodiscard]] std::string_view ltrim(std::string_view s) noexcept {
    while (!s.empty() && is_ws(s.front())) { s.remove_prefix(1); }
    return s;
}

[[nodiscard]] std::string_view rtrim(std::string_view s) noexcept {
    while (!s.empty() && is_ws(s.back())) { s.remove_suffix(1); }
    return s;
}

[[nodiscard]] std::string_view trim(std::string_view s) noexcept {
    return rtrim(ltrim(s));
}

[[nodiscard]] bool starts_with(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() &&
           s.substr(0, prefix.size()) == prefix;
}

[[nodiscard]] bool ends_with(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size() &&
           s.substr(s.size() - suffix.size()) == suffix;
}

[[nodiscard]] PapaError rule_error(ErrorKind kind, std::string detail,
                                   std::size_t line, std::size_t column) {
    std::string out;
    out.reserve(detail.size() + 16);
    out.append(std::to_string(line));
    out.push_back(':');
    out.append(std::to_string(column));
    out.append(": ");
    out.append(detail);
    return ::papa::make_error(kind, std::move(out));
}

[[nodiscard]] PapaError rule_error(ErrorKind kind, std::string detail) {
    return ::papa::make_error(kind, std::move(detail));
}

// scope conformance table
// Mirrors capa.rules.SUPPORTED_FEATURES from plan section 19, with the same
// upward-propagation policy CAPA applies at corpus load time:
//   instruction features bubble into BB, function, and file rule sets
//   BB features bubble into function and file
//   function features bubble into file
// File-only features (Import, Export, Section, file-origin characteristics)
// stay file-only because lower scopes never extract them

[[nodiscard]] int scope_level(Scope s) noexcept {
    switch (s) {
        case Scope::kInstruction: return 1;
        case Scope::kBasicBlock:  return 2;
        case Scope::kFunction:    return 3;
        case Scope::kFile:        return 4;
        default:                  return 0;
    }
}

// Lowest scope at which a non-characteristic feature may appear in a rule
// File-only features return kFile and are filtered out everywhere else
// Instruction features return kInstruction so any of insn, BB, function, file accept them
[[nodiscard]] std::optional<Scope> feature_origin(FeatureTag tag) noexcept {
    using ::papa::features::FeatureTag;
    switch (tag) {
        case FeatureTag::kOs:
        case FeatureTag::kArch:
        case FeatureTag::kFormat:
        case FeatureTag::kMatchedRule:
        case FeatureTag::kString:
        case FeatureTag::kSubstring:
        case FeatureTag::kRegex:
            return Scope::kInstruction;     // valid at any non-global scope

        case FeatureTag::kImport:
        case FeatureTag::kExport:
        case FeatureTag::kSection:
            return Scope::kFile;

        case FeatureTag::kFunctionName:
        case FeatureTag::kClass:
        case FeatureTag::kNamespace:
            // file or instruction in capa
            // We model as instruction-origin and disallow function/BB explicitly below
            return Scope::kInstruction;

        case FeatureTag::kApi:
        case FeatureTag::kMnemonic:
        case FeatureTag::kNumber:
        case FeatureTag::kOffset:
        case FeatureTag::kBytes:
        case FeatureTag::kOperandNumber:
        case FeatureTag::kOperandOffset:
        case FeatureTag::kProperty:
            return Scope::kInstruction;

        case FeatureTag::kCharacteristic:
            return std::nullopt;            // per-value rules apply

        case FeatureTag::kBasicBlock:
            return std::nullopt;            // extractor-only tag, never legal in rules
    }
    return std::nullopt;
}

[[nodiscard]] bool is_feature_allowed(FeatureTag tag, Scope scope) noexcept {
    using ::papa::features::FeatureTag;
    if (tag == FeatureTag::kBasicBlock) { return false; }

    // Dynamic scopes (process/thread/call/span of calls) are out of scope for
    // PAPA's static pipeline. We accept any feature inside them so the rule
    // corpus loads cleanly
    // The dynamic backend (post-v1) will own validation for those scopes
    if (scope == Scope::kProcess     || scope == Scope::kThread ||
        scope == Scope::kCall        || scope == Scope::kSpanOfCalls) {
        return true;
    }

    // FunctionName, Class, Namespace originate at instruction scope in dotnet
    // and at file scope for native PE inspection
    // CAPA propagates them through BB and function, so any insn-or-higher
    // static scope accepts them
    if (tag == FeatureTag::kFunctionName ||
        tag == FeatureTag::kClass        ||
        tag == FeatureTag::kNamespace) {
        return scope_level(scope) >= scope_level(Scope::kInstruction);
    }

    if (tag == FeatureTag::kCharacteristic) { return true; }

    // All other tags follow the bubble-up policy from their origin scope
    const auto origin = feature_origin(tag);
    if (!origin.has_value()) { return false; }
    return scope_level(scope) >= scope_level(*origin);
}

// Allow-list for characteristic values per scope
// Each name has an origin scope and is valid at that scope or higher
[[nodiscard]] bool is_characteristic_allowed(std::string_view value, Scope scope) noexcept {
    // Dynamic scopes are accepted unconditionally (see is_feature_allowed)
    if (scope == Scope::kProcess     || scope == Scope::kThread ||
        scope == Scope::kCall        || scope == Scope::kSpanOfCalls) {
        return true;
    }
    static constexpr std::array<std::string_view, 3> kFileOrigin{
        "embedded pe", "mixed mode", "forwarded export"};
    static constexpr std::array<std::string_view, 4> kFnOrigin{
        "loop", "calls from", "calls to", "recursive call"};
    static constexpr std::array<std::string_view, 2> kBbOrigin{
        "tight loop", "stack string"};
    static constexpr std::array<std::string_view, 8> kInsnOrigin{
        "nzxor", "peb access", "fs access", "gs access",
        "call $+5", "cross section flow", "indirect call", "unmanaged call"};

    auto in = [](std::span<const std::string_view> arr, std::string_view v) {
        return std::find(arr.begin(), arr.end(), v) != arr.end();
    };

    if (in(kFileOrigin, value)) { return scope == Scope::kFile; }
    if (in(kFnOrigin,   value)) { return scope_level(scope) >= scope_level(Scope::kFunction); }
    if (in(kBbOrigin,   value)) { return scope_level(scope) >= scope_level(Scope::kBasicBlock); }
    if (in(kInsnOrigin, value)) { return scope_level(scope) >= scope_level(Scope::kInstruction); }
    // Unknown characteristic name: accept and let the matcher reconcile
    // The corpus grows without needing parser changes
    return true;
}

// low-level parse helpers
// Find unquoted ' = ' in s, ignoring matches inside double or single quotes
[[nodiscard]] std::optional<std::size_t> find_inline_desc_sep(std::string_view s) noexcept {
    bool in_dq = false;
    bool in_sq = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '"' && !in_sq) { in_dq = !in_dq; continue; }
        if (c == '\'' && !in_dq) { in_sq = !in_sq; continue; }
        if (in_dq || in_sq) { continue; }
        if (c == ' ' && i + 2 < s.size() && s[i + 1] == '=' && s[i + 2] == ' ') {
            return i;
        }
    }
    return std::nullopt;
}

// "0x..." with optional leading minus, otherwise std::from_chars decimal/hex
// Returns one of three variant alternatives based on the literal shape
[[nodiscard]] Expected<NumberValue> parse_number(std::string_view s) noexcept {
    if (s.empty()) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule, "empty number literal")};
    }

    // Detect float vs integer
    // A leading 0x or 0X always means hex integer regardless of any 'e' digits
    // Otherwise the presence of '.', 'e', or 'E' triggers float parsing
    const bool is_hex_prefix =
        (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ||
        (s.size() >= 3 && (s[0] == '+' || s[0] == '-') &&
                          s[1] == '0' && (s[2] == 'x' || s[2] == 'X'));
    if (!is_hex_prefix &&
        (s.find('.') != std::string_view::npos ||
         s.find('e') != std::string_view::npos ||
         s.find('E') != std::string_view::npos)) {
        double v = 0.0;
        const char* first = s.data();
        const char* last  = s.data() + s.size();
        auto [ptr, ec] = std::from_chars(first, last, v);
        if (ec != std::errc{} || ptr != last) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                                         std::string{"invalid float: "}.append(s))};
        }
        return NumberValue{v};
    }

    bool negative = false;
    std::string_view body = s;
    if (!body.empty() && body.front() == '-') {
        negative = true;
        body.remove_prefix(1);
    } else if (!body.empty() && body.front() == '+') {
        body.remove_prefix(1);
    }

    int base = 10;
    if (starts_with(body, "0x") || starts_with(body, "0X")) {
        base = 16;
        body.remove_prefix(2);
    }
    if (body.empty()) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
                                     std::string{"invalid integer: "}.append(s))};
    }

    std::uint64_t mag = 0;
    const char* first = body.data();
    const char* last  = body.data() + body.size();
    auto [ptr, ec] = std::from_chars(first, last, mag, base);
    if (ec != std::errc{} || ptr != last) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
                                     std::string{"invalid integer: "}.append(s))};
    }

    if (negative) {
        // Promote to int64. Reject magnitudes that would overflow on negation
        if (mag > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ULL) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                                         std::string{"negative magnitude overflows int64: "}.append(s))};
        }
        return NumberValue{-static_cast<std::int64_t>(mag)};
    }
    return NumberValue{mag};
}

// Try parse an unsigned size_t accepting decimal or 0x-prefixed hex
// CAPA rules use both forms in count(...) bounds, e.g. "count(api(foo)): 0x10"
[[nodiscard]] std::optional<std::size_t> parse_size_t(std::string_view s) noexcept {
    s = trim(s);
    if (s.empty()) { return std::nullopt; }
    int base = 10;
    if (starts_with(s, "0x") || starts_with(s, "0X")) {
        base = 16;
        s.remove_prefix(2);
        if (s.empty()) { return std::nullopt; }
    }
    std::size_t v = 0;
    const char* first = s.data();
    const char* last  = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, v, base);
    if (ec != std::errc{} || ptr != last) { return std::nullopt; }
    return v;
}

[[nodiscard]] Expected<std::optional<Scope>>
parse_scope_name(std::string_view name) noexcept {
    const auto t = trim(name);
    if (t == "file")          return std::optional<Scope>{Scope::kFile};
    if (t == "function")      return std::optional<Scope>{Scope::kFunction};
    if (t == "basic block")   return std::optional<Scope>{Scope::kBasicBlock};
    if (t == "instruction")   return std::optional<Scope>{Scope::kInstruction};
    if (t == "global")        return std::optional<Scope>{Scope::kGlobal};
    if (t == "process")       return std::optional<Scope>{Scope::kProcess};
    if (t == "thread")        return std::optional<Scope>{Scope::kThread};
    if (t == "call")          return std::optional<Scope>{Scope::kCall};
    if (t == "span of calls") return std::optional<Scope>{Scope::kSpanOfCalls};
    // CAPA uses "unsupported" to mark a rule that does not target the given
    // pipeline
    // We model this as an absent scope so the rule never participates
    // in matching at that level
    if (t == "unsupported")   return std::optional<Scope>{};
    return Unexpected{rule_error(ErrorKind::kInvalidRule,
                                 std::string{"unknown scope name: "}.append(t))};
}

// meta extraction
[[nodiscard]] Expected<void>
collect_string_list(const yaml::Node& seq, std::vector<std::string>& out,
                    std::string_view ctx) {
    if (seq.kind() != yaml::NodeKind::kSequence) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            std::string{ctx}.append(" must be a sequence"),
            seq.line(), seq.column())};
    }
    for (const auto& item : seq.sequence()) {
        if (item.kind() != yaml::NodeKind::kScalar) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                std::string{ctx}.append(" entries must be scalar"),
                item.line(), item.column())};
        }
        out.emplace_back(item.scalar());
    }
    return {};
}

[[nodiscard]] Expected<void> parse_meta(const yaml::Node& rule_node, RuleMeta& out) {
    const auto* meta_node = rule_node.find("meta");
    if (meta_node == nullptr) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "rule is missing 'meta:'", rule_node.line(), rule_node.column())};
    }
    if (meta_node->kind() != yaml::NodeKind::kMapping) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "'meta:' must be a mapping", meta_node->line(), meta_node->column())};
    }

    for (const auto& [key, val] : meta_node->mapping()) {
        if (key == "name") {
            if (val.kind() != yaml::NodeKind::kScalar) {
                return Unexpected{rule_error(ErrorKind::kInvalidRule,
                    "'meta.name' must be scalar", val.line(), val.column())};
            }
            out.name.assign(val.scalar());
        } else if (key == "namespace") {
            if (val.kind() != yaml::NodeKind::kScalar) {
                return Unexpected{rule_error(ErrorKind::kInvalidRule,
                    "'meta.namespace' must be scalar", val.line(), val.column())};
            }
            std::string ns(val.scalar());
            if (!ns.empty()) { out.namespace_ = std::move(ns); }
        } else if (key == "scope") {
            // legacy single-scope key
            if (val.kind() != yaml::NodeKind::kScalar) {
                return Unexpected{rule_error(ErrorKind::kInvalidRule,
                    "'meta.scope' must be scalar", val.line(), val.column())};
            }
            auto sc = parse_scope_name(val.scalar());
            if (!sc) { return Unexpected{sc.error()}; }
            out.scopes.static_scope = *sc;
        } else if (key == "scopes") {
            if (val.kind() != yaml::NodeKind::kMapping) {
                return Unexpected{rule_error(ErrorKind::kInvalidRule,
                    "'meta.scopes' must be a mapping", val.line(), val.column())};
            }
            for (const auto& [skey, sval] : val.mapping()) {
                if (sval.kind() != yaml::NodeKind::kScalar) {
                    return Unexpected{rule_error(ErrorKind::kInvalidRule,
                        "'meta.scopes' entries must be scalar", sval.line(), sval.column())};
                }
                auto sc = parse_scope_name(sval.scalar());
                if (!sc) { return Unexpected{sc.error()}; }
                // sc is already an optional<Scope> where nullopt encodes "unsupported"
                if      (skey == "static")  { out.scopes.static_scope  = *sc; }
                else if (skey == "dynamic") { out.scopes.dynamic_scope = *sc; }
                else {
                    return Unexpected{rule_error(ErrorKind::kInvalidRule,
                        std::string{"unknown scopes key: "}.append(skey),
                        sval.line(), sval.column())};
                }
            }
        } else if (key == "authors") {
            auto r = collect_string_list(val, out.authors, "meta.authors");
            if (!r) { return Unexpected{r.error()}; }
        } else if (key == "att&ck") {
            auto r = collect_string_list(val, out.att_and_ck, "meta.att&ck");
            if (!r) { return Unexpected{r.error()}; }
        } else if (key == "mbc") {
            auto r = collect_string_list(val, out.mbc, "meta.mbc");
            if (!r) { return Unexpected{r.error()}; }
        } else if (key == "examples") {
            auto r = collect_string_list(val, out.examples, "meta.examples");
            if (!r) { return Unexpected{r.error()}; }
        } else if (key == "references") {
            auto r = collect_string_list(val, out.references, "meta.references");
            if (!r) { return Unexpected{r.error()}; }
        } else if (key == "description") {
            if (val.kind() != yaml::NodeKind::kScalar) {
                return Unexpected{rule_error(ErrorKind::kInvalidRule,
                    "'meta.description' must be scalar", val.line(), val.column())};
            }
            out.description = std::string(val.scalar());
        } else if (key == "lib") {
            if (val.kind() != yaml::NodeKind::kScalar) {
                return Unexpected{rule_error(ErrorKind::kInvalidRule,
                    "'meta.lib' must be scalar", val.line(), val.column())};
            }
            out.lib = (val.scalar() == "true" || val.scalar() == "True" || val.scalar() == "yes");
        }
        // Unknown meta keys are accepted silently to allow rule-corpus growth
    }

    if (out.name.empty()) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "rule is missing 'meta.name'", meta_node->line(), meta_node->column())};
    }
    return {};
}

// feature parsing
// Parse a leaf "feature: value [= description]" into a FeaturePtr
// Mirrors capa's trim_dll_part: since capa v7 the api feature matches on the
// bare symbol, so a single-dot native name like kernel32.CreateFileA is reduced
// to CreateFileA. Ordinal imports (ws2_32.#1) and dotnet names (Class::Method)
// keep their full form. This lets api rules match calls whose import resolves
// through an API-Set dll (api-ms-win-...) rather than the classic dll.
[[nodiscard]] std::string trim_dll_part(std::string_view api) {
    if (api.find(".#") != std::string_view::npos) { return std::string(api); }
    std::size_t dots = 0;
    for (const char c : api) {
        if (c == '.') { ++dots; }
    }
    if (dots == 1 && api.find("::") == std::string_view::npos) {
        return std::string(api.substr(api.find('.') + 1U));
    }
    return std::string(api);
}

// key has already been split off the YAML mapping
// value is the raw YAML scalar
// description, when non-empty, comes from inline "= ..." or a sibling description key
[[nodiscard]] Expected<FeaturePtr>
build_feature_leaf(std::string_view key,
                   std::string_view raw_value,
                   std::string description,
                   std::size_t line,
                   std::size_t column) {
    auto err = [&](std::string msg) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule, std::move(msg), line, column)};
    };

    auto split_for_desc = [&](std::string_view text) -> std::pair<std::string_view, std::string> {
        std::string desc(description);
        const auto pos = find_inline_desc_sep(text);
        std::string_view value = text;
        if (pos.has_value()) {
            value = trim(text.substr(0, *pos));
            std::string_view tail = text.substr(*pos + kInlineDescSep.size());
            if (desc.empty()) { desc.assign(trim(tail)); }
        } else {
            value = trim(text);
        }
        return {value, std::move(desc)};
    };

    // operand[i].number / operand[i].offset
    if (starts_with(key, "operand[")) {
        const auto bracket_close = key.find(']');
        if (bracket_close == std::string_view::npos) {
            return err(std::string{"malformed operand key: "}.append(key));
        }
        const auto idx_str = key.substr(8, bracket_close - 8);
        const auto idx = parse_size_t(idx_str);
        if (!idx.has_value() || *idx > 4) {
            return err(std::string{"operand index out of range: "}.append(key));
        }
        const auto kind = key.substr(bracket_close + 1);
        if (kind == ".number") {
            auto [v, desc] = split_for_desc(raw_value);
            auto num = parse_number(v);
            if (!num) { return Unexpected{num.error()}; }
            return std::make_shared<const OperandNumber>(*idx, *num, std::move(desc));
        }
        if (kind == ".offset") {
            auto [v, desc] = split_for_desc(raw_value);
            auto num = parse_number(v);
            if (!num) { return Unexpected{num.error()}; }
            std::int64_t off = 0;
            if (std::holds_alternative<std::int64_t>(*num)) {
                off = std::get<std::int64_t>(*num);
            } else if (std::holds_alternative<std::uint64_t>(*num)) {
                off = static_cast<std::int64_t>(std::get<std::uint64_t>(*num));
            } else {
                return err("operand offset cannot be floating point");
            }
            return std::make_shared<const OperandOffset>(*idx, off, std::move(desc));
        }
        return err(std::string{"unknown operand suffix: "}.append(key));
    }

    // property/read and property/write
    if (starts_with(key, "property/")) {
        Property::Access acc = Property::Access::kNone;
        const auto suffix = key.substr(std::string_view{"property/"}.size());
        if      (suffix == "read")  { acc = Property::Access::kRead; }
        else if (suffix == "write") { acc = Property::Access::kWrite; }
        else {
            return err(std::string{"unknown property access: "}.append(key));
        }
        auto [v, desc] = split_for_desc(raw_value);
        return std::make_shared<const Property>(std::string(v), acc, std::move(desc));
    }

    auto [value, desc] = split_for_desc(raw_value);

    if (key == "api") {
        return std::make_shared<const Api>(trim_dll_part(value), std::move(desc));
    }
    if (key == "import") {
        return std::make_shared<const Import>(std::string(value), std::move(desc));
    }
    if (key == "export") {
        return std::make_shared<const Export>(std::string(value), std::move(desc));
    }
    if (key == "section") {
        return std::make_shared<const Section>(std::string(value), std::move(desc));
    }
    if (key == "function-name") {
        return std::make_shared<const FunctionName>(std::string(value), std::move(desc));
    }
    if (key == "mnemonic") {
        return std::make_shared<const Mnemonic>(std::string(value), std::move(desc));
    }
    if (key == "characteristic") {
        return std::make_shared<const Characteristic>(std::string(value), std::move(desc));
    }
    if (key == "class") {
        return std::make_shared<const Class>(std::string(value), std::move(desc));
    }
    if (key == "namespace") {
        return std::make_shared<const Namespace>(std::string(value), std::move(desc));
    }
    if (key == "os") {
        return std::make_shared<const Os>(std::string(value), std::move(desc));
    }
    if (key == "arch") {
        return std::make_shared<const Arch>(std::string(value), std::move(desc));
    }
    if (key == "format") {
        return std::make_shared<const Format>(std::string(value), std::move(desc));
    }
    if (key == "match") {
        return std::make_shared<const MatchedRule>(std::string(value), std::move(desc));
    }
    if (key == "number") {
        auto num = parse_number(value);
        if (!num) { return Unexpected{num.error()}; }
        return std::make_shared<const Number>(*num, std::move(desc));
    }
    if (key == "offset") {
        auto num = parse_number(value);
        if (!num) { return Unexpected{num.error()}; }
        std::int64_t off = 0;
        if (std::holds_alternative<std::int64_t>(*num)) {
            off = std::get<std::int64_t>(*num);
        } else if (std::holds_alternative<std::uint64_t>(*num)) {
            off = static_cast<std::int64_t>(std::get<std::uint64_t>(*num));
        } else {
            return err("offset cannot be floating point");
        }
        return std::make_shared<const Offset>(off, std::move(desc));
    }
    if (key == "string") {
        // /pattern/ or /pattern/i is a regex literal
        if (value.size() >= 2 && value.front() == '/' &&
            (ends_with(value, "/") || ends_with(value, "/i"))) {
            return std::make_shared<const Regex>(std::string(value), std::move(desc));
        }
        return std::make_shared<const String>(std::string(value), std::move(desc));
    }
    if (key == "substring") {
        return std::make_shared<const Substring>(std::string(value), std::move(desc));
    }
    if (key == "bytes") {
        auto bl = ::papa::rules::RuleParser::parse_bytes_literal(value);
        if (!bl) { return Unexpected{bl.error()}; }
        if (bl->has_wildcards) {
            return err("bytes wildcards are not yet supported in v1");
        }
        std::vector<std::byte> bytes;
        bytes.reserve(bl->pattern.size());
        for (const auto& opt : bl->pattern) {
            // pattern entries are non-null when has_wildcards is false
            bytes.push_back(*opt);
        }
        return std::make_shared<const Bytes>(std::move(bytes), std::move(desc));
    }

    return err(std::string{"unknown feature key: "}.append(key));
}

// Parse a count(...) feature key
// Returns the inner feature key (api, number, ...) and inner value
[[nodiscard]] std::optional<std::pair<std::string_view, std::string_view>>
split_count_call(std::string_view key) noexcept {
    constexpr std::string_view kPrefix = "count(";
    if (!starts_with(key, kPrefix)) { return std::nullopt; }
    if (!ends_with(key, ")"))       { return std::nullopt; }
    auto inner = key.substr(kPrefix.size(), key.size() - kPrefix.size() - 1);
    // inner should look like "api(name)" or "characteristic(loop)" etc
    const auto open = inner.find('(');
    if (open == std::string_view::npos) { return std::nullopt; }
    if (!ends_with(inner, ")")) { return std::nullopt; }
    auto inner_key   = inner.substr(0, open);
    auto inner_value = inner.substr(open + 1, inner.size() - open - 2);
    return std::make_pair(inner_key, inner_value);
}

// Forward declaration so statement parsing can recurse through operators and subscopes
[[nodiscard]] Expected<std::unique_ptr<Statement>>
parse_statement_item(const yaml::Node& mapping, Scope scope);

// True when the sequence item is a CAPA inline description label
// CAPA rules sprinkle "- description: free text" entries inside operator children
// to annotate intent
// These have no match semantics and are stripped here so the engine does not
// try to evaluate them as predicates
[[nodiscard]] bool is_inline_description_item(const yaml::Node& node) noexcept {
    if (node.kind() != yaml::NodeKind::kMapping) { return false; }
    const auto m = node.mapping();
    return !m.empty() && m.front().first == "description";
}

// Parse the value of an operator key (and/or/not/...) into an ordered child list
// Inline description items are filtered because they label the surrounding
// statement rather than contribute to its truth value
[[nodiscard]] Expected<std::vector<std::unique_ptr<Statement>>>
parse_statement_children(const yaml::Node& seq_node, Scope scope) {
    if (seq_node.kind() != yaml::NodeKind::kSequence) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "expected a sequence of child statements",
            seq_node.line(), seq_node.column())};
    }
    std::vector<std::unique_ptr<Statement>> out;
    out.reserve(seq_node.sequence().size());
    for (const auto& child : seq_node.sequence()) {
        if (is_inline_description_item(child)) { continue; }
        auto st = parse_statement_item(child, scope);
        if (!st) { return Unexpected{st.error()}; }
        out.push_back(std::move(*st));
    }
    return out;
}

// The mapping argument is one item of a top-level features sequence
// Each item must be a one-key mapping whose key drives the dispatch
[[nodiscard]] Expected<std::unique_ptr<Statement>>
parse_statement_item(const yaml::Node& node, Scope scope) {
    if (node.kind() != yaml::NodeKind::kMapping) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "feature item must be a mapping", node.line(), node.column())};
    }
    if (node.mapping().empty()) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "feature mapping is empty", node.line(), node.column())};
    }

    // First key drives the dispatch
    // Sibling keys may carry an out-of-line "description"
    const auto& first = node.mapping().front();
    const std::string_view key = first.first;
    const yaml::Node& value = first.second;

    // operators
    if (key == "and") {
        auto kids = parse_statement_children(value, scope);
        if (!kids) { return Unexpected{kids.error()}; }
        return std::make_unique<And>(std::move(*kids));
    }
    if (key == "or") {
        auto kids = parse_statement_children(value, scope);
        if (!kids) { return Unexpected{kids.error()}; }
        return std::make_unique<Or>(std::move(*kids));
    }
    if (key == "not") {
        auto kids = parse_statement_children(value, scope);
        if (!kids) { return Unexpected{kids.error()}; }
        if (kids->size() != 1) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                "'not' takes exactly one child", value.line(), value.column())};
        }
        return std::make_unique<Not>(std::move(kids->front()));
    }
    if (key == "optional") {
        auto kids = parse_statement_children(value, scope);
        if (!kids) { return Unexpected{kids.error()}; }
        return std::make_unique<Some>(0, std::move(*kids));
    }
    // "N or more"
    {
        const auto pos = key.rfind(" or more");
        if (pos != std::string_view::npos && pos + std::string_view{" or more"}.size() == key.size()) {
            const auto n = parse_size_t(key.substr(0, pos));
            if (!n.has_value()) {
                return Unexpected{rule_error(ErrorKind::kInvalidRule,
                    std::string{"malformed N-or-more: "}.append(key),
                    node.line(), node.column())};
            }
            auto kids = parse_statement_children(value, scope);
            if (!kids) { return Unexpected{kids.error()}; }
            return std::make_unique<Some>(*n, std::move(*kids));
        }
    }

    // subscope nodes
    auto subscope_kind = [&]() -> std::optional<Scope> {
        if (key == "basic block")     return Scope::kBasicBlock;
        if (key == "instruction")     return Scope::kInstruction;
        if (key == "function")        return Scope::kFunction;
        if (key == "call")            return Scope::kCall;
        if (key == "process")         return Scope::kProcess;
        if (key == "thread")          return Scope::kThread;
        if (key == "span of calls")   return Scope::kSpanOfCalls;
        return std::nullopt;
    }();
    if (subscope_kind.has_value()) {
        // Inner statements are evaluated at the subscope's scope, not the parent's
        // A "basic block:" inside a function rule means the inner features must
        // conform to basic-block scope rules, e.g. "loop" is a function-only
        // characteristic and is rejected here
        auto kids = parse_statement_children(value, *subscope_kind);
        if (!kids) { return Unexpected{kids.error()}; }
        std::unique_ptr<Statement> inner;
        if (kids->size() == 1) {
            inner = std::move(kids->front());
        } else {
            inner = std::make_unique<And>(std::move(*kids));
        }
        return std::make_unique<Subscope>(*subscope_kind, std::move(inner));
    }

    // com/class and com/interface expand into Or(Bytes(le_guid), String(canonical_guid))
    // The lookup tables live in com_classes.cpp and com_interfaces.cpp
    if (key == "com/class" || key == "com/interface") {
        if (value.kind() != yaml::NodeKind::kScalar) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                std::string{"'"}.append(key).append("' value must be scalar"),
                value.line(), value.column())};
        }
        const auto split_pair = ::papa::rules::RuleParser::split_inline_description(
            value.scalar());
        const std::string_view name_part = split_pair.first;
        const std::string desc_str(split_pair.second.has_value()
            ? std::string(*split_pair.second)
            : std::string{});

        const ComKind com_kind = (key == "com/class") ? ComKind::kClass : ComKind::kInterface;
        const ComEntry* entry  = ::papa::rules::lookup_com(com_kind, name_part);
        if (entry == nullptr) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                std::string{"unknown COM "}
                    .append(com_kind == ComKind::kClass ? "class" : "interface")
                    .append(" name: ").append(name_part),
                value.line(), value.column())};
        }

        // Both child features must be valid at the rule's scope
        // String is universally allowed and Bytes bubbles up from instruction scope
        if (!is_feature_allowed(FeatureTag::kBytes,  scope) ||
            !is_feature_allowed(FeatureTag::kString, scope)) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                std::string{"'"}.append(key).append("' not allowed at scope ")
                    .append(::papa::rules::to_string(scope)),
                node.line(), node.column())};
        }

        std::vector<std::byte> bytes_value(entry->guid_bytes.begin(),
                                           entry->guid_bytes.end());
        auto bytes_feat  = std::make_shared<const Bytes>(std::move(bytes_value), desc_str);
        auto string_feat = std::make_shared<const String>(
            std::string(entry->guid_string), desc_str);

        std::vector<std::unique_ptr<Statement>> kids;
        kids.reserve(2);
        kids.push_back(std::make_unique<FeatureStatement>(std::move(bytes_feat)));
        kids.push_back(std::make_unique<FeatureStatement>(std::move(string_feat)));
        return std::make_unique<Or>(std::move(kids));
    }

    // count(basic blocks) or count(basic block) is a tag form CAPA rules use
    // to set a numeric bound on the number of basic blocks in the function
    // Internally we count occurrences of the BasicBlock tag feature, which
    // PapaNativeStaticExtractor emits exactly once per basic block
    if (key == "count(basic blocks)" || key == "count(basic block)") {
        if (value.kind() != yaml::NodeKind::kScalar) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                "count(basic blocks) value must be a scalar range",
                value.line(), value.column())};
        }
        auto rng = ::papa::rules::RuleParser::parse_count_range(value.scalar());
        if (!rng) { return Unexpected{rng.error()}; }
        auto bb = std::make_shared<const ::papa::features::BasicBlock>();
        return std::make_unique<Range>(std::move(bb), rng->min, rng->max);
    }

    // count(feature(value))
    if (auto split = split_count_call(key); split.has_value()) {
        const auto& [inner_key, inner_value] = *split;
        if (value.kind() != yaml::NodeKind::kScalar) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                "count(...) value must be a scalar range",
                value.line(), value.column())};
        }
        auto rng = ::papa::rules::RuleParser::parse_count_range(value.scalar());
        if (!rng) { return Unexpected{rng.error()}; }
        auto feat = build_feature_leaf(inner_key, inner_value, std::string{},
                                       node.line(), node.column());
        if (!feat) { return Unexpected{feat.error()}; }
        if (!is_feature_allowed((*feat)->tag(), scope)) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                std::string{"feature in count(): "}.append(inner_key)
                    .append(" not allowed at scope ")
                    .append(::papa::rules::to_string(scope)),
                node.line(), node.column())};
        }
        return std::make_unique<Range>(std::move(*feat), rng->min, rng->max);
    }

    // leaf feature
    if (value.kind() != yaml::NodeKind::kScalar) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            std::string{"feature '"}.append(key).append("' expects a scalar value"),
            value.line(), value.column())};
    }
    // sibling description key support
    std::string sibling_desc;
    if (node.mapping().size() > 1) {
        for (std::size_t i = 1; i < node.mapping().size(); ++i) {
            const auto& [skey, sval] = node.mapping()[i];
            if (skey == "description") {
                if (sval.kind() != yaml::NodeKind::kScalar) {
                    return Unexpected{rule_error(ErrorKind::kInvalidRule,
                        "'description' must be scalar", sval.line(), sval.column())};
                }
                sibling_desc.assign(sval.scalar());
            } else {
                return Unexpected{rule_error(ErrorKind::kInvalidRule,
                    std::string{"unexpected sibling key in feature mapping: "}.append(skey),
                    sval.line(), sval.column())};
            }
        }
    }
    auto feat = build_feature_leaf(key, value.scalar(), std::move(sibling_desc),
                                   value.line(), value.column());
    if (!feat) { return Unexpected{feat.error()}; }

    // Scope conformance
    if (!is_feature_allowed((*feat)->tag(), scope)) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            std::string{"feature '"}.append(key).append("' not allowed at scope ")
                .append(::papa::rules::to_string(scope)),
            node.line(), node.column())};
    }
    if ((*feat)->tag() == FeatureTag::kCharacteristic) {
        const auto* c = static_cast<const Characteristic*>(feat->get());
        if (!is_characteristic_allowed(c->value(), scope)) {
            return Unexpected{rule_error(ErrorKind::kInvalidRule,
                std::string{"characteristic '"}.append(c->value())
                    .append("' not allowed at scope ")
                    .append(::papa::rules::to_string(scope)),
                node.line(), node.column())};
        }
    }
    return std::make_unique<FeatureStatement>(std::move(*feat));
}

[[nodiscard]] Expected<std::unique_ptr<Statement>>
parse_features_root(const yaml::Node& seq_node, Scope scope) {
    if (seq_node.kind() != yaml::NodeKind::kSequence) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "'features:' must be a sequence", seq_node.line(), seq_node.column())};
    }
    if (seq_node.sequence().empty()) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "'features:' is empty", seq_node.line(), seq_node.column())};
    }
    auto kids = parse_statement_children(seq_node, scope);
    if (!kids) { return Unexpected{kids.error()}; }
    if (kids->size() == 1) {
        return std::move(kids->front());
    }
    return std::make_unique<And>(std::move(*kids));
}

}  // namespace

// public API
::papa::Expected<std::unique_ptr<Rule>>
RuleParser::parse(std::string_view yaml_text, std::string_view source_path) {
    auto yaml_r = yaml::parse(yaml_text);
    if (!yaml_r) { return Unexpected{yaml_r.error()}; }
    const yaml::Node& root = *yaml_r;

    if (root.kind() != yaml::NodeKind::kMapping) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "rule document must have a top-level mapping",
            root.line(), root.column())};
    }
    const auto* rule_node = root.find("rule");
    if (rule_node == nullptr) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "missing top-level 'rule:'", root.line(), root.column())};
    }
    if (rule_node->kind() != yaml::NodeKind::kMapping) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "'rule:' must be a mapping", rule_node->line(), rule_node->column())};
    }

    RuleMeta meta;
    meta.source_path = std::string(source_path);
    auto meta_r = parse_meta(*rule_node, meta);
    if (!meta_r) { return Unexpected{meta_r.error()}; }

    const auto* features_node = rule_node->find("features");
    if (features_node == nullptr) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule,
            "rule is missing 'features:'", rule_node->line(), rule_node->column())};
    }

    const Scope scope = meta.scopes.static_scope.value_or(Scope::kFunction);
    auto root_stmt = parse_features_root(*features_node, scope);
    if (!root_stmt) { return Unexpected{root_stmt.error()}; }

    return std::make_unique<Rule>(std::move(meta), std::move(*root_stmt),
                                  std::string(yaml_text));
}

::papa::Expected<NumberValue>
RuleParser::parse_number_literal(std::string_view text) {
    return parse_number(trim(text));
}

::papa::Expected<BytesLiteral>
RuleParser::parse_bytes_literal(std::string_view text) {
    BytesLiteral out;
    std::string_view s = text;
    auto err = [&](std::string msg) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule, std::move(msg))};
    };
    auto hex_nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') { return c - '0'; }
        if (c >= 'a' && c <= 'f') { return 10 + (c - 'a'); }
        if (c >= 'A' && c <= 'F') { return 10 + (c - 'A'); }
        return -1;
    };

    for (std::size_t i = 0; i < s.size();) {
        if (is_ws(s[i])) { ++i; continue; }
        if (i + 1 >= s.size()) {
            return err("bytes literal has odd nibble count");
        }
        const char a = s[i];
        const char b = s[i + 1];
        if (a == '?' && b == '?') {
            out.pattern.emplace_back(std::nullopt);
            out.has_wildcards = true;
            i += 2;
            continue;
        }
        const int hi = hex_nibble(a);
        const int lo = hex_nibble(b);
        if (hi < 0 || lo < 0) {
            std::string msg = "bytes literal has invalid hex pair: ";
            msg.push_back(a);
            msg.push_back(b);
            return err(std::move(msg));
        }
        out.pattern.emplace_back(static_cast<std::byte>((hi << 4) | lo));
        i += 2;
    }
    if (out.pattern.empty()) {
        return err("bytes literal is empty");
    }
    return out;
}

::papa::Expected<CountRange>
RuleParser::parse_count_range(std::string_view text) {
    const auto t = trim(text);
    auto err = [&](std::string msg) {
        return Unexpected{rule_error(ErrorKind::kInvalidRule, std::move(msg))};
    };

    // "(min, max)"
    if (!t.empty() && t.front() == '(' && t.back() == ')') {
        auto body = t.substr(1, t.size() - 2);
        const auto comma = body.find(',');
        if (comma == std::string_view::npos) {
            return err(std::string{"count range tuple missing comma: "}.append(t));
        }
        const auto lo = parse_size_t(trim(body.substr(0, comma)));
        const auto hi = parse_size_t(trim(body.substr(comma + 1)));
        if (!lo.has_value() || !hi.has_value()) {
            return err(std::string{"count range tuple parts not integral: "}.append(t));
        }
        if (*lo > *hi) {
            return err(std::string{"count range min > max: "}.append(t));
        }
        return CountRange{*lo, *hi};
    }

    // "N or more"
    if (ends_with(t, " or more")) {
        const auto head = t.substr(0, t.size() - std::string_view{" or more"}.size());
        const auto n = parse_size_t(head);
        if (!n.has_value()) {
            return err(std::string{"count range 'N or more' lacks integer: "}.append(t));
        }
        return CountRange{*n, std::numeric_limits<std::size_t>::max()};
    }

    // "N or fewer" is the inclusive upper-bound dual of "N or more"
    if (ends_with(t, " or fewer")) {
        const auto head = t.substr(0, t.size() - std::string_view{" or fewer"}.size());
        const auto n = parse_size_t(head);
        if (!n.has_value()) {
            return err(std::string{"count range 'N or fewer' lacks integer: "}.append(t));
        }
        return CountRange{0U, *n};
    }

    // bare integer
    const auto n = parse_size_t(t);
    if (!n.has_value()) {
        return err(std::string{"count range value not integral: "}.append(t));
    }
    return CountRange{*n, *n};
}

std::pair<std::string_view, std::optional<std::string_view>>
RuleParser::split_inline_description(std::string_view text) {
    const auto pos = find_inline_desc_sep(text);
    if (!pos.has_value()) { return {trim(text), std::nullopt}; }
    auto value = trim(text.substr(0, *pos));
    auto desc  = trim(text.substr(*pos + kInlineDescSep.size()));
    return {value, desc};
}

}  // namespace papa::rules
