#include "papa/features/common.h"

#include "papa/engine.h"
#include "papa/util/hashing.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace papa::features {

namespace {

// Fold the feature tag into the payload hash so different kinds with identical payload
// bytes never collide in a FeatureSet bucket
std::size_t mix_tag(FeatureTag t, std::size_t h) noexcept {
    return util::hashing::hash_combine(static_cast<std::size_t>(t), h);
}

// Accept "/pattern/" or "/pattern/i" and fall back to treating the whole
// literal as the pattern so construction never throws on rule-side typos
struct RegexLiteral {
    std::string pattern;
    bool        case_insensitive{false};
};

RegexLiteral parse_regex_literal(std::string_view lit) {
    if (lit.size() >= 2 && lit.front() == '/') {
        if (lit.size() >= 3 && lit.back() == 'i' && lit[lit.size() - 2] == '/') {
            return RegexLiteral{std::string(lit.substr(1, lit.size() - 3)), true};
        }
        if (lit.back() == '/') {
            return RegexLiteral{std::string(lit.substr(1, lit.size() - 2)), false};
        }
    }
    return RegexLiteral{std::string(lit), false};
}

// "any" wildcard used by Os and Arch evaluate paths
// Kept local so the constants module does not need to leak in through the header
constexpr std::string_view kAnyWildcard = "any";

}  // namespace

// String
String::String(std::string value, std::string desc)
    : Feature(FeatureTag::kString, "string", std::move(desc)),
      value_(std::move(value)) {}

String::String(FeatureTag t, std::string_view tname, std::string value, std::string desc)
    : Feature(t, tname, std::move(desc)),
      value_(std::move(value)) {}

std::size_t String::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool String::equals(const Feature& o) const noexcept {
    if (o.tag() != tag_) { return false; }
    // Safe within the String hierarchy: a matching tag implies the dynamic type
    // is String or a subclass whose storage layout begins with String
    const auto& rhs = static_cast<const String&>(o);
    return value_ == rhs.value_;
}

std::string String::to_string() const {
    std::string out;
    out.reserve(type_name().size() + value_.size() + 4);
    out.append(type_name());
    out.append("(\"");
    out.append(value_);
    out.append("\")");
    return out;
}

// Substring
Substring::Substring(std::string value, std::string desc)
    : String(FeatureTag::kSubstring, "substring", std::move(value), std::move(desc)) {}

engine::Result Substring::evaluate(const FeatureSet& fs, bool sc) const {
    engine::Result r;
    r.node = this;
    // Iterate the dedicated string index so we never traverse non-String entries
    for (const auto& f : fs.strings()) {
        const auto& s = static_cast<const String&>(*f);
        if (s.value().find(value_) != std::string::npos) {
            r.success = true;
            const auto it = fs.find(f);
            if (it != fs.end()) {
                r.locations.insert(it->second.begin(), it->second.end());
            }
            if (sc) { return r; }
        }
    }
    return r;
}

bool Substring::matches(const FeatureSet& fs) const {
    for (const auto& f : fs.strings()) {
        const auto& s = static_cast<const String&>(*f);
        if (s.value().find(value_) != std::string::npos) { return true; }
    }
    return false;
}

// Regex
Regex::Regex(std::string literal, std::string desc)
    : String(FeatureTag::kRegex, "regex", std::move(literal), std::move(desc)) {
    auto parsed = parse_regex_literal(value_);
    pattern_          = std::move(parsed.pattern);
    case_insensitive_ = parsed.case_insensitive;
    auto flags = std::regex::ECMAScript | std::regex::optimize;
    if (case_insensitive_) { flags |= std::regex::icase; }
    // CAPA rules use Python's re flavor, which has constructs std::regex lacks. An
    // incompatible pattern is marked dead rather than aborting the corpus load
    try {
        compiled_     = std::regex(pattern_, flags);
        compiled_ok_  = true;
    } catch (const std::regex_error&) {
        compiled_ok_  = false;
    }
}

engine::Result Regex::evaluate(const FeatureSet& fs, bool sc) const {
    engine::Result r;
    r.node = this;
    // A pattern std::regex could not compile produces no matches
    if (!compiled_ok_) { return r; }
    for (const auto& f : fs.strings()) {
        const auto& s = static_cast<const String&>(*f);
        if (std::regex_search(s.value(), compiled_)) {
            r.success = true;
            const auto it = fs.find(f);
            if (it != fs.end()) {
                r.locations.insert(it->second.begin(), it->second.end());
            }
            if (sc) { return r; }
        }
    }
    return r;
}

bool Regex::matches(const FeatureSet& fs) const {
    if (!compiled_ok_) { return false; }
    for (const auto& f : fs.strings()) {
        const auto& s = static_cast<const String&>(*f);
        if (std::regex_search(s.value(), compiled_)) { return true; }
    }
    return false;
}

// Bytes
Bytes::Bytes(std::vector<std::byte> value, std::string desc)
    : Feature(FeatureTag::kBytes, "bytes", std::move(desc)),
      value_(std::move(value)) {}

engine::Result Bytes::evaluate(const FeatureSet& fs, bool sc) const {
    engine::Result r;
    r.node = this;
    // Iterate the dedicated bytes index for the same reason as Substring
    // An empty rule pattern matches every Bytes feature, matching CAPA semantics
    for (const auto& f : fs.bytes_features()) {
        const auto& b = static_cast<const Bytes&>(*f);
        auto cand = b.value();
        if (cand.size() < value_.size()) { continue; }
        if (std::equal(value_.begin(), value_.end(), cand.begin())) {
            r.success = true;
            const auto it = fs.find(f);
            if (it != fs.end()) {
                r.locations.insert(it->second.begin(), it->second.end());
            }
            if (sc) { return r; }
        }
    }
    return r;
}

bool Bytes::matches(const FeatureSet& fs) const {
    for (const auto& f : fs.bytes_features()) {
        const auto& b = static_cast<const Bytes&>(*f);
        auto cand = b.value();
        if (cand.size() < value_.size()) { continue; }
        if (std::equal(value_.begin(), value_.end(), cand.begin())) { return true; }
    }
    return false;
}

std::size_t Bytes::hash() const noexcept {
    // FNV-1a 64-bit over the raw byte buffer
    const std::size_t payload =
        util::hashing::fnv1a64(std::span<const std::byte>(value_.data(), value_.size()));
    return mix_tag(tag_, payload);
}

bool Bytes::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kBytes) { return false; }
    const auto& rhs = static_cast<const Bytes&>(o);
    return value_ == rhs.value_;
}

std::string Bytes::to_string() const {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(8 + value_.size() * 3);
    out.append("bytes(");
    for (std::size_t i = 0; i < value_.size(); ++i) {
        if (i != 0) { out.push_back(' '); }
        auto byte = std::to_integer<std::uint8_t>(value_[i]);
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0F]);
    }
    out.push_back(')');
    return out;
}

// Number
Number::Number(Value v, std::string desc)
    : Feature(FeatureTag::kNumber, "number", std::move(desc)),
      value_(std::move(v)) {}

Number::Number(FeatureTag t, std::string_view tname, Value v, std::string desc)
    : Feature(t, tname, std::move(desc)),
      value_(std::move(v)) {}

std::size_t Number::hash() const noexcept {
    // Treat the double alternative bitwise so NaN values hash stably and
    // the distinct variant alternatives 1u64 vs 1i64 vs 1.0 mix to different seeds
    const std::size_t payload = std::visit([](auto x) noexcept -> std::size_t {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, double>) {
            return util::hashing::hash_double_bits(x);
        } else {
            return std::hash<T>{}(x);
        }
    }, value_);
    return mix_tag(tag_, util::hashing::hash_combine(payload, value_.index()));
}

bool Number::equals(const Feature& o) const noexcept {
    if (o.tag() != tag_) { return false; }
    const auto& rhs = static_cast<const Number&>(o);
    // std::variant::operator== compares by active alternative first
    // Differing alternatives always compare unequal even when payloads match
    return value_ == rhs.value_;
}

std::string Number::to_string() const {
    std::ostringstream os;
    os << type_name() << '(';
    std::visit([&os](auto v) { os << v; }, value_);
    os << ')';
    return os.str();
}

// Offset
Offset::Offset(std::int64_t v, std::string desc)
    : Feature(FeatureTag::kOffset, "offset", std::move(desc)),
      value_(v) {}

Offset::Offset(FeatureTag t, std::string_view tname, std::int64_t v, std::string desc)
    : Feature(t, tname, std::move(desc)),
      value_(v) {}

std::size_t Offset::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::int64_t>{}(value_));
}

bool Offset::equals(const Feature& o) const noexcept {
    if (o.tag() != tag_) { return false; }
    const auto& rhs = static_cast<const Offset&>(o);
    return value_ == rhs.value_;
}

std::string Offset::to_string() const {
    std::ostringstream os;
    os << type_name() << '(' << value_ << ')';
    return os.str();
}

// MatchedRule
MatchedRule::MatchedRule(std::string name, std::string desc)
    : Feature(FeatureTag::kMatchedRule, "match", std::move(desc)),
      name_(std::move(name)) {}

std::size_t MatchedRule::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(name_));
}

bool MatchedRule::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kMatchedRule) { return false; }
    const auto& rhs = static_cast<const MatchedRule&>(o);
    return name_ == rhs.name_;
}

std::string MatchedRule::to_string() const {
    return "match(\"" + name_ + "\")";
}

// Characteristic
Characteristic::Characteristic(std::string v, std::string desc)
    : Feature(FeatureTag::kCharacteristic, "characteristic", std::move(desc)),
      value_(std::move(v)) {}

std::size_t Characteristic::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Characteristic::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kCharacteristic) { return false; }
    const auto& rhs = static_cast<const Characteristic&>(o);
    return value_ == rhs.value_;
}

std::string Characteristic::to_string() const {
    return "characteristic(\"" + value_ + "\")";
}

// Class
Class::Class(std::string v, std::string desc)
    : Feature(FeatureTag::kClass, "class", std::move(desc)),
      value_(std::move(v)) {}

std::size_t Class::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Class::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kClass) { return false; }
    const auto& rhs = static_cast<const Class&>(o);
    return value_ == rhs.value_;
}

std::string Class::to_string() const {
    return "class(\"" + value_ + "\")";
}

// Namespace
Namespace::Namespace(std::string v, std::string desc)
    : Feature(FeatureTag::kNamespace, "namespace", std::move(desc)),
      value_(std::move(v)) {}

std::size_t Namespace::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Namespace::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kNamespace) { return false; }
    const auto& rhs = static_cast<const Namespace&>(o);
    return value_ == rhs.value_;
}

std::string Namespace::to_string() const {
    return "namespace(\"" + value_ + "\")";
}

// Os
Os::Os(std::string v, std::string desc)
    : Feature(FeatureTag::kOs, "os", std::move(desc)),
      value_(std::move(v)) {}

engine::Result Os::evaluate(const FeatureSet& fs, bool sc) const {
    // Exact-structural path first to handle the common case without scanning
    auto r = Feature::evaluate(fs, sc);
    if (r.success) { return r; }

    // Wildcard pass: rule side "any" matches any concrete Os in the set and
    // set side "any" matches any concrete rule
    r.node = this;
    const bool self_any = (value_ == kAnyWildcard);
    for (const auto& [f, locs] : fs) {
        if (!f || f->tag() != FeatureTag::kOs) { continue; }
        const auto& other = static_cast<const Os&>(*f);
        if (self_any || other.value_ == kAnyWildcard) {
            r.success = true;
            r.locations.insert(locs.begin(), locs.end());
            if (sc) { return r; }
        }
    }
    return r;
}

bool Os::matches(const FeatureSet& fs) const {
    if (Feature::matches(fs)) { return true; }
    const bool self_any = (value_ == kAnyWildcard);
    for (const auto& [f, locs] : fs) {
        if (!f || f->tag() != FeatureTag::kOs) { continue; }
        const auto& other = static_cast<const Os&>(*f);
        if (self_any || other.value_ == kAnyWildcard) { return true; }
    }
    return false;
}

std::size_t Os::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Os::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kOs) { return false; }
    const auto& rhs = static_cast<const Os&>(o);
    return value_ == rhs.value_;
}

std::string Os::to_string() const {
    return "os(" + value_ + ")";
}

// Arch
Arch::Arch(std::string v, std::string desc)
    : Feature(FeatureTag::kArch, "arch", std::move(desc)),
      value_(std::move(v)) {}

engine::Result Arch::evaluate(const FeatureSet& fs, bool sc) const {
    auto r = Feature::evaluate(fs, sc);
    if (r.success) { return r; }

    r.node = this;
    const bool self_any = (value_ == kAnyWildcard);
    for (const auto& [f, locs] : fs) {
        if (!f || f->tag() != FeatureTag::kArch) { continue; }
        const auto& other = static_cast<const Arch&>(*f);
        if (self_any || other.value_ == kAnyWildcard) {
            r.success = true;
            r.locations.insert(locs.begin(), locs.end());
            if (sc) { return r; }
        }
    }
    return r;
}

bool Arch::matches(const FeatureSet& fs) const {
    if (Feature::matches(fs)) { return true; }
    const bool self_any = (value_ == kAnyWildcard);
    for (const auto& [f, locs] : fs) {
        if (!f || f->tag() != FeatureTag::kArch) { continue; }
        const auto& other = static_cast<const Arch&>(*f);
        if (self_any || other.value_ == kAnyWildcard) { return true; }
    }
    return false;
}

std::size_t Arch::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Arch::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kArch) { return false; }
    const auto& rhs = static_cast<const Arch&>(o);
    return value_ == rhs.value_;
}

std::string Arch::to_string() const {
    return "arch(" + value_ + ")";
}

// Format
Format::Format(std::string v, std::string desc)
    : Feature(FeatureTag::kFormat, "format", std::move(desc)),
      value_(std::move(v)) {}

std::size_t Format::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool Format::equals(const Feature& o) const noexcept {
    if (o.tag() != FeatureTag::kFormat) { return false; }
    const auto& rhs = static_cast<const Format&>(o);
    return value_ == rhs.value_;
}

std::string Format::to_string() const {
    return "format(" + value_ + ")";
}

}  // namespace papa::features
