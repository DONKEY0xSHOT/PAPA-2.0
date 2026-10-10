#include "papa/features/common.h"

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/util/hashing.h"
#include "papa/util/regex_prefilter.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace papa::features {

namespace {

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

// "any" wildcard used by the Os evaluate paths
// Kept local so the constants module does not need to leak in through the header
constexpr std::string_view kAnyWildcard = "any";

// The set-side wildcard, found by lookup instead of a scan of the whole set
[[nodiscard]] const FeaturePtr& any_os() {
    static const FeaturePtr any = std::make_shared<const Os>(std::string(kAnyWildcard));
    return any;
}

}  // namespace

// Substring
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
    : ValueFeature(FeatureTag::kRegex, std::move(literal), std::move(desc)) {
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
    required_ = util::required_literal(pattern_, case_insensitive_);
}

engine::Result Regex::evaluate(const FeatureSet& fs, bool sc) const {
    engine::Result r;
    r.node = this;
    // A pattern std::regex could not compile produces no matches
    if (!compiled_ok_) { return r; }
    for (const auto& f : fs.strings()) {
        const auto& s = static_cast<const String&>(*f);
        if (!util::contains_literal(s.value(), required_, case_insensitive_)) { continue; }
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
        if (!util::contains_literal(s.value(), required_, case_insensitive_)) { continue; }
        if (std::regex_search(s.value(), compiled_)) { return true; }
    }
    return false;
}

// Bytes
Bytes::Bytes(std::vector<std::byte> value, std::string desc)
    : Feature(FeatureTag::kBytes, std::move(desc)),
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

// Number
Number::Number(Value v, std::string desc)
    : Feature(FeatureTag::kNumber, std::move(desc)),
      value_(std::move(v)) {}

std::size_t hash_number_value(const Number::Value& v) noexcept {
    // Treat the double alternative bitwise so NaN values hash stably and
    // the distinct variant alternatives 1u64 vs 1i64 vs 1.0 mix to different seeds
    std::size_t payload = 0;
    if (const auto* u = std::get_if<std::uint64_t>(&v)) {
        payload = std::hash<std::uint64_t>{}(*u);
    } else if (const auto* i = std::get_if<std::int64_t>(&v)) {
        payload = std::hash<std::int64_t>{}(*i);
    } else if (const auto* d = std::get_if<double>(&v)) {
        payload = util::hashing::hash_double_bits(*d);
    }
    return util::hashing::hash_combine(payload, v.index());
}

bool number_values_equal(const Number::Value& a, const Number::Value& b) noexcept {
    if (a.index() != b.index()) { return false; }
    if (const auto* u = std::get_if<std::uint64_t>(&a)) { return *u == *std::get_if<std::uint64_t>(&b); }
    if (const auto* i = std::get_if<std::int64_t>(&a)) { return *i == *std::get_if<std::int64_t>(&b); }
    if (const auto* d = std::get_if<double>(&a)) { return *d == *std::get_if<double>(&b); }
    return true;
}

std::size_t Number::hash() const noexcept {
    return mix_tag(tag_, hash_number_value(value_));
}

bool Number::equals(const Feature& o) const noexcept {
    if (o.tag() != tag_) { return false; }
    const auto& rhs = static_cast<const Number&>(o);
    return number_values_equal(value_, rhs.value_);
}

// Offset
Offset::Offset(std::int64_t v, std::string desc)
    : Feature(FeatureTag::kOffset, std::move(desc)),
      value_(v) {}

std::size_t Offset::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::int64_t>{}(value_));
}

bool Offset::equals(const Feature& o) const noexcept {
    if (o.tag() != tag_) { return false; }
    const auto& rhs = static_cast<const Offset&>(o);
    return value_ == rhs.value_;
}

// Os
engine::Result Os::evaluate(const FeatureSet& fs, bool sc) const {
    auto r = Feature::evaluate(fs, sc);
    if (r.success) { return r; }
    if (value_ != kAnyWildcard) {
        // Set side any matches every concrete rule value
        if (const auto it = fs.find(any_os()); it != fs.end()) {
            r.success = true;
            r.locations.insert(it->second.begin(), it->second.end());
        }
        return r;
    }
    // Rule side any matches every Os in the set
    for (const auto& [f, locs] : fs) {
        if (!f || f->tag() != FeatureTag::kOs) { continue; }
        r.success = true;
        r.locations.insert(locs.begin(), locs.end());
        if (sc) { return r; }
    }
    return r;
}

bool Os::matches(const FeatureSet& fs) const {
    if (Feature::matches(fs)) { return true; }
    if (value_ != kAnyWildcard) { return fs.find(any_os()) != fs.end(); }
    for (const auto& entry : fs) {
        if (entry.first && entry.first->tag() == FeatureTag::kOs) { return true; }
    }
    return false;
}

std::pair<FeaturePtr, Address> make_characteristic(std::string_view name, std::uint64_t va) {
    return {std::make_shared<const Characteristic>(std::string(name)), va_address(va)};
}

}  // namespace papa::features
