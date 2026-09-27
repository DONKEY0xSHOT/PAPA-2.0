#include "papa/rules/feature_index.h"

#include "papa/engine.h"
#include "papa/features/common.h"
#include "papa/features/insn.h"
#include "papa/rules/rule.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

namespace papa::rules {

namespace {

// A feature can be indexed only when its match semantics are structural presence in the
// set
[[nodiscard]] bool indexable(features::FeatureTag tag) noexcept {
    switch (tag) {
        case features::FeatureTag::kSubstring:
        case features::FeatureTag::kRegex:
        case features::FeatureTag::kBytes:
        case features::FeatureTag::kOs:
        case features::FeatureTag::kArch:
        case features::FeatureTag::kMatchedRule:
            return false;
        default:
            return true;
    }
}

// What a subtree needs: one of feats present, scored like capa to pick among and-children
// wild means no structurally present feature is provably required
struct Requirement {
    int                               score{0};
    std::vector<features::FeaturePtr> feats;
    bool                              wild{false};
};

[[nodiscard]] Requirement wild() {
    Requirement r;
    r.wild = true;
    return r;
}

// capa's number score: small and near-maximum values are common, others selective
[[nodiscard]] int number_score(const features::Number::Value& v) noexcept {
    std::uint64_t x = 0;
    if (const auto* u = std::get_if<std::uint64_t>(&v)) {
        x = *u;
    } else if (const auto* i = std::get_if<std::int64_t>(&v)) {
        if (*i < 0) { return *i >= -0x8000 ? 3 : 7; }
        x = static_cast<std::uint64_t>(*i);
    } else {
        return 7;
    }
    const bool common = x <= 0x8000ULL || (x >= 0xFFFFFF00ULL && x <= 0xFFFFFFFFULL) ||
                        x >= 0xFFFFFFFFFFFFFF00ULL;
    return common ? 3 : 7;
}

// capa's _score_feature, higher means more selective
[[nodiscard]] int score(const features::Feature& f) {
    using features::FeatureTag;
    switch (f.tag()) {
        case FeatureTag::kString:        return 9;
        case FeatureTag::kApi:           return 8;
        case FeatureTag::kExport:        return 7;
        case FeatureTag::kNumber:
            return number_score(static_cast<const features::Number&>(f).value());
        case FeatureTag::kOperandNumber:
            return number_score(static_cast<const features::OperandNumber&>(f).value());
        case FeatureTag::kClass:
        case FeatureTag::kNamespace:
        case FeatureTag::kProperty:
        case FeatureTag::kImport:
        case FeatureTag::kSection:
        case FeatureTag::kFunctionName:  return 5;
        case FeatureTag::kCharacteristic:
        case FeatureTag::kOffset:
        case FeatureTag::kOperandOffset: return 4;
        case FeatureTag::kMnemonic:      return 2;
        case FeatureTag::kBasicBlock:    return 1;
        default:                         return 0;
    }
}

[[nodiscard]] Requirement leaf(const features::FeaturePtr& f) {
    if (!f || !indexable(f->tag())) { return wild(); }
    Requirement r;
    r.score = score(*f);
    r.feats.push_back(f);
    return r;
}

// A port of capa's _index_rules_by_feature recursion
// nullopt means the subtree adds no requirement, as for not, optional and count(x): 0
[[nodiscard]] std::optional<Requirement> requirement(const engine::Statement& st) {
    const std::string_view name = st.name();
    if (name == "feature") {
        return leaf(static_cast<const engine::FeatureStatement&>(st).feature());
    }
    if (name == "count") {
        const auto& range = static_cast<const engine::Range&>(st);
        if (range.min() == 0) { return std::nullopt; }
        return leaf(range.feature());
    }
    if (name == "not" || name == "optional") { return std::nullopt; }
    if (name == "and") {
        std::optional<Requirement> best;
        for (const auto& child : st.children()) {
            // A missing child makes the and unsatisfiable, so skipping it stays sound
            if (!child) { continue; }
            auto r = requirement(*child);
            if (!r.has_value() || r->wild) { continue; }
            if (!best.has_value() || r->score > best->score ||
                (r->score == best->score && r->feats.size() < best->feats.size())) {
                best = std::move(r);
            }
        }
        if (!best.has_value()) { return wild(); }
        return best;
    }
    if (name == "or" || name == "some") {
        Requirement any;
        any.score = std::numeric_limits<int>::max();
        for (const auto& child : st.children()) {
            // A missing child never matches, so it adds nothing to the union
            if (!child) { continue; }
            auto r = requirement(*child);
            if (!r.has_value() || r->wild) { return wild(); }
            any.score = std::min(any.score, r->score);
            any.feats.insert(any.feats.end(), r->feats.begin(), r->feats.end());
        }
        if (any.feats.empty()) { return wild(); }
        return any;
    }
    return wild();
}

}  // namespace

void RuleFeatureIndex::build(std::span<const Rule* const> rules) {
    order_.assign(rules.begin(), rules.end());
    always_run_.assign(order_.size(), 1U);
    by_feature_.clear();
    indexed_count_ = 0;

    for (std::size_t i = 0; i < order_.size(); ++i) {
        const auto req = requirement(order_[i]->statement());
        if (!req.has_value() || req->wild) { continue; }

        always_run_[i] = 0U;
        ++indexed_count_;
        for (const auto& f : req->feats) {
            auto& slot = by_feature_[f];
            const auto idx = static_cast<std::uint32_t>(i);
            // An or-block can name the same feature more than once
            if (std::find(slot.begin(), slot.end(), idx) == slot.end()) { slot.push_back(idx); }
        }
    }
}

void RuleFeatureIndex::select(const features::FeatureSet& fs,
                              std::vector<const Rule*>&   out) const {
    out.clear();
    if (order_.empty()) { return; }

    // Reused per thread so the hot path does not allocate. Analysis runs one
    // worker per core and each keeps its own scratch
    thread_local std::vector<std::uint8_t> hit;
    hit.assign(order_.size(), 0U);

    for (const auto& entry : fs) {
        const auto it = by_feature_.find(entry.first);
        if (it == by_feature_.end()) { continue; }
        for (const std::uint32_t idx : it->second) { hit[idx] = 1U; }
    }

    for (std::size_t i = 0; i < order_.size(); ++i) {
        if (always_run_[i] != 0U || hit[i] != 0U) { out.push_back(order_[i]); }
    }
}

}  // namespace papa::rules
