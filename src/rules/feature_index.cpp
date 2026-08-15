#include "papa/rules/feature_index.h"

#include "papa/engine.h"
#include "papa/rules/rule.h"

#include <algorithm>
#include <string_view>

namespace papa::rules {

namespace {

// A feature can be indexed only when its match semantics are structural
// presence in the set. The scanning and wildcard evaluators can succeed against
// a value the set does not contain (a substring of a longer string, a byte
// prefix, an os or arch wildcard), so their absence proves nothing.
// MatchedRule is excluded for a different reason: matching injects those
// features as it goes, so a rule needing one may become matchable partway
// through a cycle, after the candidate list was already chosen
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

// Collect the leaves whose absence guarantees the statement cannot succeed.
// Only and-statements propagate a requirement. An or gives no guarantee because
// another branch may carry the match, a not inverts the test, and an optional
// or an "N or more" can succeed without any particular child
void collect_required(const engine::Statement*          st,
                      std::vector<features::FeaturePtr>& out) {
    if (st == nullptr) { return; }

    const std::string_view name = st->name();

    if (name == "feature") {
        const auto& f = static_cast<const engine::FeatureStatement*>(st)->feature();
        if (f && indexable(f->tag())) { out.push_back(f); }
        return;
    }

    if (name == "count") {
        // count(feature) with a zero minimum is vacuously true when the feature
        // is absent, so only a positive minimum makes the feature required
        const auto* range = static_cast<const engine::Range*>(st);
        const auto& f     = range->feature();
        if (range->min() > 0 && f && indexable(f->tag())) { out.push_back(f); }
        return;
    }

    if (name == "and") {
        for (const auto& child : st->children()) {
            collect_required(child.get(), out);
        }
    }
}

}  // namespace

void RuleFeatureIndex::build(std::span<const Rule* const> rules) {
    order_.assign(rules.begin(), rules.end());
    always_run_.assign(order_.size(), 1U);
    by_feature_.clear();
    indexed_count_ = 0;

    std::vector<features::FeaturePtr> required;
    for (std::size_t i = 0; i < order_.size(); ++i) {
        required.clear();
        collect_required(&order_[i]->statement(), required);
        if (required.empty()) { continue; }

        always_run_[i] = 0U;
        ++indexed_count_;
        for (const auto& f : required) {
            auto& slot = by_feature_[f];
            const auto idx = static_cast<std::uint32_t>(i);
            // A rule can require the same feature more than once
            if (std::find(slot.begin(), slot.end(), idx) == slot.end()) {
                slot.push_back(idx);
            }
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
