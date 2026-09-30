#include "papa/rules/feature_index.h"

#include "papa/engine.h"
#include "papa/features/common.h"
#include "papa/features/insn.h"
#include "papa/rules/rule.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <unordered_set>
#include <utility>
#include <variant>

namespace papa::rules {

namespace {

using engine::StatementKind;
using features::FeatureTag;

// A feature is indexable when a structural lookup in the set decides whether it matches
// Unlike capa, match: and scanning leaves are never indexed
[[nodiscard]] bool indexable(FeatureTag tag) noexcept {
    switch (tag) {
        // Scanning and wildcard features can match without an equal feature in the set
        case FeatureTag::kSubstring:
        case FeatureTag::kRegex:
        case FeatureTag::kBytes:
        case FeatureTag::kOs:
        // A global feature that is not selective, which capa does not index either
        case FeatureTag::kArch:
        // Injected during the match cycle, after select has already picked the candidates
        case FeatureTag::kMatchedRule:
            return false;
        case FeatureTag::kString:
        case FeatureTag::kNumber:
        case FeatureTag::kOffset:
        case FeatureTag::kMnemonic:
        case FeatureTag::kApi:
        case FeatureTag::kImport:
        case FeatureTag::kExport:
        case FeatureTag::kSection:
        case FeatureTag::kFunctionName:
        case FeatureTag::kClass:
        case FeatureTag::kNamespace:
        case FeatureTag::kProperty:
        case FeatureTag::kCharacteristic:
        case FeatureTag::kFormat:
        case FeatureTag::kOperandNumber:
        case FeatureTag::kOperandOffset:
        case FeatureTag::kBasicBlock:
            return true;
    }
    return false;
}

// capa's number score, where small and near-maximum values are common and others selective
// Scoring a double as 7 extends capa, whose numbers are always integers
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
[[nodiscard]] int score(const features::Feature& f) noexcept {
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
        case FeatureTag::kFormat:        return 0;
        // Never indexable, so never scored
        case FeatureTag::kSubstring:
        case FeatureTag::kRegex:
        case FeatureTag::kBytes:
        case FeatureTag::kOs:
        case FeatureTag::kArch:
        case FeatureTag::kMatchedRule:   return 0;
    }
    return 0;
}

using Feats = std::unordered_set<features::FeaturePtr,
                                 features::FeatureHashKey,
                                 features::FeatureEqKey>;

// Features a subtree cannot match without, any one of which must be present
// Empty when nothing is provably required, as under not, optional or a scanning leaf
struct Need {
    int   score{0};
    Feats feats;
};

[[nodiscard]] Need leaf(const features::FeaturePtr& f) {
    if (!f || !indexable(f->tag())) { return {}; }
    return {score(*f), Feats{f}};
}

// A port of capa's _index_rules_by_feature recursion
[[nodiscard]] Need need(const engine::Statement* st) {
    if (st == nullptr) { return {}; }
    switch (st->kind()) {
        case StatementKind::kFeature:
            return leaf(static_cast<const engine::FeatureStatement*>(st)->feature());
        case StatementKind::kRange: {
            // count(x) with a zero minimum is satisfied without x
            const auto* range = static_cast<const engine::Range*>(st);
            return range->min() == 0 ? Need{} : leaf(range->feature());
        }
        case StatementKind::kAnd: {
            // Every child must match, so the most selective one is enough, ties going to fewer
            Need best;
            for (const auto& child : st->children()) {
                Need n = need(child.get());
                if (n.feats.empty()) { continue; }
                if (best.feats.empty() || n.score > best.score ||
                    (n.score == best.score && n.feats.size() < best.feats.size())) {
                    best = std::move(n);
                }
            }
            return best;
        }
        case StatementKind::kOr:
        case StatementKind::kSome: {
            // Any child can satisfy it, so an unconstrained child leaves nothing required
            Need any{std::numeric_limits<int>::max(), {}};
            for (const auto& child : st->children()) {
                Need n = need(child.get());
                if (n.feats.empty()) { return {}; }
                any.score = std::min(any.score, n.score);
                any.feats.merge(n.feats);
            }
            if (any.feats.empty()) { return {}; }
            return any;
        }
        // not, optional and subscope require nothing
        case StatementKind::kNot:
        case StatementKind::kOptional:
        case StatementKind::kSubscope:
            return {};
    }
    return {};
}

}  // namespace

void RuleFeatureIndex::build(std::span<const Rule* const> rules) {
    order_.assign(rules.begin(), rules.end());
    always_run_.assign(order_.size(), 1U);
    by_feature_.clear();

    for (std::size_t i = 0; i < order_.size(); ++i) {
        const Need n = need(&order_[i]->statement());
        // A rule with nothing provably required stays always-run
        if (n.feats.empty()) { continue; }

        always_run_[i] = 0U;
        const auto idx = static_cast<std::uint32_t>(i);
        for (const auto& f : n.feats) { by_feature_[f].push_back(idx); }
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
