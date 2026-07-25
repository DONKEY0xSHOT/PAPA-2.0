#include "papa/engine.h"

#include "papa/exceptions.h"
#include "papa/features/common.h"
#include "papa/rules/rule.h"

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace papa::engine {

// And
And::And(std::vector<std::unique_ptr<Statement>> kids) {
    children_ = std::move(kids);
}

Result And::evaluate(const features::FeatureSet& fs, bool sc) const {
    Result r;
    r.node = this;
    bool all_ok = true;
    r.children.reserve(children_.size());
    for (const auto& child : children_) {
        if (!child) {
            // Defensive guard against a null child slot
            // A null would otherwise dereference in the recursive call
            // Treat it as a false child so a construction bug fails loudly
            // rather than silently succeeding
            all_ok = false;
            if (sc) { break; }
            continue;
        }
        auto cr = child->evaluate(fs, sc);
        const bool ok = cr.success;
        r.children.push_back(std::move(cr));
        if (!ok) {
            all_ok = false;
            if (sc) { break; }
        }
    }
    r.success = all_ok;
    if (r.success) {
        // Union locations from all children so downstream callers can report
        // every binding site that justifies the successful And
        for (const auto& cr : r.children) {
            r.locations.insert(cr.locations.begin(), cr.locations.end());
        }
    }
    return r;
}

// Or
Or::Or(std::vector<std::unique_ptr<Statement>> kids) {
    children_ = std::move(kids);
}

Result Or::evaluate(const features::FeatureSet& fs, bool sc) const {
    Result r;
    r.node = this;
    bool any_ok = false;
    r.children.reserve(children_.size());
    for (const auto& child : children_) {
        if (!child) { continue; }
        auto cr = child->evaluate(fs, sc);
        const bool ok = cr.success;
        if (ok) {
            r.locations.insert(cr.locations.begin(), cr.locations.end());
            any_ok = true;
        }
        r.children.push_back(std::move(cr));
        if (ok && sc) { break; }
    }
    r.success = any_ok;
    return r;
}

// Not
Not::Not(std::unique_ptr<Statement> kid) {
    if (!kid) {
        throw PapaInvariantError("Not statement requires a non-null child");
    }
    children_.push_back(std::move(kid));
}

Result Not::evaluate(const features::FeatureSet& fs, bool /*sc*/) const {
    Result r;
    r.node = this;

    // Not needs the precise truth value of its child
    // Passing short_circuit=false ensures child evaluation is not truncated
    auto cr = children_[0]->evaluate(fs, /*sc=*/false);
    r.success = !cr.success;
    r.children.push_back(std::move(cr));

    // A successful Not carries no locations of its own because negation
    // has no positive binding to report
    return r;
}

// Some
Some::Some(std::size_t count, std::vector<std::unique_ptr<Statement>> kids)
    : count_(count) {
    children_ = std::move(kids);
}

Result Some::evaluate(const features::FeatureSet& fs, bool sc) const {
    Result r;
    r.node = this;
    r.children.reserve(children_.size());

    // count_ == 0 is the "optional:" idiom and is unconditionally true
    // Children are still evaluated so result trees reflect the full structure
    // for renderers, though short-circuit may shorten the walk once satisfied
    std::size_t ok_count = 0;
    for (const auto& child : children_) {
        if (!child) { continue; }
        auto cr = child->evaluate(fs, sc);
        const bool ok = cr.success;
        if (ok) {
            r.locations.insert(cr.locations.begin(), cr.locations.end());
            ++ok_count;
        }
        r.children.push_back(std::move(cr));
        if (sc && count_ > 0 && ok_count >= count_) { break; }
    }

    if (count_ == 0) {
        r.success = true;
    } else {
        r.success = (ok_count >= count_);
    }
    return r;
}

// Range
Range::Range(features::FeaturePtr feat, std::size_t min, std::size_t max)
    : feat_(std::move(feat)), min_(min), max_(max) {
    if (!feat_) {
        throw PapaInvariantError("Range statement requires a non-null feature");
    }
}

Result Range::evaluate(const features::FeatureSet& fs, bool /*sc*/) const {
    Result r;
    r.node = this;

    const auto it  = fs.find(feat_);
    const std::size_t cnt = (it == fs.end()) ? 0 : it->second.size();

    // CAPA edge case: when min == 0 and the feature is absent, succeed with
    // empty locations so "count(...): 0 or more" is vacuously true
    if (min_ == 0 && cnt == 0) {
        r.success = true;
        return r;
    }

    r.success = (cnt >= min_) && (cnt <= max_);
    if (r.success && it != fs.end()) {
        r.locations.insert(it->second.begin(), it->second.end());
    }
    return r;
}

// Subscope
Subscope::Subscope(rules::Scope scope, std::unique_ptr<Statement> inner)
    : scope_(scope), inner_(std::move(inner)) {
    if (!inner_) {
        throw PapaInvariantError("Subscope requires a non-null inner statement");
    }
}

Result Subscope::evaluate(const features::FeatureSet&, bool) const {
    // Subscope must be extracted into its own Rule before matching begins
    // Reaching evaluate means the RuleSet build pipeline has a bug
    // Fail fast with a logic-error subclass rather than return a misleading result
    throw PapaInvariantError(
        "Subscope statement reached evaluate before extraction");
}

// FeatureStatement
FeatureStatement::FeatureStatement(features::FeaturePtr f)
    : feature_(std::move(f)) {
    if (!feature_) {
        throw PapaInvariantError("FeatureStatement requires a non-null feature");
    }
}

Result FeatureStatement::evaluate(const features::FeatureSet& fs, bool sc) const {
    return feature_->evaluate(fs, sc);
}

void index_rule_matches(features::FeatureSet& fs,
                        const rules::Rule& rule,
                        std::span<const features::Address> addresses) {
    if (addresses.empty()) { return; }

    auto emit = [&](std::string name) {
        // Allocate one MatchedRule per distinct name and attach it to every address
        // The FeatureSet deduplicates by structural equality so repeated calls
        // with the same name share a single entry and only extend its address set
        auto mr = std::make_shared<const features::MatchedRule>(std::move(name));
        for (const auto& addr : addresses) {
            fs.add(mr, addr);
        }
    };

    emit(rule.name());
    for (auto ns : rule.namespace_hierarchy()) {
        emit(std::move(ns));
    }
}

// evaluate_quick fast paths
// These avoid every Result/vector allocation that the full evaluate() builds
// for the renderer. The probe pass in match() only needs a boolean

bool And::evaluate_quick(const features::FeatureSet& fs) const {
    for (const auto& child : children_) {
        if (!child)                          { return false; }
        if (!child->evaluate_quick(fs))      { return false; }
    }
    return true;
}

bool Or::evaluate_quick(const features::FeatureSet& fs) const {
    for (const auto& child : children_) {
        if (!child)                          { continue; }
        if (child->evaluate_quick(fs))       { return true; }
    }
    return false;
}

bool Not::evaluate_quick(const features::FeatureSet& fs) const {
    if (children_.empty() || !children_.front()) {
        // Defensive: a malformed Not is conservatively false
        return false;
    }
    return !children_.front()->evaluate_quick(fs);
}

bool Some::evaluate_quick(const features::FeatureSet& fs) const {
    if (count_ == 0) { return true; }
    std::size_t hits = 0;
    for (const auto& child : children_) {
        if (!child) { continue; }
        if (child->evaluate_quick(fs)) {
            ++hits;
            if (hits >= count_) { return true; }
        }
    }
    return false;
}

bool FeatureStatement::evaluate_quick(const features::FeatureSet& fs) const {
    // Delegate to the feature's own evaluate path so subclass-specific scans
    // (substring, regex, bytes-prefix) all reach the right semantics
    return feature_->evaluate(fs, /*sc=*/true).success;
}

// match
std::pair<features::FeatureSet, MatchResults>
match(std::span<const rules::Rule* const> rules_topo,
      features::FeatureSet fs,
      const features::Address& addr) {
    MatchResults out;

    for (const rules::Rule* rule : rules_topo) {
        if (!rule) { continue; }

        // Probe pass: boolean-only short-circuit, no allocations
        if (!rule->statement().evaluate_quick(fs)) { continue; }

        // Full pass produces the complete result tree consumed by renderers
        Result full = rule->statement().evaluate(fs, /*sc=*/false);
        out[rule->name()].emplace_back(addr, std::move(full));

        // Inject MatchedRule so later rules in topological order can depend on this one
        std::array<features::Address, 1> addrs{addr};
        index_rule_matches(fs, *rule, addrs);
    }

    return {std::move(fs), std::move(out)};
}

}  // namespace papa::engine
