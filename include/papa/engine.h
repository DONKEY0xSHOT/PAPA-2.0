#pragma once

#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/rules/scope.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace papa::rules {
class Rule;
}  // namespace papa::rules

namespace papa::engine {

class Statement;

// Evaluation outcome produced by every Statement and Feature in a rule
// The node variant points into rule-owned memory and is never owned here
struct Result {
    bool                                      success{false};
    std::variant<std::monostate,
                 const Statement*,
                 const features::Feature*>    node{};
    std::vector<Result>                       children;
    std::unordered_set<features::Address>     locations;

    explicit operator bool() const noexcept { return success; }
};

// Rule-match table keyed by rule name
// Each value is a list of per-address evaluation results
using MatchResults = std::unordered_map<
    std::string,
    std::vector<std::pair<features::Address, Result>>>;

/// Base class for nodes in a rule's logical tree
class Statement {
public:
    virtual ~Statement() = default;

    [[nodiscard]] virtual Result           evaluate(const features::FeatureSet& fs,
                                                    bool short_circuit) const = 0;

    /// Boolean-only fast path used by RuleSet::match for the cheap probe pass.
    /// Skips the Result tree entirely, eliminating per-evaluation allocations.
    /// The default delegates to evaluate(fs, true) so subclasses that have not
    /// overridden it remain correct
    [[nodiscard]] virtual bool evaluate_quick(const features::FeatureSet& fs) const {
        return evaluate(fs, /*short_circuit=*/true).success;
    }

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    [[nodiscard]] std::span<const std::unique_ptr<Statement>> children() const noexcept {
        return children_;
    }

    // Mutable accessor used by RuleSet to rewrite Subscope placeholders into
    // MatchedRule leaves at corpus build time
    // Callers must preserve every subclass child-count invariant when assigning
    [[nodiscard]] std::span<std::unique_ptr<Statement>> children_for_rewrite() noexcept {
        return children_;
    }

protected:
    std::vector<std::unique_ptr<Statement>> children_;
};

// Logical AND
// Evaluates children and succeeds only when every child succeeds
class And : public Statement {
public:
    explicit And(std::vector<std::unique_ptr<Statement>> kids);
    [[nodiscard]] Result evaluate(const features::FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool   evaluate_quick(const features::FeatureSet& fs) const override;
    [[nodiscard]] std::string_view name() const noexcept override { return "and"; }
};

// Logical OR
// Succeeds when at least one child succeeds
class Or : public Statement {
public:
    explicit Or(std::vector<std::unique_ptr<Statement>> kids);
    [[nodiscard]] Result evaluate(const features::FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool   evaluate_quick(const features::FeatureSet& fs) const override;
    [[nodiscard]] std::string_view name() const noexcept override { return "or"; }
};

// Logical NOT over exactly one child
class Not : public Statement {
public:
    explicit Not(std::unique_ptr<Statement> kid);
    [[nodiscard]] Result evaluate(const features::FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool   evaluate_quick(const features::FeatureSet& fs) const override;
    [[nodiscard]] std::string_view name() const noexcept override { return "not"; }
};

// Require at least N children to succeed
// count == 0 is the "optional" idiom and is unconditionally true
class Some : public Statement {
public:
    Some(std::size_t count, std::vector<std::unique_ptr<Statement>> kids);
    [[nodiscard]] Result evaluate(const features::FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool   evaluate_quick(const features::FeatureSet& fs) const override;
    [[nodiscard]] std::string_view name() const noexcept override {
        return count_ == 0 ? "optional" : "some";
    }
    [[nodiscard]] std::size_t count() const noexcept { return count_; }

private:
    std::size_t count_{0};
};

// Require the feature's occurrence count to lie in [min, max]
// Key edge case: if min == 0 and the feature is absent (count == 0), succeed with no locations
class Range : public Statement {
public:
    Range(features::FeaturePtr feat, std::size_t min, std::size_t max);
    [[nodiscard]] Result evaluate(const features::FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool   evaluate_quick(const features::FeatureSet& fs) const override;
    [[nodiscard]] std::string_view name() const noexcept override { return "count"; }

    [[nodiscard]] std::size_t min() const noexcept { return min_; }
    [[nodiscard]] std::size_t max() const noexcept { return max_; }
    [[nodiscard]] const features::FeaturePtr& feature() const noexcept { return feat_; }

private:
    features::FeaturePtr feat_;
    std::size_t          min_{0};
    std::size_t          max_{0};
};

// Placeholder that must be extracted to a separate rule before matching
// evaluate throws PapaInvariantError because reaching it indicates a RuleSet bug
class Subscope : public Statement {
public:
    Subscope(rules::Scope scope, std::unique_ptr<Statement> inner);
    [[nodiscard]] Result evaluate(const features::FeatureSet& fs, bool sc) const override;
    [[nodiscard]] std::string_view name() const noexcept override { return "subscope"; }

    [[nodiscard]] rules::Scope scope() const noexcept { return scope_; }
    [[nodiscard]] const Statement& inner() const noexcept { return *inner_; }
    [[nodiscard]] std::unique_ptr<Statement> take_inner() noexcept { return std::move(inner_); }

private:
    rules::Scope               scope_;
    std::unique_ptr<Statement> inner_;
};

// Leaf Statement that wraps one Feature so the tree is uniform
class FeatureStatement : public Statement {
public:
    explicit FeatureStatement(features::FeaturePtr f);
    [[nodiscard]] Result evaluate(const features::FeatureSet& fs, bool sc) const override;
    [[nodiscard]] bool   evaluate_quick(const features::FeatureSet& fs) const override;
    [[nodiscard]] std::string_view name() const noexcept override { return "feature"; }

    [[nodiscard]] const features::FeaturePtr& feature() const noexcept { return feature_; }

private:
    features::FeaturePtr feature_;
};

// Top-level match: walk rules in topological order, record matches, inject MatchedRule into fs
[[nodiscard]] std::pair<features::FeatureSet, MatchResults>
match(std::span<const rules::Rule* const> rules_topo,
      features::FeatureSet fs,
      const features::Address& addr);

// Add MatchedRule features for a rule and its namespace hierarchy at each address
void index_rule_matches(features::FeatureSet& fs,
                        const rules::Rule& rule,
                        std::span<const features::Address> addresses);

}  // namespace papa::engine
