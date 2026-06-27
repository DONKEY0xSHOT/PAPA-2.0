#pragma once

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace papa::rules {

// A built corpus
// Holds owning Rule pointers plus per-name, per-namespace, and per-scope indexes
// Topological order per scope satisfies all same-scope match references
class RuleSet {
public:
    // Build from a directory of YAML files
    // Each file with a .yml or .yaml extension is parsed via RuleParser
    [[nodiscard]] static Expected<RuleSet>
    from_directory(const std::filesystem::path& dir);

    // Build from an explicit list of already-parsed rules
    // Performs subscope extraction, dependency validation, and topological sort
    [[nodiscard]] static Expected<RuleSet>
    from_rules(std::vector<std::unique_ptr<Rule>> rules);

    RuleSet(RuleSet&&) noexcept;
    RuleSet& operator=(RuleSet&&) noexcept;
    RuleSet(const RuleSet&)            = delete;
    RuleSet& operator=(const RuleSet&) = delete;
    ~RuleSet();

    // Run the engine match for the given scope
    // Wraps engine::match with the scope's topologically-ordered rule view
    [[nodiscard]] std::pair<features::FeatureSet, engine::MatchResults>
    match(Scope                       scope,
          features::FeatureSet        fs,
          const features::Address&    addr) const;

    // Number of rules including synthetic subscope rules
    [[nodiscard]] std::size_t size() const noexcept { return rules_.size(); }

    // Look up a rule by exact name
    // Returns nullptr if no rule has that name
    [[nodiscard]] const Rule* find(std::string_view name) const noexcept;

    // Rules whose namespace is exactly the given string, in registration order
    // Used by the renderer to splice a `match: namespace` subtree, like capa
    [[nodiscard]] std::span<const Rule* const>
    rules_in_namespace(std::string_view ns) const noexcept;

    // Topologically-ordered rules for the given scope
    // Returns an empty span when no rule is registered at that scope
    [[nodiscard]] std::span<const Rule* const> rules_by_scope(Scope scope) const noexcept;

    // All rules at any scope
    [[nodiscard]] std::span<const std::unique_ptr<Rule>> all_rules() const noexcept {
        return rules_;
    }

private:
    RuleSet();

    // Pipeline steps
    // Each step returns an error rather than throwing so corpus build is recoverable
    static Expected<void>
    extract_subscope_rules(std::vector<std::unique_ptr<Rule>>& rules);

    Expected<void> index_rules();
    Expected<void> validate_dependencies();
    Expected<void> topologically_sort();

    // Storage
    // rules_ owns every rule including synthetic ones spawned by subscope extraction
    std::vector<std::unique_ptr<Rule>>                          rules_;
    std::unordered_map<std::string, const Rule*>                by_name_;
    std::unordered_map<std::string, std::vector<const Rule*>>   by_namespace_;
    std::unordered_map<Scope, std::vector<const Rule*>>         by_scope_topo_;
};

}  // namespace papa::rules
