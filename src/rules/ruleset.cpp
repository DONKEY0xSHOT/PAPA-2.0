#include "papa/rules/ruleset.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/rules/optimizer.h"
#include "papa/rules/parser.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <queue>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace papa::rules {

namespace {

template <typename T>
using Expected = ::papa::Expected<T>;
using ::papa::ErrorKind;
using ::papa::Unexpected;

// Walk a statement tree top-down replacing each Subscope node
// Newly-spawned synthetic rules are appended to spawned in the order they are
// discovered, which keeps test output deterministic
void extract_subscopes_in(std::unique_ptr<engine::Statement>& slot,
                          const std::string&                  parent_name,
                          std::size_t&                        counter,
                          std::vector<std::unique_ptr<Rule>>& spawned) {
    if (slot == nullptr) { return; }

    if (auto* sub = dynamic_cast<engine::Subscope*>(slot.get()); sub != nullptr) {
        std::string syn_name(parent_name);
        syn_name.push_back('/');
        syn_name.append(std::to_string(counter++));

        const Scope inner_scope = sub->scope();
        auto        inner       = sub->take_inner();

        // Recurse into the new rule's inner tree before adopting it
        // Using a fresh counter rooted at the new name keeps the synthetic names
        // unique per parent and reproducible across runs
        std::size_t inner_counter = 0;
        extract_subscopes_in(inner, syn_name, inner_counter, spawned);

        RuleMeta meta;
        meta.name                = syn_name;
        meta.scopes.static_scope = inner_scope;
        meta.lib                 = true;
        meta.is_subscope_rule    = true;
        meta.parent              = parent_name;
        spawned.push_back(std::make_unique<Rule>(
            std::move(meta), std::move(inner), std::string{}));

        auto match_feat = std::make_shared<const features::MatchedRule>(syn_name);
        slot = std::make_unique<engine::FeatureStatement>(std::move(match_feat));
        return;
    }

    for (auto& child : slot->children_for_rewrite()) {
        if (child) {
            extract_subscopes_in(child, parent_name, counter, spawned);
        }
    }
}

// Collect every MatchedRule name referenced anywhere in the statement tree
// Both leaf FeatureStatement nodes and Range nodes can wrap a MatchedRule
void collect_match_names(const engine::Statement& s, std::vector<std::string>& out) {
    if (const auto* fs = dynamic_cast<const engine::FeatureStatement*>(&s); fs != nullptr) {
        const auto& feat = fs->feature();
        if (feat && feat->tag() == features::FeatureTag::kMatchedRule) {
            const auto* mr = static_cast<const features::MatchedRule*>(feat.get());
            out.emplace_back(mr->rule_name());
        }
    }
    if (const auto* range = dynamic_cast<const engine::Range*>(&s); range != nullptr) {
        const auto& feat = range->feature();
        if (feat && feat->tag() == features::FeatureTag::kMatchedRule) {
            const auto* mr = static_cast<const features::MatchedRule*>(feat.get());
            out.emplace_back(mr->rule_name());
        }
    }
    for (const auto& child : s.children()) {
        if (child) {
            collect_match_names(*child, out);
        }
    }
}

}  // namespace

// ctor / dtor / move
RuleSet::RuleSet()                              = default;
RuleSet::~RuleSet()                             = default;
RuleSet::RuleSet(RuleSet&&) noexcept            = default;
RuleSet& RuleSet::operator=(RuleSet&&) noexcept = default;

// public accessors
const Rule* RuleSet::find(std::string_view name) const noexcept {
    // unordered_map<std::string,...> is not heterogeneous-lookup capable in C++20
    // The transient std::string is acceptable because find is not on the match hot path
    auto it = by_name_.find(std::string(name));
    return it == by_name_.end() ? nullptr : it->second;
}

std::span<const Rule* const> RuleSet::rules_by_scope(Scope scope) const noexcept {
    auto it = by_scope_topo_.find(scope);
    if (it == by_scope_topo_.end()) { return {}; }
    return it->second;
}

std::span<const Rule* const> RuleSet::rules_in_namespace(std::string_view ns) const noexcept {
    auto it = by_namespace_.find(std::string(ns));
    if (it == by_namespace_.end()) { return {}; }
    return it->second;
}

std::pair<features::FeatureSet, engine::MatchResults>
RuleSet::match(Scope scope, features::FeatureSet fs, const features::Address& addr) const {
    const auto it = index_by_scope_.find(scope);
    if (it == index_by_scope_.end()) {
        return engine::match(rules_by_scope(scope), std::move(fs), addr);
    }

    // Reused per thread so a match cycle does not allocate. The index preserves
    // the topological order, which same-scope match references depend on
    thread_local std::vector<const Rule*> candidates;
    it->second.select(fs, candidates);
    return engine::match(candidates, std::move(fs), addr);
}

// pipeline
Expected<RuleSet> RuleSet::from_rules(std::vector<std::unique_ptr<Rule>> rules) {
    auto sub = extract_subscope_rules(rules);
    if (!sub) { return Unexpected{sub.error()}; }

    RuleSet rs;
    rs.rules_ = std::move(rules);

    // Reorder each rule's statement children so cheap, selective features
    // evaluate first, the way capa's optimizer does. Parity-neutral on results
    for (auto& r : rs.rules_) {
        if (r && r->statement_) { optimize(*r->statement_); }
    }

    auto idx = rs.index_rules();
    if (!idx) { return Unexpected{idx.error()}; }

    auto val = rs.validate_dependencies();
    if (!val) { return Unexpected{val.error()}; }

    auto topo = rs.topologically_sort();
    if (!topo) { return Unexpected{topo.error()}; }

    // Index each scope's rules by the features they cannot match without, so a
    // match cycle only evaluates the rules a feature set could satisfy
    for (const auto& [scope, ordered] : rs.by_scope_topo_) {
        rs.index_by_scope_[scope].build(ordered);
    }

    return rs;
}

Expected<void>
RuleSet::extract_subscope_rules(std::vector<std::unique_ptr<Rule>>& rules) {
    std::vector<std::unique_ptr<Rule>> spawned;

    // Iterate the original input only
    // Synthetic rules already had their tree rewritten when they were spawned
    // so revisiting them is unnecessary
    const std::size_t original = rules.size();
    for (std::size_t i = 0; i < original; ++i) {
        if (rules[i] == nullptr) { continue; }
        std::size_t counter = 0;
        extract_subscopes_in(rules[i]->statement_, rules[i]->meta_.name, counter, spawned);
    }

    rules.reserve(rules.size() + spawned.size());
    for (auto& s : spawned) {
        rules.push_back(std::move(s));
    }
    return {};
}

Expected<void> RuleSet::index_rules() {
    by_name_.clear();
    by_namespace_.clear();

    for (const auto& r : rules_) {
        if (r == nullptr) { continue; }
        const std::string& name = r->name();
        if (name.empty()) {
            return Unexpected{::papa::make_error(ErrorKind::kInvalidRule,
                "encountered rule with empty name")};
        }
        auto [_it, inserted] = by_name_.emplace(name, r.get());
        if (!inserted) {
            return Unexpected{::papa::make_error(ErrorKind::kInvalidRule,
                std::string{"duplicate rule name: "}.append(name))};
        }
        // Register the rule under every prefix of its namespace path
        for (const auto& ns : r->namespace_hierarchy()) {
            by_namespace_[ns].push_back(r.get());
        }
    }
    return {};
}

Expected<void> RuleSet::validate_dependencies() {
    // Drop rules whose match: refs cannot be resolved
    // Cross-rule references frequently target rules that PAPA's parser had to
    // skip earlier in the load (irregular YAML, COM class lookup, etc.)
    // The dependent rule cannot fire either way so dropping it keeps the corpus
    // useful instead of failing the whole load
    std::vector<std::unique_ptr<Rule>> kept;
    kept.reserve(rules_.size());
    for (auto& r : rules_) {
        if (r == nullptr) { continue; }
        std::vector<std::string> refs;
        collect_match_names(r->statement(), refs);
        bool ok = true;
        for (const auto& ref : refs) {
            if (by_name_.find(ref) != by_name_.end())      { continue; }
            if (by_namespace_.find(ref) != by_namespace_.end()) { continue; }
            std::cerr << "warning: dropping rule '" << r->name()
                      << "': unresolved reference '" << ref << "'\n";
            ok = false;
            break;
        }
        if (ok) { kept.push_back(std::move(r)); }
    }
    rules_ = std::move(kept);
    // Re-index since we dropped rules
    return index_rules();
}

Expected<void> RuleSet::topologically_sort() {
    by_scope_topo_.clear();

    // Group rules by static scope
    std::unordered_map<Scope, std::vector<const Rule*>> grouped;
    for (const auto& r : rules_) {
        if (r == nullptr) { continue; }
        grouped[r->scope()].push_back(r.get());
    }

    for (auto& [scope, group] : grouped) {
        // Stable lexicographic ordering pre-Kahn so any tie-break is deterministic
        std::sort(group.begin(), group.end(),
            [](const Rule* a, const Rule* b) { return a->name() < b->name(); });

        const std::unordered_set<const Rule*> in_scope(group.begin(), group.end());

        std::unordered_map<const Rule*, std::vector<const Rule*>> succ;
        std::unordered_map<const Rule*, std::size_t>              indegree;
        for (const Rule* r : group) { indegree[r] = 0; }

        for (const Rule* r : group) {
            std::vector<std::string> refs;
            collect_match_names(r->statement(), refs);

            std::unordered_set<const Rule*> deps_for_r;
            for (const auto& ref : refs) {
                std::vector<const Rule*> resolved;
                if (auto it_n = by_name_.find(ref); it_n != by_name_.end()) {
                    resolved.push_back(it_n->second);
                } else if (auto it_ns = by_namespace_.find(ref); it_ns != by_namespace_.end()) {
                    resolved = it_ns->second;
                }
                for (const Rule* dep : resolved) {
                    if (dep == r) { continue; }
                    if (in_scope.find(dep) == in_scope.end()) { continue; }
                    if (!deps_for_r.insert(dep).second) { continue; }
                    succ[dep].push_back(r);
                    indegree[r] += 1;
                }
            }
        }

        // Kahn's algorithm with a min-heap on rule name to keep ties deterministic
        const auto cmp = [](const Rule* a, const Rule* b) {
            return a->name() > b->name();
        };
        std::priority_queue<const Rule*, std::vector<const Rule*>, decltype(cmp)> ready(cmp);
        for (const Rule* r : group) {
            if (indegree[r] == 0) { ready.push(r); }
        }

        std::vector<const Rule*> sorted;
        sorted.reserve(group.size());
        while (!ready.empty()) {
            const Rule* r = ready.top();
            ready.pop();
            sorted.push_back(r);
            auto it = succ.find(r);
            if (it == succ.end()) { continue; }
            for (const Rule* s : it->second) {
                if (--indegree[s] == 0) { ready.push(s); }
            }
        }
        if (sorted.size() != group.size()) {
            return Unexpected{::papa::make_error(ErrorKind::kCycle,
                std::string{"dependency cycle in scope: "}
                    .append(::papa::rules::to_string(scope)))};
        }
        by_scope_topo_[scope] = std::move(sorted);
    }
    return {};
}

// file system entry point
Expected<RuleSet> RuleSet::from_directory(const std::filesystem::path& dir) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(dir, ec) || ec) {
        return Unexpected{::papa::make_error(ErrorKind::kIoError,
            std::string{"rules path does not exist: "}.append(dir.string()))};
    }
    if (!fs::is_directory(dir, ec) || ec) {
        return Unexpected{::papa::make_error(ErrorKind::kIoError,
            std::string{"rules path is not a directory: "}.append(dir.string()))};
    }

    std::vector<std::unique_ptr<Rule>> parsed;

    fs::recursive_directory_iterator it(dir, ec);
    if (ec) {
        return Unexpected{::papa::make_error(ErrorKind::kIoError,
            std::string{"cannot enumerate rules directory: "}.append(ec.message()))};
    }
    for (; it != fs::recursive_directory_iterator(); ++it) {
        const auto& entry = *it;
        // Skip hidden directories (e.g. .github) so CI workflows do not pose
        // as rule files
        // recursive_directory_iterator::disable_recursion_pending stops descent
        // into the directory we just observed
        const auto stem = entry.path().filename().string();
        if (!stem.empty() && stem.front() == '.') {
            if (entry.is_directory(ec)) {
                it.disable_recursion_pending();
            }
            continue;
        }
        if (!entry.is_regular_file(ec) || ec) { continue; }
        const auto ext = entry.path().extension().string();
        if (ext != ".yml" && ext != ".yaml") { continue; }

        std::ifstream ifs(entry.path(), std::ios::binary);
        if (!ifs) {
            return Unexpected{::papa::make_error(ErrorKind::kIoError,
                std::string{"cannot open rule file: "}.append(entry.path().string()))};
        }
        std::stringstream buf;
        buf << ifs.rdbuf();
        const std::string content = buf.str();

        auto r = RuleParser::parse(content, entry.path().string());
        if (!r) {
            // Tolerate per-file parse failures so a single malformed rule does
            // not block the whole corpus from loading
            // The first 1045-rule capa corpus survey produced a small handful
            // of files with constructs the v1 YAML parser rejects (irregular
            // indents, Python-only regex flavors). We log to stderr and skip
            std::cerr << "warning: skipping rule " << entry.path().string()
                      << ": " << r.error().detail << '\n';
            continue;
        }
        parsed.push_back(std::move(*r));
    }

    return from_rules(std::move(parsed));
}

}  // namespace papa::rules
