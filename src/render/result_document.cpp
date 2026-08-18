#include "papa/render/result_document.h"

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/loader.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace papa::render {

namespace {

// papa::features::linearize provides a stable scalar projection of Address
// The renderer uses it to sort match locations deterministically across runs
using ::papa::features::linearize;

// Collect the names of rules referenced via match: inside a successful result
void collect_matched_rules(const engine::Result&  result,
                           std::set<std::string>& out) {
    if (!result.success) { return; }
    if (const auto* feat = std::get_if<const features::Feature*>(&result.node)) {
        if (*feat != nullptr &&
            (*feat)->tag() == features::FeatureTag::kMatchedRule) {
            out.insert(static_cast<const features::MatchedRule*>(*feat)->rule_name());
        }
    }
    for (const auto& child : result.children) {
        collect_matched_rules(child, out);
    }
}

// True when a rule is a user-facing capability rather than a building block
[[nodiscard]] bool is_capability_rule(const rules::RuleMeta& m) {
    if (m.lib || m.is_subscope_rule) { return false; }
    return !(m.namespace_.has_value() && m.namespace_->starts_with("internal/"));
}

// Sort match locations so PAPA's report is deterministic across runs
void sort_addresses(std::vector<features::Address>& addrs) {
    std::sort(addrs.begin(), addrs.end(),
              [](const features::Address& a, const features::Address& b) {
                  return linearize(a) < linearize(b);
              });
}

// Translate a logic statement into capa's node type plus its extra fields
void fill_statement(MatchNode& node, const engine::Statement& st) {
    const std::string_view name = st.name();
    if (name == "some") {
        node.statement_type = "some";
        node.count = static_cast<std::int64_t>(static_cast<const engine::Some&>(st).count());
    } else if (name == "count") {
        // capa names the range statement "range", not "count"
        node.statement_type = "range";
        const auto& range = static_cast<const engine::Range&>(st);
        node.range_min   = static_cast<std::int64_t>(range.min());
        node.range_max   = static_cast<std::int64_t>(range.max());
        node.range_child = range.feature().get();
    } else if (name == "subscope") {
        node.statement_type = "subscope";
        node.subscope = static_cast<const engine::Subscope&>(st).scope();
    } else {
        // and / or / not / optional carry only their type
        node.statement_type = std::string(name);
    }
}

// Guards against pathological reference chains (the rule graph is acyclic)
constexpr int kMaxMatchDepth = 256;

// Build capa's match tree from an engine result, splicing in the trees of rules
// a `match:` feature references. Faithful to capa's Match.from_capa
[[nodiscard]] MatchNode build_match(const rules::RuleSet&        ruleset,
                                    const engine::MatchResults&  matches,
                                    const engine::Result&        result,
                                    int                          depth) {
    MatchNode node;
    node.success = result.success;

    if (const auto* fp = std::get_if<const features::Feature*>(&result.node);
        fp != nullptr && *fp != nullptr) {
        node.is_feature = true;
        node.feature = *fp;
    } else if (const auto* sp = std::get_if<const engine::Statement*>(&result.node);
               sp != nullptr && *sp != nullptr) {
        fill_statement(node, **sp);
    }

    node.children.reserve(result.children.size());
    for (const auto& child : result.children) {
        node.children.push_back(build_match(ruleset, matches, child, depth + 1));
    }

    // Locations belong to feature nodes and the range statement, only on success
    if (result.success && (node.is_feature || node.statement_type == "range")) {
        node.locations.assign(result.locations.begin(), result.locations.end());
        sort_addresses(node.locations);
    }

    const bool is_match_feature =
        node.is_feature && node.success &&
        node.feature->tag() == features::FeatureTag::kMatchedRule;
    if (!is_match_feature || depth >= kMaxMatchDepth) {
        return node;
    }

    const std::string& name =
        static_cast<const features::MatchedRule*>(node.feature)->rule_name();

    std::vector<features::Address> locs(result.locations.begin(), result.locations.end());
    sort_addresses(locs);

    // Splice one referenced rule's matches in as children at the shared locations
    const auto splice_rule = [&](const std::string& rule_name) {
        const auto it = matches.find(rule_name);
        if (it == matches.end()) { return; }
        std::unordered_map<std::uint64_t, const engine::Result*> by_loc;
        for (const auto& [addr, res] : it->second) {
            by_loc.emplace(linearize(addr), &res);
        }
        for (const auto& loc : locs) {
            if (const auto rm = by_loc.find(linearize(loc)); rm != by_loc.end()) {
                node.children.push_back(build_match(ruleset, matches, *rm->second, depth + 1));
            }
        }
    };

    if (const rules::Rule* rule = ruleset.find(name); rule != nullptr) {
        if (rule->meta().is_subscope_rule) {
            // capa rewrites the node into the subscope it stands for, keeping the
            // locations already gathered from the original match feature
            node.is_feature = false;
            node.feature = nullptr;
            node.statement_type = "subscope";
            node.subscope = rule->meta().scopes.static_scope.has_value()
                                ? rule->meta().scopes.static_scope
                                : rule->meta().scopes.dynamic_scope;
        }
        splice_rule(name);
    } else {
        // a namespace reference pulls in every matching rule beneath it
        for (const rules::Rule* ns_rule : ruleset.rules_in_namespace(name)) {
            splice_rule(ns_rule->name());
        }
    }
    return node;
}

}  // namespace

ResultDocument
build_document(Metadata                                   metadata,
               const rules::RuleSet&                      ruleset,
               const ::papa::engine::MatchResults&        matches) {
    ResultDocument doc;
    doc.meta = std::move(metadata);

    for (const auto& [rule_name, addr_list] : matches) {
        const rules::Rule* rule = ruleset.find(rule_name);
        if (rule == nullptr) {
            // Match for an unknown name should not happen but we tolerate it by
            // skipping rather than aborting the whole report
            continue;
        }
        // Filter synthetic subscope rules: they exist only inside the engine
        if (rule->meta().is_subscope_rule) { continue; }

        // capa hides rules that another capability rule pulls in via match:
        if (is_capability_rule(rule->meta())) {
            for (const auto& [_addr, res] : addr_list) {
                collect_matched_rules(res, doc.matched_subrules);
            }
        }

        RuleReport rep;
        rep.meta        = rule->meta();
        rep.source_yaml = rule->definition();
        rep.match_count = addr_list.size();

        rep.addresses.reserve(addr_list.size());
        for (const auto& [addr, _] : addr_list) {
            rep.addresses.push_back(addr);
        }
        // Deterministic ordering for byte-identical re-runs
        std::sort(rep.addresses.begin(), rep.addresses.end(),
                  [](const features::Address& a, const features::Address& b) {
                      return linearize(a) < linearize(b);
                  });
        // Drop duplicates produced by overlapping match scopes
        rep.addresses.erase(
            std::unique(rep.addresses.begin(), rep.addresses.end(),
                        [](const features::Address& a, const features::Address& b) {
                            return linearize(a) == linearize(b);
                        }),
            rep.addresses.end());

        // capa's (address, match-tree) pairs for the JSON report, address-sorted
        rep.matches.reserve(addr_list.size());
        for (const auto& [addr, res] : addr_list) {
            rep.matches.emplace_back(addr, build_match(ruleset, matches, res, 0));
        }
        std::sort(rep.matches.begin(), rep.matches.end(),
                  [](const auto& a, const auto& b) {
                      return linearize(a.first) < linearize(b.first);
                  });

        doc.rules.emplace(rule_name, std::move(rep));
    }
    return doc;
}

std::string posix_path(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::weakly_canonical(p, ec);
    if (ec) { resolved = std::filesystem::absolute(p, ec); }
    if (ec) { resolved = p; }
    return resolved.generic_string();
}

}  // namespace papa::render
