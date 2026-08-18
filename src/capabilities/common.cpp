#include "papa/capabilities/common.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"
#include "papa/rules/scope.h"

#include <cstddef>
#include <string>
#include <unordered_set>
#include <string_view>
#include <utility>
#include <vector>

namespace papa::capabilities {

namespace {

// Exact namespace prefix CAPA uses to gate static-only limitation rules. Anything at
// or below this prefix counts
constexpr std::string_view kStaticLimitationPrefix = "internal/limitation/static";

[[nodiscard]] bool
namespace_starts_with(std::string_view ns, std::string_view prefix) noexcept {
    if (ns.size() < prefix.size()) { return false; }
    if (ns.substr(0, prefix.size()) != prefix) { return false; }
    // A bare prefix match is fine. Extra segments must start with a slash so an unrelated
    // namespace like internal/limitation/static_other does not match
    return ns.size() == prefix.size() || ns[prefix.size()] == '/';
}

// Every rule name or namespace a statement tree references through match:. Unlike the
// feature index this walks every branch, since a negated reference matters too
void collect_match_refs(const ::papa::engine::Statement* s,
                        std::vector<std::string>&        out) {
    if (s == nullptr) { return; }

    const auto note = [&out](const features::FeaturePtr& f) {
        if (f && f->tag() == features::FeatureTag::kMatchedRule) {
            out.emplace_back(
                static_cast<const features::MatchedRule*>(f.get())->rule_name());
        }
    };

    const std::string_view name = s->name();
    if (name == "feature") {
        note(static_cast<const ::papa::engine::FeatureStatement*>(s)->feature());
        return;
    }
    if (name == "count") {
        note(static_cast<const ::papa::engine::Range*>(s)->feature());
        return;
    }
    for (const auto& child : s->children()) {
        collect_match_refs(child.get(), out);
    }
}

}  // namespace

std::vector<const ::papa::rules::Rule*>
limitation_gate_rules(const ::papa::rules::RuleSet& rules) {
    const auto file_rules = rules.rules_by_scope(::papa::rules::Scope::kFile);

    // Seed with the limitation rules themselves
    std::vector<const ::papa::rules::Rule*> work;
    for (const auto* r : file_rules) {
        const auto& ns = r->namespace_();
        if (ns.has_value() && namespace_starts_with(*ns, kStaticLimitationPrefix)) {
            work.push_back(r);
        }
    }

    // Walk match: references to their closure
    std::unordered_set<const ::papa::rules::Rule*> closure;
    std::vector<std::string>                       refs;
    while (!work.empty()) {
        const auto* r = work.back();
        work.pop_back();
        if (!closure.insert(r).second) { continue; }

        refs.clear();
        collect_match_refs(&r->statement(), refs);
        for (const auto& ref : refs) {
            if (const auto* by_name = rules.find(ref); by_name != nullptr) {
                work.push_back(by_name);
            }
            for (const auto* in_ns : rules.rules_in_namespace(ref)) {
                work.push_back(in_ns);
            }
        }
    }

    // Emit in the scope's topological order so same-scope match references
    // still resolve before the rules that depend on them
    std::vector<const ::papa::rules::Rule*> out;
    out.reserve(closure.size());
    for (const auto* r : file_rules) {
        if (closure.count(r) != 0) { out.push_back(r); }
    }
    return out;
}

::papa::Expected<FileCapabilities>
find_file_capabilities(
    const ::papa::rules::RuleSet&                                     rules,
    const ::papa::features::extractors::StaticFeatureExtractor&       extractor,
    const std::vector<::papa::features::extractors::FeatureWithAddress>*
        cached_file_features) {
    // Collect file and global features up front so we can reuse the FeatureSet
    // across the file match plus any caller that wants the same vocabulary
    features::FeatureSet fs;
    {
        auto globals = extractor.extract_global_features();
        for (auto& [feat, addr] : globals) {
            fs.add(std::move(feat), addr);
        }
        if (cached_file_features != nullptr) {
            // Copying shares the immutable feature objects through their
            // refcounts, which is far cheaper than carving the file again
            for (const auto& [feat, addr] : *cached_file_features) {
                fs.add(feat, addr);
            }
        } else {
            auto file_feats = extractor.extract_file_features();
            for (auto& [feat, addr] : file_feats) {
                fs.add(std::move(feat), addr);
            }
        }
    }

    const features::Address base = extractor.get_base_address();
    auto [merged_fs, matches] =
        rules.match(::papa::rules::Scope::kFile, std::move(fs), base);

    const std::size_t feature_count = merged_fs.size();
    return FileCapabilities{
        std::move(merged_fs),
        std::move(matches),
        feature_count,
    };
}

::papa::Expected<FileCapabilities>
find_limitation_capabilities(
    const ::papa::rules::RuleSet&                                     rules,
    const ::papa::features::extractors::StaticFeatureExtractor&       extractor,
    const std::vector<::papa::features::extractors::FeatureWithAddress>*
        cached_file_features) {
    features::FeatureSet fs;
    {
        auto globals = extractor.extract_global_features();
        for (auto& [feat, addr] : globals) {
            fs.add(std::move(feat), addr);
        }
        if (cached_file_features != nullptr) {
            for (const auto& [feat, addr] : *cached_file_features) {
                fs.add(feat, addr);
            }
        } else {
            auto file_feats = extractor.extract_file_features();
            for (auto& [feat, addr] : file_feats) {
                fs.add(std::move(feat), addr);
            }
        }
    }

    const auto              gate = limitation_gate_rules(rules);
    const features::Address base = extractor.get_base_address();
    auto [merged_fs, matches] = ::papa::engine::match(gate, std::move(fs), base);

    const std::size_t feature_count = merged_fs.size();
    return FileCapabilities{
        std::move(merged_fs),
        std::move(matches),
        feature_count,
    };
}

bool has_static_limitation(const ::papa::rules::RuleSet& rules,
                           const FileCapabilities&       file_caps) noexcept {
    for (const auto& [rule_name, _matches] : file_caps.matches) {
        const ::papa::rules::Rule* rule = rules.find(rule_name);
        if (rule == nullptr)             { continue; }
        const auto& ns = rule->namespace_();
        if (!ns.has_value())             { continue; }
        if (namespace_starts_with(*ns, kStaticLimitationPrefix)) { return true; }
    }
    return false;
}

}  // namespace papa::capabilities
