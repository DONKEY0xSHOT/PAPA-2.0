#include "papa/capabilities/common.h"

#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"
#include "papa/rules/scope.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace papa::capabilities {

namespace {

// Exact namespace prefix CAPA uses to gate static-only limitation rules
// Anything strictly below this prefix counts (e.g., the leaf
// "internal/limitation/static/dotnet")
// The prefix itself is also a valid rule path that should match exactly
constexpr std::string_view kStaticLimitationPrefix = "internal/limitation/static";

[[nodiscard]] bool
namespace_starts_with(std::string_view ns, std::string_view prefix) noexcept {
    if (ns.size() < prefix.size()) { return false; }
    if (ns.substr(0, prefix.size()) != prefix) { return false; }
    // A bare prefix match is fine
    // If there are more segments they must start with '/' so we do not match
    // an unrelated namespace like "internal/limitation/static_other"
    return ns.size() == prefix.size() || ns[prefix.size()] == '/';
}

}  // namespace

::papa::Expected<FileCapabilities>
find_file_capabilities(const ::papa::rules::RuleSet&                            rules,
                       const ::papa::features::extractors::StaticFeatureExtractor& extractor) {
    // Collect file and global features up front so we can reuse the FeatureSet
    // across the file match plus any caller that wants the same vocabulary
    features::FeatureSet fs;
    {
        auto globals = extractor.extract_global_features();
        for (auto& [feat, addr] : globals) {
            fs.add(std::move(feat), addr);
        }
        auto file_feats = extractor.extract_file_features();
        for (auto& [feat, addr] : file_feats) {
            fs.add(std::move(feat), addr);
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
