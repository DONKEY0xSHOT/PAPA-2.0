#pragma once

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/loader.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace papa::render {

// One node of a rule's match tree, mirroring capa's Match model. A node wraps either a
// feature (leaf) or a logic statement
struct MatchNode {
    bool                            success{false};
    bool                            is_feature{false};
    const features::Feature*        feature{nullptr};   // set when is_feature
    std::string                     statement_type;     // set when not is_feature
    std::optional<std::int64_t>     count;              // "some" statement
    std::optional<std::int64_t>     range_min;          // "range" statement
    std::optional<std::int64_t>     range_max;          // "range" statement
    const features::Feature*        range_child{nullptr};
    std::optional<rules::Scope>     subscope;           // "subscope" statement
    std::vector<MatchNode>          children;
    std::vector<features::Address>  locations;
};

// One rule's worth of report content, with the deduplicated sorted addresses, the
// raw match count capa renders, and capa's address and match-tree pairs
struct RuleReport {
    rules::RuleMeta                                              meta;
    std::string                                                 source_yaml;
    std::vector<features::Address>                              addresses;
    std::size_t                                                 match_count{0};
    std::vector<std::pair<features::Address, MatchNode>>        matches;
};

// The full document a renderer consumes
struct ResultDocument {
    Metadata                            meta;
    std::map<std::string, RuleReport>   rules;
    std::set<std::string>               matched_subrules;
};

// Build a renderer-friendly document from raw analysis output
[[nodiscard]] ResultDocument
build_document(Metadata                                   metadata,
               const rules::RuleSet&                      ruleset,
               const ::papa::engine::MatchResults&        matches);

// Resolve a sample path to capa's absolute, forward-slash form
// (Path.resolve().as_posix()), shared by the text and JSON renderers
[[nodiscard]] std::string posix_path(const std::filesystem::path& p);

}  // namespace papa::render
