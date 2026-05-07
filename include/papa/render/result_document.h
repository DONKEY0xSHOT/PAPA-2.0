#pragma once

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/loader.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace papa::render {

// One rule's worth of report content
// addresses is the deduplicated, sorted list of locations where the rule fired
struct RuleReport {
    rules::RuleMeta                 meta;
    std::string                     source_yaml;       // raw rule YAML when available
    std::vector<features::Address>  addresses;
};

// The full document a renderer consumes
// Rule names are already stripped of synthetic subscope rules so end users do
// not see the internal "parent/0" entries
struct ResultDocument {
    Metadata                            meta;
    std::map<std::string, RuleReport>   rules;
};

// Build a renderer-friendly document from raw analysis output
// Synthetic subscope rules (lib + is_subscope_rule) are filtered because they
// only exist to keep the engine match cycle hierarchical and have no meaning
// to a user reading the report
[[nodiscard]] ResultDocument
build_document(Metadata                                   metadata,
               const rules::RuleSet&                      ruleset,
               const ::papa::engine::MatchResults&        matches);

}  // namespace papa::render
