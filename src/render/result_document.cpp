#include "papa/render/result_document.h"

#include "papa/engine.h"
#include "papa/features/address.h"
#include "papa/loader.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace papa::render {

namespace {

// papa::features::linearize provides a stable scalar projection of Address
// The renderer uses it to sort match locations deterministically across runs
using ::papa::features::linearize;

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

        RuleReport rep;
        rep.meta        = rule->meta();
        rep.source_yaml = rule->definition();

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

        doc.rules.emplace(rule_name, std::move(rep));
    }
    return doc;
}

}  // namespace papa::render
