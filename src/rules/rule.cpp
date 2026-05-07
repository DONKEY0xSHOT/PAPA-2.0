#include "papa/rules/rule.h"

#include "papa/engine.h"
#include "papa/exceptions.h"

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace papa::rules {

namespace {

// Static scope used when neither old "scope:" nor new "scopes.static:" is set
// CAPA defaults to function scope so unscoped legacy rules keep matching where
// they used to before the dual-scope schema landed
constexpr Scope kDefaultStaticScope = Scope::kFunction;

}  // namespace

Rule::Rule(RuleMeta                            meta,
           std::unique_ptr<engine::Statement>  stmt,
           std::string                         definition)
    : meta_(std::move(meta)),
      statement_(std::move(stmt)),
      definition_(std::move(definition)) {
    // Rules without a root statement cannot be evaluated
    // Fail fast rather than allow a null deref inside the matching hot path
    if (!statement_) {
        throw PapaInvariantError("Rule constructed with null statement");
    }
}

Rule::Rule(std::string                         name,
           std::optional<std::string>          ns,
           Scope                               scope,
           std::unique_ptr<engine::Statement>  stmt,
           bool                                is_lib)
    : statement_(std::move(stmt)) {
    if (!statement_) {
        throw PapaInvariantError("Rule constructed with null statement");
    }
    meta_.name        = std::move(name);
    meta_.namespace_  = std::move(ns);
    meta_.scopes.static_scope = scope;
    meta_.lib         = is_lib;
}

Rule::~Rule()                                = default;
Rule::Rule(Rule&&) noexcept                  = default;
Rule& Rule::operator=(Rule&&) noexcept       = default;

const engine::Statement& Rule::statement() const {
    // statement_ is enforced non-null in every constructor
    return *statement_;
}

Scope Rule::scope() const noexcept {
    // Engine matching always operates on the static scope
    // The dynamic scope is consulted only by the dynamic pipeline which v1 omits
    return meta_.scopes.static_scope.value_or(kDefaultStaticScope);
}

std::vector<std::string> Rule::namespace_hierarchy() const {
    std::vector<std::string> out;
    const auto& ns = meta_.namespace_;
    if (!ns.has_value() || ns->empty()) { return out; }
    // Walk from the full namespace down, trimming one path component per step
    std::string current = *ns;
    while (!current.empty()) {
        out.push_back(current);
        const auto slash = current.rfind('/');
        if (slash == std::string::npos) { break; }
        current.resize(slash);
    }
    return out;
}

}  // namespace papa::rules
