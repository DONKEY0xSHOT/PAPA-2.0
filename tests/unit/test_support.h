#pragma once

#include "papa/engine.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

/// Helpers shared by the unit tests
namespace papa_tests {

/// A rule around stmt with only its name, namespace and static scope set
[[nodiscard]] inline std::unique_ptr<papa::rules::Rule>
make_rule(std::string                               name,
          std::optional<std::string>                ns,
          papa::rules::Scope                        scope,
          std::unique_ptr<papa::engine::Statement>  stmt) {
    papa::rules::RuleMeta meta;
    meta.name                = std::move(name);
    meta.namespace_          = std::move(ns);
    meta.scopes.static_scope = scope;
    return std::make_unique<papa::rules::Rule>(std::move(meta), std::move(stmt), std::string{});
}

}  // namespace papa_tests
