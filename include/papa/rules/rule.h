#pragma once

#include "papa/rules/scope.h"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace papa::engine {
class Statement;
}  // namespace papa::engine

namespace papa::rules {

class RuleParser;
class RuleSet;

// A rule may declare a static scope, a dynamic scope, or both
// Either may be absent which signals "do not match in that pipeline"
struct Scopes {
    std::optional<Scope> static_scope;
    std::optional<Scope> dynamic_scope;
};

// Rule metadata
// Mirrors capa.rules.RuleMeta key-for-key so the json renderer can map it directly
// All collection fields preserve the order they appear in the source YAML
struct RuleMeta {
    std::string                 name;
    Scopes                      scopes;
    std::optional<std::string>  namespace_;       // trailing underscore avoids the C++ keyword
    std::vector<std::string>    authors;
    std::vector<std::string>    att_and_ck;       // "att&ck:" key in YAML
    std::vector<std::string>    mbc;
    std::vector<std::string>    examples;
    std::vector<std::string>    references;
    std::optional<std::string>  description;
    bool                        lib{false};
    bool                        is_subscope_rule{false};
    bool                        is_nursery{false};
    std::optional<std::string>  parent;           // present on synthetic subscope rules
    std::string                 source_path;
};

// A parsed rule
// Carries metadata, the compiled engine statement, and the original YAML text
class Rule {
public:
    /// Full-meta constructor used when parsing a rule document
    Rule(RuleMeta                            meta,
         std::unique_ptr<engine::Statement>  stmt,
         std::string                         definition);

    /// Convenience constructor used by tests and synthetic rules.
    /// Builds a RuleMeta with only name, namespace, static_scope, and lib set
    Rule(std::string                         name,
         std::optional<std::string>          ns,
         Scope                               scope,
         std::unique_ptr<engine::Statement>  stmt,
         bool                                is_lib = false);

    // Out-of-line so the incomplete Statement type in this header is fine
    ~Rule();
    Rule(Rule&&) noexcept;
    Rule& operator=(Rule&&) noexcept;
    Rule(const Rule&)            = delete;
    Rule& operator=(const Rule&) = delete;

    [[nodiscard]] const RuleMeta&                   meta()       const noexcept { return meta_; }
    [[nodiscard]] const std::string&                definition() const noexcept { return definition_; }
    [[nodiscard]] const engine::Statement&          statement()  const;

    // Convenience accessors that read through to meta_
    // Kept so existing engine code does not need to switch to meta() everywhere
    [[nodiscard]] const std::string&                name()        const noexcept { return meta_.name; }
    [[nodiscard]] const std::optional<std::string>& namespace_()  const noexcept { return meta_.namespace_; }
    [[nodiscard]] Scope                             scope()       const noexcept;
    [[nodiscard]] bool                              is_lib()      const noexcept { return meta_.lib; }

    // "a/b/c" expands to {"a/b/c", "a/b", "a"} and is empty when namespace is absent
    // Order is specific to general so renderers can prefer the deepest match
    [[nodiscard]] std::vector<std::string> namespace_hierarchy() const;

private:
    RuleMeta                            meta_;
    std::unique_ptr<engine::Statement>  statement_;
    std::string                         definition_;

    friend class RuleParser;
    friend class RuleSet;
};

}  // namespace papa::rules
