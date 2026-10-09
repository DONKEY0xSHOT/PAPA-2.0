#pragma once

#include <span>
#include <string_view>

namespace papa::rules {

/// One rule file of the capa-rules corpus compiled into the binary
struct EmbeddedRule {
    std::string_view path;   // relative, forward slashes
    std::string_view text;
};

/// The vendored capa-rules corpus, sorted by path
[[nodiscard]] std::span<const EmbeddedRule> embedded_rules() noexcept;

}  // namespace papa::rules
