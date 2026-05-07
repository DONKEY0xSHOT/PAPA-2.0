#pragma once

#include "papa/exceptions.h"
#include "papa/rules/rule.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace papa::engine {
class Statement;
}  // namespace papa::engine

namespace papa::rules {

// Numeric literal parsed from "number:" or "operand[i].number:"
// The active alternative depends on syntax: 0x prefix or unsigned digits give
// std::uint64_t, leading minus gives std::int64_t, decimal point gives double
using NumberValue = std::variant<std::uint64_t, std::int64_t, double>;

// Result of parsing a "bytes:" literal
// Each pattern entry is either a concrete byte or std::nullopt for "??" wildcards
// has_wildcards lets the matcher pick the fast prefix path when no wildcards exist
struct BytesLiteral {
    std::vector<std::optional<std::byte>> pattern;
    bool                                  has_wildcards{false};
};

// Inclusive count range parsed from a "count(...)" value string
// "or more" maps max to SIZE_MAX, single integers map to a degenerate min == max
struct CountRange {
    std::size_t min{0};
    std::size_t max{0};
};

// Stateless rule parser
// Uses the YAML subset parser internally and produces engine::Statement trees
class RuleParser {
public:
    // Parse one rule document
    // source_path is recorded in meta and surfaces in error messages for diagnostics
    [[nodiscard]] static Expected<std::unique_ptr<Rule>>
    parse(std::string_view yaml_text, std::string_view source_path);

    // Helpers exposed for unit testing
    // Each accepts the literal as it appears in YAML after key+colon stripping

    [[nodiscard]] static Expected<NumberValue>
    parse_number_literal(std::string_view text);

    [[nodiscard]] static Expected<BytesLiteral>
    parse_bytes_literal(std::string_view text);

    [[nodiscard]] static Expected<CountRange>
    parse_count_range(std::string_view text);

    // Split "value = description" so the second piece carries the trailing comment
    // Skips matches inside quoted strings to keep escape and quote behavior intact
    [[nodiscard]] static std::pair<std::string_view, std::optional<std::string_view>>
    split_inline_description(std::string_view text);
};

}  // namespace papa::rules
