#pragma once

#include "papa/exceptions.h"

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace papa::util::yaml {

// Pull the single-argument Expected alias into this nested namespace
// The two-argument primary template would otherwise shadow the alias
template <typename T>
using Expected = ::papa::Expected<T>;

enum class NodeKind : std::uint8_t {
    kScalar,
    kSequence,
    kMapping,
};

class Node;

// Mapping pairs preserve YAML insertion order
// Required so JSON output and round-trip diffing remain deterministic
using MappingEntry = std::pair<std::string, Node>;

// Recursive immutable AST node
// Storage uses unique_ptr-backed vectors so Node is movable but not copyable
class Node {
public:
    Node() noexcept;
    explicit Node(std::string scalar, std::size_t line, std::size_t column) noexcept;
    Node(std::vector<Node> sequence, std::size_t line, std::size_t column) noexcept;
    Node(std::vector<MappingEntry> mapping, std::size_t line, std::size_t column) noexcept;

    Node(const Node&)            = delete;
    Node& operator=(const Node&) = delete;
    Node(Node&&) noexcept;
    Node& operator=(Node&&) noexcept;
    ~Node();

    [[nodiscard]] NodeKind    kind()   const noexcept { return kind_; }
    [[nodiscard]] std::size_t line()   const noexcept { return line_; }
    [[nodiscard]] std::size_t column() const noexcept { return column_; }

    // Accessors throw PapaInvariantError on kind mismatch
    [[nodiscard]] std::string_view              scalar()   const;
    [[nodiscard]] std::span<const Node>         sequence() const;
    [[nodiscard]] std::span<const MappingEntry> mapping()  const;

    // Convenience finder for mapping nodes
    // Returns nullptr if the key is absent or the node is not a mapping
    [[nodiscard]] const Node* find(std::string_view key) const noexcept;

private:
    NodeKind                       kind_   { NodeKind::kScalar };
    std::size_t                    line_   { 0 };
    std::size_t                    column_ { 0 };
    std::string                    scalar_;
    std::vector<Node>              sequence_;
    std::vector<MappingEntry>      mapping_;
};

// Deepest nesting the parser will descend before rejecting a document.
// Parsing is recursive and a rules directory is untrusted input, so this is a
// DoS bound. Real CAPA rules nest under ten levels, so the limit is generous
inline constexpr std::size_t kMaxNestingDepth = 64;

// Parse a YAML document
// Returns kYamlParseError with a line:column-prefixed detail on failure
[[nodiscard]] Expected<Node> parse(std::string_view text);

}  // namespace papa::util::yaml
