#pragma once

#include "papa/features/extractors/papa_native/flirt/flirt_format.h"

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

/// One node-level FLAIR pattern. The bitset marks wildcard positions
/// (linker-rewritable bytes). Positions clear in the bitset must match
/// the corresponding byte exactly
struct FlirtPattern {
    std::array<std::uint8_t, kMaxPatternLength>  bytes   {};
    std::bitset<kMaxPatternLength>               wildcard{};
    std::uint8_t                                 length  {0};

    /// True when buf's first `length` bytes match. Wildcard positions
    /// accept any byte. Returns false if buf is shorter than `length`
    [[nodiscard]] bool matches(std::span<const std::uint8_t> buf) const noexcept;
};

/// Whether a module name is the function's public symbol or a local one. The
/// distinction drives which addresses a match names but not the match itself
enum class FlirtNameType : std::uint8_t { kPublic, kLocal };

/// A public/local symbol a module assigns at a function-relative offset. The
/// offset is delta-accumulated across a module's names and may be negative
struct FlirtName {
    std::int64_t   offset {0};
    std::string    name;
    FlirtNameType  type   {FlirtNameType::kPublic};
};

/// A single byte the candidate must carry at a function-relative offset, used
/// to disambiguate modules that share a pattern and CRC
struct FlirtTailByte {
    std::uint32_t  offset {0};
    std::uint8_t   value  {0};
};

/// An assertion that the candidate references a named function at a
/// function-relative offset. A name of "." denotes a data reference. These are
/// what disambiguate FLIRT collisions and are validated against the binary
struct FlirtReference {
    std::uint32_t  offset {0};
    std::string    name;
};

/// A leaf-module record. The matcher needs the tail CRC plus the tail bytes.
/// The library classifier additionally needs the names and references. All are
/// retained so papa's FLIRT matches capa's reference-gated decision
struct FlirtModule {
    std::uint16_t                tail_crc16    {0};
    std::uint16_t                tail_length   {0};
    std::uint32_t                function_size {0};
    std::vector<FlirtName>       names;
    std::vector<FlirtTailByte>   tail_bytes;
    std::vector<FlirtReference>  references;
};

/// Internal node in the pattern tree. Leaves are nodes with no children
/// and a non-empty leaf_modules list. Internal nodes have children and
/// an empty leaf_modules list. Both lists may be empty for the synthetic
/// root
struct FlirtNode {
    FlirtPattern                              pattern;
    std::vector<std::unique_ptr<FlirtNode>>   children;
    std::vector<FlirtModule>                  leaf_modules;
};

/// One parsed .sig file. Move-only because the node graph is owned via
/// unique_ptr
class FlirtTree {
public:
    FlirtTree() = default;
    FlirtTree(FlirtHeader header, std::unique_ptr<FlirtNode> root) noexcept;

    FlirtTree(FlirtTree&&) noexcept            = default;
    FlirtTree& operator=(FlirtTree&&) noexcept = default;
    FlirtTree(const FlirtTree&)                = delete;
    FlirtTree& operator=(const FlirtTree&)     = delete;

    [[nodiscard]] const FlirtHeader& header() const noexcept { return header_; }
    [[nodiscard]] const FlirtNode*   root()   const noexcept { return root_.get(); }

    /// Total number of leaf modules reachable from the root
    [[nodiscard]] std::size_t        module_count() const noexcept;

private:
    FlirtHeader                  header_{};
    std::unique_ptr<FlirtNode>   root_;
};

}  // namespace papa::features::extractors::papa_native::flirt
