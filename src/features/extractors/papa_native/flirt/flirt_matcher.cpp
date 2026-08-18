#include "papa/features/extractors/papa_native/flirt/flirt_matcher.h"

#include "papa/features/extractors/papa_native/flirt/flirt_crc16.h"
#include "papa/features/extractors/papa_native/flirt/flirt_format.h"
#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace papa::features::extractors::papa_native::flirt {

namespace {

// Verifies a single leaf module against the function bytes
[[nodiscard]] bool module_verifies(const FlirtModule& module,
                                   std::span<const std::uint8_t> function_bytes) noexcept {
    const std::size_t needed = kMaxPatternLength + module.tail_length;
    if (function_bytes.size() < needed) {
        return false;
    }
    const auto tail = function_bytes.subspan(kMaxPatternLength, module.tail_length);
    if (flirt_crc16(tail) != module.tail_crc16) {
        return false;
    }
    // Tail bytes are a hard filter, matching python-flirt's match_tail_bytes: every
    // byte the module records must equal the function, or the module is eliminated
    for (const FlirtTailByte& tb : module.tail_bytes) {
        const std::size_t pos = kMaxPatternLength + module.tail_length + tb.offset;
        if (pos >= function_bytes.size() || function_bytes[pos] != tb.value) {
            return false;
        }
    }
    return true;
}

// Collects every leaf module that matches by pattern prefix, tail CRC, and tail bytes.
// A node whose pattern fails prunes its whole subtree
void collect_matching(const FlirtNode& node,
                      std::span<const std::uint8_t> function_bytes,
                      std::vector<const FlirtModule*>& out) {
    if (!node.pattern.matches(function_bytes)) {
        return;
    }
    for (const FlirtModule& module : node.leaf_modules) {
        if (module_verifies(module, function_bytes)) {
            out.push_back(&module);
        }
    }
    for (const auto& child : node.children) {
        if (child != nullptr) {
            collect_matching(*child, function_bytes, out);
        }
    }
}

// Walks the node and its subtree. A node whose pattern fails to match prunes the whole
// subtree
[[nodiscard]] bool node_matches(const FlirtNode& node,
                                std::span<const std::uint8_t> function_bytes) noexcept {
    if (!node.pattern.matches(function_bytes)) {
        return false;
    }
    for (const FlirtModule& module : node.leaf_modules) {
        if (module_verifies(module, function_bytes)) {
            return true;
        }
    }
    for (const auto& child : node.children) {
        if (child != nullptr && node_matches(*child, function_bytes)) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool match_flirt(const FlirtTree& tree,
                 std::span<const std::uint8_t> function_bytes) noexcept {
    const FlirtNode* root = tree.root();
    if (root == nullptr) {
        return false;
    }
    return node_matches(*root, function_bytes);
}

std::vector<const FlirtModule*>
match_flirt_modules(const FlirtTree& tree,
                    std::span<const std::uint8_t> function_bytes) {
    std::vector<const FlirtModule*> out;
    const FlirtNode* root = tree.root();
    if (root != nullptr) {
        collect_matching(*root, function_bytes, out);
    }
    return out;
}

}  // namespace papa::features::extractors::papa_native::flirt
