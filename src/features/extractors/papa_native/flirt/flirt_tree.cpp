#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <utility>

namespace papa::features::extractors::papa_native::flirt {

namespace {

std::size_t count_modules_recursive(const FlirtNode* node) noexcept {
    if (node == nullptr) {
        return 0U;
    }
    std::size_t total = node->leaf_modules.size();
    for (const auto& child : node->children) {
        total += count_modules_recursive(child.get());
    }
    return total;
}

}  // namespace

bool FlirtPattern::matches(std::span<const std::uint8_t> buf) const noexcept {
    if (buf.size() < length) {
        return false;
    }
    for (std::uint8_t i = 0; i < length; ++i) {
        if (wildcard.test(i)) {
            continue;
        }
        if (buf[i] != bytes[i]) {
            return false;
        }
    }
    return true;
}

FlirtTree::FlirtTree(FlirtHeader header, std::unique_ptr<FlirtNode> root) noexcept
    : header_{std::move(header)}, root_{std::move(root)} {}

std::size_t FlirtTree::module_count() const noexcept {
    return count_modules_recursive(root_.get());
}

}  // namespace papa::features::extractors::papa_native::flirt
