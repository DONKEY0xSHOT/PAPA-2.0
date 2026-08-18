#include "papa/features/extractors/papa_native/flirt/flirt.h"

#include "papa/features/extractors/papa_native/flirt/flirt_matcher.h"
#include "papa/features/extractors/papa_native/flirt/flirt_reader.h"

#include <cstddef>
#include <exception>
#include <iostream>
#include <optional>
#include <span>
#include <thread>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

FlirtSignatureSet FlirtSignatureSet::make_embedded() {
    const std::span<const embedded::EmbeddedSig> sigs = embedded::registry();
    const std::size_t                            count = sigs.size();

    FlirtSignatureSet set;
    if (count == 0U) { return set; }

    // Each signature file decodes independently, and the shipped packs are
    // 4.5, 7.2 and 2.7 MB, so decoding them concurrently costs about as long as
    // the largest rather than their sum. This is a flat cost on every run and
    // dominates analysis of a small binary.
    // The trees are adopted afterwards in registry order, which the per-tree
    // FLIRT priming depends on, so the result does not depend on which parse
    // finished first
    std::vector<std::optional<FlirtTree>> parsed(count);
    std::vector<std::exception_ptr>       errors(count);

    const auto parse_one = [&](std::size_t i) {
        try {
            auto tree = parse_sig_buffer({sigs[i].data, sigs[i].size});
            if (tree.has_value()) { parsed[i] = std::move(tree.value()); }
        } catch (...) {
            errors[i] = std::current_exception();
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(count - 1U);
    for (std::size_t i = 1; i < count; ++i) { pool.emplace_back(parse_one, i); }
    parse_one(0);
    for (auto& t : pool) { t.join(); }

    for (auto& err : errors) {
        if (err) { std::rethrow_exception(err); }
    }

    set.trees_.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (parsed[i].has_value()) {
            set.trees_.push_back(std::move(parsed[i].value()));
        } else {
            std::cerr << "warning: skipping unparsable FLIRT signature\n";
        }
    }
    return set;
}

bool FlirtSignatureSet::add_from_buffer(std::span<const std::uint8_t> sig_bytes) noexcept {
    auto parsed = parse_sig_buffer(sig_bytes);
    if (!parsed.has_value()) {
        std::cerr << "warning: skipping unparsable FLIRT signature\n";
        return false;
    }
    trees_.push_back(std::move(parsed.value()));
    return true;
}

bool FlirtSignatureSet::classify(std::span<const std::uint8_t> function_bytes) const noexcept {
    for (const FlirtTree& tree : trees_) {
        if (match_flirt(tree, function_bytes)) {
            return true;
        }
    }
    return false;
}

std::vector<const FlirtModule*>
FlirtSignatureSet::match(std::span<const std::uint8_t> function_bytes) const {
    std::vector<const FlirtModule*> out;
    for (const FlirtTree& tree : trees_) {
        const auto hits = match_flirt_modules(tree, function_bytes);
        out.insert(out.end(), hits.begin(), hits.end());
    }
    return out;
}

}  // namespace papa::features::extractors::papa_native::flirt
