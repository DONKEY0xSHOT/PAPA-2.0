#include "papa/features/extractors/papa_native/flirt/flirt.h"

#include "papa/features/extractors/papa_native/flirt/flirt_matcher.h"
#include "papa/features/extractors/papa_native/flirt/flirt_reader.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <span>
#include <thread>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

std::vector<std::uint8_t> embedded::join(const EmbeddedSig& sig) {
    std::size_t size = 0;
    for (const std::string_view chunk : sig.chunks) { size += chunk.size(); }
    std::vector<std::uint8_t> out(size);
    std::size_t at = 0;
    for (const std::string_view chunk : sig.chunks) {
        if (chunk.empty()) { continue; }
        std::memcpy(out.data() + at, chunk.data(), chunk.size());
        at += chunk.size();
    }
    return out;
}

FlirtSignatureSet FlirtSignatureSet::make_embedded() {
    const std::span<const embedded::EmbeddedSig> sigs = embedded::registry();
    const std::size_t                            count = sigs.size();

    FlirtSignatureSet set;
    if (count == 0U) { return set; }

    // The packs decode independently, so decoding them concurrently costs about as long
    // as the largest. They are adopted afterwards in registry order
    std::vector<std::optional<FlirtTree>> parsed(count);
    std::vector<std::exception_ptr>       errors(count);

    const auto parse_one = [&](std::size_t i) {
        try {
            auto tree = parse_sig_buffer(embedded::join(sigs[i]));
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
    for (auto& tree : parsed) {
        if (tree.has_value()) {
            set.trees_.push_back(std::move(*tree));
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

}  // namespace papa::features::extractors::papa_native::flirt
