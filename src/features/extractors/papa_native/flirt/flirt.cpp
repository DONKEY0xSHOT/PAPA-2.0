#include "papa/features/extractors/papa_native/flirt/flirt.h"

#include "papa/features/extractors/papa_native/flirt/flirt_matcher.h"
#include "papa/features/extractors/papa_native/flirt/flirt_reader.h"

#include <iostream>
#include <utility>

namespace papa::features::extractors::papa_native::flirt {

FlirtSignatureSet FlirtSignatureSet::make_embedded() {
    FlirtSignatureSet set;
    for (const embedded::EmbeddedSig& sig : embedded::registry()) {
        static_cast<void>(set.add_from_buffer({sig.data, sig.size}));
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
