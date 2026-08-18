#include "papa/features/extractors/papa_native/flirt/flirt_classifier.h"

#include <optional>
#include <string>
#include <utility>

namespace papa::features::extractors::papa_native::flirt {

namespace {

// Bytes read per function for matching
constexpr std::size_t kMatchWindow     = 0x200;

// Recursion bound on reference chains. Real signature graphs are shallow. The
// cap keeps a crafted, cyclic input from exhausting the stack
constexpr std::size_t kMaxClassifyDepth = 64;

// The name a module assigns at the function entry: the name at offset 0, regardless of
// public or local kind
[[nodiscard]] std::optional<std::string> match_name(const FlirtModule& module) {
    for (const FlirtName& n : module.names) {
        if (n.offset == 0) {
            return n.name;
        }
    }
    return std::nullopt;
}

}  // namespace

FlirtClassifier::FlirtClassifier(ModuleMatchFn matcher,
                                 const FunctionContext& context, Cache& cache,
                                 OnMatch       on_match,
                                 LibraryLookup library_lookup) noexcept
    : matcher_(std::move(matcher)),
      context_(&context),
      cache_(&cache),
      on_match_(std::move(on_match)),
      library_lookup_(std::move(library_lookup)) {}

std::optional<std::string> FlirtClassifier::classify(std::uint64_t va) const {
    return classify_at(va, 0);
}

std::optional<std::string>
FlirtClassifier::classify_at(std::uint64_t va, std::size_t depth) const {
    if (const auto it = cache_->find(va); it != cache_->end()) {
        return it->second;
    }
    if (depth >= kMaxClassifyDepth || !context_->is_function_entry(va)) {
        // Transient negatives (depth cap, not a function) are left uncached so a
        // shallower visit can still resolve the same address
        return std::nullopt;
    }

    // Tentatively cache a negative so a reference cycle back to va terminates
    (*cache_)[va] = std::nullopt;

    const std::span<const std::uint8_t> bytes = context_->code_at(va, kMatchWindow);
    if (bytes.empty()) {
        return std::nullopt;
    }

    std::optional<std::string> result;
    const FlirtModule* winner = nullptr;
    for (const FlirtModule* module : matcher_(bytes)) {
        if (module == nullptr || !references_satisfied(*module, va, depth)) {
            continue;
        }
        auto name = match_name(*module);
        if (!name.has_value()) {
            continue;
        }
        if (!result.has_value()) {
            result = std::move(name);
            winner = module;
        } else if (*result != *name) {
            // Surviving candidates disagree on the name, so the match is
            // ambiguous and confers no identity
            return std::nullopt;
        }
    }

    // A match also names the functions at its other offsets, so a sibling whose own
    // bytes no signature matches is still identified
    if (winner != nullptr) {
        for (const FlirtName& named : winner->names) {
            if (named.offset != 0) {
                (*cache_)[va + static_cast<std::uint64_t>(named.offset)] = named.name;
            }
        }
        if (on_match_) {
            on_match_(va, *winner);
        }
    }

    (*cache_)[va] = result;
    return result;
}

bool FlirtClassifier::references_satisfied(const FlirtModule& module,
                                           std::uint64_t va, std::size_t depth) const {
    for (const FlirtReference& ref : module.references) {
        const std::uint64_t site_va = va + static_cast<std::uint64_t>(ref.offset);
        const std::optional<FlirtXref> xref = context_->xref_from(site_va);
        if (!xref.has_value()) {
            return false;
        }

        // A "." reference asserts a data reference rather than a named call
        if (ref.name == ".") {
            if (xref->is_code) {
                return false;
            }
            continue;
        }
        if (!xref->is_code) {
            return false;
        }

        // capa validates a named reference only against a local function that is itself a
        // matched library function of that name, never an import
        std::optional<std::string> target_name =
            classify_at(xref->target, depth + 1);
        if (library_lookup_) {
            target_name = library_lookup_(xref->target);
        }
        if (!target_name.has_value() || *target_name != ref.name) {
            return false;
        }
    }
    return true;
}

}  // namespace papa::features::extractors::papa_native::flirt
