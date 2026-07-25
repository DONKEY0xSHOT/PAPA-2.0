#pragma once

#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

/// A code or data reference emitted by an instruction, as the classifier needs
/// it. is_code distinguishes a call/jump target from a data pointer, mirroring
/// vivisect's REF_CODE / REF_DATA
struct FlirtXref {
    std::uint64_t target {0};
    bool          is_code{true};
};

/// The minimal view of the analyzed program the reference-validating classifier
/// needs. Implemented by the backend so FLIRT stays decoupled from the CFG, PE,
/// and disassembler types. Every method is a pure query
class FunctionContext {
public:
    FunctionContext()                                  = default;
    FunctionContext(const FunctionContext&)            = default;
    FunctionContext& operator=(const FunctionContext&) = default;
    FunctionContext(FunctionContext&&)                 = default;
    FunctionContext& operator=(FunctionContext&&)      = default;
    virtual ~FunctionContext()                         = default;

    /// Up to max_len code bytes at function entry va, for signature matching.
    /// Returns an empty span when va is not readable code
    [[nodiscard]] virtual std::span<const std::uint8_t>
        code_at(std::uint64_t va, std::size_t max_len) const = 0;

    /// The reference emitted by the instruction that contains site_va, if any.
    /// A call or jump yields a code reference. A data pointer yields a data one
    [[nodiscard]] virtual std::optional<FlirtXref>
        xref_from(std::uint64_t site_va) const = 0;

    /// A name already known for va without signature matching, namely an
    /// imported symbol. nullopt when va is not a known import
    [[nodiscard]] virtual std::optional<std::string_view>
        import_name(std::uint64_t va) const = 0;

    /// True when va is a recovered function entry, so recursion into it is
    /// meaningful
    [[nodiscard]] virtual bool is_function_entry(std::uint64_t va) const = 0;
};

/// Matches function bytes to the candidate leaf modules under all loaded
/// signatures. FlirtSignatureSet supplies the production implementation. Tests
/// supply a stub. The returned pointers must outlive every classify call
using ModuleMatchFn =
    std::function<std::vector<const FlirtModule*>(std::span<const std::uint8_t>)>;

/// Decides whether the function at a virtual address is a FLIRT library
/// function, returning its assigned name when so. This is a faithful port of
/// viv_utils.flirt.match_function_flirt_signatures: a pattern and tail CRC
/// candidate is accepted only when each of its referenced functions resolves to
/// a library function of the named identity, and candidates whose names disagree
/// reject the match as ambiguous. The assigned name is the module's offset-0
/// symbol of any kind, public or local. Results are memoized, so one instance
/// should serve a whole image
class FlirtClassifier {
public:
    /// Virtual address to resolved library name (or absent when not a library
    /// function). Owned by the caller so memoization persists across the many
    /// per-function classify calls an image makes
    using Cache = std::unordered_map<std::uint64_t, std::optional<std::string>>;

    /// Called when a candidate is accepted for va, with the module that won. The
    /// driver applies viv_utils.flirt's name loops from it: a local name creates
    /// its function when undefined, and both local and public names mark their
    /// address a library function. Left empty when only the name is wanted
    using OnMatch =
        std::function<void(std::uint64_t va, const FlirtModule& winner)>;

    /// The library name the workspace already holds for an address, from any
    /// signature that ran before. viv_utils.flirt satisfies a reference by
    /// reading this after recursing, so a name an earlier signature file assigned
    /// still counts. Without it the classifier falls back to its own result
    using LibraryLookup =
        std::function<std::optional<std::string>(std::uint64_t va)>;

    FlirtClassifier(ModuleMatchFn matcher, const FunctionContext& context,
                    Cache& cache, OnMatch on_match = {},
                    LibraryLookup library_lookup = {}) noexcept;

    /// The library name for the function at va, or nullopt when it is not a
    /// recognized library function
    [[nodiscard]] std::optional<std::string> classify(std::uint64_t va) const;

private:
    [[nodiscard]] std::optional<std::string>
        classify_at(std::uint64_t va, std::size_t depth) const;
    [[nodiscard]] bool references_satisfied(const FlirtModule& module,
                                            std::uint64_t va, std::size_t depth) const;

    ModuleMatchFn          matcher_;
    const FunctionContext* context_;
    Cache*                 cache_;
    OnMatch                on_match_;
    LibraryLookup          library_lookup_;
};

}  // namespace papa::features::extractors::papa_native::flirt
