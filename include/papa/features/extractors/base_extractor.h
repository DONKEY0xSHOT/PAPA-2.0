#pragma once

#include "papa/features/address.h"
#include "papa/features/feature.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace papa::features::extractors {

// Pair returned by every per-scope extraction routine
using FeatureWithAddress = std::pair<features::FeaturePtr, features::Address>;

// One opaque handle per scope addr is the public anchor used for match locations and
// rule indexing inner is backend-specific and always nullable
struct FunctionHandle {
    features::Address  addr;
    const void*        inner{nullptr};
};

struct BBHandle {
    features::Address  addr;
    const void*        inner{nullptr};
};

struct InsnHandle {
    features::Address  addr;
    const void*        inner{nullptr};
};

// Abstract base for static (non-running-code) feature extractors
class StaticFeatureExtractor {
public:
    virtual ~StaticFeatureExtractor() = default;

    // Image base or equivalent program-wide anchor address
    // Used by capabilities/* when a feature has no narrower address (e.g. file scope)
    [[nodiscard]] virtual features::Address get_base_address() const = 0;

    // Global features (Os, Arch, Format) flow into every per-scope feature set
    [[nodiscard]] virtual std::vector<FeatureWithAddress>
    extract_global_features() const = 0;

    // File-scope features (imports, exports, sections, file strings, embedded PE)
    [[nodiscard]] virtual std::vector<FeatureWithAddress>
    extract_file_features() const = 0;

    // Iterate functions (skipped when the backend is file-only)
    [[nodiscard]] virtual std::vector<FunctionHandle> get_functions() const = 0;

    // Function-scope characteristics (loop, calls_to/from, recursive, name)
    [[nodiscard]] virtual std::vector<FeatureWithAddress>
    extract_function_features(const FunctionHandle& fh) const = 0;

    // Iterate basic blocks within fh
    [[nodiscard]] virtual std::vector<BBHandle>
    get_basic_blocks(const FunctionHandle& fh) const = 0;

    // Basic-block-scope characteristics (tight_loop, stack_string)
    [[nodiscard]] virtual std::vector<FeatureWithAddress>
    extract_basic_block_features(const FunctionHandle& fh,
                                 const BBHandle&       bbh) const = 0;

    // Iterate instructions within bbh
    [[nodiscard]] virtual std::vector<InsnHandle>
    get_instructions(const FunctionHandle& fh,
                     const BBHandle&       bbh) const = 0;

    // Per-instruction features (api, mnemonic, number, offset, bytes, string,
    // operand[i], property, characteristics, ...)
    [[nodiscard]] virtual std::vector<FeatureWithAddress>
    extract_insn_features(const FunctionHandle& fh,
                          const BBHandle&       bbh,
                          const InsnHandle&     ih) const = 0;

    // Optional hooks for backends that have symbol or signature data
    [[nodiscard]] virtual bool is_library_function(const features::Address& /*addr*/) const {
        return false;
    }
    [[nodiscard]] virtual std::optional<std::string>
    get_function_name(const features::Address& /*addr*/) const {
        return std::nullopt;
    }
};

}  // namespace papa::features::extractors
