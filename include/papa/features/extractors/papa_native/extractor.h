#pragma once

#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/library_signatures.h"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

// Concrete extractor wrapping a built PapaNativeBackend
// Owns the backend by value because every ImportTable, function, and BB pointer
// referenced via opaque handles must remain valid for the lifetime of the
// extractor
// Moving the backend out from under live handles would dangle them
class PapaNativeStaticExtractor : public ::papa::features::extractors::StaticFeatureExtractor {
public:
    explicit PapaNativeStaticExtractor(PapaNativeBackend backend);

    PapaNativeStaticExtractor(PapaNativeStaticExtractor&&) noexcept            = default;
    PapaNativeStaticExtractor& operator=(PapaNativeStaticExtractor&&) noexcept = default;
    PapaNativeStaticExtractor(const PapaNativeStaticExtractor&)                = delete;
    PapaNativeStaticExtractor& operator=(const PapaNativeStaticExtractor&)     = delete;
    ~PapaNativeStaticExtractor() override                                      = default;

    [[nodiscard]] features::Address get_base_address() const override;

    [[nodiscard]] std::vector<::papa::features::extractors::FeatureWithAddress>
    extract_global_features() const override;

    [[nodiscard]] std::vector<::papa::features::extractors::FeatureWithAddress>
    extract_file_features() const override;

    [[nodiscard]] std::vector<::papa::features::extractors::FunctionHandle>
    get_functions() const override;

    [[nodiscard]] std::vector<::papa::features::extractors::FeatureWithAddress>
    extract_function_features(
        const ::papa::features::extractors::FunctionHandle& fh) const override;

    [[nodiscard]] std::vector<::papa::features::extractors::BBHandle>
    get_basic_blocks(
        const ::papa::features::extractors::FunctionHandle& fh) const override;

    [[nodiscard]] std::vector<::papa::features::extractors::FeatureWithAddress>
    extract_basic_block_features(
        const ::papa::features::extractors::FunctionHandle& fh,
        const ::papa::features::extractors::BBHandle&       bbh) const override;

    [[nodiscard]] std::vector<::papa::features::extractors::InsnHandle>
    get_instructions(
        const ::papa::features::extractors::FunctionHandle& fh,
        const ::papa::features::extractors::BBHandle&       bbh) const override;

    [[nodiscard]] std::vector<::papa::features::extractors::FeatureWithAddress>
    extract_insn_features(
        const ::papa::features::extractors::FunctionHandle& fh,
        const ::papa::features::extractors::BBHandle&       bbh,
        const ::papa::features::extractors::InsnHandle&     ih) const override;

    [[nodiscard]] bool is_library_function(
        const features::Address& addr) const override;

    [[nodiscard]] std::optional<std::string> get_function_name(
        const features::Address& addr) const override;

    // Test and orchestrator hook for installing a symbol table after construction
    // Names are typically derived from PE exports plus PDB lookup when available
    void set_function_name(std::uint64_t va, std::string name);

    /// Replace the bundled library-signature table with caller-supplied entries.
    /// Used by tests and by callers that ship their own pattern packs.
    void set_library_signatures(LibrarySignatureSet sigs) noexcept;

    [[nodiscard]] const PapaNativeBackend& backend() const noexcept { return backend_; }

private:
    PapaNativeBackend                                       backend_;
    std::unordered_map<std::uint64_t, std::string>          function_names_;
    LibrarySignatureSet                                     library_sigs_;
};

}  // namespace papa::features::extractors::papa_native
