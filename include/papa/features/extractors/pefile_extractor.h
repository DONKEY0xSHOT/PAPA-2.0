#pragma once

#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/pe/pe_image.h"

#include <optional>
#include <string>
#include <vector>

namespace papa::features::extractors {

// Lightweight extractor that only emits global and file-scope features
// All per-function/BB/instruction methods return empty vectors so orchestrators
// can run the same loop against either backend without conditionals
class PefileFeatureExtractor : public StaticFeatureExtractor {
public:
    // The PeImage must outlive the extractor (no copy is made)
    explicit PefileFeatureExtractor(const ::papa::pe::PeImage& image) noexcept;

    [[nodiscard]] features::Address get_base_address() const override;
    [[nodiscard]] std::vector<FeatureWithAddress> extract_global_features() const override;
    [[nodiscard]] std::vector<FeatureWithAddress> extract_file_features()   const override;

    [[nodiscard]] std::vector<FunctionHandle> get_functions() const override {
        return {};
    }
    [[nodiscard]] std::vector<FeatureWithAddress>
    extract_function_features(const FunctionHandle&) const override { return {}; }

    [[nodiscard]] std::vector<BBHandle>
    get_basic_blocks(const FunctionHandle&) const override { return {}; }

    [[nodiscard]] std::vector<FeatureWithAddress>
    extract_basic_block_features(const FunctionHandle&, const BBHandle&) const override {
        return {};
    }

    [[nodiscard]] std::vector<InsnHandle>
    get_instructions(const FunctionHandle&, const BBHandle&) const override {
        return {};
    }

    [[nodiscard]] std::vector<FeatureWithAddress>
    extract_insn_features(const FunctionHandle&, const BBHandle&, const InsnHandle&) const override {
        return {};
    }

private:
    const ::papa::pe::PeImage* image_;
};

}  // namespace papa::features::extractors
