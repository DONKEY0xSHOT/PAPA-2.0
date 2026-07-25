#pragma once

#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/flirt/flirt_classifier.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace papa::features::extractors::papa_native {

/// Implements the FLIRT classifier's FunctionContext over a recovered backend.
/// This is the single place where FLIRT meets the CFG, the import table, and
/// the image, so the reference-validating classifier stays free of those
/// dependencies. One instance serves a whole classify call and its recursion
class FlirtBackendContext final : public flirt::FunctionContext {
public:
    explicit FlirtBackendContext(const PapaNativeBackend& backend) noexcept;

    [[nodiscard]] std::span<const std::uint8_t>
        code_at(std::uint64_t va, std::size_t max_len) const override;

    [[nodiscard]] std::optional<flirt::FlirtXref>
        xref_from(std::uint64_t site_va) const override;

    [[nodiscard]] std::optional<std::string_view>
        import_name(std::uint64_t va) const override;

    [[nodiscard]] bool is_function_entry(std::uint64_t va) const override;

private:
    const PapaNativeBackend*          backend_;
    // Backing store for the bytes code_at returns. Valid until the next call
    mutable std::vector<std::uint8_t> scratch_;
};

}  // namespace papa::features::extractors::papa_native
