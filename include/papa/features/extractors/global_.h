#pragma once

#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace papa::features::extractors {

// The capa arch name of a PE machine field, which is i386 or amd64, or nullopt for any other
[[nodiscard]] std::optional<std::string_view> pe_arch(std::uint16_t machine) noexcept;

// Emit Os, Arch, and Format features derived from a parsed PE image. Os is always
// "windows" because v1 only handles PE inputs
[[nodiscard]] std::vector<FeatureWithAddress>
extract_global_features(const ::papa::pe::PeImage& image);

}  // namespace papa::features::extractors
