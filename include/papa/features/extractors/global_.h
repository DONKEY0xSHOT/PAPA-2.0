#pragma once

#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"

#include <vector>

namespace papa::features::extractors {

// Emit Os, Arch, and Format features derived from a parsed PE image. Os is always
// "windows" because v1 only handles PE inputs
[[nodiscard]] std::vector<FeatureWithAddress>
extract_global_features(const ::papa::pe::PeImage& image);

}  // namespace papa::features::extractors
