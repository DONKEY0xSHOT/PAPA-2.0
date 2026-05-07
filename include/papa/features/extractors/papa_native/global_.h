#pragma once

#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"

#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

// One feature plus the address it applies to
// Global features always carry NoAddress because they characterize the image
using FeatureWithAddress = std::pair<features::FeaturePtr, features::Address>;

// Emit Os, Arch, and Format features derived from a parsed PE image
// Os is always "windows" because v1 only handles PE inputs
// Arch maps machine to "i386" or "amd64" and is omitted for unknown machines
// Format is always "pe"
[[nodiscard]] std::vector<FeatureWithAddress>
extract_global_features(const ::papa::pe::PeImage& image);

}  // namespace papa::features::extractors::papa_native
