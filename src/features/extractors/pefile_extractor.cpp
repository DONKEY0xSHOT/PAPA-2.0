#include "papa/features/extractors/pefile_extractor.h"

#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/extractors/global_.h"
#include "papa/features/extractors/pefile.h"
#include "papa/pe/pe_image.h"

#include <vector>

namespace papa::features::extractors {

PefileFeatureExtractor::PefileFeatureExtractor(const ::papa::pe::PeImage& image) noexcept
    : image_(&image) {}

features::Address PefileFeatureExtractor::get_base_address() const {
    if (image_ == nullptr) {
        // Construction guarantees a non-null image pointer
        throw ::papa::PapaInvariantError(
            "PefileFeatureExtractor used after move or with null image");
    }
    return features::va_address(image_->image_base());
}

std::vector<FeatureWithAddress>
PefileFeatureExtractor::extract_global_features() const {
    if (image_ == nullptr) { return {}; }
    return ::papa::features::extractors::extract_global_features(*image_);
}

std::vector<FeatureWithAddress>
PefileFeatureExtractor::extract_file_features() const {
    if (image_ == nullptr) { return {}; }
    return pefile::extract_file_features(*image_);
}

}  // namespace papa::features::extractors
