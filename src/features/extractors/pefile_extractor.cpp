#include "papa/features/extractors/pefile_extractor.h"

#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/extractors/pefile.h"
#include "papa/features/extractors/papa_native/global_.h"
#include "papa/pe/pe_image.h"

#include <utility>
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
    return features::Address{features::AbsoluteVirtualAddress{image_->image_base()}};
}

std::vector<FeatureWithAddress>
PefileFeatureExtractor::extract_global_features() const {
    std::vector<FeatureWithAddress> out;
    if (image_ == nullptr) { return out; }
    auto globals =
        ::papa::features::extractors::papa_native::extract_global_features(*image_);
    out.reserve(globals.size());
    for (auto& fa : globals) { out.push_back(std::move(fa)); }
    return out;
}

std::vector<FeatureWithAddress>
PefileFeatureExtractor::extract_file_features() const {
    if (image_ == nullptr) { return {}; }
    auto file_features =
        ::papa::features::extractors::pefile::extract_file_features(*image_);
    // Both pefile::FeatureWithAddress and our FeatureWithAddress alias resolve
    // to std::pair<FeaturePtr, Address> so the move is a same-type rebind
    std::vector<FeatureWithAddress> out;
    out.reserve(file_features.size());
    for (auto& fa : file_features) { out.push_back(std::move(fa)); }
    return out;
}

}  // namespace papa::features::extractors
