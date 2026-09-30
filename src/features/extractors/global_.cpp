#include "papa/features/extractors/global_.h"

#include "papa/constants.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace papa::features::extractors {

std::optional<std::string_view> pe_arch(std::uint16_t machine) noexcept {
    if (machine == constants::kImageFileMachineI386)  { return constants::arch_value::kI386; }
    if (machine == constants::kImageFileMachineAmd64) { return constants::arch_value::kAmd64; }
    return std::nullopt;
}

std::vector<FeatureWithAddress>
extract_global_features(const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    out.reserve(3);

    // Os and Format are unconditional for PE inputs in v1
    out.emplace_back(
        std::make_shared<const features::Os>(std::string(constants::os_value::kWindows)),
        features::Address{features::NoAddress{}});
    out.emplace_back(
        std::make_shared<const features::Format>(std::string(constants::format_value::kPe)),
        features::Address{features::NoAddress{}});

    // Arch depends on the machine field, and an unsupported machine emits none, as in capa
    // In capa arch: any matches only a literal Arch("any"), which a PE never produces
    if (const auto arch = pe_arch(image.machine())) {
        out.emplace_back(
            std::make_shared<const features::Arch>(std::string(*arch)),
            features::Address{features::NoAddress{}});
    }
    return out;
}

}  // namespace papa::features::extractors
