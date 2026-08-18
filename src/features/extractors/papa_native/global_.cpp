#include "papa/features/extractors/papa_native/global_.h"

#include "papa/constants.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

namespace {

// CAPA spelling for the OS, arch, and format values
constexpr const char* kOsWindowsValue = "windows";
constexpr const char* kFormatPeValue  = "pe";
constexpr const char* kArchI386Value  = "i386";
constexpr const char* kArchAmd64Value = "amd64";

}  // namespace

std::vector<FeatureWithAddress>
extract_global_features(const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    out.reserve(3);

    // Os and Format are unconditional for PE inputs in v1
    out.emplace_back(
        std::make_shared<const features::Os>(std::string(kOsWindowsValue)),
        features::Address{features::NoAddress{}});
    out.emplace_back(
        std::make_shared<const features::Format>(std::string(kFormatPeValue)),
        features::Address{features::NoAddress{}});

    // Arch depends on the machine field. Unsupported architectures are skipped so rules
    // with arch: any continue to match while specific rules remain explicit
    const auto machine = image.machine();
    const char* arch_value = nullptr;
    if (machine == ::papa::constants::kImageFileMachineI386) {
        arch_value = kArchI386Value;
    } else if (machine == ::papa::constants::kImageFileMachineAmd64) {
        arch_value = kArchAmd64Value;
    }
    if (arch_value != nullptr) {
        out.emplace_back(
            std::make_shared<const features::Arch>(std::string(arch_value)),
            features::Address{features::NoAddress{}});
    }
    return out;
}

}  // namespace papa::features::extractors::papa_native
