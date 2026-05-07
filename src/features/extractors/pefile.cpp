#include "papa/features/extractors/pefile.h"

#include "papa/constants.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/features/extractors/helpers.h"
#include "papa/features/extractors/strings.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace papa::features::extractors::pefile {

namespace {

constexpr const char* kFormatPeValue            = "pe";
constexpr const char* kEmbeddedPeCharacteristic = "embedded pe";
constexpr const char* kForwardedExportChar      = "forwarded export";

[[nodiscard]] features::Address va_addr(std::uint64_t v) {
    return features::Address{features::AbsoluteVirtualAddress{v}};
}

[[nodiscard]] features::Address fo_addr(std::uint64_t v) {
    return features::Address{features::FileOffsetAddress{v}};
}

[[nodiscard]] features::Address no_addr() {
    return features::Address{features::NoAddress{}};
}

}  // namespace

std::vector<FeatureWithAddress>
extract_file_format(const ::papa::pe::PeImage& /*image*/) {
    std::vector<FeatureWithAddress> out;
    out.emplace_back(std::make_shared<const features::Format>(std::string(kFormatPeValue)),
                     no_addr());
    return out;
}

std::vector<FeatureWithAddress>
extract_file_section_names(const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    out.reserve(image.sections().size());
    for (const auto& sec : image.sections()) {
        if (sec.name.empty()) { continue; }
        const std::uint64_t va = image.image_base() + sec.virtual_address;
        out.emplace_back(std::make_shared<const features::Section>(sec.name), va_addr(va));
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_file_import_names(const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    for (const auto& imp : image.imports()) {
        // Build the symbol token
        // Ordinals get the canonical "#<n>" form
        std::string symbol;
        if (imp.by_ordinal) {
            symbol.reserve(2 + 10);
            symbol.push_back('#');
            symbol.append(std::to_string(imp.ordinal));
        } else {
            symbol = imp.name;
        }
        if (symbol.empty()) { continue; }

        for (auto& variant :
             ::papa::features::extractors::helpers::generate_symbols(imp.dll, symbol, true)) {
            out.emplace_back(
                std::make_shared<const features::Import>(std::move(variant)),
                va_addr(imp.iat_va));
        }
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_file_export_names(const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    for (const auto& exp : image.exports()) {
        if (!exp.name.empty()) {
            out.emplace_back(std::make_shared<const features::Export>(exp.name),
                             va_addr(exp.va));
        }
        if (exp.forwarder.has_value()) {
            // Forwarded exports surface twice: once as Characteristic so file rules
            // can detect the pattern, and once as a synthetic Import so symbol-lookup
            // rules continue to match the destination
            out.emplace_back(std::make_shared<const features::Characteristic>(
                                 std::string(kForwardedExportChar)),
                             va_addr(exp.va));
            const std::string normalized =
                ::papa::features::extractors::helpers::reformat_forwarded_export_name(
                    *exp.forwarder);
            out.emplace_back(std::make_shared<const features::Import>(normalized),
                             va_addr(exp.va));
        }
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_file_embedded_pe(const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    const auto positions = ::papa::features::extractors::helpers::carve_pe_files(
        image.raw_buffer());
    out.reserve(positions.size());
    for (const auto pos : positions) {
        // The MZ at offset 0 is always the host image itself
        // Skip it so file-scope rules looking for embedded PEs do not fire on the host
        if (pos == 0U) { continue; }
        out.emplace_back(std::make_shared<const features::Characteristic>(
                             std::string(kEmbeddedPeCharacteristic)),
                         fo_addr(pos));
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_file_strings(const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    const auto buf = image.raw_buffer();
    auto ascii   = ::papa::features::extractors::strings::extract_ascii_strings(buf);
    auto unicode = ::papa::features::extractors::strings::extract_unicode_strings(buf);
    out.reserve(ascii.size() + unicode.size());
    for (auto& s : ascii) {
        out.emplace_back(std::make_shared<const features::String>(std::move(s.value)),
                         fo_addr(s.offset));
    }
    for (auto& s : unicode) {
        out.emplace_back(std::make_shared<const features::String>(std::move(s.value)),
                         fo_addr(s.offset));
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_file_features(const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    auto append = [&out](std::vector<FeatureWithAddress>&& src) {
        out.reserve(out.size() + src.size());
        for (auto& fa : src) { out.push_back(std::move(fa)); }
    };
    append(extract_file_format(image));
    append(extract_file_section_names(image));
    append(extract_file_import_names(image));
    append(extract_file_export_names(image));
    append(extract_file_embedded_pe(image));
    append(extract_file_strings(image));
    return out;
}

}  // namespace papa::features::extractors::pefile
