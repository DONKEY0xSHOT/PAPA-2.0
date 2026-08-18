#pragma once

#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/pe/pe_image.h"

#include <utility>
#include <vector>

namespace papa::features::extractors::pefile {

// Pair returned by every extractor: the feature and the location it applies to
using FeatureWithAddress = std::pair<features::FeaturePtr, features::Address>;

// Format("pe") at NoAddress
[[nodiscard]] std::vector<FeatureWithAddress>
extract_file_format(const ::papa::pe::PeImage& image);

// One Section feature per section, located at the section's virtual address
[[nodiscard]] std::vector<FeatureWithAddress>
extract_file_section_names(const ::papa::pe::PeImage& image);

// One or more Import features per import row
// generate_symbols expands each row into its dotted, bare, and AW-stripped forms
[[nodiscard]] std::vector<FeatureWithAddress>
extract_file_import_names(const ::papa::pe::PeImage& image);

// One Export feature per export
[[nodiscard]] std::vector<FeatureWithAddress>
extract_file_export_names(const ::papa::pe::PeImage& image);

// One Characteristic("embedded pe") per carved offset, addressed by file offset
[[nodiscard]] std::vector<FeatureWithAddress>
extract_file_embedded_pe(const ::papa::pe::PeImage& image);

// Every printable ASCII run and UTF-16LE run discovered in the raw buffer
// Each emitted at its FileOffsetAddress
[[nodiscard]] std::vector<FeatureWithAddress>
extract_file_strings(const ::papa::pe::PeImage& image);

// Run every extractor above and concatenate the results
// Order is stable: format, sections, imports, exports, embedded pe, strings
[[nodiscard]] std::vector<FeatureWithAddress>
extract_file_features(const ::papa::pe::PeImage& image);

}  // namespace papa::features::extractors::pefile
