#pragma once

#include "papa/exceptions.h"
#include "papa/pe/pe_image.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace papa::pe {

/// A DLL name lowercased with a trailing .dll, .drv or .so extension removed
[[nodiscard]] std::string normalize_dll_name(std::string_view dll);

class PeParser {
public:
    [[nodiscard]] static Expected<PeImage> parse(std::vector<std::byte> buffer);

    [[nodiscard]] static Expected<PeImage> parse_file(const std::filesystem::path& path);
};

}  // namespace papa::pe
