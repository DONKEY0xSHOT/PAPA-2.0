#pragma once

#include "papa/exceptions.h"
#include "papa/pe/pe_image.h"

#include <cstddef>
#include <filesystem>
#include <vector>

namespace papa::pe {

class PeParser {
public:
    [[nodiscard]] static Expected<PeImage> parse(std::vector<std::byte> buffer);

    [[nodiscard]] static Expected<PeImage> parse_file(const std::filesystem::path& path);
};

}  // namespace papa::pe
