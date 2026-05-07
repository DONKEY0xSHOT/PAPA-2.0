#pragma once

#include "papa/render/result_document.h"

#include <cstdint>
#include <ostream>
#include <string>

namespace papa::render::text {

enum class Verbosity : std::uint8_t {
    kDefault,
    kVerbose,
    kVverbose,
};

void render(const ResultDocument& doc, std::ostream& out, Verbosity v);

[[nodiscard]] std::string render_to_string(const ResultDocument& doc, Verbosity v);

}  // namespace papa::render::text
