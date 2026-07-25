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

// color enables capa's cyan styling for an interactive terminal. When false the
// output is plain and byte-identical to capa's redirected output
void render(const ResultDocument& doc, std::ostream& out, Verbosity v, bool color = false);

[[nodiscard]] std::string render_to_string(const ResultDocument& doc, Verbosity v);

}  // namespace papa::render::text
