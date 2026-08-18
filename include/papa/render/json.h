#pragma once

#include "papa/render/result_document.h"

#include <ostream>
#include <string>

namespace papa::render::json {

// Stream the document to out pretty=true emits 2-space indented JSON pretty=false emits
// compact output suitable for piping to another tool
void render(const ResultDocument& doc, std::ostream& out, bool pretty);

// Convenience that returns the rendered string
[[nodiscard]] std::string render_to_string(const ResultDocument& doc, bool pretty);

}  // namespace papa::render::json
