#pragma once

#include "papa/features/extractors/papa_native/cfg.h"

#include <functional>
#include <string>
#include <string_view>

namespace papa::features::extractors::papa_native {

/// True when the given call instruction's resolved target does not return, so flow
/// must not continue past it. An empty oracle treats no call as no-return
using NoReturnOracle = std::function<bool(const DecodedInsn&)>;

/// Port of vivisect's normFileName, forming the library half of an import's
/// libname.funcname identity
[[nodiscard]] std::string norm_file_name(std::string_view filename);

/// True when an import is one of the no-return APIs vivisect seeds for PE workspaces,
/// comparing the joined libname.funcname case-insensitively
[[nodiscard]] bool is_noreturn_api(std::string_view libname,
                                   std::string_view impname);

/// True when the function does not return: a faithful port of vivisect noret.py
/// analyzeFunction's leaf scan
[[nodiscard]] bool function_is_noreturn(const Function&       fn,
                                        const NoReturnOracle& is_noreturn);

}  // namespace papa::features::extractors::papa_native
