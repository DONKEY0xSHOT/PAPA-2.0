#pragma once

#include "papa/features/extractors/papa_native/cfg.h"

#include <functional>
#include <string>
#include <string_view>

namespace papa::features::extractors::papa_native {

/// Predicate: true when the given call instruction's resolved target does not
/// return, so code flow must not continue past it. Mirrors vivisect's
/// isNoReturnVa pruning, the IF_NOFALL bit set after a call to an exit or abort
/// style function. An empty oracle treats no call as no-return
using NoReturnOracle = std::function<bool(const DecodedInsn&)>;

/// Port of vivisect's normFileName: take the basename, lowercase it, strip the
/// final extension (joining any earlier dotted parts with '_'), then replace
/// every character outside [a-z0-9_] with '_'. This is how vivisect forms the
/// library half of an import's "libname.funcname" identity
[[nodiscard]] std::string norm_file_name(std::string_view filename);

/// True when an import is one of the no-return APIs vivisect seeds for PE
/// workspaces (the exit/abort/throw family in parsers/pe.py). libname is the
/// raw imported DLL name and impname the raw imported symbol. The match mirrors
/// vivisect: the library is normalized with norm_file_name, the symbol is left
/// as-is, and the joined "libname.funcname" is compared case-insensitively
/// against the seeded exact names and regexes
[[nodiscard]] bool is_noreturn_api(std::string_view libname,
                                   std::string_view impname);

/// True when the function does not return: a faithful port of vivisect
/// noret.py analyzeFunction's leaf scan. Among the terminal basic blocks (no
/// intra-function successors), a leaf ending in a ret or a dynamic branch is a
/// possible return, while a leaf ending in a call the oracle flags as no-return
/// does not count. With no returning leaf, the function is no-return. is_noreturn
/// recognizes a leaf's terminating no-return call (imports plus any function
/// already proven no-return by the fixpoint)
[[nodiscard]] bool function_is_noreturn(const Function&       fn,
                                        const NoReturnOracle& is_noreturn);

}  // namespace papa::features::extractors::papa_native
