#pragma once

#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/papa_native/cfg.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::function_ {

using FeatureWithAddress = std::pair<features::FeaturePtr, features::Address>;

// Detect any non-trivial cycle in the function's CFG via Tarjan's SCC
// Returns at most one feature even when the function contains many loops
[[nodiscard]] std::optional<FeatureWithAddress>
extract_loop(const Function& fn);

// Emit Characteristic("calls from") at every direct CALL site in the function
[[nodiscard]] std::vector<FeatureWithAddress>
extract_calls_from(const Function& fn);

// Emit Characteristic("calls to") at every caller VA recorded by CFG recovery
// CFG fills callers/callees during recover() before any feature extraction runs
[[nodiscard]] std::vector<FeatureWithAddress>
extract_calls_to(const Function& fn);

// Detect any direct CALL inside the function that targets the function entry
[[nodiscard]] std::optional<FeatureWithAddress>
extract_recursive_call(const Function& fn);

// Emit FunctionName when a symbol for the function entry is provided
// Names typically come from PE exports or PDB symbols
[[nodiscard]] std::optional<FeatureWithAddress>
extract_function_name(const Function& fn, std::string_view symbol);

// Aggregate every function-scope feature for one function symbol may be empty when no
// name is known
[[nodiscard]] std::vector<FeatureWithAddress>
extract_function_features(const Function& fn, std::string_view symbol);

}  // namespace papa::features::extractors::papa_native::function_
