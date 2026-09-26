#pragma once

#include <string>
#include <string_view>

namespace papa::util {

/// The longest literal every match of an ECMAScript pattern must contain, lowercased
/// when icase, or empty when no literal is provably required
[[nodiscard]] std::string required_literal(std::string_view pattern, bool icase);

/// True when haystack contains literal, folding ASCII case when icase
/// A folded literal must already be lowercase
[[nodiscard]] bool contains_literal(std::string_view haystack, std::string_view literal,
                                    bool icase) noexcept;

}  // namespace papa::util
