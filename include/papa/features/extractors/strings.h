#pragma once

#include "papa/constants.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace papa::features::extractors::strings {

// One extracted string and its absolute byte offset in the source buffer
struct ExtractedString {
    std::string   value;
    std::uint64_t offset{0};
};

// Walk buf gathering runs of printable ASCII bytes. A "run" is bounded by any non-
// printable byte and must have length >= min_len
[[nodiscard]] std::vector<ExtractedString>
extract_ascii_strings(std::span<const std::byte> buf,
                      std::size_t                min_len =
                          ::papa::constants::kMinStringLength);

// UTF-16LE counterpart that requires (printable_low, 0x00) pairs. The reported offset
// points to the first byte of the run. The value is the decoded UTF-8 form
[[nodiscard]] std::vector<ExtractedString>
extract_unicode_strings(std::span<const std::byte> buf,
                        std::size_t                min_len =
                            ::papa::constants::kMinStringLength);

// True when the kFillCheckSliceSize-sized window centered on offset is filled with a
// single byte from kRepeatFillBytes
[[nodiscard]] bool
is_in_repeat_fill_region(std::span<const std::byte> buf, std::uint64_t offset) noexcept;

}  // namespace papa::features::extractors::strings
