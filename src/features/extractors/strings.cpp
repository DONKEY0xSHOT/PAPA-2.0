#include "papa/features/extractors/strings.h"

#include "papa/constants.h"
#include "papa/util/string_utils.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace papa::features::extractors::strings {

namespace {

// Half-window each side of offset
// CAPA centers the slice and clamps to buf
constexpr std::size_t kHalfWindow = ::papa::constants::kFillCheckSliceSize / 2U;

// True when every byte in the half-open range [start, end) equals fill
[[nodiscard]] bool
range_is_all(std::span<const std::byte> buf,
             std::size_t                start,
             std::size_t                end,
             std::uint8_t               fill) noexcept {
    for (std::size_t i = start; i < end; ++i) {
        if (static_cast<std::uint8_t>(buf[i]) != fill) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool is_in_repeat_fill_region(std::span<const std::byte> buf,
                              std::uint64_t              offset) noexcept {
    if (buf.empty()) { return false; }
    if (offset >= buf.size()) { return false; }

    const std::size_t off_sz = static_cast<std::size_t>(offset);
    const std::size_t start  = (off_sz > kHalfWindow) ? (off_sz - kHalfWindow) : 0U;
    const std::size_t end    = std::min(buf.size(), off_sz + kHalfWindow);
    if (start == end) { return false; }

    for (std::uint8_t fill : ::papa::constants::kRepeatFillBytes) {
        if (range_is_all(buf, start, end, fill)) { return true; }
    }
    return false;
}

std::vector<ExtractedString>
extract_ascii_strings(std::span<const std::byte> buf, std::size_t min_len) {
    std::vector<ExtractedString> out;
    if (buf.empty() || min_len == 0) { return out; }

    std::size_t run_start = 0;
    bool        in_run    = false;

    for (std::size_t i = 0; i < buf.size(); ++i) {
        const auto byte_val = static_cast<std::uint8_t>(buf[i]);
        const bool printable = ::papa::util::is_ascii_printable(byte_val);

        if (printable) {
            if (!in_run) {
                run_start = i;
                in_run    = true;
            }
            continue;
        }

        if (in_run) {
            const std::size_t run_len = i - run_start;
            if (run_len >= min_len &&
                !is_in_repeat_fill_region(buf, run_start)) {
                ExtractedString s;
                s.value.reserve(run_len);
                for (std::size_t k = 0; k < run_len; ++k) {
                    s.value.push_back(static_cast<char>(buf[run_start + k]));
                }
                s.offset = run_start;
                out.push_back(std::move(s));
            }
            in_run = false;
        }
    }

    // Trailing run that extends to end-of-buffer
    if (in_run) {
        const std::size_t run_len = buf.size() - run_start;
        if (run_len >= min_len &&
            !is_in_repeat_fill_region(buf, run_start)) {
            ExtractedString s;
            s.value.reserve(run_len);
            for (std::size_t k = 0; k < run_len; ++k) {
                s.value.push_back(static_cast<char>(buf[run_start + k]));
            }
            s.offset = run_start;
            out.push_back(std::move(s));
        }
    }
    return out;
}

std::vector<ExtractedString>
extract_unicode_strings(std::span<const std::byte> buf, std::size_t min_len) {
    std::vector<ExtractedString> out;
    if (buf.size() < 2U || min_len == 0) { return out; }

    std::size_t run_start  = 0;       // byte offset of the first code unit
    std::size_t run_units  = 0;       // count of (lo, 0x00) pairs in the run
    bool        in_run     = false;

    auto flush = [&](std::size_t end_byte) {
        if (run_units >= min_len &&
            !is_in_repeat_fill_region(buf, run_start)) {
            ExtractedString s;
            s.value.reserve(run_units);
            for (std::size_t k = 0; k < run_units; ++k) {
                s.value.push_back(
                    static_cast<char>(buf[run_start + (k * 2U)]));
            }
            s.offset = run_start;
            out.push_back(std::move(s));
        }
        in_run    = false;
        run_units = 0;
        (void)end_byte;
    };

    for (std::size_t i = 0; i + 1U < buf.size(); i += 2U) {
        const auto low  = static_cast<std::uint8_t>(buf[i]);
        const auto high = static_cast<std::uint8_t>(buf[i + 1U]);
        const bool ok   = (high == 0U) && ::papa::util::is_ascii_printable(low);

        if (ok) {
            if (!in_run) {
                run_start = i;
                in_run    = true;
                run_units = 0;
            }
            ++run_units;
            continue;
        }
        if (in_run) { flush(i); }
    }
    if (in_run) { flush(buf.size()); }
    return out;
}

}  // namespace papa::features::extractors::strings
