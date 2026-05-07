#include "papa/features/extractors/helpers.h"

#include "papa/constants.h"
#include "papa/util/string_utils.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace papa::features::extractors::helpers {

namespace {

// Read four little-endian bytes from buf starting at offset
// Caller is responsible for the bounds check
[[nodiscard]] std::uint32_t
read_le_u32(std::span<const std::byte> buf, std::uint64_t offset) noexcept {
    const std::uint8_t b0 = static_cast<std::uint8_t>(buf[offset]);
    const std::uint8_t b1 = static_cast<std::uint8_t>(buf[offset + 1U]);
    const std::uint8_t b2 = static_cast<std::uint8_t>(buf[offset + 2U]);
    const std::uint8_t b3 = static_cast<std::uint8_t>(buf[offset + 3U]);
    return static_cast<std::uint32_t>(b0) |
           (static_cast<std::uint32_t>(b1) << 8U) |
           (static_cast<std::uint32_t>(b2) << 16U) |
           (static_cast<std::uint32_t>(b3) << 24U);
}

// XOR every byte of value with the same single-byte key
[[nodiscard]] std::uint32_t xor_u32_key8(std::uint32_t value, std::uint8_t key) noexcept {
    const std::uint32_t k = static_cast<std::uint32_t>(key);
    const std::uint32_t mask =
        k | (k << 8U) | (k << 16U) | (k << 24U);
    return value ^ mask;
}

constexpr std::size_t kPeBigramSize  = 2;
constexpr std::size_t kPeLfanewSize  = 4;
constexpr std::size_t kPeSigSize     = 4;
constexpr std::uint8_t kAsciiM       = 'M';
constexpr std::uint8_t kAsciiZ       = 'Z';

}  // namespace

std::string normalize_dll_name(std::string_view dll) {
    std::string lower = ::papa::util::to_lower_ascii(dll);
    for (const auto ext : ::papa::constants::kDllExtensions) {
        if (::papa::util::ends_with(lower, ext)) {
            lower.resize(lower.size() - ext.size());
            return lower;
        }
    }
    return lower;
}

std::optional<std::string_view> strip_aw_suffix(std::string_view symbol) {
    if (symbol.size() < 2) { return std::nullopt; }
    const char last = symbol.back();
    if (last != 'A' && last != 'W') { return std::nullopt; }
    return symbol.substr(0, symbol.size() - 1);
}

std::vector<std::string>
generate_symbols(std::string_view dll, std::string_view symbol, bool include_dll) {
    std::vector<std::string> out;

    // By-ordinal imports start with '#' and have no A/W variants
    if (!symbol.empty() && symbol.front() == '#') {
        if (include_dll) {
            std::string s;
            s.reserve(dll.size() + 1U + symbol.size());
            s.append(dll);
            s.push_back('.');
            s.append(symbol);
            out.push_back(std::move(s));
        }
        out.emplace_back(symbol);
        return out;
    }

    if (include_dll) {
        std::string s;
        s.reserve(dll.size() + 1U + symbol.size());
        s.append(dll);
        s.push_back('.');
        s.append(symbol);
        out.push_back(std::move(s));
    }
    out.emplace_back(symbol);

    if (auto base = strip_aw_suffix(symbol); base.has_value() && !base->empty()) {
        if (include_dll) {
            std::string s;
            s.reserve(dll.size() + 1U + base->size());
            s.append(dll);
            s.push_back('.');
            s.append(*base);
            out.push_back(std::move(s));
        }
        out.emplace_back(*base);
    }
    return out;
}

std::string reformat_forwarded_export_name(std::string_view forwarder) {
    const auto dot = forwarder.rfind('.');
    if (dot == std::string_view::npos) {
        return std::string(forwarder);
    }
    const auto module_part = forwarder.substr(0, dot);
    const auto symbol_part = forwarder.substr(dot + 1U);

    std::string out;
    out.reserve(forwarder.size());
    out.append(::papa::util::to_lower_ascii(module_part));
    out.push_back('.');
    out.append(symbol_part);
    return out;
}

std::vector<std::uint64_t>
carve_pe_files(std::span<const std::byte> buf) {
    std::vector<std::uint64_t> out;
    if (buf.size() < ::papa::constants::kImageDosEofLfanewOffset + kPeLfanewSize) {
        return out;
    }

    constexpr std::size_t kKeyCount = 256;
    for (std::size_t key_value = 0; key_value < kKeyCount; ++key_value) {
        const auto key = static_cast<std::uint8_t>(key_value);
        const std::uint8_t needle_lo = kAsciiM ^ key;
        const std::uint8_t needle_hi = kAsciiZ ^ key;

        for (std::uint64_t pos = 0;
             pos + kPeBigramSize <= buf.size(); ++pos) {
            if (static_cast<std::uint8_t>(buf[pos])     != needle_lo) { continue; }
            if (static_cast<std::uint8_t>(buf[pos + 1U]) != needle_hi) { continue; }

            const std::uint64_t lfanew_off = pos + ::papa::constants::kImageDosEofLfanewOffset;
            if (lfanew_off + kPeLfanewSize > buf.size()) { continue; }

            const std::uint32_t lfanew_raw = read_le_u32(buf, lfanew_off);
            const std::uint32_t lfanew     = xor_u32_key8(lfanew_raw, key);

            const std::uint64_t sig_off = pos + lfanew;
            if (sig_off + kPeSigSize > buf.size()) { continue; }

            const std::uint32_t sig_raw = read_le_u32(buf, sig_off);
            const std::uint32_t sig     = xor_u32_key8(sig_raw, key);

            if (sig == ::papa::constants::kImageNtSignature) {
                out.push_back(pos);
            }
        }
    }

    // Multiple keys may report the same position when the byte values coincide
    // Sort and de-duplicate to keep callers' assumptions about ordering simple
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

}  // namespace papa::features::extractors::helpers
