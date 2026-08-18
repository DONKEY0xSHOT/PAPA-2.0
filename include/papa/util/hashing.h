#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

namespace papa::util::hashing {

// Fractional part of the 64-bit golden ratio 2^64 / phi
// Used by hash_combine to scatter nearby payloads, matching boost::hash_combine
inline constexpr std::uint64_t kGoldenRatio64 = 0x9E3779B97F4A7C15ULL;

// Standard FNV-1a 64-bit offset basis from Fowler Noll Vo
inline constexpr std::uint64_t kFnv64OffsetBasis = 0xCBF29CE484222325ULL;

// Standard FNV-1a 64-bit prime
inline constexpr std::uint64_t kFnv64Prime = 0x100000001B3ULL;

// Mix two hash values in the spirit of boost::hash_combine
[[nodiscard]] constexpr std::size_t hash_combine(std::size_t seed,
                                                 std::size_t value) noexcept {
    return seed ^ (value
                   + static_cast<std::size_t>(kGoldenRatio64)
                   + (seed << 6)
                   + (seed >> 2));
}

// FNV-1a over an arbitrary byte range
[[nodiscard]] constexpr std::size_t fnv1a64(std::span<const std::byte> data) noexcept {
    std::uint64_t h = kFnv64OffsetBasis;
    for (std::byte b : data) {
        h ^= static_cast<std::uint64_t>(static_cast<std::uint8_t>(b));
        h *= kFnv64Prime;
    }
    return static_cast<std::size_t>(h);
}

// Type-punned hash of a double so NaNs and 0.0 vs -0.0 hash stably
// Direct std::hash<double> leaves these as implementation-defined
[[nodiscard]] inline std::size_t hash_double_bits(double value) noexcept {
    static_assert(sizeof(double) == sizeof(std::uint64_t),
                  "PAPA assumes IEEE-754 double matches uint64_t width");
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return static_cast<std::size_t>(bits);
}

}  // namespace papa::util::hashing
