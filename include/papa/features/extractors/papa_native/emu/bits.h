#pragma once

#include <cstddef>
#include <cstdint>

// Faithful port of envi/bits.py: the bit-twiddling helpers the i386 emulator
// uses for arithmetic and flag computation. Header-only constexpr so the
// opcode handlers can fold them.
//
// Type note: vivisect runs on Python arbitrary-precision ints. The carry and
// overflow predicates here take a signed 64-bit intermediate, which is exact
// for every add/sub/inc/dec/neg/cmp on operands up to 4 bytes (the result of a
// 32-bit add or subtract fits comfortably in int64). That covers all 32-bit
// general-purpose arithmetic, which is what the discovery emulator runs. For
// 8-byte operands the intermediate can saturate; such flags do not steer the
// control flow discovery depends on, and the wide-product overflow used by
// imul/mul is computed at those handlers directly against the 64-bit result.

namespace papa::features::extractors::papa_native::emu::bits {

// 2^(8*size) - 1, with u_max(0) = 0 (matching bits.py u_maxes[0] = 0).
[[nodiscard]] inline constexpr std::uint64_t u_max(std::size_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    if (size >= 8) {
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    return (1ULL << (8U * size)) - 1ULL;
}

// The sign bit mask for a given size, with sign_bit(0) = 0.
[[nodiscard]] inline constexpr std::uint64_t sign_bit(std::size_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    if (size >= 8) {
        return 0x8000000000000000ULL;
    }
    return 1ULL << (8U * size - 1U);
}

// Largest signed magnitude mask (all bits but the sign bit).
[[nodiscard]] inline constexpr std::uint64_t s_max(std::size_t size) noexcept {
    return u_max(size) ^ sign_bit(size);
}

// Mask a value to its size (unsigned).
[[nodiscard]] inline constexpr std::uint64_t
unsigned_(std::uint64_t value, std::size_t size) noexcept {
    return value & u_max(size);
}

// Interpret a value as signed of the given size.
[[nodiscard]] inline constexpr std::int64_t
signed_(std::uint64_t value, std::size_t size) noexcept {
    const std::uint64_t x = unsigned_(value, size);
    if ((x & sign_bit(size)) != 0) {
        // bits.py: x = (x - u_maxes[size]) - 1
        return static_cast<std::int64_t>(x - u_max(size) - 1ULL);
    }
    return static_cast<std::int64_t>(x);
}

// Sign-extend a value from cursize to newsize bytes.
[[nodiscard]] inline constexpr std::uint64_t
sign_extend(std::uint64_t value, std::size_t cursize, std::size_t newsize) noexcept {
    std::uint64_t x = unsigned_(value, cursize);
    if (cursize != newsize && (x & sign_bit(cursize)) != 0) {
        const std::size_t delta = newsize - cursize;
        const std::uint64_t highbits = u_max(delta);
        x |= highbits << (8U * cursize);
    }
    return x;
}

// True if the value's sign bit (for the given size) is set.
[[nodiscard]] inline constexpr bool
is_signed(std::uint64_t value, std::size_t size) noexcept {
    return (unsigned_(value, size) & sign_bit(size)) != 0;
}

// Carry out of an unsigned operation: the result overflowed the size or went
// negative. The intermediate is the (possibly negative) arithmetic result.
[[nodiscard]] inline constexpr bool
is_unsigned_carry(std::int64_t value, std::size_t size) noexcept {
    return value > static_cast<std::int64_t>(u_max(size)) || value < 0;
}

// Signed overflow: the result fell outside [-s_max, s_max]. Faithful to
// vivisect, this flags INT_MIN (value < -s_max) as overflow.
[[nodiscard]] inline constexpr bool
is_signed_overflow(std::int64_t value, std::size_t size) noexcept {
    const std::int64_t smax = static_cast<std::int64_t>(s_max(size));
    return value > smax || value < -smax;
}

// Signed carry helper (bits.py is_signed_carry), used by a few handlers.
[[nodiscard]] inline constexpr bool
is_signed_carry(std::int64_t value, std::size_t size, std::int64_t src) noexcept {
    const std::int64_t smax = static_cast<std::int64_t>(s_max(size));
    if (value > smax && smax > src) {
        return true;
    }
    if (value < -smax && -smax < -src) {
        return true;
    }
    return false;
}

// Auxiliary (BCD) carry out of bit 3 for an add.
[[nodiscard]] inline constexpr bool
is_aux_carry(std::uint64_t src, std::uint64_t dst) noexcept {
    return (dst & 0xFULL) + (src & 0xFULL) > 15ULL;
}

// Auxiliary (BCD) borrow out of bit 3 for a subtract.
[[nodiscard]] inline constexpr bool
is_aux_carry_sub(std::uint64_t src, std::uint64_t dst) noexcept {
    return (src & 0xFULL) > (dst & 0xFULL);
}

// Even parity over the low 8 bits (x86 PF). bits.py is_parity_byte looks only
// at value & 0xff, returning True when the number of set bits is even.
[[nodiscard]] inline constexpr bool is_parity_byte(std::uint64_t value) noexcept {
    std::uint8_t b = static_cast<std::uint8_t>(value & 0xFFULL);
    bool parity = true;  // even parity of zero bits
    while (b != 0) {
        parity = !parity;
        b = static_cast<std::uint8_t>(b & (b - 1U));
    }
    return parity;
}

// Most-significant bit for the given size.
[[nodiscard]] inline constexpr bool
msb(std::uint64_t value, std::size_t size) noexcept {
    return (value & sign_bit(size)) != 0;
}

// Least-significant bit.
[[nodiscard]] inline constexpr bool lsb(std::uint64_t value) noexcept {
    return (value & 1ULL) != 0;
}

// Reverse byte order over the low `size` bytes.
[[nodiscard]] inline constexpr std::uint64_t
byteswap(std::uint64_t value, std::size_t size) noexcept {
    std::uint64_t ret = 0;
    for (std::size_t i = 0; i < size; ++i) {
        ret = (ret << 8) | ((value >> (8U * i)) & 0xFFULL);
    }
    return ret;
}

}  // namespace papa::features::extractors::papa_native::emu::bits
