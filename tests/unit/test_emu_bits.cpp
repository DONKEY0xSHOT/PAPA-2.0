#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/bits.h"

#include <cstdint>

namespace bits = papa::features::extractors::papa_native::emu::bits;

// Faithful port of envi/bits.py

TEST_CASE("emu bits: u_max is 2^(8*size)-1 with u_max(0)=0") {
    CHECK(bits::u_max(0) == 0x0ULL);
    CHECK(bits::u_max(1) == 0xFFULL);
    CHECK(bits::u_max(2) == 0xFFFFULL);
    CHECK(bits::u_max(4) == 0xFFFFFFFFULL);
}

TEST_CASE("emu bits: unsigned_ masks a value to its size") {
    CHECK(bits::unsigned_(0xFFFFFFFFFFFFFFFFULL, 4) == 0xFFFFFFFFULL);
    CHECK(bits::unsigned_(0x1FFULL, 1) == 0xFFULL);
    CHECK(bits::unsigned_(0x12345678ULL, 2) == 0x5678ULL);
}

TEST_CASE("emu bits: signed_ interprets the sign bit per size") {
    CHECK(bits::signed_(0xFFULL, 1) == -1);
    CHECK(bits::signed_(0x7FULL, 1) == 127);
    CHECK(bits::signed_(0x80ULL, 1) == -128);
    CHECK(bits::signed_(0xFFFFFFFFULL, 4) == -1);
    CHECK(bits::signed_(0x00000001ULL, 4) == 1);
}

TEST_CASE("emu bits: sign_extend fills with the high bit") {
    CHECK(bits::sign_extend(0xFFULL, 1, 4) == 0xFFFFFFFFULL);
    CHECK(bits::sign_extend(0x7FULL, 1, 4) == 0x7FULL);
    CHECK(bits::sign_extend(0x8000ULL, 2, 4) == 0xFFFF8000ULL);
    CHECK(bits::sign_extend(0x1234ULL, 2, 4) == 0x1234ULL);
}

TEST_CASE("emu bits: is_signed tests the sign bit") {
    CHECK(bits::is_signed(0x80ULL, 1));
    CHECK_FALSE(bits::is_signed(0x7FULL, 1));
    CHECK(bits::is_signed(0xFFFFFFFFULL, 4));
    CHECK_FALSE(bits::is_signed(0x7FFFFFFFULL, 4));
}

TEST_CASE("emu bits: is_unsigned_carry flags over-max and negative results") {
    CHECK(bits::is_unsigned_carry(0x100000000LL, 4));   // > umax
    CHECK(bits::is_unsigned_carry(-1LL, 4));             // < 0
    CHECK_FALSE(bits::is_unsigned_carry(0xFFFFFFFFLL, 4));
    CHECK_FALSE(bits::is_unsigned_carry(0LL, 4));
}

TEST_CASE("emu bits: is_signed_overflow flags results outside [-smax, smax]") {
    // smax(1)=127. vivisect flags value < -smax, so -128 (INT8_MIN) overflows
    CHECK(bits::is_signed_overflow(128LL, 1));
    CHECK(bits::is_signed_overflow(-128LL, 1));
    CHECK_FALSE(bits::is_signed_overflow(127LL, 1));
    CHECK_FALSE(bits::is_signed_overflow(-127LL, 1));
    CHECK(bits::is_signed_overflow(0x80000000LL, 4));   // smax(4)=0x7fffffff
    CHECK_FALSE(bits::is_signed_overflow(0x7FFFFFFFLL, 4));
}

TEST_CASE("emu bits: is_aux_carry on the low nibble of an add") {
    CHECK(bits::is_aux_carry(8, 8));        // 8+8=16 > 15
    CHECK_FALSE(bits::is_aux_carry(1, 1));  // 2
    CHECK(bits::is_aux_carry(0xF, 1));      // 15+1=16
}

TEST_CASE("emu bits: is_aux_carry_sub on the low nibble of a subtract") {
    CHECK(bits::is_aux_carry_sub(5, 3));        // src&0xf > dst&0xf
    CHECK_FALSE(bits::is_aux_carry_sub(3, 5));
    CHECK_FALSE(bits::is_aux_carry_sub(5, 5));
}

TEST_CASE("emu bits: is_parity_byte is even parity over the low 8 bits") {
    CHECK(bits::is_parity_byte(0x00));   // 0 bits, even
    CHECK(bits::is_parity_byte(0xFF));   // 8 bits, even
    CHECK_FALSE(bits::is_parity_byte(0x01));  // 1 bit, odd
    CHECK(bits::is_parity_byte(0x03));   // 2 bits
    CHECK_FALSE(bits::is_parity_byte(0x07));  // 3 bits
    CHECK(bits::is_parity_byte(0x100));  // only low byte counts -> 0x00
}

TEST_CASE("emu bits: msb and lsb") {
    CHECK(bits::msb(0x80ULL, 1));
    CHECK_FALSE(bits::msb(0x7FULL, 1));
    CHECK(bits::msb(0x80000000ULL, 4));
    CHECK(bits::lsb(1));
    CHECK_FALSE(bits::lsb(2));
}

TEST_CASE("emu bits: byteswap reverses byte order per size") {
    CHECK(bits::byteswap(0x11223344ULL, 4) == 0x44332211ULL);
    CHECK(bits::byteswap(0x1122ULL, 2) == 0x2211ULL);
    CHECK(bits::byteswap(0xABULL, 1) == 0xABULL);
}
