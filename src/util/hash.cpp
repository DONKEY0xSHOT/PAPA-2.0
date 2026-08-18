#include "papa/util/hash.h"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

namespace papa::util {

namespace {

// bitwise helpers
[[nodiscard]] constexpr std::uint32_t rotr32(std::uint32_t x, int n) noexcept {
    return std::rotr(x, n);
}

[[nodiscard]] constexpr std::uint32_t rotl32(std::uint32_t x, int n) noexcept {
    return std::rotl(x, n);
}

// Big-endian word read/write used by SHA-1 and SHA-256
[[nodiscard]] constexpr std::uint32_t load_be32(const std::byte* p) noexcept {
    return (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[0])) << 24) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[1])) << 16) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[2])) <<  8) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[3])) <<  0);
}

constexpr void store_be32(std::byte* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::byte>((v >> 24) & 0xFFU);
    p[1] = static_cast<std::byte>((v >> 16) & 0xFFU);
    p[2] = static_cast<std::byte>((v >>  8) & 0xFFU);
    p[3] = static_cast<std::byte>((v >>  0) & 0xFFU);
}

constexpr void store_be64(std::byte* p, std::uint64_t v) noexcept {
    p[0] = static_cast<std::byte>((v >> 56) & 0xFFU);
    p[1] = static_cast<std::byte>((v >> 48) & 0xFFU);
    p[2] = static_cast<std::byte>((v >> 40) & 0xFFU);
    p[3] = static_cast<std::byte>((v >> 32) & 0xFFU);
    p[4] = static_cast<std::byte>((v >> 24) & 0xFFU);
    p[5] = static_cast<std::byte>((v >> 16) & 0xFFU);
    p[6] = static_cast<std::byte>((v >>  8) & 0xFFU);
    p[7] = static_cast<std::byte>((v >>  0) & 0xFFU);
}

// Little-endian word read/write used by MD5
[[nodiscard]] constexpr std::uint32_t load_le32(const std::byte* p) noexcept {
    return (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[0])) <<  0) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[1])) <<  8) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[2])) << 16) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[3])) << 24);
}

constexpr void store_le32(std::byte* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::byte>((v >>  0) & 0xFFU);
    p[1] = static_cast<std::byte>((v >>  8) & 0xFFU);
    p[2] = static_cast<std::byte>((v >> 16) & 0xFFU);
    p[3] = static_cast<std::byte>((v >> 24) & 0xFFU);
}

constexpr void store_le64(std::byte* p, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::byte>((v >> (8 * i)) & 0xFFU);
    }
}

// Generic length-encoded padding helper used by SHA family + MD5 padding_byte is 0x80
// for all three algorithms
template <bool BigEndianLength>
void pad_and_finalize(std::array<std::byte, 64>& buffer,
                      std::size_t&               buffer_len,
                      std::uint64_t              total_bits,
                      auto                       process_block_fn) noexcept {
    // Append the mandatory 0x80 byte
    buffer[buffer_len++] = std::byte{0x80};

    // If there isn't enough room for the 8-byte length, flush this block first
    if (buffer_len > 56) {
        while (buffer_len < 64) {
            buffer[buffer_len++] = std::byte{0x00};
        }
        process_block_fn();
        buffer_len = 0;
    }
    // Zero-pad up to byte 56 of the final block
    while (buffer_len < 56) {
        buffer[buffer_len++] = std::byte{0x00};
    }
    if constexpr (BigEndianLength) {
        store_be64(&buffer[56], total_bits);
    } else {
        store_le64(&buffer[56], total_bits);
    }
    process_block_fn();
}

}  // namespace

// ============================================================================. SHA-256
// ============================================================================

namespace {

// First 32 bits of the fractional parts of the cube roots of the first 64 primes
constexpr std::array<std::uint32_t, 64> kSha256K{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

constexpr std::array<std::uint32_t, 8> kSha256IV{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

}  // namespace

Sha256::Sha256() noexcept { reset(); }

void Sha256::reset() noexcept {
    state_      = kSha256IV;
    buffer_len_ = 0;
    total_bits_ = 0;
}

void Sha256::update(std::span<const std::byte> data) noexcept {
    // Bit-counter overflow would only happen for inputs above 2^61 bytes
    // We accept the overflow silently because such inputs are not realistic
    total_bits_ += static_cast<std::uint64_t>(data.size()) * 8U;

    std::size_t i = 0;
    // Fill any partial buffer
    if (buffer_len_ > 0) {
        const std::size_t need = 64U - buffer_len_;
        const std::size_t take = data.size() < need ? data.size() : need;
        std::memcpy(&buffer_[buffer_len_], data.data(), take);
        buffer_len_ += take;
        i           += take;
        if (buffer_len_ == 64) {
            process_block();
            buffer_len_ = 0;
        }
    }
    // Process full 64-byte chunks directly out of caller memory
    while (i + 64U <= data.size()) {
        std::memcpy(buffer_.data(), data.data() + i, 64U);
        process_block();
        i += 64U;
    }
    // Stash any tail for the next call or finalize
    if (i < data.size()) {
        const std::size_t tail = data.size() - i;
        std::memcpy(buffer_.data(), data.data() + i, tail);
        buffer_len_ = tail;
    }
}

void Sha256::process_block() noexcept {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t t = 0; t < 16; ++t) {
        w[t] = load_be32(&buffer_[t * 4U]);
    }
    for (std::size_t t = 16; t < 64; ++t) {
        const std::uint32_t s0 =
            rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^ (w[t - 15] >> 3);
        const std::uint32_t s1 =
            rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t t = 0; t < 64; ++t) {
        const std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t T1 = h + S1 + ch + kSha256K[t] + w[t];
        const std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t T2 = S0 + mj;
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

std::array<std::byte, 32> Sha256::finalize() noexcept {
    pad_and_finalize<true>(buffer_, buffer_len_, total_bits_,
                           [this] { process_block(); });
    std::array<std::byte, 32> digest{};
    for (std::size_t i = 0; i < 8; ++i) {
        store_be32(&digest[i * 4U], state_[i]);
    }
    reset();
    return digest;
}

// ============================================================================. SHA-1
// ============================================================================

namespace {

constexpr std::array<std::uint32_t, 5> kSha1IV{
    0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U,
};

}  // namespace

Sha1::Sha1() noexcept { reset(); }

void Sha1::reset() noexcept {
    state_      = kSha1IV;
    buffer_len_ = 0;
    total_bits_ = 0;
}

void Sha1::update(std::span<const std::byte> data) noexcept {
    total_bits_ += static_cast<std::uint64_t>(data.size()) * 8U;

    std::size_t i = 0;
    if (buffer_len_ > 0) {
        const std::size_t need = 64U - buffer_len_;
        const std::size_t take = data.size() < need ? data.size() : need;
        std::memcpy(&buffer_[buffer_len_], data.data(), take);
        buffer_len_ += take;
        i           += take;
        if (buffer_len_ == 64) {
            process_block();
            buffer_len_ = 0;
        }
    }
    while (i + 64U <= data.size()) {
        std::memcpy(buffer_.data(), data.data() + i, 64U);
        process_block();
        i += 64U;
    }
    if (i < data.size()) {
        const std::size_t tail = data.size() - i;
        std::memcpy(buffer_.data(), data.data() + i, tail);
        buffer_len_ = tail;
    }
}

void Sha1::process_block() noexcept {
    std::array<std::uint32_t, 80> w{};
    for (std::size_t t = 0; t < 16; ++t) {
        w[t] = load_be32(&buffer_[t * 4U]);
    }
    for (std::size_t t = 16; t < 80; ++t) {
        w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];

    for (std::size_t t = 0; t < 80; ++t) {
        std::uint32_t f = 0;
        std::uint32_t k = 0;
        if (t < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999U;
        } else if (t < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1U;
        } else if (t < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcU;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6U;
        }
        const std::uint32_t temp = rotl32(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }
    state_[0] += a; state_[1] += b; state_[2] += c;
    state_[3] += d; state_[4] += e;
}

std::array<std::byte, 20> Sha1::finalize() noexcept {
    pad_and_finalize<true>(buffer_, buffer_len_, total_bits_,
                           [this] { process_block(); });
    std::array<std::byte, 20> digest{};
    for (std::size_t i = 0; i < 5; ++i) {
        store_be32(&digest[i * 4U], state_[i]);
    }
    reset();
    return digest;
}

// ============================================================================. MD5
// ============================================================================

namespace {

constexpr std::array<std::uint32_t, 64> kMd5K{
    0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU,
    0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
    0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU,
    0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
    0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU,
    0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
    0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU,
    0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
    0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU,
    0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
    0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U,
    0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
    0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U,
    0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
    0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
    0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U,
};

constexpr std::array<std::uint32_t, 64> kMd5R{
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

constexpr std::array<std::uint32_t, 4> kMd5IV{
    0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U,
};

}  // namespace

Md5::Md5() noexcept { reset(); }

void Md5::reset() noexcept {
    state_      = kMd5IV;
    buffer_len_ = 0;
    total_bits_ = 0;
}

void Md5::update(std::span<const std::byte> data) noexcept {
    total_bits_ += static_cast<std::uint64_t>(data.size()) * 8U;

    std::size_t i = 0;
    if (buffer_len_ > 0) {
        const std::size_t need = 64U - buffer_len_;
        const std::size_t take = data.size() < need ? data.size() : need;
        std::memcpy(&buffer_[buffer_len_], data.data(), take);
        buffer_len_ += take;
        i           += take;
        if (buffer_len_ == 64) {
            process_block();
            buffer_len_ = 0;
        }
    }
    while (i + 64U <= data.size()) {
        std::memcpy(buffer_.data(), data.data() + i, 64U);
        process_block();
        i += 64U;
    }
    if (i < data.size()) {
        const std::size_t tail = data.size() - i;
        std::memcpy(buffer_.data(), data.data() + i, tail);
        buffer_len_ = tail;
    }
}

void Md5::process_block() noexcept {
    std::array<std::uint32_t, 16> m{};
    for (std::size_t t = 0; t < 16; ++t) {
        m[t] = load_le32(&buffer_[t * 4U]);
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];

    for (std::size_t i = 0; i < 64; ++i) {
        std::uint32_t f = 0;
        std::size_t   g = 0;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5U * i + 1U) % 16U;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3U * i + 5U) % 16U;
        } else {
            f = c ^ (b | ~d);
            g = (7U * i) % 16U;
        }
        const std::uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + kMd5K[i] + m[g], static_cast<int>(kMd5R[i]));
        a = temp;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
}

std::array<std::byte, 16> Md5::finalize() noexcept {
    pad_and_finalize<false>(buffer_, buffer_len_, total_bits_,
                            [this] { process_block(); });
    std::array<std::byte, 16> digest{};
    for (std::size_t i = 0; i < 4; ++i) {
        store_le32(&digest[i * 4U], state_[i]);
    }
    reset();
    return digest;
}

// ============================================================================

std::array<std::byte, 32> sha256(std::span<const std::byte> data) noexcept {
    Sha256 h;
    h.update(data);
    return h.finalize();
}

std::array<std::byte, 20> sha1(std::span<const std::byte> data) noexcept {
    Sha1 h;
    h.update(data);
    return h.finalize();
}

std::array<std::byte, 16> md5(std::span<const std::byte> data) noexcept {
    Md5 h;
    h.update(data);
    return h.finalize();
}

std::string hex_digest(std::span<const std::byte> digest) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(digest.size() * 2U);
    for (std::size_t i = 0; i < digest.size(); ++i) {
        const auto v = static_cast<std::uint8_t>(digest[i]);
        out[i * 2U]      = kHex[(v >> 4) & 0x0FU];
        out[i * 2U + 1U] = kHex[v & 0x0FU];
    }
    return out;
}

}  // namespace papa::util
