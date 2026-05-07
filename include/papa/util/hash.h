#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace papa::util {

// Streaming SHA-256
// Reference: RFC 6234 with the standard 64-byte block, 32-bit words
class Sha256 {
public:
    Sha256() noexcept;

    // Append message bytes
    // May be called any number of times before finalize
    void update(std::span<const std::byte> data) noexcept;

    // Produce the 32-byte digest and reset internal state for reuse
    [[nodiscard]] std::array<std::byte, 32> finalize() noexcept;

    // Reset the hasher without producing a digest
    void reset() noexcept;

private:
    void process_block() noexcept;

    std::array<std::uint32_t, 8>  state_{};
    std::array<std::byte,    64>  buffer_{};
    std::size_t                   buffer_len_{0};
    std::uint64_t                 total_bits_{0};
};

// Streaming SHA-1
// Reference: RFC 3174 with the standard 64-byte block, 32-bit words
// Included for CAPA report-format parity only, not for security uses
class Sha1 {
public:
    Sha1() noexcept;
    void update(std::span<const std::byte> data) noexcept;
    [[nodiscard]] std::array<std::byte, 20> finalize() noexcept;
    void reset() noexcept;

private:
    void process_block() noexcept;

    std::array<std::uint32_t, 5>  state_{};
    std::array<std::byte,    64>  buffer_{};
    std::size_t                   buffer_len_{0};
    std::uint64_t                 total_bits_{0};
};

// Streaming MD5
// Reference: RFC 1321 with the standard 64-byte block, 32-bit words
// Included for CAPA report-format parity only, not for security uses
class Md5 {
public:
    Md5() noexcept;
    void update(std::span<const std::byte> data) noexcept;
    [[nodiscard]] std::array<std::byte, 16> finalize() noexcept;
    void reset() noexcept;

private:
    void process_block() noexcept;

    std::array<std::uint32_t, 4>  state_{};
    std::array<std::byte,    64>  buffer_{};
    std::size_t                   buffer_len_{0};
    std::uint64_t                 total_bits_{0};
};

// One-shot helpers
[[nodiscard]] std::array<std::byte, 32> sha256(std::span<const std::byte> data) noexcept;
[[nodiscard]] std::array<std::byte, 20> sha1  (std::span<const std::byte> data) noexcept;
[[nodiscard]] std::array<std::byte, 16> md5   (std::span<const std::byte> data) noexcept;

// Lower-case hex encoding of a digest
// CAPA emits digests as lowercase hex with no separator, matching what every
// well-known checksum tool produces by default
[[nodiscard]] std::string hex_digest(std::span<const std::byte> digest);

}  // namespace papa::util
