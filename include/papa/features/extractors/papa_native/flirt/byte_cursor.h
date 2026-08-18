#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace papa::features::extractors::papa_native::flirt::detail {

/// Bounds-checked forward cursor over a borrowed byte buffer. Every read validates
/// remaining length first and advances the position only on success
class ByteCursor {
public:
    /// Construct a cursor positioned at the start of `buf`
    explicit ByteCursor(std::span<const std::uint8_t> buf) noexcept
        : buf_{buf}, pos_{0} {}

    /// True when at least `n` bytes remain from the current position
    [[nodiscard]] bool remaining(std::size_t n) const noexcept {
        return pos_ + n <= buf_.size();
    }

    /// Current read offset from the start of the buffer
    [[nodiscard]] std::size_t offset() const noexcept { return pos_; }

    /// Read one unsigned byte
    [[nodiscard]] bool read_u8(std::uint8_t& out) noexcept {
        if (!remaining(1)) {
            return false;
        }
        out = buf_[pos_];
        ++pos_;
        return true;
    }

    /// Read a little-endian unsigned 16-bit value
    [[nodiscard]] bool read_u16_le(std::uint16_t& out) noexcept {
        if (!remaining(2)) {
            return false;
        }
        out = static_cast<std::uint16_t>(
            buf_[pos_] | (static_cast<std::uint16_t>(buf_[pos_ + 1]) << 8));
        pos_ += 2;
        return true;
    }

    /// Read a little-endian unsigned 32-bit value
    [[nodiscard]] bool read_u32_le(std::uint32_t& out) noexcept {
        if (!remaining(4)) {
            return false;
        }
        std::uint32_t v = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            v |= static_cast<std::uint32_t>(buf_[pos_ + i]) << (8U * i);
        }
        out = v;
        pos_ += 4;
        return true;
    }

    /// Read a FLAIR variable-length integer in the 0..0x7FFF range
    [[nodiscard]] bool read_vle16(std::uint16_t& out) noexcept {
        if (!remaining(1)) {
            return false;
        }
        const std::uint8_t b0 = buf_[pos_];
        if ((b0 & 0x80U) == 0U) {
            out = b0;
            pos_ += 1;
            return true;
        }
        if (!remaining(2)) {
            return false;
        }
        const std::uint8_t b1 = buf_[pos_ + 1];
        out = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(b0 & 0x7FU) << 8) | b1);
        pos_ += 2;
        return true;
    }

    /// Read a FLAIR variable-length integer of up to 32 bits. The top bits of the lead
    /// byte select a 1, 2, 4, or 5 byte encoding
    [[nodiscard]] bool read_vle32(std::uint32_t& out) noexcept {
        if (!remaining(1)) {
            return false;
        }
        const std::uint8_t b0 = buf_[pos_];
        if ((b0 & 0x80U) != 0x80U) {
            out = b0;
            pos_ += 1;
            return true;
        }
        if ((b0 & 0xC0U) != 0xC0U) {
            if (!remaining(2)) {
                return false;
            }
            const std::uint8_t b1 = buf_[pos_ + 1];
            out = (static_cast<std::uint32_t>(b0 & 0x7FU) << 8)
                  | static_cast<std::uint32_t>(b1);
            pos_ += 2;
            return true;
        }
        if ((b0 & 0xE0U) != 0xE0U) {
            if (!remaining(4)) {
                return false;
            }
            out = (static_cast<std::uint32_t>(b0 & 0x3FU) << 24)
                  | (static_cast<std::uint32_t>(buf_[pos_ + 1]) << 16)
                  | (static_cast<std::uint32_t>(buf_[pos_ + 2]) << 8)
                  | static_cast<std::uint32_t>(buf_[pos_ + 3]);
            pos_ += 4;
            return true;
        }
        if (!remaining(5)) {
            return false;
        }
        out = (static_cast<std::uint32_t>(buf_[pos_ + 1]) << 24)
              | (static_cast<std::uint32_t>(buf_[pos_ + 2]) << 16)
              | (static_cast<std::uint32_t>(buf_[pos_ + 3]) << 8)
              | static_cast<std::uint32_t>(buf_[pos_ + 4]);
        pos_ += 5;
        return true;
    }

    /// Copy `n` bytes into `dst`
    [[nodiscard]] bool read_bytes(std::uint8_t* dst, std::size_t n) noexcept {
        if (!remaining(n)) {
            return false;
        }
        std::memcpy(dst, buf_.data() + pos_, n);
        pos_ += n;
        return true;
    }

    /// Advance the cursor by `n` bytes without reading them
    [[nodiscard]] bool skip(std::size_t n) noexcept {
        if (!remaining(n)) {
            return false;
        }
        pos_ += n;
        return true;
    }

private:
    std::span<const std::uint8_t> buf_;
    std::size_t                   pos_;
};

}  // namespace papa::features::extractors::papa_native::flirt::detail
