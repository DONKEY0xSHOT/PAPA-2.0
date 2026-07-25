#include "papa/pe/pe_image.h"

#include "papa/constants.h"
#include "papa/exceptions.h"

#include <algorithm>
#include <cstring>

namespace papa::pe {

Expected<std::span<const std::byte>> PeImage::read_at_file_offset(
    std::uint64_t off, std::size_t n) const {
    if (off > buffer_.size() || n > buffer_.size() - off) {
        return Unexpected{make_error(
            ErrorKind::kOutOfBounds, "file offset out of range")};
    }
    return std::span<const std::byte>(buffer_.data() + off, n);
}

std::optional<std::uint64_t> PeImage::rva_to_file_offset(std::uint64_t rva) const noexcept {
    // RVAs inside the header region map directly
    if (const auto* s = section_containing_rva(rva); s != nullptr) {
        const std::uint64_t delta = rva - s->virtual_address;
        if (delta >= s->raw_size) {
            return std::nullopt;  // zero-fill region
        }
        return std::uint64_t{s->raw_offset} + delta;
    }

    // Headers
    // Section headers start at file offset 0 and span SizeOfHeaders
    if (rva < buffer_.size()) {
        // Only trust this fallback for small RVAs typical of PE headers
        constexpr std::uint64_t kHeaderGuard = 0x1000;
        if (rva < kHeaderGuard) {
            return rva;
        }
    }
    return std::nullopt;
}

std::optional<std::uint64_t> PeImage::file_offset_to_rva(std::uint64_t off) const noexcept {
    for (const auto& s : sections_) {
        if (off >= s.raw_offset && off < std::uint64_t{s.raw_offset} + s.raw_size) {
            return std::uint64_t{s.virtual_address} + (off - s.raw_offset);
        }
    }
    return std::nullopt;
}

Expected<std::span<const std::byte>> PeImage::read_at_rva(
    std::uint64_t rva, std::size_t n) const {
    const auto maybe = rva_to_file_offset(rva);
    if (!maybe.has_value()) {
        return Unexpected{make_error(ErrorKind::kOutOfBounds, "rva not mapped")};
    }
    return read_at_file_offset(*maybe, n);
}

const ParsedSection* PeImage::section_containing_rva(std::uint64_t rva) const noexcept {
    for (const auto& s : sections_) {
        const std::uint64_t end = std::uint64_t{s.virtual_address} +
                                  std::max(s.virtual_size, s.raw_size);
        if (rva >= s.virtual_address && rva < end) {
            return &s;
        }
    }
    return nullptr;
}

std::size_t PeImage::readable_bytes_at_rva(std::uint64_t rva) const noexcept {
    const auto off = rva_to_file_offset(rva);
    if (!off.has_value() || *off >= buffer_.size()) {
        return 0;
    }
    std::size_t avail = buffer_.size() - static_cast<std::size_t>(*off);
    // Mapped data stops at the end of the containing section's raw bytes
    if (const auto* s = section_containing_rva(rva); s != nullptr) {
        const std::uint64_t delta = rva - s->virtual_address;
        if (delta >= s->raw_size) {
            return 0;
        }
        avail = std::min<std::size_t>(
            avail, static_cast<std::size_t>(s->raw_size - delta));
    }
    return avail;
}

bool PeImage::probe_readable(std::uint64_t rva, std::size_t n) const noexcept {
    const auto* s = section_containing_rva(rva);
    if (s == nullptr) {
        return false;
    }
    if ((s->characteristics & constants::kImageScnMemRead) == 0) {
        return false;
    }
    const std::uint64_t end = std::uint64_t{s->virtual_address} +
                              std::max(s->virtual_size, s->raw_size);
    return rva + n <= end;
}

}  // namespace papa::pe
