#pragma once

#include "papa/exceptions.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace papa::pe {

struct ParsedSection {
    std::string   name;
    std::uint32_t virtual_address;
    std::uint32_t virtual_size;
    std::uint32_t raw_offset;
    std::uint32_t raw_size;
    std::uint32_t characteristics;
};

struct ParsedImport {
    std::string   dll;          // lowercased, extension stripped
    std::string   name;         // empty iff imported by ordinal
    std::uint32_t ordinal{0};
    std::uint64_t iat_va{0};    // absolute VA of the IAT slot
    bool          by_ordinal{false};
    bool          delayed{false};
};

struct ParsedExport {
    std::string                name;
    std::uint32_t              ordinal;
    std::uint64_t              va;
    std::optional<std::string> forwarder;
};

struct ParsedRelocation {
    std::uint32_t rva;   // RVA of the relocation site (page RVA + entry offset)
    std::uint16_t type;  // IMAGE_REL_BASED_* type, e.g. 3 HIGHLOW, 10 DIR64, 0 ABSOLUTE
};

class PeParser;  // friend

class PeImage {
public:
    [[nodiscard]] std::uint16_t machine() const noexcept         { return machine_; }
    [[nodiscard]] std::uint64_t image_base() const noexcept      { return image_base_; }
    [[nodiscard]] std::uint32_t entry_point_rva() const noexcept { return entry_point_rva_; }
    [[nodiscard]] std::uint32_t size_of_image() const noexcept   { return size_of_image_; }
    [[nodiscard]] bool          is_64bit() const noexcept        { return is_64bit_; }

    [[nodiscard]] std::span<const std::byte>          raw_buffer() const noexcept { return buffer_; }
    [[nodiscard]] std::span<const ParsedSection>      sections()   const noexcept { return sections_; }
    [[nodiscard]] std::span<const ParsedImport>       imports()    const noexcept { return imports_; }
    [[nodiscard]] std::span<const ParsedExport>       exports()    const noexcept { return exports_; }
    [[nodiscard]] std::span<const std::uint64_t>      tls_callbacks_va() const noexcept {
        return tls_callbacks_;
    }
    [[nodiscard]] std::span<const ParsedRelocation>   relocations() const noexcept {
        return relocations_;
    }

    [[nodiscard]] Expected<std::span<const std::byte>>
        read_at_rva(std::uint64_t rva, std::size_t n) const;

    [[nodiscard]] Expected<std::span<const std::byte>>
        read_at_file_offset(std::uint64_t off, std::size_t n) const;

    [[nodiscard]] const ParsedSection* section_containing_rva(std::uint64_t rva) const noexcept;

    [[nodiscard]] std::optional<std::uint64_t> rva_to_file_offset(std::uint64_t rva) const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_rva(std::uint64_t off) const noexcept;

    [[nodiscard]] bool probe_readable(std::uint64_t rva, std::size_t n) const noexcept;

private:
    friend class PeParser;
    PeImage() = default;

    std::vector<std::byte>     buffer_;
    std::uint16_t              machine_{0};
    std::uint64_t              image_base_{0};
    std::uint32_t              entry_point_rva_{0};
    std::uint32_t              size_of_image_{0};
    bool                       is_64bit_{false};
    std::vector<ParsedSection>    sections_;
    std::vector<ParsedImport>     imports_;
    std::vector<ParsedExport>     exports_;
    std::vector<std::uint64_t>    tls_callbacks_;
    std::vector<ParsedRelocation> relocations_;
};

}  // namespace papa::pe
