#pragma once

// Builds valid PE images in memory so the test suite never needs a real executable
// on disk. The images are small but structurally genuine

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace papa_tests {

/// One imported DLL and the function names taken from it
struct ImportSpec {
    std::string              dll;
    std::vector<std::string> functions;
};

/// One exported function, named, pointing at an offset into the code section
struct ExportSpec {
    std::string   name;
    std::uint32_t code_offset{0};
};

/// A synthetic PE image. Set the fields, call build(), get a byte buffer that
/// papa::pe::PeParser::parse accepts
class PeBuilder {
public:
    static constexpr std::uint32_t kSectionAlign = 0x1000;
    static constexpr std::uint32_t kFileAlign    = 0x200;
    static constexpr std::uint32_t kTextRva      = 0x1000;
    static constexpr std::uint32_t kRdataRva     = 0x2000;
    static constexpr std::uint32_t kPdataRva     = 0x3000;
    static constexpr std::uint32_t kRelocRva     = 0x4000;

    bool          x64{true};
    std::uint64_t image_base{0};  // 0 selects the usual default for the bitness
    // Machine code placed at kTextRva. The entry point is its first byte
    std::vector<std::uint8_t> code;
    std::vector<ImportSpec>   imports;
    std::vector<ExportSpec>   exports;
    // Code offsets whose 4 or 8 byte slot holds an absolute address to relocate
    std::vector<std::uint32_t> reloc_code_offsets;
    // (begin, end) code offsets forming x64 .pdata RUNTIME_FUNCTION records
    std::vector<std::pair<std::uint32_t, std::uint32_t>> pdata_functions;
    // Code offsets of TLS callback routines
    std::vector<std::uint32_t> tls_callbacks;

    [[nodiscard]] std::uint64_t base() const noexcept {
        if (image_base != 0) {
            return image_base;
        }
        return x64 ? 0x140000000ULL : 0x400000ULL;
    }

    [[nodiscard]] std::vector<std::byte> build() const;

private:
    struct Blob {
        std::vector<std::uint8_t> bytes;
        std::uint32_t             rva{0};

        template <typename T>
        void put(const T& value) {
            const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
            bytes.insert(bytes.end(), p, p + sizeof(T));
        }
        void put_bytes(const void* p, std::size_t n) {
            const auto* b = static_cast<const std::uint8_t*>(p);
            bytes.insert(bytes.end(), b, b + n);
        }
        void pad_to(std::size_t n) {
            if (bytes.size() < n) {
                bytes.resize(n, 0);
            }
        }
        [[nodiscard]] std::uint32_t here() const noexcept {
            return rva + static_cast<std::uint32_t>(bytes.size());
        }
    };
};

namespace detail {

inline std::uint32_t align_up(std::uint32_t v, std::uint32_t a) noexcept {
    return (v + a - 1U) / a * a;
}

// Writes a little-endian scalar into a buffer at a byte offset
template <typename T>
void poke(std::vector<std::uint8_t>& buf, std::size_t off, T value) {
    std::memcpy(buf.data() + off, &value, sizeof(T));
}

}  // namespace detail

inline std::vector<std::byte> PeBuilder::build() const {
    using detail::align_up;
    using detail::poke;

    // .rdata holds the import and export directories
    Blob rdata;
    rdata.rva = kRdataRva;

    // Import directory: descriptors, then per-DLL lookup and address tables,
    // then the name strings
    const std::uint32_t import_dir_rva = rdata.here();
    const std::size_t   descriptor_count = imports.size() + 1U;
    rdata.bytes.resize(rdata.bytes.size() + descriptor_count * 20U, 0);

    const std::uint32_t thunk_size = x64 ? 8U : 4U;
    std::vector<std::uint32_t> ilt_rvas;
    std::vector<std::uint32_t> iat_rvas;
    std::vector<std::uint32_t> dll_name_rvas;
    std::vector<std::vector<std::uint32_t>> hint_name_rvas;

    for (const ImportSpec& imp : imports) {
        std::vector<std::uint32_t> names;
        for (const std::string& fn : imp.functions) {
            names.push_back(rdata.here());
            const std::uint16_t hint = 0;
            rdata.put(hint);
            rdata.put_bytes(fn.data(), fn.size() + 1U);
            if (rdata.bytes.size() % 2U != 0U) {
                rdata.bytes.push_back(0);  // keep the next hint aligned
            }
        }
        hint_name_rvas.push_back(std::move(names));

        dll_name_rvas.push_back(rdata.here());
        rdata.put_bytes(imp.dll.data(), imp.dll.size() + 1U);
        if (rdata.bytes.size() % 2U != 0U) {
            rdata.bytes.push_back(0);
        }
    }

    for (std::size_t i = 0; i < imports.size(); ++i) {
        ilt_rvas.push_back(rdata.here());
        for (const std::uint32_t name_rva : hint_name_rvas[i]) {
            if (x64) {
                rdata.put(std::uint64_t{name_rva});
            } else {
                rdata.put(std::uint32_t{name_rva});
            }
        }
        rdata.bytes.insert(rdata.bytes.end(), thunk_size, 0);  // terminator
    }
    for (std::size_t i = 0; i < imports.size(); ++i) {
        iat_rvas.push_back(rdata.here());
        for (const std::uint32_t name_rva : hint_name_rvas[i]) {
            if (x64) {
                rdata.put(std::uint64_t{name_rva});
            } else {
                rdata.put(std::uint32_t{name_rva});
            }
        }
        rdata.bytes.insert(rdata.bytes.end(), thunk_size, 0);
    }

    for (std::size_t i = 0; i < imports.size(); ++i) {
        const std::size_t at = static_cast<std::size_t>(import_dir_rva - rdata.rva) + i * 20U;
        poke<std::uint32_t>(rdata.bytes, at + 0U,  ilt_rvas[i]);
        poke<std::uint32_t>(rdata.bytes, at + 12U, dll_name_rvas[i]);
        poke<std::uint32_t>(rdata.bytes, at + 16U, iat_rvas[i]);
    }

    // Export directory
    std::uint32_t export_dir_rva  = 0;
    std::uint32_t export_dir_size = 0;
    if (!exports.empty()) {
        std::vector<std::uint32_t> name_rvas;
        for (const ExportSpec& e : exports) {
            name_rvas.push_back(rdata.here());
            rdata.put_bytes(e.name.data(), e.name.size() + 1U);
        }
        const std::uint32_t module_name_rva = rdata.here();
        const std::string   module_name     = "synthetic.exe";
        rdata.put_bytes(module_name.data(), module_name.size() + 1U);
        while (rdata.bytes.size() % 4U != 0U) {
            rdata.bytes.push_back(0);
        }

        const std::uint32_t functions_rva = rdata.here();
        for (const ExportSpec& e : exports) {
            rdata.put(std::uint32_t{kTextRva + e.code_offset});
        }
        const std::uint32_t names_rva = rdata.here();
        for (const std::uint32_t r : name_rvas) {
            rdata.put(r);
        }
        const std::uint32_t ordinals_rva = rdata.here();
        for (std::size_t i = 0; i < exports.size(); ++i) {
            rdata.put(static_cast<std::uint16_t>(i));
        }
        while (rdata.bytes.size() % 4U != 0U) {
            rdata.bytes.push_back(0);
        }

        export_dir_rva = rdata.here();
        rdata.put(std::uint32_t{0});                 // Characteristics
        rdata.put(std::uint32_t{0});                 // TimeDateStamp
        rdata.put(std::uint16_t{0});                 // MajorVersion
        rdata.put(std::uint16_t{0});                 // MinorVersion
        rdata.put(module_name_rva);                  // Name
        rdata.put(std::uint32_t{1});                 // Base
        rdata.put(static_cast<std::uint32_t>(exports.size()));  // NumberOfFunctions
        rdata.put(static_cast<std::uint32_t>(exports.size()));  // NumberOfNames
        rdata.put(functions_rva);
        rdata.put(names_rva);
        rdata.put(ordinals_rva);
        export_dir_size = 40U;
    }

    // TLS directory, pointing at callbacks in the code section
    std::uint32_t tls_dir_rva  = 0;
    std::uint32_t tls_dir_size = 0;
    if (!tls_callbacks.empty()) {
        while (rdata.bytes.size() % 8U != 0U) {
            rdata.bytes.push_back(0);
        }
        const std::uint32_t callback_array_rva = rdata.here();
        for (const std::uint32_t off : tls_callbacks) {
            if (x64) {
                rdata.put(std::uint64_t{base() + kTextRva + off});
            } else {
                rdata.put(static_cast<std::uint32_t>(base() + kTextRva + off));
            }
        }
        if (x64) {
            rdata.put(std::uint64_t{0});
        } else {
            rdata.put(std::uint32_t{0});
        }

        tls_dir_rva = rdata.here();
        if (x64) {
            rdata.put(std::uint64_t{0});  // StartAddressOfRawData
            rdata.put(std::uint64_t{0});  // EndAddressOfRawData
            rdata.put(std::uint64_t{0});  // AddressOfIndex
            rdata.put(std::uint64_t{base() + callback_array_rva});
            rdata.put(std::uint32_t{0});  // SizeOfZeroFill
            rdata.put(std::uint32_t{0});  // Characteristics
            tls_dir_size = 40U;
        } else {
            rdata.put(std::uint32_t{0});
            rdata.put(std::uint32_t{0});
            rdata.put(std::uint32_t{0});
            rdata.put(static_cast<std::uint32_t>(base() + callback_array_rva));
            rdata.put(std::uint32_t{0});
            rdata.put(std::uint32_t{0});
            tls_dir_size = 24U;
        }
    }

    // .pdata, the x64 exception table. Each record needs an UNWIND_INFO whose
    // version is 1, or the walk stops at it
    Blob pdata;
    pdata.rva = kPdataRva;
    if (x64 && !pdata_functions.empty()) {
        const std::uint32_t unwind_rva =
            kPdataRva + static_cast<std::uint32_t>(pdata_functions.size()) * 12U;
        for (const auto& fn : pdata_functions) {
            pdata.put(std::uint32_t{kTextRva + fn.first});
            pdata.put(std::uint32_t{kTextRva + fn.second});
            pdata.put(unwind_rva);
        }
        pdata.put(std::uint8_t{1});  // Version 1, no flags
        pdata.put(std::uint8_t{0});  // SizeOfProlog
        pdata.put(std::uint8_t{0});  // CountOfCodes
        pdata.put(std::uint8_t{0});  // FrameRegister / FrameOffset
    }

    // .reloc, one block covering the code page
    Blob reloc;
    reloc.rva = kRelocRva;
    if (!reloc_code_offsets.empty()) {
        const std::uint16_t type      = x64 ? 10U : 3U;  // DIR64 or HIGHLOW
        std::uint32_t       block_size =
            8U + static_cast<std::uint32_t>(reloc_code_offsets.size()) * 2U;
        if (block_size % 4U != 0U) {
            block_size += 2U;  // pad the block to a 4-byte multiple
        }
        reloc.put(std::uint32_t{kTextRva});
        reloc.put(block_size);
        for (const std::uint32_t off : reloc_code_offsets) {
            reloc.put(static_cast<std::uint16_t>((std::uint32_t{type} << 12) |
                                                 (off & 0x0FFFU)));
        }
        while (reloc.bytes.size() < block_size) {
            reloc.put(std::uint16_t{0});
        }
    }

    // Assemble the sections
    struct Section {
        const char*               name;
        std::uint32_t             rva;
        std::vector<std::uint8_t> data;
        std::uint32_t             characteristics;
    };
    constexpr std::uint32_t kCode        = 0x00000020U;
    constexpr std::uint32_t kInitialized = 0x00000040U;
    constexpr std::uint32_t kExecute     = 0x20000000U;
    constexpr std::uint32_t kRead        = 0x40000000U;

    std::vector<Section> sections;
    sections.push_back({".text", kTextRva, code, kCode | kExecute | kRead});
    sections.push_back({".rdata", kRdataRva, rdata.bytes, kInitialized | kRead});
    if (!pdata.bytes.empty()) {
        sections.push_back({".pdata", kPdataRva, pdata.bytes, kInitialized | kRead});
    }
    if (!reloc.bytes.empty()) {
        sections.push_back({".reloc", kRelocRva, reloc.bytes, kInitialized | kRead});
    }

    const std::uint32_t opt_size     = x64 ? 240U : 224U;
    const std::uint32_t headers_size = align_up(
        0x80U + 24U + opt_size + static_cast<std::uint32_t>(sections.size()) * 40U,
        kFileAlign);

    std::vector<std::uint8_t> out(headers_size, 0);

    // DOS header, with e_lfanew pointing at the PE signature
    out[0] = 'M';
    out[1] = 'Z';
    poke<std::uint32_t>(out, 0x3CU, 0x80U);

    std::size_t off = 0x80U;
    out[off + 0] = 'P';
    out[off + 1] = 'E';
    off += 4U;

    // File header
    poke<std::uint16_t>(out, off + 0U, x64 ? 0x8664U : 0x014CU);       // Machine
    poke<std::uint16_t>(out, off + 2U,
                        static_cast<std::uint16_t>(sections.size()));  // NumberOfSections
    poke<std::uint16_t>(out, off + 16U, static_cast<std::uint16_t>(opt_size));
    poke<std::uint16_t>(out, off + 18U, 0x0022U);  // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    off += 20U;

    const std::size_t opt_off = off;
    poke<std::uint16_t>(out, opt_off + 0U, x64 ? 0x20BU : 0x10BU);  // Magic
    poke<std::uint32_t>(out, opt_off + 16U, kTextRva);              // AddressOfEntryPoint
    poke<std::uint32_t>(out, opt_off + 20U, kTextRva);              // BaseOfCode

    std::size_t dd_off = 0;
    if (x64) {
        poke<std::uint64_t>(out, opt_off + 24U, base());          // ImageBase
        poke<std::uint32_t>(out, opt_off + 32U, kSectionAlign);
        poke<std::uint32_t>(out, opt_off + 36U, kFileAlign);
        poke<std::uint16_t>(out, opt_off + 68U, 5U);              // MajorSubsystemVersion
        poke<std::uint32_t>(out, opt_off + 56U,
                            align_up(kRelocRva + kSectionAlign, kSectionAlign));
        poke<std::uint32_t>(out, opt_off + 60U, headers_size);    // SizeOfHeaders
        poke<std::uint16_t>(out, opt_off + 68U, 3U);              // Subsystem (console)
        poke<std::uint32_t>(out, opt_off + 108U, 16U);            // NumberOfRvaAndSizes
        dd_off = opt_off + 112U;
    } else {
        poke<std::uint32_t>(out, opt_off + 24U, 0U);              // BaseOfData
        poke<std::uint32_t>(out, opt_off + 28U,
                            static_cast<std::uint32_t>(base()));  // ImageBase
        poke<std::uint32_t>(out, opt_off + 32U, kSectionAlign);
        poke<std::uint32_t>(out, opt_off + 36U, kFileAlign);
        poke<std::uint32_t>(out, opt_off + 56U,
                            align_up(kRelocRva + kSectionAlign, kSectionAlign));
        poke<std::uint32_t>(out, opt_off + 60U, headers_size);
        poke<std::uint16_t>(out, opt_off + 68U, 3U);
        poke<std::uint32_t>(out, opt_off + 92U, 16U);             // NumberOfRvaAndSizes
        dd_off = opt_off + 96U;
    }

    const auto set_dir = [&out, dd_off](std::size_t index, std::uint32_t rva,
                                        std::uint32_t size) {
        poke<std::uint32_t>(out, dd_off + index * 8U, rva);
        poke<std::uint32_t>(out, dd_off + index * 8U + 4U, size);
    };
    if (export_dir_rva != 0) {
        set_dir(0, export_dir_rva, export_dir_size);
    }
    if (!imports.empty()) {
        set_dir(1, import_dir_rva,
                static_cast<std::uint32_t>(descriptor_count * 20U));
    }
    if (x64 && !pdata.bytes.empty()) {
        set_dir(3, kPdataRva,
                static_cast<std::uint32_t>(pdata_functions.size()) * 12U);
    }
    if (!reloc.bytes.empty()) {
        set_dir(5, kRelocRva, static_cast<std::uint32_t>(reloc.bytes.size()));
    }
    if (tls_dir_rva != 0) {
        set_dir(9, tls_dir_rva, tls_dir_size);
    }

    // Section table, then the section bodies at file-aligned offsets
    std::size_t   sh_off   = opt_off + opt_size;
    std::uint32_t file_pos = headers_size;
    for (const Section& s : sections) {
        const std::uint32_t raw = align_up(
            static_cast<std::uint32_t>(s.data.size()), kFileAlign);
        std::memcpy(out.data() + sh_off, s.name, std::strlen(s.name));
        poke<std::uint32_t>(out, sh_off + 8U,  static_cast<std::uint32_t>(s.data.size()));
        poke<std::uint32_t>(out, sh_off + 12U, s.rva);
        poke<std::uint32_t>(out, sh_off + 16U, raw);
        poke<std::uint32_t>(out, sh_off + 20U, file_pos);
        poke<std::uint32_t>(out, sh_off + 36U, s.characteristics);
        sh_off += 40U;
        file_pos += raw;
    }

    out.resize(file_pos, 0);
    file_pos = headers_size;
    for (const Section& s : sections) {
        if (!s.data.empty()) {
            std::memcpy(out.data() + file_pos, s.data.data(), s.data.size());
        }
        file_pos += align_up(static_cast<std::uint32_t>(s.data.size()), kFileAlign);
    }

    std::vector<std::byte> bytes(out.size());
    std::memcpy(bytes.data(), out.data(), out.size());
    return bytes;
}

}  // namespace papa_tests
