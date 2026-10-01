#pragma once

// Builds valid PE images in memory so the test suite never needs a real executable
// on disk. The images are small but structurally genuine

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace papa_tests {

/// One imported DLL and the functions taken from it. A function spelled "#N" is
/// imported by ordinal N
struct ImportSpec {
    std::string              dll;
    std::vector<std::string> functions;
};

/// One exported function, named, pointing at an offset into the code section or, when
/// forwarder is set, forwarded to another DLL's export such as "ntdll.RtlAllocateHeap"
struct ExportSpec {
    std::string   name;
    std::uint32_t code_offset{0};
    std::string   forwarder;
};

/// One extra section placed after the standard ones. A virtual_size of 0 means the
/// size of bytes, and a larger one leaves the tail unbacked by file data
struct SectionSpec {
    std::string               name;
    std::vector<std::uint8_t> bytes;
    std::uint32_t             characteristics{0};
    std::uint32_t             virtual_size{0};
};

/// File offsets of the header structures in the image build() returns
struct HeaderLayout {
    std::size_t e_lfanew{0};          // the DOS header field that points at nt_headers
    std::size_t nt_headers{0};        // the PE signature
    std::size_t file_header{0};
    std::size_t optional_header{0};
    std::size_t data_directories{0};
    std::size_t section_table{0};
    std::size_t section_count{0};
    std::size_t size_of_headers{0};

    /// File offset of data directory entry index
    [[nodiscard]] std::size_t data_directory(std::size_t index) const noexcept {
        return data_directories + index * 8U;
    }

    /// File offset of the header of section index
    [[nodiscard]] std::size_t section_header(std::size_t index) const noexcept {
        return section_table + index * 40U;
    }
};

/// A synthetic PE image that papa::pe::PeParser::parse accepts. Its sections sit back
/// to back on 0x1000 boundaries: .text, .rdata, .data, .pdata, the extras, .reloc
class PeBuilder {
public:
    static constexpr std::uint32_t kSectionAlign = 0x1000;
    static constexpr std::uint32_t kFileAlign    = 0x200;
    static constexpr std::uint32_t kTextRva      = 0x1000;

    static constexpr std::uint32_t kScnCode              = 0x00000020U;
    static constexpr std::uint32_t kScnInitializedData   = 0x00000040U;
    static constexpr std::uint32_t kScnUninitializedData = 0x00000080U;
    static constexpr std::uint32_t kScnExecute           = 0x20000000U;
    static constexpr std::uint32_t kScnRead              = 0x40000000U;
    static constexpr std::uint32_t kScnWrite             = 0x80000000U;

    bool          x64{true};
    std::uint64_t image_base{0};  // 0 selects the usual default for the bitness
    // Machine code placed at kTextRva
    std::vector<std::uint8_t> code;
    // Code offset of the entry point
    std::uint32_t             entry_offset{0};
    std::vector<ImportSpec>   imports;
    // Imports bound through the delay-load directory instead of the import directory
    std::vector<ImportSpec>   delay_imports;
    std::vector<ExportSpec>   exports;
    // Contents of a read-write .data section, left out when empty
    std::vector<std::uint8_t> data;
    std::vector<SectionSpec>  extra_sections;
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

    /// Virtual address of a code offset
    [[nodiscard]] std::uint64_t code_va(std::uint32_t offset) const noexcept {
        return base() + kTextRva + offset;
    }

    /// Appends one function to the code on a 16-byte boundary, padding with int3, and
    /// records its .pdata row, which build() emits on x64. Returns its code offset
    std::uint32_t add_function(const std::vector<std::uint8_t>& bytes);

    /// RVA where the named section lands, 0 when there is none
    [[nodiscard]] std::uint32_t section_rva(std::string_view name) const;

    /// Virtual address of an offset into the .data section
    [[nodiscard]] std::uint64_t data_va(std::uint32_t offset) const {
        return base() + section_rva(".data") + offset;
    }

    /// Virtual address of the IAT slot for fn of dll as spelled in imports or
    /// delay_imports, 0 when absent. It holds until a section changes size
    [[nodiscard]] std::uint64_t iat_va(std::string_view dll, std::string_view fn) const;

    /// File offsets of the headers in the image build() would return
    [[nodiscard]] HeaderLayout header_layout() const;

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
        void align(std::size_t a) {
            while (bytes.size() % a != 0U) {
                bytes.push_back(0);
            }
        }
        [[nodiscard]] std::uint32_t here() const noexcept {
            return rva + static_cast<std::uint32_t>(bytes.size());
        }
    };

    struct Section {
        std::string               name;
        std::uint32_t             rva{0};
        std::vector<std::uint8_t> bytes;
        std::uint32_t             virtual_size{0};
        std::uint32_t             characteristics{0};
    };

    // Everything build() serializes, laid out at final RVAs
    struct Image {
        std::vector<Section>                                         sections;
        std::array<std::pair<std::uint32_t, std::uint32_t>, 16>      dirs{};
        std::map<std::pair<std::string, std::string>, std::uint32_t> iat_rvas;
        std::uint32_t                                                size_of_image{0};
    };

    [[nodiscard]] Image assemble() const;
    void put_imports(Blob& rdata, const std::vector<ImportSpec>& specs, bool delayed,
                     Image& image) const;
    [[nodiscard]] HeaderLayout layout_for(std::size_t section_count) const noexcept;
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

inline std::uint32_t PeBuilder::add_function(const std::vector<std::uint8_t>& bytes) {
    while (code.size() % 16U != 0U) {
        code.push_back(0xCC);
    }
    const auto offset = static_cast<std::uint32_t>(code.size());
    code.insert(code.end(), bytes.begin(), bytes.end());
    pdata_functions.emplace_back(offset, static_cast<std::uint32_t>(code.size()));
    return offset;
}

inline std::uint32_t PeBuilder::section_rva(std::string_view name) const {
    for (const Section& s : assemble().sections) {
        if (s.name == name) {
            return s.rva;
        }
    }
    return 0;
}

inline std::uint64_t PeBuilder::iat_va(std::string_view dll, std::string_view fn) const {
    const Image image = assemble();
    const auto  it    = image.iat_rvas.find({std::string(dll), std::string(fn)});
    return it == image.iat_rvas.end() ? 0U : base() + it->second;
}

inline HeaderLayout PeBuilder::header_layout() const {
    return layout_for(assemble().sections.size());
}

inline HeaderLayout PeBuilder::layout_for(std::size_t section_count) const noexcept {
    HeaderLayout l;
    l.e_lfanew         = 0x3C;
    l.nt_headers       = 0x80;
    l.file_header      = l.nt_headers + 4U;
    l.optional_header  = l.file_header + 20U;
    l.data_directories = l.optional_header + (x64 ? 112U : 96U);
    l.section_table    = l.optional_header + (x64 ? 240U : 224U);
    l.section_count    = section_count;
    l.size_of_headers  = detail::align_up(
        static_cast<std::uint32_t>(l.section_table + section_count * 40U), kFileAlign);
    return l;
}

// Writes the import descriptors (or delay-load descriptors) for specs, then the
// hint/name entries and DLL names, then every lookup table, then every address table
inline void PeBuilder::put_imports(Blob& rdata, const std::vector<ImportSpec>& specs,
                                   bool delayed, Image& image) const {
    using detail::poke;
    const std::uint32_t descriptor_size  = delayed ? 32U : 20U;
    const std::uint32_t dir_rva          = rdata.here();
    const std::size_t   descriptor_count = specs.size() + 1U;
    rdata.bytes.resize(rdata.bytes.size() + descriptor_count * descriptor_size, 0);

    const std::uint32_t thunk_size   = x64 ? 8U : 4U;
    const std::uint64_t ordinal_flag = x64 ? 0x8000000000000000ULL : 0x80000000ULL;
    std::vector<std::uint32_t>              dll_name_rvas;
    std::vector<std::vector<std::uint64_t>> thunks;

    for (const ImportSpec& imp : specs) {
        std::vector<std::uint64_t> values;
        for (const std::string& fn : imp.functions) {
            if (fn.size() > 1U && fn[0] == '#') {
                std::uint16_t ordinal = 0;
                std::from_chars(fn.data() + 1, fn.data() + fn.size(), ordinal);
                values.push_back(ordinal_flag | ordinal);
                continue;
            }
            values.push_back(rdata.here());
            const std::uint16_t hint = 0;
            rdata.put(hint);
            rdata.put_bytes(fn.data(), fn.size() + 1U);
            rdata.align(2);  // keep the next hint aligned
        }
        thunks.push_back(std::move(values));

        dll_name_rvas.push_back(rdata.here());
        rdata.put_bytes(imp.dll.data(), imp.dll.size() + 1U);
        rdata.align(2);
    }

    const auto put_table = [&](std::vector<std::uint32_t>& rvas, bool is_iat) {
        for (std::size_t i = 0; i < specs.size(); ++i) {
            rvas.push_back(rdata.here());
            for (std::size_t j = 0; j < thunks[i].size(); ++j) {
                if (is_iat) {
                    image.iat_rvas.emplace(
                        std::make_pair(specs[i].dll, specs[i].functions[j]), rdata.here());
                }
                if (x64) {
                    rdata.put(std::uint64_t{thunks[i][j]});
                } else {
                    rdata.put(static_cast<std::uint32_t>(thunks[i][j]));
                }
            }
            rdata.bytes.insert(rdata.bytes.end(), thunk_size, 0);  // terminator
        }
    };
    std::vector<std::uint32_t> ilt_rvas;
    std::vector<std::uint32_t> iat_rvas;
    put_table(ilt_rvas, false);
    put_table(iat_rvas, true);

    for (std::size_t i = 0; i < specs.size(); ++i) {
        const std::size_t at = std::size_t{dir_rva - rdata.rva} + i * descriptor_size;
        if (delayed) {
            poke<std::uint32_t>(rdata.bytes, at + 0U,  1U);  // Attributes, RVA based
            poke<std::uint32_t>(rdata.bytes, at + 4U,  dll_name_rvas[i]);
            poke<std::uint32_t>(rdata.bytes, at + 12U, iat_rvas[i]);
            poke<std::uint32_t>(rdata.bytes, at + 16U, ilt_rvas[i]);
        } else {
            poke<std::uint32_t>(rdata.bytes, at + 0U,  ilt_rvas[i]);
            poke<std::uint32_t>(rdata.bytes, at + 12U, dll_name_rvas[i]);
            poke<std::uint32_t>(rdata.bytes, at + 16U, iat_rvas[i]);
        }
    }
    if (!specs.empty()) {
        image.dirs[delayed ? 13U : 1U] = {
            dir_rva, static_cast<std::uint32_t>(descriptor_count * descriptor_size)};
    }
}

inline PeBuilder::Image PeBuilder::assemble() const {
    using detail::align_up;
    using detail::poke;

    Image         image;
    std::uint32_t next_rva = kTextRva;
    const auto place = [&image, &next_rva](std::string name, std::vector<std::uint8_t> bytes,
                                           std::uint32_t virtual_size,
                                           std::uint32_t characteristics) {
        const std::uint32_t rva = next_rva;
        next_rva = align_up(rva + std::max<std::uint32_t>(virtual_size, 1U), kSectionAlign);
        image.sections.push_back(
            {std::move(name), rva, std::move(bytes), virtual_size, characteristics});
    };
    const auto size_of = [](const std::vector<std::uint8_t>& bytes) {
        return static_cast<std::uint32_t>(bytes.size());
    };

    place(".text", code, size_of(code), kScnCode | kScnExecute | kScnRead);

    // .rdata holds the import, export, TLS and delay-load directories
    Blob rdata;
    rdata.rva = next_rva;
    put_imports(rdata, imports, false, image);

    if (!exports.empty()) {
        std::vector<std::uint32_t> name_rvas;
        for (const ExportSpec& e : exports) {
            name_rvas.push_back(rdata.here());
            rdata.put_bytes(e.name.data(), e.name.size() + 1U);
        }
        const std::uint32_t module_name_rva = rdata.here();
        const std::string   module_name     = "synthetic.exe";
        rdata.put_bytes(module_name.data(), module_name.size() + 1U);
        rdata.align(4);

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
        rdata.align(4);

        const std::uint32_t export_dir_rva = rdata.here();
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

        // A forwarder string lies inside the export directory, which is how a loader
        // tells it from code
        for (std::size_t i = 0; i < exports.size(); ++i) {
            if (exports[i].forwarder.empty()) {
                continue;
            }
            poke<std::uint32_t>(rdata.bytes, std::size_t{functions_rva - rdata.rva} + i * 4U,
                                rdata.here());
            rdata.put_bytes(exports[i].forwarder.data(), exports[i].forwarder.size() + 1U);
        }
        image.dirs[0] = {export_dir_rva, rdata.here() - export_dir_rva};
    }

    // TLS directory, pointing at callbacks in the code section
    if (!tls_callbacks.empty()) {
        rdata.align(8);
        const std::uint32_t callback_array_rva = rdata.here();
        for (const std::uint32_t off : tls_callbacks) {
            if (x64) {
                rdata.put(std::uint64_t{code_va(off)});
            } else {
                rdata.put(static_cast<std::uint32_t>(code_va(off)));
            }
        }
        if (x64) {
            rdata.put(std::uint64_t{0});
        } else {
            rdata.put(std::uint32_t{0});
        }

        const std::uint32_t tls_dir_rva = rdata.here();
        if (x64) {
            rdata.put(std::uint64_t{0});  // StartAddressOfRawData
            rdata.put(std::uint64_t{0});  // EndAddressOfRawData
            rdata.put(std::uint64_t{0});  // AddressOfIndex
            rdata.put(std::uint64_t{base() + callback_array_rva});
            rdata.put(std::uint32_t{0});  // SizeOfZeroFill
            rdata.put(std::uint32_t{0});  // Characteristics
            image.dirs[9] = {tls_dir_rva, 40U};
        } else {
            rdata.put(std::uint32_t{0});
            rdata.put(std::uint32_t{0});
            rdata.put(std::uint32_t{0});
            rdata.put(static_cast<std::uint32_t>(base() + callback_array_rva));
            rdata.put(std::uint32_t{0});
            rdata.put(std::uint32_t{0});
            image.dirs[9] = {tls_dir_rva, 24U};
        }
    }

    if (!delay_imports.empty()) {
        rdata.align(4);
        put_imports(rdata, delay_imports, true, image);
    }
    place(".rdata", rdata.bytes, size_of(rdata.bytes), kScnInitializedData | kScnRead);

    if (!data.empty()) {
        place(".data", data, size_of(data), kScnInitializedData | kScnRead | kScnWrite);
    }

    // .pdata, the x64 exception table. Each record needs an UNWIND_INFO whose
    // version is 1, or the walk stops at it
    if (x64 && !pdata_functions.empty()) {
        Blob pdata;
        pdata.rva = next_rva;
        const auto rows = static_cast<std::uint32_t>(pdata_functions.size());
        const std::uint32_t unwind_rva = pdata.rva + rows * 12U;
        for (const auto& fn : pdata_functions) {
            pdata.put(std::uint32_t{kTextRva + fn.first});
            pdata.put(std::uint32_t{kTextRva + fn.second});
            pdata.put(unwind_rva);
        }
        pdata.put(std::uint8_t{1});  // Version 1, no flags
        pdata.put(std::uint8_t{0});  // SizeOfProlog
        pdata.put(std::uint8_t{0});  // CountOfCodes
        pdata.put(std::uint8_t{0});  // FrameRegister / FrameOffset
        image.dirs[3] = {pdata.rva, rows * 12U};
        place(".pdata", pdata.bytes, size_of(pdata.bytes), kScnInitializedData | kScnRead);
    }

    for (const SectionSpec& s : extra_sections) {
        place(s.name, s.bytes, s.virtual_size != 0U ? s.virtual_size : size_of(s.bytes),
              s.characteristics);
    }

    // .reloc, one block per code page, each padded to a 4-byte multiple with an
    // ABSOLUTE entry
    if (!reloc_code_offsets.empty()) {
        Blob reloc;
        reloc.rva = next_rva;
        const std::uint32_t type = x64 ? 10U : 3U;  // DIR64 or HIGHLOW
        std::map<std::uint32_t, std::vector<std::uint16_t>> pages;
        for (const std::uint32_t off : reloc_code_offsets) {
            const std::uint32_t rva = kTextRva + off;
            pages[rva & ~0x0FFFU].push_back(
                static_cast<std::uint16_t>((type << 12) | (rva & 0x0FFFU)));
        }
        for (auto& [page, entries] : pages) {
            if (entries.size() % 2U != 0U) {
                entries.push_back(0);
            }
            reloc.put(page);
            reloc.put(static_cast<std::uint32_t>(8U + entries.size() * 2U));
            for (const std::uint16_t e : entries) {
                reloc.put(e);
            }
        }
        image.dirs[5] = {reloc.rva, size_of(reloc.bytes)};
        place(".reloc", reloc.bytes, size_of(reloc.bytes), kScnInitializedData | kScnRead);
    }

    image.size_of_image = next_rva;
    return image;
}

inline std::vector<std::byte> PeBuilder::build() const {
    using detail::align_up;
    using detail::poke;

    const Image        image = assemble();
    const HeaderLayout l     = layout_for(image.sections.size());

    // The headers always fill at least one file-aligned block. Saying so lets GCC see
    // that the buffer is never empty, or -O2 warns of a null dereference below
    std::vector<std::uint8_t> out(std::max<std::size_t>(l.size_of_headers, kFileAlign), 0);

    // DOS header, with e_lfanew pointing at the PE signature
    poke<std::uint16_t>(out, 0, 0x5A4DU);  // MZ
    poke<std::uint32_t>(out, l.e_lfanew, static_cast<std::uint32_t>(l.nt_headers));
    poke<std::uint32_t>(out, l.nt_headers, 0x00004550U);  // PE and two NULs

    // File header
    poke<std::uint16_t>(out, l.file_header + 0U, x64 ? 0x8664U : 0x014CU);  // Machine
    poke<std::uint16_t>(out, l.file_header + 2U,
                        static_cast<std::uint16_t>(image.sections.size()));  // NumberOfSections
    poke<std::uint16_t>(out, l.file_header + 16U,
                        static_cast<std::uint16_t>(l.section_table - l.optional_header));
    // Characteristics, EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    poke<std::uint16_t>(out, l.file_header + 18U, 0x0022U);

    // Optional header. The fields from SectionAlignment on sit at the same offsets in
    // PE32 and PE32+
    const std::size_t opt = l.optional_header;
    poke<std::uint16_t>(out, opt + 0U, x64 ? 0x20BU : 0x10BU);     // Magic
    poke<std::uint32_t>(out, opt + 16U, kTextRva + entry_offset);  // AddressOfEntryPoint
    poke<std::uint32_t>(out, opt + 20U, kTextRva);                 // BaseOfCode
    if (x64) {
        poke<std::uint64_t>(out, opt + 24U, base());               // ImageBase
    } else {
        poke<std::uint32_t>(out, opt + 24U, 0U);                   // BaseOfData
        poke<std::uint32_t>(out, opt + 28U, static_cast<std::uint32_t>(base()));
    }
    poke<std::uint32_t>(out, opt + 32U, kSectionAlign);
    poke<std::uint32_t>(out, opt + 36U, kFileAlign);
    poke<std::uint16_t>(out, opt + 48U, 5U);                       // MajorSubsystemVersion
    poke<std::uint32_t>(out, opt + 56U, image.size_of_image);
    poke<std::uint32_t>(out, opt + 60U, static_cast<std::uint32_t>(l.size_of_headers));
    poke<std::uint16_t>(out, opt + 68U, 3U);                       // Subsystem (console)
    poke<std::uint32_t>(out, l.data_directories - 4U, 16U);        // NumberOfRvaAndSizes

    for (std::size_t i = 0; i < image.dirs.size(); ++i) {
        if (image.dirs[i].first != 0) {
            poke<std::uint32_t>(out, l.data_directory(i), image.dirs[i].first);
            poke<std::uint32_t>(out, l.data_directory(i) + 4U, image.dirs[i].second);
        }
    }

    // Section table, then the section bodies at file-aligned offsets
    auto file_pos = static_cast<std::uint32_t>(l.size_of_headers);
    for (std::size_t i = 0; i < image.sections.size(); ++i) {
        const Section&      s   = image.sections[i];
        const std::size_t   sh  = l.section_header(i);
        const std::uint32_t raw = align_up(static_cast<std::uint32_t>(s.bytes.size()), kFileAlign);
        std::memcpy(out.data() + sh, s.name.data(), std::min<std::size_t>(s.name.size(), 8U));
        poke<std::uint32_t>(out, sh + 8U,  s.virtual_size);
        poke<std::uint32_t>(out, sh + 12U, s.rva);
        poke<std::uint32_t>(out, sh + 16U, raw);
        poke<std::uint32_t>(out, sh + 20U, file_pos);
        poke<std::uint32_t>(out, sh + 36U, s.characteristics);
        file_pos += raw;
    }

    out.resize(file_pos, 0);
    file_pos = static_cast<std::uint32_t>(l.size_of_headers);
    for (const Section& s : image.sections) {
        if (!s.bytes.empty()) {
            std::memcpy(out.data() + file_pos, s.bytes.data(), s.bytes.size());
        }
        file_pos += align_up(static_cast<std::uint32_t>(s.bytes.size()), kFileAlign);
    }

    std::vector<std::byte> bytes(out.size());
    std::memcpy(bytes.data(), out.data(), out.size());
    return bytes;
}

}  // namespace papa_tests
