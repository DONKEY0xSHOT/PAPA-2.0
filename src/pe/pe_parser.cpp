#include "papa/pe/pe_parser.h"

#include "papa/constants.h"
#include "papa/exceptions.h"
#include "papa/pe/ordinal_names.h"
#include "papa/pe/pe_structs.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace papa::pe {

namespace {

template <typename T>
[[nodiscard]] bool read_le(std::span<const std::byte> buf, std::size_t off, T& out) noexcept {
    static_assert(std::is_trivially_copyable_v<T>);
    if (off > buf.size() || sizeof(T) > buf.size() - off) {
        return false;
    }
    std::memcpy(&out, buf.data() + off, sizeof(T));
    return true;
}

[[nodiscard]] std::string short_name_to_string(const std::array<std::uint8_t, 8>& n) {
    std::string s;
    s.reserve(constants::kImageSizeofShortName);
    for (std::uint8_t c : n) {
        if (c == 0) { break; }
        s.push_back(static_cast<char>(c));
    }
    return s;
}

[[nodiscard]] std::string to_lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

[[nodiscard]] std::string normalize_dll_name(std::string_view dll) {
    std::string lower = to_lower_ascii(dll);
    for (const auto& ext : constants::kDllExtensions) {
        if (lower.size() >= ext.size() &&
            std::string_view{lower.data() + lower.size() - ext.size(), ext.size()} == ext) {
            lower.resize(lower.size() - ext.size());
            break;
        }
    }
    return lower;
}

[[nodiscard]] Expected<std::string> read_cstring_at_rva(
    const PeImage& image, std::uint64_t rva, std::size_t max_len = 4096) {
    const auto maybe = image.rva_to_file_offset(rva);
    if (!maybe.has_value()) {
        return Unexpected{make_error(ErrorKind::kOutOfBounds, "string rva not mapped")};
    }
    const auto buf = image.raw_buffer();
    std::string out;
    out.reserve(64);
    const std::uint64_t start = *maybe;
    if (start >= buf.size()) {
        return Unexpected{make_error(ErrorKind::kOutOfBounds, "string start past EOF")};
    }
    for (std::size_t i = 0; i < max_len; ++i) {
        const std::uint64_t pos = start + i;
        if (pos >= buf.size()) {
            return Unexpected{make_error(ErrorKind::kBadPe, "unterminated string")};
        }
        const char c = static_cast<char>(buf[pos]);
        if (c == '\0') {
            return out;
        }
        out.push_back(c);
    }
    return Unexpected{make_error(ErrorKind::kBadPe, "string exceeds max length")};
}

struct DataDirectory {
    std::uint32_t rva{0};
    std::uint32_t size{0};
};

[[nodiscard]] DataDirectory get_data_directory(
    const std::vector<ImageDataDirectory>& dirs, std::uint32_t idx) noexcept {
    if (idx >= dirs.size()) { return {}; }
    return DataDirectory{dirs[idx].VirtualAddress, dirs[idx].Size};
}

// Walk one import descriptor and append parsed entries
[[nodiscard]] Expected<void> walk_import_descriptor(
    const PeImage& image,
    const ImageImportDescriptor& desc,
    bool delayed,
    std::vector<ParsedImport>& out) {
    if (desc.Name == 0) { return {}; }

    auto dll_name = read_cstring_at_rva(image, desc.Name);
    if (!dll_name) { return Unexpected{dll_name.error()}; }
    const std::string normalized_dll = normalize_dll_name(*dll_name);

    const std::uint32_t ilt_rva = (desc.OriginalFirstThunk != 0) ? desc.OriginalFirstThunk
                                                                 : desc.FirstThunk;
    const std::uint32_t iat_rva = desc.FirstThunk;
    if (ilt_rva == 0) {
        return Unexpected{make_error(ErrorKind::kBadPe, "import descriptor missing ILT")};
    }

    const bool is_64 = image.is_64bit();
    const std::size_t ptr_size = is_64 ? 8U : 4U;
    const std::uint64_t ordinal_flag = is_64
        ? constants::kImageOrdinalFlag64
        : std::uint64_t{constants::kImageOrdinalFlag32};

    for (std::size_t slot = 0; slot < constants::kMaxImportsPerDll; ++slot) {
        const std::uint64_t slot_rva = std::uint64_t{ilt_rva} + slot * ptr_size;
        auto bytes = image.read_at_rva(slot_rva, ptr_size);
        if (!bytes) { return Unexpected{bytes.error()}; }

        std::uint64_t entry = 0;
        if (is_64) {
            if (!read_le<std::uint64_t>(*bytes, 0, entry)) {
                return Unexpected{make_error(ErrorKind::kBadPe, "truncated ILT slot")};
            }
        } else {
            std::uint32_t e32 = 0;
            if (!read_le<std::uint32_t>(*bytes, 0, e32)) {
                return Unexpected{make_error(ErrorKind::kBadPe, "truncated ILT slot")};
            }
            entry = e32;
        }
        if (entry == 0) { break; }

        ParsedImport item;
        item.dll     = normalized_dll;
        item.iat_va  = image.image_base() + iat_rva + slot * ptr_size;
        item.delayed = delayed;

        if ((entry & ordinal_flag) != 0) {
            item.ordinal    = static_cast<std::uint32_t>(entry & 0xFFFFu);
            item.by_ordinal = true;
            // Resolve the DLLs commonly linked by ordinal (ws2_32, oleaut32) to
            // their symbol names the way vivisect's ordlookup does, so api and
            // import features use the name (getsockname) rather than the ordinal.
            // A resolved import is then a named one
            if (const auto name = lookup_ordinal_name(normalized_dll, item.ordinal);
                name.has_value()) {
                item.name       = std::string{*name};
                item.by_ordinal = false;
            }
        } else {
            const std::uint64_t hint_rva = entry & 0x7FFFFFFFu;
            const std::uint64_t name_rva = hint_rva + 2;
            auto name = read_cstring_at_rva(image, name_rva);
            if (!name) { return Unexpected{name.error()}; }
            item.name       = std::move(*name);
            item.by_ordinal = false;
        }

        out.push_back(std::move(item));
    }
    return {};
}

[[nodiscard]] Expected<std::vector<ParsedImport>> parse_imports(
    const PeImage& image, const std::vector<ImageDataDirectory>& dirs) {
    std::vector<ParsedImport> out;
    const auto dd = get_data_directory(dirs, constants::kImageDirectoryEntryImport);
    if (dd.rva == 0 || dd.size == 0) { return out; }

    for (std::size_t i = 0; i < constants::kMaxImportDescriptors; ++i) {
        const std::uint64_t desc_rva =
            std::uint64_t{dd.rva} + i * sizeof(ImageImportDescriptor);
        auto bytes = image.read_at_rva(desc_rva, sizeof(ImageImportDescriptor));
        if (!bytes) { return Unexpected{bytes.error()}; }

        ImageImportDescriptor desc{};
        if (!read_le<ImageImportDescriptor>(*bytes, 0, desc)) {
            return Unexpected{make_error(ErrorKind::kBadPe, "truncated import descriptor")};
        }
        if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0 && desc.Name == 0) {
            break;
        }
        if (auto r = walk_import_descriptor(image, desc, /*delayed=*/false, out); !r) {
            return Unexpected{r.error()};
        }
    }
    return out;
}

[[nodiscard]] Expected<std::vector<ParsedImport>> parse_delay_imports(
    const PeImage& image, const std::vector<ImageDataDirectory>& dirs) {
    std::vector<ParsedImport> out;
    const auto dd = get_data_directory(dirs, constants::kImageDirectoryEntryDelayImport);
    if (dd.rva == 0 || dd.size == 0) { return out; }

    for (std::size_t i = 0; i < constants::kMaxImportDescriptors; ++i) {
        const std::uint64_t desc_rva =
            std::uint64_t{dd.rva} + i * sizeof(ImageDelayImportDescriptor);
        auto bytes = image.read_at_rva(desc_rva, sizeof(ImageDelayImportDescriptor));
        if (!bytes) { return Unexpected{bytes.error()}; }

        ImageDelayImportDescriptor desc{};
        if (!read_le<ImageDelayImportDescriptor>(*bytes, 0, desc)) {
            return Unexpected{make_error(ErrorKind::kBadPe, "truncated delay import")};
        }
        if (desc.Name == 0 && desc.DelayImportAddressTable == 0) { break; }

        ImageImportDescriptor shim{};
        shim.OriginalFirstThunk = desc.DelayImportNameTable;
        shim.Name               = desc.Name;
        shim.FirstThunk         = desc.DelayImportAddressTable;

        if (shim.Name == 0) { continue; }
        if (auto r = walk_import_descriptor(image, shim, /*delayed=*/true, out); !r) {
            return Unexpected{r.error()};
        }
    }
    return out;
}

[[nodiscard]] Expected<std::vector<ParsedExport>> parse_exports(
    const PeImage& image, const std::vector<ImageDataDirectory>& dirs) {
    std::vector<ParsedExport> out;
    const auto dd = get_data_directory(dirs, constants::kImageDirectoryEntryExport);
    if (dd.rva == 0 || dd.size == 0) { return out; }

    auto dir_bytes = image.read_at_rva(dd.rva, sizeof(ImageExportDirectory));
    if (!dir_bytes) { return Unexpected{dir_bytes.error()}; }

    ImageExportDirectory edir{};
    if (!read_le<ImageExportDirectory>(*dir_bytes, 0, edir)) {
        return Unexpected{make_error(ErrorKind::kBadPe, "truncated export directory")};
    }

    // NumberOfFunctions and NumberOfNames are attacker-controlled 32-bit header
    // fields, so neither may size an allocation or bound a loop on its own. Clamp
    // each to the entries the image can actually supply, which leaves every valid
    // PE untouched and stops a crafted count from asking for gigabytes
    const std::uint32_t func_count = static_cast<std::uint32_t>(std::min<std::size_t>(
        {edir.NumberOfFunctions,
         image.readable_bytes_at_rva(edir.AddressOfFunctions) / sizeof(std::uint32_t),
         constants::kMaxExportsPerImage}));
    const std::uint32_t name_count = static_cast<std::uint32_t>(std::min<std::size_t>(
        {edir.NumberOfNames,
         image.readable_bytes_at_rva(edir.AddressOfNames) / sizeof(std::uint32_t),
         constants::kMaxExportsPerImage}));

    std::vector<std::string> name_by_func_index(func_count);

    for (std::uint32_t i = 0; i < name_count; ++i) {
        const std::uint64_t name_rva_off =
            std::uint64_t{edir.AddressOfNames} + i * sizeof(std::uint32_t);
        const std::uint64_t ord_off =
            std::uint64_t{edir.AddressOfNameOrdinals} + i * sizeof(std::uint16_t);

        auto name_rva_bytes = image.read_at_rva(name_rva_off, sizeof(std::uint32_t));
        auto ord_bytes      = image.read_at_rva(ord_off,      sizeof(std::uint16_t));
        if (!name_rva_bytes || !ord_bytes) { continue; }

        std::uint32_t name_rva = 0;
        std::uint16_t func_idx = 0;
        if (!read_le<std::uint32_t>(*name_rva_bytes, 0, name_rva)) { continue; }
        if (!read_le<std::uint16_t>(*ord_bytes, 0, func_idx))      { continue; }
        if (func_idx >= func_count) { continue; }

        auto s = read_cstring_at_rva(image, name_rva);
        if (!s) { continue; }
        name_by_func_index[func_idx] = std::move(*s);
    }

    out.reserve(func_count);
    // Widened before the addition. Both halves are header fields, so a crafted
    // rva near the top of the range would wrap and produce an end below the
    // start, which turns the forwarder test below into a coin flip
    const std::uint64_t export_dir_end = std::uint64_t{dd.rva} + dd.size;

    for (std::uint32_t i = 0; i < func_count; ++i) {
        const std::uint64_t func_rva_off =
            std::uint64_t{edir.AddressOfFunctions} + i * sizeof(std::uint32_t);
        auto func_bytes = image.read_at_rva(func_rva_off, sizeof(std::uint32_t));
        if (!func_bytes) { continue; }

        std::uint32_t func_rva = 0;
        if (!read_le<std::uint32_t>(*func_bytes, 0, func_rva)) { continue; }
        if (func_rva == 0) { continue; }

        ParsedExport pe_exp;
        pe_exp.name    = name_by_func_index[i];
        pe_exp.ordinal = edir.Base + i;
        pe_exp.va      = image.image_base() + func_rva;

        if (func_rva >= dd.rva && func_rva < export_dir_end) {
            auto fwd = read_cstring_at_rva(image, func_rva);
            if (fwd) {
                pe_exp.forwarder = std::move(*fwd);
                pe_exp.va        = 0;
            }
        }
        out.push_back(std::move(pe_exp));
    }
    return out;
}

[[nodiscard]] Expected<std::vector<std::uint64_t>> parse_tls_callbacks(
    const PeImage& image, const std::vector<ImageDataDirectory>& dirs) {
    std::vector<std::uint64_t> callbacks;
    const auto dd = get_data_directory(dirs, constants::kImageDirectoryEntryTls);
    if (dd.rva == 0 || dd.size == 0) { return callbacks; }

    std::uint64_t callbacks_va = 0;
    if (image.is_64bit()) {
        auto b = image.read_at_rva(dd.rva, sizeof(ImageTlsDirectory64));
        if (!b) { return Unexpected{b.error()}; }
        ImageTlsDirectory64 t{};
        if (!read_le<ImageTlsDirectory64>(*b, 0, t)) {
            return Unexpected{make_error(ErrorKind::kBadPe, "truncated tls64")};
        }
        callbacks_va = t.AddressOfCallBacks;
    } else {
        auto b = image.read_at_rva(dd.rva, sizeof(ImageTlsDirectory32));
        if (!b) { return Unexpected{b.error()}; }
        ImageTlsDirectory32 t{};
        if (!read_le<ImageTlsDirectory32>(*b, 0, t)) {
            return Unexpected{make_error(ErrorKind::kBadPe, "truncated tls32")};
        }
        callbacks_va = t.AddressOfCallBacks;
    }
    if (callbacks_va == 0) { return callbacks; }
    if (callbacks_va < image.image_base()) { return callbacks; }

    const std::uint64_t callbacks_rva = callbacks_va - image.image_base();
    const std::size_t   ptr_size      = image.is_64bit() ? 8U : 4U;

    for (std::size_t i = 0; i < 256; ++i) {
        const std::uint64_t slot_rva = callbacks_rva + i * ptr_size;
        auto b = image.read_at_rva(slot_rva, ptr_size);
        if (!b) { break; }

        std::uint64_t cb = 0;
        if (image.is_64bit()) {
            if (!read_le<std::uint64_t>(*b, 0, cb)) { break; }
        } else {
            std::uint32_t cb32 = 0;
            if (!read_le<std::uint32_t>(*b, 0, cb32)) { break; }
            cb = cb32;
        }
        if (cb == 0) { break; }
        callbacks.push_back(cb);
    }
    return callbacks;
}

// Parse the base-relocation directory into (rva, type) entries, faithful to
// vivisect PE.parseRelocations. Every entry is retained including the type-0
// ABSOLUTE block padding so the pointers pass sees the same set vivisect does.
// A corrupt directory is tolerated: the walk stops and the partial list stands,
// matching vivisect's log-and-return behavior rather than failing the parse
[[nodiscard]] std::vector<ParsedRelocation> parse_relocations(
    const PeImage& image, const std::vector<ImageDataDirectory>& dirs) {
    std::vector<ParsedRelocation> out;
    const auto dd = get_data_directory(dirs, constants::kImageDirectoryEntryBaseReloc);
    if (dd.rva == 0 || dd.size == 0) { return out; }

    // Read the whole directory, clamped to the bytes actually mapped in the
    // containing section, then walk fixed-size block headers within it
    std::uint64_t avail = dd.size;
    if (const auto* s = image.section_containing_rva(dd.rva); s != nullptr) {
        const std::uint64_t delta     = dd.rva - s->virtual_address;
        const std::uint64_t remaining = (delta < s->raw_size) ? (s->raw_size - delta) : 0;
        avail = std::min<std::uint64_t>(dd.size, remaining);
    }
    auto dir = image.read_at_rva(dd.rva, static_cast<std::size_t>(avail));
    if (!dir) { return out; }
    const std::span<const std::byte> relbytes = *dir;

    std::size_t pos = 0;
    while (pos < relbytes.size()) {
        const std::size_t remaining = relbytes.size() - pos;
        if (remaining < 8) { break; }  // need an 8-byte block header

        std::uint32_t page_rva  = 0;
        std::uint32_t chunk_size = 0;
        if (!read_le<std::uint32_t>(relbytes, pos, page_rva) ||
            !read_le<std::uint32_t>(relbytes, pos + 4, chunk_size)) {
            break;
        }
        if (chunk_size == 0) { break; }          // corrupt: zero-size chunk
        if (chunk_size > remaining) { break; }   // corrupt: chunk past directory
        if (chunk_size < 8) { break; }           // corrupt: header without entries

        const std::size_t body_end = pos + chunk_size;
        for (std::size_t roff = pos + 8; roff + sizeof(std::uint16_t) <= body_end;
             roff += sizeof(std::uint16_t)) {
            std::uint16_t entry = 0;
            if (!read_le<std::uint16_t>(relbytes, roff, entry)) { break; }
            const auto rtype  = static_cast<std::uint16_t>(entry >> 12);
            const auto offset = static_cast<std::uint32_t>(entry & 0x0fffu);
            if (out.size() >= constants::kMaxRelocations) {
                return out;
            }
            out.push_back(ParsedRelocation{page_rva + offset, rtype});
        }
        pos += chunk_size;
    }
    return out;
}

}  // namespace

Expected<PeImage> PeParser::parse(std::vector<std::byte> buffer) {
    PeImage img;
    img.buffer_ = std::move(buffer);
    std::span<const std::byte> buf{img.buffer_};

    ImageDosHeader dos{};
    if (!read_le<ImageDosHeader>(buf, 0, dos)) {
        return Unexpected{make_error(ErrorKind::kNotPe, "buffer too small for DOS header")};
    }
    if (dos.e_magic != constants::kImageDosSignature) {
        return Unexpected{make_error(ErrorKind::kNotPe, "missing MZ signature")};
    }
    if (dos.e_lfanew < 0 || static_cast<std::uint64_t>(dos.e_lfanew) >= buf.size()) {
        return Unexpected{make_error(ErrorKind::kBadPe, "e_lfanew out of range")};
    }
    const std::uint32_t nt_off = static_cast<std::uint32_t>(dos.e_lfanew);

    std::uint32_t nt_sig = 0;
    if (!read_le<std::uint32_t>(buf, nt_off, nt_sig)) {
        return Unexpected{make_error(ErrorKind::kBadPe, "NT header truncated")};
    }
    if (nt_sig != constants::kImageNtSignature) {
        return Unexpected{make_error(ErrorKind::kNotPe, "missing PE signature")};
    }

    ImageFileHeader fh{};
    if (!read_le<ImageFileHeader>(buf, nt_off + 4, fh)) {
        return Unexpected{make_error(ErrorKind::kBadPe, "file header truncated")};
    }
    img.machine_ = fh.Machine;

    const std::uint32_t opt_off = nt_off + 4 + static_cast<std::uint32_t>(sizeof(ImageFileHeader));
    std::uint16_t opt_magic = 0;
    if (!read_le<std::uint16_t>(buf, opt_off, opt_magic)) {
        return Unexpected{make_error(ErrorKind::kBadPe, "optional header truncated")};
    }

    std::uint32_t num_dirs = 0;
    std::uint32_t dir_off  = 0;

    if (opt_magic == constants::kOptionalHeaderMagic32) {
        img.is_64bit_ = false;
        ImageOptionalHeader32 oh{};
        if (!read_le<ImageOptionalHeader32>(buf, opt_off, oh)) {
            return Unexpected{make_error(ErrorKind::kBadPe, "PE32 optional header truncated")};
        }
        img.image_base_      = oh.ImageBase;
        img.entry_point_rva_ = oh.Common.AddressOfEntryPoint;
        img.size_of_image_   = oh.SizeOfImage;
        num_dirs             = oh.NumberOfRvaAndSizes;
        dir_off              = opt_off + static_cast<std::uint32_t>(sizeof(ImageOptionalHeader32));
    } else if (opt_magic == constants::kOptionalHeaderMagic64) {
        img.is_64bit_ = true;
        ImageOptionalHeader64 oh{};
        if (!read_le<ImageOptionalHeader64>(buf, opt_off, oh)) {
            return Unexpected{make_error(ErrorKind::kBadPe, "PE32+ optional header truncated")};
        }
        img.image_base_      = oh.ImageBase;
        img.entry_point_rva_ = oh.Common.AddressOfEntryPoint;
        img.size_of_image_   = oh.SizeOfImage;
        num_dirs             = oh.NumberOfRvaAndSizes;
        dir_off              = opt_off + static_cast<std::uint32_t>(sizeof(ImageOptionalHeader64));
    } else {
        return Unexpected{make_error(ErrorKind::kBadPe, "unknown optional header magic")};
    }

    if (num_dirs > constants::kImageNumberOfDirectoryEntries) {
        num_dirs = constants::kImageNumberOfDirectoryEntries;
    }

    std::vector<ImageDataDirectory> dirs(num_dirs);
    for (std::uint32_t i = 0; i < num_dirs; ++i) {
        if (!read_le<ImageDataDirectory>(
                buf, dir_off + i * sizeof(ImageDataDirectory), dirs[i])) {
            return Unexpected{make_error(ErrorKind::kBadPe, "data directory truncated")};
        }
    }

    const std::uint32_t sec_off =
        dir_off + num_dirs * static_cast<std::uint32_t>(sizeof(ImageDataDirectory));
    // NumberOfSections is a raw header field, so clamp before it sizes an
    // allocation. The Windows loader itself refuses far fewer than this, and a
    // truncated table is caught per header below
    const std::uint16_t num_sections = static_cast<std::uint16_t>(
        std::min<std::size_t>(fh.NumberOfSections, constants::kMaxSectionsPerImage));
    img.sections_.reserve(num_sections);
    for (std::uint16_t i = 0; i < num_sections; ++i) {
        ImageSectionHeader sh{};
        if (!read_le<ImageSectionHeader>(
                buf, sec_off + i * sizeof(ImageSectionHeader), sh)) {
            return Unexpected{make_error(ErrorKind::kBadPe, "section header truncated")};
        }
        ParsedSection ps;
        ps.name            = short_name_to_string(sh.Name);
        ps.virtual_address = sh.VirtualAddress;
        ps.virtual_size    = sh.VirtualSize;
        ps.raw_offset      = sh.PointerToRawData;
        ps.raw_size        = sh.SizeOfRawData;
        ps.characteristics = sh.Characteristics;
        img.sections_.push_back(std::move(ps));
    }

    // Sections are ready
    // Directory walkers can now use RVA to file-offset mapping safely
    {
        auto r = parse_imports(img, dirs);
        if (!r) { return Unexpected{r.error()}; }
        img.imports_ = std::move(*r);
    }
    {
        auto r = parse_delay_imports(img, dirs);
        if (!r) { return Unexpected{r.error()}; }
        auto& dst = img.imports_;
        dst.insert(dst.end(),
                   std::make_move_iterator(r->begin()),
                   std::make_move_iterator(r->end()));
    }
    {
        auto r = parse_exports(img, dirs);
        if (!r) { return Unexpected{r.error()}; }
        img.exports_ = std::move(*r);
    }
    {
        auto r = parse_tls_callbacks(img, dirs);
        if (!r) { return Unexpected{r.error()}; }
        img.tls_callbacks_ = std::move(*r);
    }
    img.relocations_ = parse_relocations(img, dirs);

    return img;
}

Expected<PeImage> PeParser::parse_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        return Unexpected{make_error(ErrorKind::kIoError, "cannot open file")};
    }
    const auto size = f.tellg();
    if (size <= 0) {
        return Unexpected{make_error(ErrorKind::kIoError, "empty or unreadable file")};
    }
    f.seekg(0, std::ios::beg);
    std::vector<std::byte> buf(static_cast<std::size_t>(size));
    f.read(reinterpret_cast<char*>(buf.data()), size);  // I/O boundary
    if (!f) {
        return Unexpected{make_error(ErrorKind::kIoError, "short read")};
    }
    return parse(std::move(buf));
}

}  // namespace papa::pe
