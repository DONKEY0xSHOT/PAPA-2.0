#include "papa/features/extractors/papa_native/flirt/flirt_reader.h"

#include "papa/features/extractors/papa_native/flirt/byte_cursor.h"
#include "papa/features/extractors/papa_native/flirt/flirt_decompress.h"
#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace papa::features::extractors::papa_native::flirt {

using detail::ByteCursor;

std::size_t header_size_for_version(std::uint8_t version) noexcept {
    // Header size by version: 37 bytes for v8, 41 for v9 which adds n_functions, and 45
    // for v10 which adds pattern_size
    if (version >= 10) { return 45U; }
    if (version >= 9)  { return 41U; }
    if (version >= 8)  { return 37U; }
    return 0U;
}

Expected<FlirtHeader> parse_header(std::span<const std::uint8_t> data) noexcept {
    ByteCursor cur{data};

    std::array<std::uint8_t, kIdasgnMagic.size()> magic_buf{};
    if (!cur.read_bytes(magic_buf.data(), magic_buf.size())) {
        return Unexpected{make_error(ErrorKind::kFlirtTruncated, "header magic")};
    }
    for (std::size_t i = 0; i < kIdasgnMagic.size(); ++i) {
        if (std::byte{magic_buf[i]} != kIdasgnMagic[i]) {
            return Unexpected{make_error(
                ErrorKind::kFlirtBadMagic, "first 6 bytes are not IDASGN")};
        }
    }

    FlirtHeader hdr;
    std::uint8_t version_byte = 0;
    if (!cur.read_u8(version_byte)) {
        return Unexpected{make_error(ErrorKind::kFlirtTruncated, "version")};
    }
    if (!is_supported_version(version_byte)) {
        return Unexpected{make_error(
            ErrorKind::kFlirtUnsupportedVersion,
            "version " + std::to_string(version_byte) + " is outside [8, 10]")};
    }
    hdr.version = version_byte;

    std::uint8_t arch_byte = 0;
    if (!cur.read_u8(arch_byte)) {
        return Unexpected{make_error(ErrorKind::kFlirtTruncated, "arch")};
    }
    switch (arch_byte) {
        case 0:  hdr.arch = FlirtArch::kAny;   break;
        case 1:  hdr.arch = FlirtArch::kX86;   break;
        case 2:  hdr.arch = FlirtArch::kX64;   break;
        default: hdr.arch = FlirtArch::kOther; break;
    }

    if (!cur.read_u32_le(hdr.file_types)
        || !cur.read_u16_le(hdr.os_types)
        || !cur.read_u16_le(hdr.app_types)
        || !cur.read_u16_le(hdr.features)
        || !cur.read_u16_le(hdr.old_n_functions)
        || !cur.read_u16_le(hdr.pattern_crc16)) {
        return Unexpected{make_error(ErrorKind::kFlirtTruncated, "header body")};
    }

    if (!cur.read_bytes(reinterpret_cast<std::uint8_t*>(hdr.ctype.data()),
                        hdr.ctype.size())) {
        return Unexpected{make_error(ErrorKind::kFlirtTruncated, "ctype")};
    }

    if (!cur.read_u8(hdr.library_name_len)
        || !cur.read_u16_le(hdr.ctypes_crc16)) {
        return Unexpected{make_error(ErrorKind::kFlirtTruncated, "ln_len/ctypes_crc16")};
    }

    if (hdr.version >= 9) {
        if (!cur.read_u32_le(hdr.n_functions)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "n_functions")};
        }
    }
    if (hdr.version >= 10) {
        if (!cur.read_u16_le(hdr.pattern_size)
            || !cur.read_u16_le(hdr.unknown_v10)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "v10 fields")};
        }
    }

    if (hdr.library_name_len > 0U) {
        const auto ln = static_cast<std::size_t>(hdr.library_name_len);
        std::vector<std::uint8_t> name_buf(ln);
        if (!cur.read_bytes(name_buf.data(), ln)) {
            return Unexpected{make_error(
                ErrorKind::kFlirtTruncated, "library_name body")};
        }
        hdr.library_name.assign(name_buf.begin(), name_buf.end());
    }

    return hdr;
}

namespace {

// Trailing parsing-flags byte after each module. Bits drive the leaf loops
constexpr std::uint8_t kMorePublicNames        = 0x01;
constexpr std::uint8_t kTailBytes              = 0x02;
constexpr std::uint8_t kReferencedFunctions    = 0x04;
constexpr std::uint8_t kMoreModulesWithSameCrc = 0x08;
constexpr std::uint8_t kMoreModules            = 0x10;

// A name's bytes are all >= 0x20. A byte below that, when peeked before the
// name characters, is an optional per-name flag byte rather than text
constexpr std::uint8_t kNameTextFloor          = 0x20;

// Per-name flag-byte bits (the optional control byte that precedes a name). LOCAL marks
// a local rather than public symbol
constexpr std::uint8_t kNameLocal              = 0x02;
constexpr std::uint8_t kNameNegativeOffset     = 0x10;

// FLAIR's vword. Counts and offsets are vint16 before v9 and vint32 from v9
// on. The result rides in a u32 either way
[[nodiscard]] bool read_word(ByteCursor& cur, std::uint8_t version,
                             std::uint32_t& out) noexcept {
    if (version < 9U) {
        std::uint16_t v = 0;
        if (!cur.read_vle16(v)) {
            return false;
        }
        out = v;
        return true;
    }
    return cur.read_vle32(out);
}

// Reads the variant mask whose set bits mark wildcard positions. The read width
// follows the segment length, a 2-byte vint below 0x10 and otherwise a 4-byte vint
[[nodiscard]] bool read_variant_mask(ByteCursor& cur, std::uint16_t length,
                                     std::uint64_t& out) noexcept {
    if (length == 0U) {
        out = 0U;
        return true;
    }
    if (length < 0x10U) {
        std::uint16_t v = 0;
        if (!cur.read_vle16(v)) {
            return false;
        }
        out = v;
        return true;
    }
    std::uint32_t v = 0;
    if (!cur.read_vle32(v)) {
        return false;
    }
    out = v;
    return true;
}

// Parses the public/local name records of one module into `out`
[[nodiscard]] Expected<std::uint8_t> parse_module_names(
    ByteCursor& cur, std::uint8_t version, std::vector<FlirtName>& out) noexcept {
    std::uint8_t flags = 0;
    std::int64_t base_offset = 0;
    for (;;) {
        std::uint32_t relative_offset = 0;
        if (!read_word(cur, version, relative_offset)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "name offset")};
        }

        std::uint8_t peek = 0;
        if (!cur.read_u8(peek)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "name lead")};
        }
        // A control byte here is the per-name flag byte. Real text starts at
        // the next byte. Otherwise the byte just read is the first character
        std::uint8_t name_flags = 0;
        if (peek < kNameTextFloor) {
            name_flags = peek;
            if (!cur.read_u8(peek)) {
                return Unexpected{make_error(ErrorKind::kFlirtTruncated, "name first char")};
            }
        }
        // Consume the name. Characters run until a control byte, which is the
        // trailing parsing-flags byte and is left consumed in `peek`
        std::string name;
        while (peek >= kNameTextFloor) {
            name.push_back(static_cast<char>(peek));
            std::uint8_t next = 0;
            if (!cur.read_u8(next)) {
                return Unexpected{make_error(ErrorKind::kFlirtTruncated, "name body")};
            }
            peek = next;
        }
        flags = peek;

        const std::int64_t rel = static_cast<std::int64_t>(relative_offset);
        const std::int64_t offset = (name_flags & kNameNegativeOffset) != 0U
            ? base_offset - rel
            : base_offset + rel;
        base_offset = offset;

        FlirtName entry;
        entry.offset = offset;
        entry.name   = std::move(name);
        entry.type   = (name_flags & kNameLocal) != 0U
            ? FlirtNameType::kLocal
            : FlirtNameType::kPublic;
        out.push_back(std::move(entry));

        if ((flags & kMorePublicNames) == 0U) {
            break;
        }
    }
    return flags;
}

// Parses the tail-byte records that may follow a module's names into `out`
[[nodiscard]] Expected<bool> parse_tail_bytes(
    ByteCursor& cur, std::uint8_t version, std::vector<FlirtTailByte>& out) noexcept {
    std::uint32_t count = 1;
    if (version >= 8U) {
        if (!read_word(cur, version, count)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "tail count")};
        }
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t offset = 0;
        std::uint8_t value = 0;
        if (!read_word(cur, version, offset) || !cur.read_u8(value)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "tail byte")};
        }
        FlirtTailByte entry;
        entry.offset = offset;
        entry.value  = value;
        out.push_back(entry);
    }
    return true;
}

// Parses referenced-function records into `out`. Each is an absolute, function-relative
// offset plus a size byte and that many name characters
[[nodiscard]] Expected<bool> parse_referenced_functions(
    ByteCursor& cur, std::uint8_t version, std::vector<FlirtReference>& out) noexcept {
    std::uint32_t count = 1;
    if (version >= 8U) {
        if (!read_word(cur, version, count)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "ref count")};
        }
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t offset = 0;
        if (!read_word(cur, version, offset)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "ref offset")};
        }
        std::uint8_t size_byte = 0;
        if (!cur.read_u8(size_byte)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "ref size")};
        }
        std::uint32_t name_len = size_byte;
        if (size_byte == 0U) {
            std::uint16_t real = 0;
            if (!cur.read_vle16(real)) {
                return Unexpected{make_error(ErrorKind::kFlirtTruncated, "ref size ext")};
            }
            name_len = real;
        }
        std::string name;
        name.reserve(name_len);
        for (std::uint32_t k = 0; k < name_len; ++k) {
            std::uint8_t ch = 0;
            if (!cur.read_u8(ch)) {
                return Unexpected{make_error(ErrorKind::kFlirtTruncated, "ref name")};
            }
            name.push_back(static_cast<char>(ch));
        }
        FlirtReference entry;
        entry.offset = offset;
        entry.name   = std::move(name);
        out.push_back(std::move(entry));
    }
    return true;
}

// Parses the module records of a leaf node into `out`
[[nodiscard]] Expected<bool> parse_leaf_modules(
    ByteCursor& cur, std::uint8_t version,
    std::vector<FlirtModule>& out) noexcept {
    for (;;) {
        std::uint8_t crc_len = 0;
        std::uint16_t crc16 = 0;
        if (!cur.read_u8(crc_len)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "crc length")};
        }
        // The module CRC16 is stored most-significant byte first on disk
        std::uint8_t crc_hi = 0;
        std::uint8_t crc_lo = 0;
        if (!cur.read_u8(crc_hi) || !cur.read_u8(crc_lo)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "crc16")};
        }
        crc16 = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(crc_hi) << 8) | crc_lo);

        std::uint8_t flags = 0;
        for (;;) {
            std::uint32_t function_size = 0;
            if (!read_word(cur, version, function_size)) {
                return Unexpected{make_error(ErrorKind::kFlirtTruncated, "function size")};
            }

            FlirtModule module;
            module.tail_crc16    = crc16;
            module.tail_length   = crc_len;
            module.function_size = function_size;

            auto names = parse_module_names(cur, version, module.names);
            if (!names.has_value()) {
                return Unexpected{names.error()};
            }
            flags = names.value();

            if ((flags & kTailBytes) != 0U) {
                auto tb = parse_tail_bytes(cur, version, module.tail_bytes);
                if (!tb.has_value()) {
                    return Unexpected{tb.error()};
                }
            }
            if ((flags & kReferencedFunctions) != 0U) {
                auto rf = parse_referenced_functions(cur, version, module.references);
                if (!rf.has_value()) {
                    return Unexpected{rf.error()};
                }
            }

            out.push_back(std::move(module));

            if ((flags & kMoreModulesWithSameCrc) == 0U) {
                break;
            }
        }

        if ((flags & kMoreModules) == 0U) {
            break;
        }
    }
    return true;
}

// Recursively parses a tree node. A child count of zero turns the current node into a
// leaf carrying module records
[[nodiscard]] Expected<bool> parse_node(
    ByteCursor& cur, std::uint8_t version, FlirtNode& node,
    const FlirtPattern& prefix, std::size_t depth) noexcept {
    if (depth > kMaxTreeDepth) {
        return Unexpected{make_error(ErrorKind::kFlirtTooDeep, "tree depth")};
    }

    std::uint16_t child_count = 0;
    if (!cur.read_vle16(child_count)) {
        return Unexpected{make_error(ErrorKind::kFlirtTruncated, "child count")};
    }

    // Every node carries its accumulated pattern so the matcher can prune by
    // prefix while descending. Leaves additionally hold the module records
    node.pattern = prefix;
    if (child_count == 0U) {
        return parse_leaf_modules(cur, version, node.leaf_modules);
    }

    node.children.reserve(child_count);
    for (std::uint16_t i = 0; i < child_count; ++i) {
        std::uint16_t length = 0;
        if (version < 10U) {
            std::uint8_t b = 0;
            if (!cur.read_u8(b)) {
                return Unexpected{make_error(ErrorKind::kFlirtTruncated, "pattern length")};
            }
            length = b;
        } else if (!cur.read_vle16(length)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "pattern length")};
        }

        const std::size_t prefix_len = prefix.length;
        if (prefix_len + length > kMaxPatternLength) {
            return Unexpected{make_error(
                ErrorKind::kFlirtBadNode, "pattern exceeds max length")};
        }

        std::uint64_t mask = 0;
        if (!read_variant_mask(cur, length, mask)) {
            return Unexpected{make_error(ErrorKind::kFlirtTruncated, "variant mask")};
        }

        // The variant mask marks wildcard positions. Mask bit (length-1-p) governs
        // segment position p, matching the FLAIR layout
        std::size_t literal_count = 0;
        for (std::uint16_t bit = 0; bit < length; ++bit) {
            if ((mask & (std::uint64_t{1} << bit)) == 0U) {
                ++literal_count;
            }
        }

        std::array<std::uint8_t, kMaxPatternLength> literals{};
        if (literal_count > 0U) {
            if (!cur.read_bytes(literals.data(), literal_count)) {
                return Unexpected{make_error(ErrorKind::kFlirtTruncated, "pattern bytes")};
            }
        }

        FlirtPattern pattern = prefix;
        std::size_t next_literal = 0;
        for (std::uint16_t p = 0; p < length; ++p) {
            const std::size_t dst = prefix_len + p;
            if ((mask & (std::uint64_t{1} << (length - 1U - p))) != 0U) {
                pattern.wildcard.set(dst);
            } else {
                pattern.bytes[dst] = literals[next_literal];
                ++next_literal;
            }
        }
        pattern.length = static_cast<std::uint8_t>(prefix_len + length);

        auto child = std::make_unique<FlirtNode>();
        auto sub = parse_node(cur, version, *child, pattern, depth + 1U);
        if (!sub.has_value()) {
            return Unexpected{sub.error()};
        }
        node.children.push_back(std::move(child));
    }
    return true;
}

}  // namespace

Expected<FlirtTree> parse_sig_buffer(std::span<const std::uint8_t> sig) noexcept {
    auto header = parse_header(sig);
    if (!header.has_value()) {
        return Unexpected{header.error()};
    }
    FlirtHeader hdr = std::move(header.value());

    const std::size_t body_offset =
        header_size_for_version(hdr.version) +
        static_cast<std::size_t>(hdr.library_name_len);
    if (body_offset > sig.size()) {
        return Unexpected{make_error(ErrorKind::kFlirtTruncated, "body offset")};
    }
    const std::span<const std::uint8_t> body_span = sig.subspan(body_offset);

    std::vector<std::uint8_t> inflated;
    std::span<const std::uint8_t> body = body_span;
    if (hdr.is_compressed()) {
        auto decompressed = decompress_inflate(body_span);
        if (!decompressed.has_value()) {
            return Unexpected{decompressed.error()};
        }
        inflated = std::move(decompressed.value());
        body = inflated;
    }

    auto root = std::make_unique<FlirtNode>();
    ByteCursor cur{body};
    const FlirtPattern empty_prefix{};
    auto parsed = parse_node(cur, hdr.version, *root, empty_prefix, 0U);
    if (!parsed.has_value()) {
        return Unexpected{parsed.error()};
    }

    return FlirtTree{std::move(hdr), std::move(root)};
}

}  // namespace papa::features::extractors::papa_native::flirt
