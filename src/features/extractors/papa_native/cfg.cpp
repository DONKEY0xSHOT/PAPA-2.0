#include "papa/features/extractors/papa_native/cfg.h"

#include "papa/constants.h"
#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/emu_discovery.h"
#include "papa/features/extractors/papa_native/jump_tables.h"
#include "papa/features/extractors/papa_native/noreturn.h"
#include "papa/features/extractors/papa_native/viv/engine.h"
#include "papa/pe/pe_image.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

namespace {

// Read a little-endian scalar from a byte span with full bounds checks
template <typename T>
[[nodiscard]] bool read_le(std::span<const std::byte> buf, std::size_t off, T& out) noexcept {
    if (off > buf.size() || sizeof(T) > buf.size() - off) {
        return false;
    }
    std::memcpy(&out, buf.data() + off, sizeof(T));
    return true;
}

// True when va lies within the image's virtual footprint
[[nodiscard]] bool va_in_image(const pe::PeImage& image, std::uint64_t va) noexcept {
    const std::uint64_t base = image.image_base();
    if (va < base) {
        return false;
    }
    const std::uint64_t rva = va - base;
    return rva < image.size_of_image();
}

struct PdataRanges {
    std::vector<std::pair<std::uint64_t, std::uint64_t>>  ranges;     // sorted by start
    std::unordered_set<std::uint64_t>                     starts;     // VA set
};

/// Iterate the .pdata RUNTIME_FUNCTION array and harvest authoritative
/// function entry points and end addresses. The end is exclusive
[[nodiscard]] PdataRanges collect_pdata_ranges(const pe::PeImage& image) {
    PdataRanges out;
    if (!image.is_64bit()) { return out; }
    const pe::ParsedSection* pdata = nullptr;
    for (const auto& s : image.sections()) {
        if (s.name == ".pdata") { pdata = &s; break; }
    }
    if (pdata == nullptr) { return out; }
    // raw_size is an unvalidated section-header field, so it cannot size an
    // allocation on its own. Clamp to the records the image can actually supply
    const std::size_t count = std::min<std::size_t>(
        {pdata->raw_size / constants::kRuntimeFunctionSize,
         image.readable_bytes_at_rva(pdata->virtual_address) /
             constants::kRuntimeFunctionSize,
         constants::kMaxPdataEntries});
    out.ranges.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t off = std::uint64_t{pdata->virtual_address} +
                                  i * constants::kRuntimeFunctionSize;
        auto bytes = image.read_at_rva(off, constants::kRuntimeFunctionSize);
        if (!bytes) { break; }
        std::uint32_t begin_rva  = 0;
        std::uint32_t end_rva    = 0;
        std::uint32_t unwind_rva = 0;
        if (!read_le<std::uint32_t>(*bytes, 0, begin_rva))  { break; }
        if (!read_le<std::uint32_t>(*bytes, 4, end_rva))    { break; }
        if (!read_le<std::uint32_t>(*bytes, 8, unwind_rva)) { break; }
        // Read the UNWIND_INFO VerFlags byte and classify the entry the way vivisect
        // parsers/pe.py does
        std::optional<std::uint8_t> verflags;
        const std::uint64_t uiva = image.image_base() + unwind_rva;
        if (va_in_image(image, uiva)) {
            if (auto uw = image.read_at_rva(unwind_rva, 1); uw && !uw->empty()) {
                verflags = static_cast<std::uint8_t>((*uw)[0]);
            }
        }
        const PdataEntryKind kind = cfg::classify_pdata_unwind(verflags);
        if (kind == PdataEntryKind::kStop) { break; }
        if (kind == PdataEntryKind::kSkipChained) { continue; }

        const std::uint64_t begin_va = image.image_base() + begin_rva;
        const std::uint64_t end_va   = image.image_base() + end_rva;
        if (!va_in_image(image, begin_va)) { continue; }
        out.ranges.emplace_back(begin_va, end_va);
        out.starts.insert(begin_va);
    }
    std::sort(out.ranges.begin(), out.ranges.end());
    return out;
}

// Build the reverse-edge map: callees across all functions become callers
void fill_callers(std::vector<Function>& funcs) {
    std::unordered_map<std::uint64_t, std::size_t> by_va;
    by_va.reserve(funcs.size());
    for (std::size_t i = 0; i < funcs.size(); ++i) {
        by_va.emplace(funcs[i].va, i);
    }
    for (const auto& caller : funcs) {
        for (std::uint64_t callee_va : caller.callees) {
            auto it = by_va.find(callee_va);
            if (it == by_va.end()) {
                continue;
            }
            funcs[it->second].callers.push_back(caller.va);
        }
    }
    // Deduplicate per callee so one caller with two call sites counts once
    for (auto& f : funcs) {
        std::sort(f.callers.begin(), f.callers.end());
        f.callers.erase(std::unique(f.callers.begin(), f.callers.end()), f.callers.end());
    }
}

// A function start in code without a .pdata table sits just past a boundary, a return
// or alignment padding
[[nodiscard]] bool is_boundary_byte(std::uint8_t b) noexcept {
    return b == 0xC3U || b == 0xCCU || b == 0x90U;  // ret, int3 pad, nop pad
}

// True when the bytes begin with one of vivisect's i386 function-entry signatures,
// the exact set its funcentries pass matches
[[nodiscard]] bool is_x86_function_prologue(std::span<const std::uint8_t> b) noexcept {
    if (b.size() < 3U) {
        return false;
    }
    if (b[0] == 0x55U && b[1] == 0x8BU && b[2] == 0xECU) { return true; }  // push ebp / mov ebp, esp
    if (b[0] == 0x55U && b[1] == 0x89U && b[2] == 0xE5U) { return true; }  // push ebp / mov ebp, esp (gcc)
    if (b[0] == 0x56U && b[1] == 0x8BU && b[2] == 0xF1U) { return true; }  // push esi / mov esi, ecx
    if (b.size() >= 5U && b[0] == 0x8BU && b[1] == 0xFFU &&
        b[2] == 0x55U && b[3] == 0x8BU && b[4] == 0xECU) {
        return true;  // mov edi, edi / push ebp / mov ebp, esp
    }
    if (b.size() >= 8U && b[0] == 0x6AU && b[2] == 0x68U && b[7] == 0xE8U) {
        return true;  // push imm8 / push imm32 / call
    }
    return false;
}

}  // namespace

PdataEntryKind
cfg::classify_pdata_unwind(std::optional<std::uint8_t> verflags) noexcept {
    if (!verflags.has_value()) {
        return PdataEntryKind::kStop;
    }
    // VerFlags packs Version in bits 0..2 and Flags in bits 3..7
    const unsigned ver = static_cast<unsigned>(*verflags) & 0x07U;
    if (ver != 1U) {
        return PdataEntryKind::kStop;
    }
    constexpr unsigned kUnwFlagChainInfo = 0x04U;
    const unsigned flags = static_cast<unsigned>(*verflags) >> 3;
    if ((flags & kUnwFlagChainInfo) != 0U) {
        return PdataEntryKind::kSkipChained;
    }
    return PdataEntryKind::kSeed;
}

std::vector<std::uint64_t> cfg::pdata_function_begins(const pe::PeImage& image) {
    const auto pdata = collect_pdata_ranges(image);
    std::vector<std::uint64_t> begins(pdata.starts.begin(), pdata.starts.end());
    std::sort(begins.begin(), begins.end());
    return begins;
}

// Public: build a reader that decodes through a PE image's virtual space
InsnReader cfg::make_image_reader(const pe::PeImage& image, const Disassembler& disasm) {
    // The caller is responsible for keeping the image and disassembler alive
    // for the lifetime of the returned reader
    const pe::PeImage* img = &image;
    const Disassembler* dis = &disasm;
    return [img, dis](std::uint64_t va) -> Expected<DecodedInsn> {
        if (va < img->image_base()) {
            return Unexpected{make_error(ErrorKind::kOutOfBounds, "va below image base")};
        }
        const std::uint64_t rva = va - img->image_base();
        // Read up to one full x86 instruction
        // Near a section's end the returned span is shorter than that cap
        std::size_t want = constants::kMaxInsnBytes;
        auto bytes = img->read_at_rva(rva, want);
        while (!bytes && want > 0) {
            --want;
            bytes = img->read_at_rva(rva, want);
        }
        if (!bytes || bytes->empty()) {
            return Unexpected{make_error(ErrorKind::kOutOfBounds, "no bytes at va")};
        }
        return dis->decode(*bytes, va);
    };
}

// Public: build a reader over a fixed region
// Used by unit tests to feed synthetic instruction byte sequences
InsnReader cfg::make_span_reader(std::span<const std::byte> region,
                                 std::uint64_t base_va,
                                 const Disassembler& disasm) {
    const Disassembler* dis = &disasm;
    // Copy the span into the closure
    // The pointed-to buffer must outlive the returned reader
    return [region, base_va, dis](std::uint64_t va) -> Expected<DecodedInsn> {
        if (va < base_va) {
            return Unexpected{make_error(ErrorKind::kOutOfBounds, "va below region base")};
        }
        const std::uint64_t off = va - base_va;
        if (off >= region.size()) {
            return Unexpected{make_error(ErrorKind::kOutOfBounds, "va past region end")};
        }
        const std::size_t avail = std::min<std::size_t>(
            constants::kMaxInsnBytes, region.size() - static_cast<std::size_t>(off));
        return dis->decode(region.subspan(static_cast<std::size_t>(off), avail), va);
    };
}

std::vector<std::uint64_t> cfg::find_function_prologues(
    std::span<const std::uint8_t> code, std::uint64_t base_va,
    std::span<const std::uint8_t> covered) {
    std::vector<std::uint64_t> out;
    if (code.size() < 4U) {
        return out;
    }
    // Start at 1 so the boundary byte (code[i-1]) exists
    for (std::size_t i = 1U; i + 3U < code.size(); ++i) {
        if (i < covered.size() && covered[i] != 0U) {
            continue;
        }
        if (!is_boundary_byte(code[i - 1U])) {
            continue;
        }
        if (is_x86_function_prologue(code.subspan(i))) {
            out.push_back(base_va + static_cast<std::uint64_t>(i));
        }
    }
    return out;
}

Expected<RecoveredImage> cfg::recover(const pe::PeImage&  image,
                                           const Disassembler& disasm) {
    // The discovery engine runs the ordered passes and per-function analysis internally.
    // Only the caller edges are added here, being a whole-image view
    RecoveredImage out = viv::discover_functions(image, disasm);
    fill_callers(out.functions);
    return out;
}

}  // namespace papa::features::extractors::papa_native
