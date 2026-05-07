#include "papa/features/extractors/papa_native/insn.h"

#include "papa/constants.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/features/basic_block.h"
#include "papa/features/extractors/helpers.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/indirect_calls.h"
#include "papa/pe/pe_image.h"
#include "papa/util/string_utils.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::insn {

namespace {

// Spelling table for the characteristic features emitted by this module
// Kept in named constants because every name has to match a CAPA rule literal
// One typo here would cause every rule using the characteristic to silently miss
constexpr const char* kCharCallPlus5     = "call $+5";
constexpr const char* kCharIndirectCall  = "indirect call";
constexpr const char* kCharFsAccess      = "fs access";
constexpr const char* kCharGsAccess      = "gs access";
constexpr const char* kCharPebAccess     = "peb access";
constexpr const char* kCharNzxor         = "nzxor";
constexpr const char* kCharCrossSection  = "cross section flow";

// XOR mnemonics CAPA considers for the nzxor characteristic
// SSE/AVX variants are included because they appear in cryptographic loops
// where the underlying register pair often differs even when the symbolic
// operand text looks the same to a human reader
constexpr std::array<ZydisMnemonic, 4> kXorMnemonics{
    ZYDIS_MNEMONIC_XOR,
    ZYDIS_MNEMONIC_XORPS,
    ZYDIS_MNEMONIC_XORPD,
    ZYDIS_MNEMONIC_PXOR,
};

[[nodiscard]] features::Address va_addr(std::uint64_t va) noexcept {
    return features::Address{features::AbsoluteVirtualAddress{va}};
}

// Lift a Characteristic into an addressed feature pair
// Used by every characteristic-emitting extractor below
[[nodiscard]] FeatureWithAddress
make_characteristic(const char* name, std::uint64_t va) {
    return { std::make_shared<const features::Characteristic>(std::string(name)),
             va_addr(va) };
}

// True when the operand carries a memory access whose displacement matches
// the requested offset. Register and immediate operands are skipped
[[nodiscard]] bool
operand_disp_equals(const DecodedOperand& op, std::int64_t want) noexcept {
    switch (op.kind) {
        case OperandKind::kRegMem:
        case OperandKind::kSib:
        case OperandKind::kImmMem:
            return op.disp == want;
        default:
            return false;
    }
}

// Compute the absolute virtual address an operand points to, if any
// kImm:    the immediate is treated as a candidate pointer
// kImmMem: the displacement carries the absolute address directly
// kRipRel: target is ins.va + ins.length + disp on x64 RIP-relative encoding
// All other operand kinds return nullopt because they do not encode a fixed VA
[[nodiscard]] std::optional<std::uint64_t>
operand_target_va(const DecodedInsn& ins, const DecodedOperand& op) noexcept {
    switch (op.kind) {
        case OperandKind::kImm:
            return op.imm;
        case OperandKind::kImmMem:
            return static_cast<std::uint64_t>(op.disp);
        case OperandKind::kRipRel:
            return ins.va + ins.length + static_cast<std::uint64_t>(op.disp);
        default:
            return std::nullopt;
    }
}

// True when reg is a stack-pointer or frame-pointer for the given bitness
// Uses ZydisRegisterGetLargestEnclosing so partial-width aliases (sp/bp/esp/...) all resolve correctly
[[nodiscard]] bool is_stack_reg(ZydisRegister reg, bool is_64bit) noexcept {
    if (reg == ZYDIS_REGISTER_NONE) { return false; }
    const ZydisMachineMode mode =
        is_64bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    const ZydisRegister enclosing = ZydisRegisterGetLargestEnclosing(mode, reg);
    if (is_64bit) {
        return enclosing == ZYDIS_REGISTER_RSP || enclosing == ZYDIS_REGISTER_RBP;
    }
    return enclosing == ZYDIS_REGISTER_ESP || enclosing == ZYDIS_REGISTER_EBP;
}

// True when the instruction is "add esp, k" or "sub esp, k" (or rsp variants)
// Such instructions are suppressed as Number-feature sources because they
// describe stack-frame management rather than constants in user code
[[nodiscard]] bool
is_stack_adjust(const DecodedInsn& ins, bool is_64bit) noexcept {
    if (ins.zyd_mnem != ZYDIS_MNEMONIC_ADD &&
        ins.zyd_mnem != ZYDIS_MNEMONIC_SUB) {
        return false;
    }
    if (ins.operand_count < 2) { return false; }
    const auto& dst = ins.operands[0];
    const auto& src = ins.operands[1];
    if (dst.kind != OperandKind::kReg) { return false; }
    if (src.kind != OperandKind::kImm) { return false; }
    return is_stack_reg(dst.base_reg, is_64bit);
}

// Read at most cap bytes starting at va
// Returns an empty vector if the read fails or va is unreadable
[[nodiscard]] std::vector<std::byte>
read_bytes_capped(const ::papa::pe::PeImage& image,
                  std::uint64_t              va,
                  std::size_t                cap) {
    if (va == 0U || cap == 0U) { return {}; }
    if (va < image.image_base()) { return {}; }
    const std::uint64_t rva = va - image.image_base();
    auto reader = image.read_at_rva(rva, cap);
    if (!reader) {
        // Re-try with a smaller window when the section ends before cap
        // Probe the available size by binary stepping until a read succeeds
        std::size_t hi = cap;
        std::size_t lo = 0;
        while (hi - lo > 1U) {
            const std::size_t mid = lo + (hi - lo) / 2U;
            auto attempt = image.read_at_rva(rva, mid);
            if (attempt) { lo = mid; }
            else         { hi = mid; }
        }
        if (lo == 0U) { return {}; }
        auto final_read = image.read_at_rva(rva, lo);
        if (!final_read) { return {}; }
        return std::vector<std::byte>(final_read->begin(), final_read->end());
    }
    return std::vector<std::byte>(reader->begin(), reader->end());
}

// Read a printable string at va, trying ASCII then UTF-16LE
// Returns empty optional when no run of length >= kMinStringLength is found
[[nodiscard]] std::optional<std::string>
read_string_at_va(const ::papa::pe::PeImage& image, std::uint64_t va) {
    constexpr std::size_t kStringProbeBytes = 0x100;
    auto buf = read_bytes_capped(image, va, kStringProbeBytes);
    if (buf.empty()) { return std::nullopt; }

    // Find the first NUL byte to bound the candidate ASCII string
    std::size_t end = 0;
    while (end < buf.size() && buf[end] != std::byte{0x00}) { ++end; }
    if (end >= ::papa::constants::kMinStringLength) {
        std::string ascii_candidate;
        ascii_candidate.reserve(end);
        for (std::size_t i = 0; i < end; ++i) {
            ascii_candidate.push_back(static_cast<char>(buf[i]));
        }
        if (::papa::util::is_ascii_printable(ascii_candidate)) {
            return ascii_candidate;
        }
    }

    // UTF-16LE: read pairs of (printable_low, 0x00)
    std::size_t units = 0;
    while ((units * 2U) + 1U < buf.size()) {
        const auto low  = static_cast<std::uint8_t>(buf[units * 2U]);
        const auto high = static_cast<std::uint8_t>(buf[(units * 2U) + 1U]);
        if (low == 0U && high == 0U) { break; }
        if (high != 0U) { return std::nullopt; }
        if (!::papa::util::is_ascii_printable(low)) { return std::nullopt; }
        ++units;
    }
    if (units >= ::papa::constants::kMinStringLength) {
        std::string out;
        out.reserve(units);
        for (std::size_t i = 0; i < units; ++i) {
            out.push_back(static_cast<char>(buf[i * 2U]));
        }
        return out;
    }
    return std::nullopt;
}

// True when every byte in buf is zero
[[nodiscard]] bool all_zero(std::span<const std::byte> buf) noexcept {
    for (const auto b : buf) {
        if (b != std::byte{0x00}) { return false; }
    }
    return true;
}

}  // namespace

namespace {

/// Single-shared interned Mnemonic per Zydis enum value.
/// Most binaries use ~30 distinct mnemonics across 100K+ instructions, so
/// interning replaces 100K+ allocations with a one-time static table fill.
[[nodiscard]] const features::FeaturePtr&
interned_mnemonic(ZydisMnemonic m, std::string_view text) {
    static std::array<features::FeaturePtr, ZYDIS_MNEMONIC_MAX_VALUE + 1> table{};
    auto& slot = table[static_cast<std::size_t>(m)];
    if (!slot) {
        slot = std::make_shared<const features::Mnemonic>(std::string(text));
    }
    return slot;
}

}  // namespace

std::optional<FeatureWithAddress>
extract_mnemonic(const DecodedInsn& ins) {
    // Partial decodes leave mnemonic_str empty; skip them so we never construct
    // a Mnemonic feature with no value
    if (ins.mnemonic_str.empty()) { return std::nullopt; }
    return FeatureWithAddress{
        interned_mnemonic(ins.zyd_mnem, ins.mnemonic_str),
        va_addr(ins.va)
    };
}

std::optional<FeatureWithAddress>
extract_call_plus_5(const DecodedInsn& ins) {
    if (!ins.is_call) { return std::nullopt; }
    if (!ins.branch_target.has_value()) { return std::nullopt; }
    // The target equals the address of the instruction immediately following
    // the CALL when the relative offset encoded by the CALL is zero
    if (*ins.branch_target != ins.va + ::papa::constants::kCallPlus5Distance) {
        return std::nullopt;
    }
    return make_characteristic(kCharCallPlus5, ins.va);
}

std::optional<FeatureWithAddress>
extract_indirect_call(const DecodedInsn& ins) {
    if (!ins.is_call)              { return std::nullopt; }
    if (ins.operand_count == 0)    { return std::nullopt; }

    // CAPA classifies a CALL as indirect when the destination operand is a
    // register, a register-relative memory access, or a SIB memory access
    // Direct PC-relative and direct-imm-mem CALLs are not indirect
    const auto& op0 = ins.operands[0];
    switch (op0.kind) {
        case OperandKind::kReg:
        case OperandKind::kRegMem:
        case OperandKind::kSib:
            return make_characteristic(kCharIndirectCall, ins.va);
        default:
            return std::nullopt;
    }
}

std::vector<FeatureWithAddress>
extract_segment_access(const DecodedInsn& ins) {
    std::vector<FeatureWithAddress> out;
    if (ins.has_prefix_fs) {
        out.push_back(make_characteristic(kCharFsAccess, ins.va));
    }
    if (ins.has_prefix_gs) {
        out.push_back(make_characteristic(kCharGsAccess, ins.va));
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_bytes(const DecodedInsn& ins, const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    // CALLs target code
    // Their operands are not data sources for Bytes features
    if (ins.is_call) { return out; }

    for (std::size_t i = 0; i < ins.operand_count; ++i) {
        const auto& op = ins.operands[i];
        const auto target = operand_target_va(ins, op);
        if (!target.has_value()) { continue; }

        const std::uint64_t va = *target;
        if (va < image.image_base()) { continue; }
        if (!image.probe_readable(va - image.image_base(), 1)) { continue; }

        auto buf = read_bytes_capped(image, va, ::papa::constants::kMaxBytesFeatureSize);
        if (buf.empty())     { continue; }
        if (all_zero(buf))   { continue; }
        // Strings are surfaced separately by extract_string and would otherwise
        // produce noisy Bytes matches with no semantic value
        if (::papa::util::is_ascii_printable(std::string_view(
                reinterpret_cast<const char*>(buf.data()), buf.size()))) {
            continue;
        }
        if (::papa::util::is_utf16le_printable(buf)) { continue; }

        out.emplace_back(
            std::make_shared<const features::Bytes>(std::move(buf)),
            va_addr(ins.va));
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_number(const DecodedInsn& ins, const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    const bool is_64bit = image.is_64bit();
    const bool stack_adjust = is_stack_adjust(ins, is_64bit);

    for (std::size_t i = 0; i < ins.operand_count; ++i) {
        const auto& op = ins.operands[i];
        if (op.kind != OperandKind::kImm && op.kind != OperandKind::kImmMem) { continue; }
        const std::uint64_t v = (op.kind == OperandKind::kImm)
            ? op.imm
            : static_cast<std::uint64_t>(op.disp);

        // add esp, 4 / sub rsp, 0x20 carry stack-management semantics
        // Surface them as nothing so rules looking for real numeric constants
        // do not see frame-management noise
        if (stack_adjust) { continue; }

        // Pointer-like values are picked up by extract_bytes / extract_string
        // probe_readable expects an RVA, so subtract image base when possible
        if (v >= image.image_base()) {
            const std::uint64_t rva = v - image.image_base();
            if (image.probe_readable(rva, 1)) { continue; }
        }

        const features::Number::Value val{v};
        out.emplace_back(
            std::make_shared<const features::Number>(val),
            va_addr(ins.va));
        out.emplace_back(
            std::make_shared<const features::OperandNumber>(i, val),
            va_addr(ins.va));

        // "add reg, small_imm" doubles as a struct-offset hint in MSVC code
        // Range matches CAPA insn.py:84 which caps offsets at kMaxStructureSize
        if ((ins.zyd_mnem == ZYDIS_MNEMONIC_ADD ||
             ins.zyd_mnem == ZYDIS_MNEMONIC_SUB) &&
            ins.operand_count >= 2 &&
            ins.operands[0].kind == OperandKind::kReg &&
            !is_stack_reg(ins.operands[0].base_reg, is_64bit) &&
            v > 0U && v < ::papa::constants::kMaxStructureSize) {
            const std::int64_t signed_v = static_cast<std::int64_t>(v);
            out.emplace_back(
                std::make_shared<const features::Offset>(signed_v),
                va_addr(ins.va));
            out.emplace_back(
                std::make_shared<const features::OperandOffset>(i, signed_v),
                va_addr(ins.va));
        }
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_offset(const DecodedInsn& ins, const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    const bool is_64bit = image.is_64bit();

    for (std::size_t i = 0; i < ins.operand_count; ++i) {
        const auto& op = ins.operands[i];
        if (op.kind != OperandKind::kRegMem && op.kind != OperandKind::kSib) { continue; }
        // Stack-frame relative accesses describe local layout, not struct geometry
        if (is_stack_reg(op.base_reg, is_64bit)) { continue; }
        // Zero displacement carries no offset semantics worth surfacing
        if (op.disp == 0) { continue; }

        out.emplace_back(
            std::make_shared<const features::Offset>(op.disp),
            va_addr(ins.va));
        out.emplace_back(
            std::make_shared<const features::OperandOffset>(i, op.disp),
            va_addr(ins.va));

        // For "lea reg, [reg + off]" where off does not point at readable memory,
        // CAPA also surfaces the displacement as a Number because the LEA is
        // commonly used to materialize plain integer constants
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_LEA && op.disp > 0) {
            const std::uint64_t v = static_cast<std::uint64_t>(op.disp);
            const std::uint64_t rva =
                (v >= image.image_base()) ? (v - image.image_base()) : v;
            if (!image.probe_readable(rva, 1)) {
                const features::Number::Value num_v{v};
                out.emplace_back(
                    std::make_shared<const features::Number>(num_v),
                    va_addr(ins.va));
                out.emplace_back(
                    std::make_shared<const features::OperandNumber>(i, num_v),
                    va_addr(ins.va));
            }
        }
    }
    return out;
}

bool is_security_cookie(const Function&    fn,
                        const BasicBlock&  bb,
                        const DecodedInsn& ins,
                        bool               is_64bit) noexcept {
    // The cookie XOR always reads or writes a stack-relative register
    // CAPA inspects the second operand because vivisect orders xor's destination first
    if (ins.operand_count < 2) { return false; }
    const auto& src = ins.operands[1];
    if (src.kind != OperandKind::kReg) { return false; }
    if (!is_stack_reg(src.base_reg, is_64bit)) { return false; }
    if (fn.basic_blocks.empty())                { return false; }

    const auto& entry_bb = fn.basic_blocks.front();
    // Prologue window: first kSecurityCookieBytesDelta bytes of the entry block
    if (&bb == &entry_bb &&
        ins.va < entry_bb.va + ::papa::constants::kSecurityCookieBytesDelta) {
        return true;
    }
    // Epilogue window: last kSecurityCookieBytesDelta bytes before a return
    if (!bb.instructions.empty() && bb.instructions.back().is_return) {
        const auto& last = bb.instructions.back();
        const std::uint64_t bb_end = last.va + last.length;
        if (bb_end >= ::papa::constants::kSecurityCookieBytesDelta &&
            ins.va > bb_end - ::papa::constants::kSecurityCookieBytesDelta) {
            return true;
        }
    }
    return false;
}

std::optional<FeatureWithAddress>
extract_nzxor(const Function&    fn,
              const BasicBlock&  bb,
              const DecodedInsn& ins,
              bool               is_64bit) {
    if (std::find(kXorMnemonics.begin(), kXorMnemonics.end(), ins.zyd_mnem) ==
        kXorMnemonics.end()) {
        return std::nullopt;
    }
    if (ins.operand_count < 2) { return std::nullopt; }

    // "xor reg, reg" with the same register on both sides is a clear-to-zero
    // idiom and not nzxor evidence
    const auto& dst = ins.operands[0];
    const auto& src = ins.operands[1];
    if (dst.kind == OperandKind::kReg &&
        src.kind == OperandKind::kReg &&
        dst.base_reg == src.base_reg &&
        dst.base_reg != ZYDIS_REGISTER_NONE) {
        return std::nullopt;
    }

    if (is_security_cookie(fn, bb, ins, is_64bit)) { return std::nullopt; }

    return make_characteristic(kCharNzxor, ins.va);
}

std::vector<FeatureWithAddress>
extract_string(const DecodedInsn& ins, const ::papa::pe::PeImage& image) {
    std::vector<FeatureWithAddress> out;
    for (std::size_t i = 0; i < ins.operand_count; ++i) {
        const auto target = operand_target_va(ins, ins.operands[i]);
        if (!target.has_value()) { continue; }
        if (*target < image.image_base()) { continue; }

        auto s = read_string_at_va(image, *target);
        if (!s.has_value()) { continue; }
        if (s->size() < ::papa::constants::kMinStringLength) { continue; }

        out.emplace_back(
            std::make_shared<const features::String>(std::move(*s)),
            va_addr(ins.va));
    }
    return out;
}

std::optional<FeatureWithAddress>
extract_cross_section_flow(const DecodedInsn&         ins,
                           const ::papa::pe::PeImage& image,
                           const ImportTable&         imports) {
    // Only direct branches matter
    // Indirect targets go through registers and are handled by extract_api_features
    // when the target resolves to an IAT slot
    const bool is_branch = ins.is_call || ins.is_jump;
    if (!is_branch)                       { return std::nullopt; }
    if (!ins.branch_target.has_value())   { return std::nullopt; }
    if (ins.va < image.image_base())      { return std::nullopt; }

    const std::uint64_t target = *ins.branch_target;
    // Direct calls into the IAT cross sections by definition
    // They are not CAPA cross-section-flow evidence and are filtered out
    if (imports.by_iat_va.find(target) != imports.by_iat_va.end()) {
        return std::nullopt;
    }

    const std::uint64_t src_rva = ins.va - image.image_base();
    if (target < image.image_base()) { return std::nullopt; }
    const std::uint64_t dst_rva = target - image.image_base();

    const auto* src_section = image.section_containing_rva(src_rva);
    const auto* dst_section = image.section_containing_rva(dst_rva);
    if (src_section == nullptr || dst_section == nullptr) { return std::nullopt; }
    if (src_section == dst_section)                       { return std::nullopt; }

    return make_characteristic(kCharCrossSection, ins.va);
}

std::optional<FeatureWithAddress>
extract_peb_access(const DecodedInsn& ins, bool is_64bit) {
    // Each bitness reaches PEB through a different segment-prefixed offset
    // The instruction must wear the matching prefix and reference the matching
    // displacement on at least one operand for the pattern to qualify
    const std::int64_t want_disp = is_64bit
        ? static_cast<std::int64_t>(::papa::constants::kPebOffsetX64)
        : static_cast<std::int64_t>(::papa::constants::kPebOffsetX86);
    const bool prefix_ok = is_64bit ? ins.has_prefix_gs : ins.has_prefix_fs;
    if (!prefix_ok) { return std::nullopt; }

    for (std::size_t i = 0; i < ins.operand_count; ++i) {
        if (operand_disp_equals(ins.operands[i], want_disp)) {
            return make_characteristic(kCharPebAccess, ins.va);
        }
    }
    return std::nullopt;
}

}  // namespace papa::features::extractors::papa_native::insn

namespace papa::features::extractors::papa_native {

ImportTable build_import_table(const ::papa::pe::PeImage& image) {
    ImportTable table;
    const auto rows = image.imports();
    table.by_iat_va.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.iat_va == 0U) { continue; }
        table.by_iat_va.emplace(row.iat_va, &row);
    }
    return table;
}

}  // namespace papa::features::extractors::papa_native

namespace papa::features::extractors::papa_native::insn {

namespace {

// Emit one Api feature per generate_symbols variant and append to out
void emit_api_variants(const ::papa::pe::ParsedImport& imp,
                       std::uint64_t                   addr_va,
                       std::vector<FeatureWithAddress>& out) {
    // For ordinal-only imports the symbol is "#<ordinal>"
    // Otherwise the symbol is the named import as recorded by the PE parser
    std::string symbol;
    if (imp.by_ordinal) {
        symbol.reserve(2 + 10);
        symbol.push_back('#');
        symbol.append(std::to_string(imp.ordinal));
    } else {
        symbol = imp.name;
    }
    if (symbol.empty()) { return; }

    auto variants = ::papa::features::extractors::helpers::generate_symbols(
        imp.dll, symbol, /*include_dll=*/true);
    for (auto& v : variants) {
        out.emplace_back(
            std::make_shared<const features::Api>(std::move(v)),
            va_addr(addr_va));
    }
}

// True when the four bytes at the given VA are the CET ENDBRANCH thunk prefix
// CAPA skips 4 bytes when this prefix is present so the chain follower lines
// up with the actual JMP/CALL inside the thunk
[[nodiscard]] bool
has_endbranch_prefix(const ::papa::pe::PeImage& image, std::uint64_t va) noexcept {
    if (va < image.image_base()) { return false; }
    auto r = image.read_at_rva(va - image.image_base(),
                               ::papa::constants::kEndbranchSkipLen);
    if (!r) { return false; }
    const auto bytes = *r;
    if (bytes.size() < ::papa::constants::kEndbranchBytes.size()) { return false; }
    for (std::size_t i = 0; i < ::papa::constants::kEndbranchBytes.size(); ++i) {
        if (static_cast<std::uint8_t>(bytes[i]) !=
            ::papa::constants::kEndbranchBytes[i]) {
            return false;
        }
    }
    return true;
}

// Decode the instruction at va and return its branch target when the
// instruction is an unconditional direct JMP or CALL
// Returns nullopt for any other instruction shape because CAPA's thunk
// follower only follows direct unconditional control flow
[[nodiscard]] std::optional<std::uint64_t>
follow_one_thunk(const ::papa::pe::PeImage& image,
                 const Disassembler&        disasm,
                 std::uint64_t              va) {
    if (va < image.image_base()) { return std::nullopt; }
    constexpr std::size_t kMaxFetch = ::papa::constants::kMaxInsnBytes;
    auto r = image.read_at_rva(va - image.image_base(), kMaxFetch);
    if (!r) {
        // Section may end inside the candidate instruction
        // Binary-shrink the request to find the largest readable prefix
        std::size_t hi = kMaxFetch;
        std::size_t lo = 0;
        while (hi - lo > 1U) {
            const std::size_t mid = lo + (hi - lo) / 2U;
            auto attempt = image.read_at_rva(va - image.image_base(), mid);
            if (attempt) { lo = mid; }
            else         { hi = mid; }
        }
        if (lo == 0U) { return std::nullopt; }
        r = image.read_at_rva(va - image.image_base(), lo);
        if (!r) { return std::nullopt; }
    }
    auto decoded = disasm.decode(*r, va);
    if (!decoded) { return std::nullopt; }
    const auto& d = *decoded;
    const bool is_branch = d.is_jump || d.is_call;
    if (!is_branch)        { return std::nullopt; }
    if (d.is_conditional)  { return std::nullopt; }
    if (!d.branch_target.has_value()) { return std::nullopt; }
    return d.branch_target;
}

}  // namespace

std::vector<FeatureWithAddress>
extract_api_features(const Function&            fn,
                     const BasicBlock&          bb,
                     const DecodedInsn&         ins,
                     const ::papa::pe::PeImage& image,
                     const ImportTable&         imports,
                     const Disassembler&        disasm) {
    (void)fn;
    (void)bb;
    std::vector<FeatureWithAddress> out;

    // CAPA limits API extraction to call-class instructions
    // Jump-style thunks are followed only when the original instruction itself is a CALL
    if (!ins.is_call)              { return out; }
    if (ins.operand_count == 0)    { return out; }

    const auto& op0 = ins.operands[0];

    // Helper: look up a candidate IAT VA in the import table and emit variants
    const auto try_emit_from_iat = [&](std::uint64_t iat_va) -> bool {
        const auto it = imports.by_iat_va.find(iat_va);
        if (it == imports.by_iat_va.end()) { return false; }
        emit_api_variants(*it->second, ins.va, out);
        return true;
    };

    switch (op0.kind) {
        case OperandKind::kImmMem:
            try_emit_from_iat(static_cast<std::uint64_t>(op0.disp));
            break;

        case OperandKind::kRipRel: {
            const std::uint64_t target = ins.va + ins.length +
                                         static_cast<std::uint64_t>(op0.disp);
            try_emit_from_iat(target);
            break;
        }

        case OperandKind::kPcRel: {
            std::optional<std::uint64_t> target = op0.imm;
            if (!target.has_value() && ins.branch_target.has_value()) {
                target = ins.branch_target;
            }
            if (!target.has_value()) { break; }

            // Walk up to kThunkChainDepthDelta thunk hops
            // ENDBRANCH prefix is skipped at each hop because CET-protected
            // thunks land on the endbr instruction before the real control flow
            for (std::size_t hop = 0;
                 hop < ::papa::constants::kThunkChainDepthDelta; ++hop) {
                if (try_emit_from_iat(*target)) { break; }
                if (has_endbranch_prefix(image, *target)) {
                    *target += ::papa::constants::kEndbranchSkipLen;
                }
                auto next = follow_one_thunk(image, disasm, *target);
                if (!next.has_value()) { break; }
                target = next;
            }
            break;
        }

        case OperandKind::kReg: {
            // Indirect call through a register: backward-slice within the BB
            // The slicer returns the resolved constant when one is encoded
            // close enough to the call to be reliable
            auto def = find_definition(fn, ins.va, op0.base_reg, image.is_64bit());
            if (!def.has_value() || !def->value.has_value()) { break; }
            try_emit_from_iat(*def->value);
            break;
        }

        case OperandKind::kRegMem:
        case OperandKind::kSib:
        case OperandKind::kImm:
        case OperandKind::kUnknown:
            // No reliable IAT lookup possible from these operand shapes
            break;
    }
    return out;
}

}  // namespace papa::features::extractors::papa_native::insn
