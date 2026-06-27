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

// True for the base registers CAPA excludes from memory-access offset features:
// the frame pointer (ebp/rbp) and the 32-bit stack pointer (esp). By a quirk of
// CAPA's register filter it keeps the 64-bit stack pointer (rsp), so offsets off
// rsp -- common when a function spills struct fields to stack locals -- must be
// emitted to match capa (viv/insn.py extract_insn_offset_features).
[[nodiscard]] bool is_offset_excluded_reg(ZydisRegister reg, bool is_64bit) noexcept {
    if (reg == ZYDIS_REGISTER_NONE) { return false; }
    const ZydisMachineMode mode =
        is_64bit ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    const ZydisRegister enclosing = ZydisRegisterGetLargestEnclosing(mode, reg);
    if (is_64bit) {
        return enclosing == ZYDIS_REGISTER_RBP;
    }
    return enclosing == ZYDIS_REGISTER_ESP || enclosing == ZYDIS_REGISTER_EBP;
}

// True when the instruction is "add esp, k" -- the single stack-management form
// CAPA suppresses as a Number-feature source. extract_op_number_features skips
// the immediate of `add esp, imm` (the cdecl cleanup after a call), keyed on the
// destination being the 32-bit esp specifically (opers[0].reg == REG_ESP). CAPA
// does NOT suppress `sub esp`, `add rsp`, or `sub rsp`, so neither do we
// (viv/insn.py extract_op_number_features).
[[nodiscard]] bool
is_add_esp(const DecodedInsn& ins) noexcept {
    if (ins.zyd_mnem != ZYDIS_MNEMONIC_ADD) { return false; }
    if (ins.operand_count < 1) { return false; }
    const auto& dst = ins.operands[0];
    return dst.kind == OperandKind::kReg && dst.base_reg == ZYDIS_REGISTER_ESP;
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
    // Partial decodes leave mnemonic_str empty. Skip them so we never construct
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
    const bool suppress_number = is_add_esp(ins);

    for (std::size_t i = 0; i < ins.operand_count; ++i) {
        const auto& op = ins.operands[i];
        if (op.kind != OperandKind::kImm && op.kind != OperandKind::kImmMem) { continue; }
        std::uint64_t v = (op.kind == OperandKind::kImm)
            ? op.imm
            : static_cast<std::uint64_t>(op.disp);

        // Zydis sign-extends a narrow immediate to 64 bits, so imm32 0xefcdab89
        // arrives as 0xffffffffefcdab89. CAPA keeps the value at the operation
        // width, which is the destination operand's width, not the immediate's
        // encoded width: a sign-extended imm8 in "cmp eax, 0xcc" stays
        // 0xffffffcc, while "cmp al, 0xcc" is 0xcc. Mask to the first register
        // or memory operand's width to match (e.g. the MD5/SHA1 magic constants).
        if (op.kind == OperandKind::kImm) {
            // Default to the architecture pointer width so an imm-only
            // instruction (push 0x80000002) masks to its real width instead of
            // keeping Zydis's 64-bit sign extension. A register or memory operand
            // overrides it with the destination width (cmp eax, 0xcc -> 0xffffffcc).
            std::size_t op_width = is_64bit ? 8U : 4U;
            for (std::size_t j = 0; j < ins.operand_count; ++j) {
                const auto k = ins.operands[j].kind;
                if (k == OperandKind::kReg || k == OperandKind::kRegMem ||
                    k == OperandKind::kRipRel || k == OperandKind::kImmMem ||
                    k == OperandKind::kSib) {
                    op_width = ins.operands[j].width_bytes;
                    break;
                }
            }
            if (op_width >= 1U && op_width < 8U) {
                v &= (std::uint64_t{1} << (op_width * 8U)) - 1U;
            }
        }

        // CAPA suppresses the number only of `add esp, imm` (the cdecl call
        // cleanup). See is_add_esp. Every other add/sub keeps its number.
        if (suppress_number) { continue; }

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

        // "add reg, small_imm" doubles as a struct-offset hint in MSVC code.
        // capa restricts this to add, not sub (extract_op_number_features), so a
        // sub immediate is never surfaced as an offset.
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_ADD &&
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
        // capa excludes the stack and frame pointer only for a plain ModRM
        // [reg+disp] operand (i386RegMemOper, no SIB byte). A SIB-encoded operand
        // (i386SibOper, which includes [rsp+disp] since rsp forces a SIB byte, and
        // any indexed [base+idx*scale+disp]) is never excluded, so it yields its
        // offset even on a stack or frame base. sib_encoded, not the operand kind,
        // is what tells the two apart (papa keys kind on the index register).
        if (!op.sib_encoded && is_offset_excluded_reg(op.base_reg, is_64bit)) { continue; }

        // For a SIB operand with no base register the displacement is an absolute
        // address: vivisect stores it as i386SibOper.imm and leaves disp 0, so the
        // offset is 0. That is how capa counts gs:[0x60] as offset(0) (the second
        // InLoadOrderModuleList walk step the runtime-linking rules need). A SIB
        // with a base, and any plain [reg+disp], keep the displacement as offset.
        const std::int64_t off =
            (op.kind == OperandKind::kSib && op.base_reg == ZYDIS_REGISTER_NONE)
                ? std::int64_t{0}
                : op.disp;

        // A zero displacement is still an offset. capa emits offset(0) for a bare
        // [reg] dereference, which is how the runtime-linking rules count the
        // mov reg, [reg] steps that walk PEB_LDR_DATA InLoadOrderModuleList.Flink.
        out.emplace_back(
            std::make_shared<const features::Offset>(off),
            va_addr(ins.va));
        out.emplace_back(
            std::make_shared<const features::OperandOffset>(i, off),
            va_addr(ins.va));

        // For "lea reg, [reg + off]" where off does not point at readable memory,
        // CAPA also surfaces the displacement as a Number because the LEA is
        // commonly used to materialize plain integer constants. A stack/frame
        // base means the lea computes a local address, not a constant, so it is
        // excluded here even though rsp offsets are kept above. CAPA only does
        // this in its i386RegMemOper branch, so a SIB-encoded operand (the
        // i386SibOper branch, e.g. "lea rcx, [r12 + 0xB8]" where r12 forces a SIB
        // byte) yields an offset only and never a number. Matching this stopped a
        // false get-number-of-processors match on msedge.
        if (ins.zyd_mnem == ZYDIS_MNEMONIC_LEA && op.disp > 0 &&
            !is_stack_reg(op.base_reg, is_64bit) && !op.sib_encoded) {
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
    // CAPA inspects the second operand (vivisect orders xor's destination first)
    // and rejects a cookie only when that operand is a register that is not a
    // stack or frame pointer. An immediate or memory operand still reaches the
    // prologue/epilogue position check, so "xor reg, imm" early in the entry
    // block counts as a cookie just as in viv/insn.py is_security_cookie.
    if (ins.operand_count < 2) { return false; }
    const auto& src = ins.operands[1];
    if (src.kind == OperandKind::kReg && !is_stack_reg(src.base_reg, is_64bit)) {
        return false;
    }
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
    const bool is_branch = ins.is_call || ins.is_jump;
    if (!is_branch)                  { return std::nullopt; }
    if (ins.va < image.image_base()) { return std::nullopt; }

    // The address whose section is compared against the branch site. For a
    // direct branch it is the branch target. For a branch through a memory
    // pointer (call/jmp [rip+disp] on x64, [abs] on x86) vivisect reports the
    // operand's data slot, not the dereferenced code pointer, so a call into a
    // function-pointer table in .rdata counts as cross-section flow. Register
    // and otherwise-unresolved indirect branches yield no static target.
    std::uint64_t target = 0;
    if (ins.branch_target.has_value()) {
        target = *ins.branch_target;
    } else if (ins.operand_count > 0 &&
               ins.operands[0].kind == OperandKind::kRipRel) {
        target = ins.va + ins.length +
                 static_cast<std::uint64_t>(ins.operands[0].disp);
    } else if (ins.operand_count > 0 &&
               ins.operands[0].kind == OperandKind::kImmMem) {
        target = static_cast<std::uint64_t>(ins.operands[0].disp);
    } else {
        return std::nullopt;
    }

    // A branch that reads its target from an IAT slot is an ordinary import,
    // not cross-section-flow evidence. CAPA filters these out.
    if (imports.by_iat_va.find(target) != imports.by_iat_va.end()) {
        return std::nullopt;
    }

    if (target < image.image_base()) { return std::nullopt; }
    const std::uint64_t src_rva = ins.va - image.image_base();
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

// Decode the single instruction located at va, reading through the image
// Used to walk a thunk chain one hop at a time. The section may end inside the
// candidate instruction, so the request is binary-shrunk to the largest
// readable prefix before decoding.
[[nodiscard]] std::optional<DecodedInsn>
decode_insn_at(const ::papa::pe::PeImage& image,
               const Disassembler&        disasm,
               std::uint64_t              va) {
    if (va < image.image_base()) { return std::nullopt; }
    constexpr std::size_t kMaxFetch = ::papa::constants::kMaxInsnBytes;
    auto r = image.read_at_rva(va - image.image_base(), kMaxFetch);
    if (!r) {
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
    return *decoded;
}

}  // namespace

std::vector<FeatureWithAddress> extract_flirt_call_api(
    const DecodedInsn& ins,
    const std::function<std::optional<std::string>(std::uint64_t)>& flirt_name) {
    std::vector<FeatureWithAddress> out;
    if (!flirt_name) { return out; }

    const bool is_tail_jmp = ins.is_jump && !ins.is_conditional;
    if (!ins.is_call && !is_tail_jmp) { return out; }
    if (ins.operand_count == 0) { return out; }
    if (ins.operands[0].kind != OperandKind::kPcRel) { return out; }
    if (!ins.branch_target.has_value()) { return out; }

    const auto name = flirt_name(*ins.branch_target);
    if (!name.has_value() || name->empty()) { return out; }

    // capa yields the library name and, for a leading-underscore name, the form
    // with one underscore removed (e.g. __beginthreadex yields _beginthreadex),
    // so a rule can match either spelling.
    out.emplace_back(std::make_shared<const features::Api>(*name), va_addr(ins.va));
    if (name->front() == '_' && name->size() > 1U) {
        out.emplace_back(std::make_shared<const features::Api>(name->substr(1)),
                         va_addr(ins.va));
    }
    return out;
}

const ::papa::pe::ParsedImport*
resolve_direct_call_import(const DecodedInsn&         ins,
                           const ::papa::pe::PeImage& image,
                           const ImportTable&         imports,
                           const Disassembler&        disasm) {
    if (ins.operand_count == 0) { return nullptr; }
    const auto& op0 = ins.operands[0];

    const auto lookup = [&](std::uint64_t iat_va) -> const ::papa::pe::ParsedImport* {
        const auto it = imports.by_iat_va.find(iat_va);
        return it == imports.by_iat_va.end() ? nullptr : it->second;
    };

    switch (op0.kind) {
        case OperandKind::kImmMem:
            return lookup(static_cast<std::uint64_t>(op0.disp));

        case OperandKind::kRipRel:
            return lookup(ins.va + ins.length + static_cast<std::uint64_t>(op0.disp));

        case OperandKind::kPcRel: {
            std::optional<std::uint64_t> target = ins.branch_target;
            if (!target.has_value()) { return nullptr; }

            for (std::size_t hop = 0;
                 hop < ::papa::constants::kThunkChainDepthDelta; ++hop) {
                if (const auto* row = lookup(*target)) { return row; }
                if (has_endbranch_prefix(image, *target)) {
                    *target += ::papa::constants::kEndbranchSkipLen;
                }
                const auto step = decode_insn_at(image, disasm, *target);
                if (!step.has_value()) { return nullptr; }
                const auto& d = *step;
                if ((!d.is_jump && !d.is_call) || d.is_conditional ||
                    d.operand_count == 0) {
                    return nullptr;
                }
                const auto& thunk_op = d.operands[0];
                if (thunk_op.kind == OperandKind::kRipRel) {
                    return lookup(d.va + d.length +
                                  static_cast<std::uint64_t>(thunk_op.disp));
                }
                if (thunk_op.kind == OperandKind::kImmMem) {
                    return lookup(static_cast<std::uint64_t>(thunk_op.disp));
                }
                if (thunk_op.kind == OperandKind::kPcRel) {
                    if (!d.branch_target.has_value()) { return nullptr; }
                    target = d.branch_target;
                    continue;
                }
                return nullptr;
            }
            return nullptr;
        }

        default:
            return nullptr;
    }
}

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

    // CAPA extracts API features from call and unconditional jmp instructions
    // A tail-call jmp through the IAT or a thunk chain is an API use just like a
    // call. Library and thunk functions are filtered out before extraction, so a
    // forwarder's own jmp never reaches here.
    const bool is_tail_jmp = ins.is_jump && !ins.is_conditional;
    if (!ins.is_call && !is_tail_jmp) { return out; }
    if (ins.operand_count == 0)       { return out; }

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
        case OperandKind::kRipRel:
        case OperandKind::kPcRel:
            // Direct IAT call or thunk chain. The shared resolver applies the
            // same operand and thunk-walk logic the no-return oracle relies on,
            // so both agree on which import a call reaches.
            if (const auto* row =
                    resolve_direct_call_import(ins, image, imports, disasm)) {
                emit_api_variants(*row, ins.va, out);
            }
            break;

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
