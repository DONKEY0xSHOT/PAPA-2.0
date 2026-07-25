#include "papa/features/extractors/papa_native/basic_block.h"

#include "papa/constants.h"
#include "papa/features/address.h"
#include "papa/features/basic_block.h"
#include "papa/features/common.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/util/string_utils.h"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::basic_block {

namespace {

// CAPA spelling for the two basic-block characteristics
// Stored as named constants so any rename of the rule corpus changes one place
constexpr const char* kCharTightLoop   = "tight loop";
constexpr const char* kCharStackString = "stack string";

[[nodiscard]] features::Address va_addr(std::uint64_t va) noexcept {
    return features::Address{features::AbsoluteVirtualAddress{va}};
}

[[nodiscard]] FeatureWithAddress
make_characteristic(const char* name, std::uint64_t va) {
    return { std::make_shared<const features::Characteristic>(std::string(name)),
             va_addr(va) };
}

// Mirror of the same helper in insn.cpp
// Keeping it private here avoids a public dependency between the two extractor
// modules just to share a three-line predicate
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

// Count printable bytes in the low width_bytes octets of imm
// Returns the number of leading printable bytes
// Stops counting at the first non-printable byte and returns the partial count
[[nodiscard]] std::size_t
leading_printable_bytes(std::uint64_t imm, std::size_t width_bytes) noexcept {
    if (width_bytes == 0U) { return 0U; }
    std::size_t count = 0;
    for (std::size_t i = 0; i < width_bytes; ++i) {
        const std::uint8_t b =
            static_cast<std::uint8_t>((imm >> (i * 8U)) & 0xFFU);
        if (!::papa::util::is_ascii_printable(b)) { return count; }
        ++count;
    }
    return count;
}

// Default operand width when Zydis did not populate width_bytes
// Most stack-store operands are dword on x86 and qword on x64
// We conservatively fall back to four because that matches the common
// stack-string idiom in MSVC shellcode and minimizes false positives compared
// to assuming eight
constexpr std::size_t kDefaultStoreWidth = 4;

}  // namespace

std::optional<FeatureWithAddress>
extract_tight_loop(const BasicBlock& bb) {
    for (const std::uint64_t succ : bb.successors) {
        if (succ == bb.va) {
            return make_characteristic(kCharTightLoop, bb.va);
        }
    }
    return std::nullopt;
}

std::optional<FeatureWithAddress>
extract_stack_string(const BasicBlock& bb, bool is_64bit) {
    // Walk the block accumulating consecutive printable-byte stores into the
    // stack frame. Any non-matching instruction resets the accumulator
    std::size_t printable_run = 0;
    std::uint64_t run_anchor_va = bb.va;

    for (const auto& ins : bb.instructions) {
        const bool is_stack_store =
            ins.zyd_mnem == ZYDIS_MNEMONIC_MOV &&
            ins.operand_count >= 2 &&
            (ins.operands[0].kind == OperandKind::kRegMem ||
             ins.operands[0].kind == OperandKind::kSib) &&
            is_stack_reg(ins.operands[0].base_reg, is_64bit) &&
            ins.operands[1].kind == OperandKind::kImm;

        if (!is_stack_store) {
            printable_run = 0;
            run_anchor_va = ins.va + ins.length;
            continue;
        }

        const auto& src = ins.operands[1];
        const std::size_t width =
            src.width_bytes != 0U ? src.width_bytes : kDefaultStoreWidth;
        const std::size_t printable = leading_printable_bytes(src.imm, width);
        if (printable < width) {
            // Mixed instruction: count whatever leading bytes are printable
            // but reset because the next store cannot extend a partial run
            printable_run = printable;
            run_anchor_va = ins.va;
            if (printable_run >= ::papa::constants::kMinStackStringLen) {
                return make_characteristic(kCharStackString, run_anchor_va);
            }
            printable_run = 0;
            continue;
        }
        if (printable_run == 0U) { run_anchor_va = ins.va; }
        printable_run += printable;
        if (printable_run >= ::papa::constants::kMinStackStringLen) {
            return make_characteristic(kCharStackString, run_anchor_va);
        }
    }
    return std::nullopt;
}

/// Per-basic-block feature aggregate consumed by capabilities orchestration
std::vector<FeatureWithAddress>
extract_basic_block_features(const BasicBlock& bb, bool is_64bit) {
    std::vector<FeatureWithAddress> out;
    // Emit a BasicBlock tag feature for every BB
    // The function-scope FeatureSet aggregates these so count(basic blocks)
    // rules see one address per basic block in the parent function
    out.emplace_back(
        std::make_shared<const ::papa::features::BasicBlock>(),
        ::papa::features::Address{
            ::papa::features::AbsoluteVirtualAddress{bb.va}});
    if (auto tl = extract_tight_loop(bb); tl.has_value()) {
        out.push_back(std::move(*tl));
    }
    if (auto ss = extract_stack_string(bb, is_64bit); ss.has_value()) {
        out.push_back(std::move(*ss));
    }
    return out;
}

}  // namespace papa::features::extractors::papa_native::basic_block
