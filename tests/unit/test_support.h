#pragma once

#include "papa/constants.h"
#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/// Helpers shared by the unit tests
namespace papa_tests {

/// The listed values as a std::array of std::byte
template <typename... B>
[[nodiscard]] constexpr std::array<std::byte, sizeof...(B)> bytes(B... values) {
    return std::array<std::byte, sizeof...(B)>{std::byte{static_cast<std::uint8_t>(values)}...};
}

/// The listed values as a std::vector of std::byte
[[nodiscard]] inline std::vector<std::byte> byte_vec(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (const std::uint8_t b : values) { out.push_back(std::byte{b}); }
    return out;
}

/// The characters of text viewed as bytes. The text must outlive the span
[[nodiscard]] inline std::span<const std::byte> text_bytes(std::string_view text) noexcept {
    return std::as_bytes(std::span<const char>(text.data(), text.size()));
}

/// A register operand
[[nodiscard]] inline papa::features::extractors::papa_native::DecodedOperand
reg(ZydisRegister r, std::size_t width) {
    papa::features::extractors::papa_native::DecodedOperand op;
    op.kind        = papa::features::extractors::papa_native::OperandKind::kReg;
    op.base_reg    = r;
    op.width_bytes = width;
    return op;
}

/// An immediate operand
[[nodiscard]] inline papa::features::extractors::papa_native::DecodedOperand
imm(std::uint64_t value, std::size_t width) {
    papa::features::extractors::papa_native::DecodedOperand op;
    op.kind        = papa::features::extractors::papa_native::OperandKind::kImm;
    op.imm         = value;
    op.width_bytes = width;
    return op;
}

/// A [base + disp] memory operand
[[nodiscard]] inline papa::features::extractors::papa_native::DecodedOperand
mem(ZydisRegister base, std::int64_t disp, std::size_t width) {
    papa::features::extractors::papa_native::DecodedOperand op;
    op.kind        = papa::features::extractors::papa_native::OperandKind::kRegMem;
    op.base_reg    = base;
    op.disp        = disp;
    op.width_bytes = width;
    return op;
}

/// A two-byte instruction at 0x1000 with the given mnemonic and operands
template <typename... Ops>
[[nodiscard]] papa::features::extractors::papa_native::DecodedInsn
insn(ZydisMnemonic mnemonic, const Ops&... ops) {
    static_assert(sizeof...(Ops) <= papa::constants::kMaxOperandCount);
    const std::array<papa::features::extractors::papa_native::DecodedOperand, sizeof...(Ops)>
        list{ops...};
    papa::features::extractors::papa_native::DecodedInsn out;
    out.va       = 0x1000;
    out.length   = 2;
    out.zyd_mnem = mnemonic;
    std::copy(list.begin(), list.end(), out.operands.begin());
    out.operand_count = list.size();
    return out;
}

/// A function whose entry is the first block, made of the blocks in order
[[nodiscard]] inline papa::features::extractors::papa_native::Function
function(std::vector<papa::features::extractors::papa_native::BasicBlock> blocks) {
    papa::features::extractors::papa_native::Function fn;
    fn.va           = blocks.empty() ? 0U : blocks.front().va;
    fn.basic_blocks = std::move(blocks);
    return fn;
}

/// A function of one block holding insns, both starting at the first instruction
[[nodiscard]] inline papa::features::extractors::papa_native::Function
single_block_function(std::vector<papa::features::extractors::papa_native::DecodedInsn> insns) {
    const std::uint64_t entry = insns.empty() ? 0U : insns.front().va;
    return function({{entry, std::move(insns)}});
}

/// A rule around stmt with only its name, namespace and static scope set
[[nodiscard]] inline std::unique_ptr<papa::rules::Rule>
make_rule(std::string                               name,
          std::optional<std::string>                ns,
          papa::rules::Scope                        scope,
          std::unique_ptr<papa::engine::Statement>  stmt) {
    papa::rules::RuleMeta meta;
    meta.name                = std::move(name);
    meta.namespace_          = std::move(ns);
    meta.scopes.static_scope = scope;
    return std::make_unique<papa::rules::Rule>(std::move(meta), std::move(stmt), std::string{});
}

/// The embedded FLIRT signatures, decoded once per test process and shared
[[nodiscard]] inline const papa::features::extractors::papa_native::flirt::FlirtSignatureSet&
shared_flirt_sigs() {
    static const auto set =
        papa::features::extractors::papa_native::flirt::FlirtSignatureSet::make_embedded();
    return set;
}

/// An InsnReader over a contiguous region starting at base_va. The region and disasm
/// must outlive the returned reader
[[nodiscard]] inline papa::features::extractors::papa_native::InsnReader
make_span_reader(std::span<const std::byte> region, std::uint64_t base_va,
                 const papa::features::extractors::papa_native::Disassembler& disasm) {
    using papa::features::extractors::papa_native::DecodedInsn;
    const auto* dis = &disasm;
    return [region, base_va, dis](std::uint64_t va) -> papa::Expected<DecodedInsn> {
        if (va < base_va) {
            return papa::Unexpected{
                papa::make_error(papa::ErrorKind::kOutOfBounds, "va below region base")};
        }
        const std::uint64_t off = va - base_va;
        if (off >= region.size()) {
            return papa::Unexpected{
                papa::make_error(papa::ErrorKind::kOutOfBounds, "va past region end")};
        }
        const std::size_t avail = std::min<std::size_t>(
            papa::constants::kMaxInsnBytes, region.size() - static_cast<std::size_t>(off));
        return dis->decode(region.subspan(static_cast<std::size_t>(off), avail), va);
    };
}

}  // namespace papa_tests
