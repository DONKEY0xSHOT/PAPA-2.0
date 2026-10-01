#include "papa/features/extractors/papa_native/imports.h"

#include "papa/constants.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace papa::features::extractors::papa_native {

namespace {

// True when the four bytes at the given VA are the CET ENDBRANCH thunk prefix
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

// Decode the single instruction located at va, reading through the image. Used to walk
// a thunk chain one hop at a time
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

}  // namespace papa::features::extractors::papa_native
