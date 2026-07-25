#include "papa/features/extractors/papa_native/flirt_backend_context.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/insn.h"
#include "papa/pe/pe_image.h"

#include <algorithm>

namespace papa::features::extractors::papa_native {

namespace {

// The static reference a single instruction emits, if any. A call or jump
// yields a code reference to its target. Any other instruction that dereferences
// a fixed address yields a data reference. Register-indexed and register-only
// operands cannot be resolved statically and yield nothing
[[nodiscard]] std::optional<flirt::FlirtXref> resolve_xref(const DecodedInsn& ins) {
    if (ins.is_call || ins.is_jump) {
        if (ins.branch_target.has_value()) {
            return flirt::FlirtXref{*ins.branch_target, /*is_code=*/true};
        }
        if (ins.operand_count > 0) {
            const DecodedOperand& op = ins.operands[0];
            if (op.kind == OperandKind::kRipRel) {
                return flirt::FlirtXref{
                    ins.va + ins.length + static_cast<std::uint64_t>(op.disp), true};
            }
            if (op.kind == OperandKind::kImmMem) {
                return flirt::FlirtXref{static_cast<std::uint64_t>(op.disp), true};
            }
        }
        return std::nullopt;
    }
    for (std::size_t i = 0; i < ins.operand_count; ++i) {
        const DecodedOperand& op = ins.operands[i];
        if (op.kind == OperandKind::kRipRel) {
            return flirt::FlirtXref{
                ins.va + ins.length + static_cast<std::uint64_t>(op.disp), /*is_code=*/false};
        }
        if (op.kind == OperandKind::kImmMem) {
            return flirt::FlirtXref{static_cast<std::uint64_t>(op.disp), /*is_code=*/false};
        }
    }
    return std::nullopt;
}

}  // namespace

FlirtBackendContext::FlirtBackendContext(const PapaNativeBackend& backend) noexcept
    : backend_(&backend) {}

std::span<const std::uint8_t>
FlirtBackendContext::code_at(std::uint64_t va, std::size_t max_len) const {
    const auto& image = backend_->image();
    if (va < image.image_base()) {
        return {};
    }
    const std::uint64_t rva = va - image.image_base();
    auto bytes = image.read_at_rva(rva, max_len);
    if (!bytes) {
        // The section may end before max_len. Halve the window until a read fits
        for (std::size_t cap = max_len; cap > 0; cap >>= 1) {
            auto retry = image.read_at_rva(rva, cap);
            if (retry) { bytes = std::move(retry); break; }
        }
        if (!bytes) {
            return {};
        }
    }
    scratch_.clear();
    scratch_.reserve(bytes->size());
    for (const std::byte b : *bytes) {
        scratch_.push_back(static_cast<std::uint8_t>(b));
    }
    return scratch_;
}

bool FlirtBackendContext::is_function_entry(std::uint64_t va) const {
    const auto& funcs = backend_->functions();
    const auto it = std::lower_bound(
        funcs.begin(), funcs.end(), va,
        [](const Function& f, std::uint64_t v) noexcept { return f.va < v; });
    return it != funcs.end() && it->va == va;
}

std::optional<flirt::FlirtXref>
FlirtBackendContext::xref_from(std::uint64_t site_va) const {
    const auto& funcs = backend_->functions();
    // The only function that can contain site_va is the last one whose entry is
    // at or before it, since functions are sorted by entry VA
    auto it = std::upper_bound(
        funcs.begin(), funcs.end(), site_va,
        [](std::uint64_t v, const Function& f) noexcept { return v < f.va; });
    if (it == funcs.begin()) {
        return std::nullopt;
    }
    --it;
    for (const BasicBlock& bb : it->basic_blocks) {
        for (const DecodedInsn& ins : bb.instructions) {
            if (ins.va <= site_va && site_va < ins.va + ins.length) {
                return resolve_xref(ins);
            }
        }
    }
    return std::nullopt;
}

std::optional<std::string_view>
FlirtBackendContext::import_name(std::uint64_t va) const {
    const auto& by_iat = backend_->imports().by_iat_va;
    const auto it = by_iat.find(va);
    if (it == by_iat.end() || it->second == nullptr || it->second->name.empty()) {
        return std::nullopt;
    }
    return std::string_view(it->second->name);
}

}  // namespace papa::features::extractors::papa_native
