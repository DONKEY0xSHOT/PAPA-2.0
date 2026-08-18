#include "papa/features/extractors/papa_native/viv/flirt_analysis.h"

#include <span>
#include <utility>

#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/viv/discovery.h"
#include "papa/pe/pe_image.h"

namespace papa::features::extractors::papa_native::viv {

namespace {

// The static reference a single instruction emits, if any
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
                ins.va + ins.length + static_cast<std::uint64_t>(op.disp),
                /*is_code=*/false};
        }
        if (op.kind == OperandKind::kImmMem) {
            return flirt::FlirtXref{static_cast<std::uint64_t>(op.disp),
                                    /*is_code=*/false};
        }
    }
    return std::nullopt;
}

}  // namespace

DiscoveryFlirtContext::DiscoveryFlirtContext(const pe::PeImage& image,
                                             InsnReader read, const Discovery& disc)
    : image_(&image), read_(std::move(read)), disc_(&disc) {}

std::span<const std::uint8_t>
DiscoveryFlirtContext::code_at(std::uint64_t va, std::size_t max_len) const {
    if (va < image_->image_base()) {
        return {};
    }
    const std::uint64_t rva = va - image_->image_base();
    auto bytes = image_->read_at_rva(rva, max_len);
    if (!bytes) {
        // The section may end before max_len. Halve the window until a read fits
        for (std::size_t cap = max_len; cap > 0; cap >>= 1) {
            auto retry = image_->read_at_rva(rva, cap);
            if (retry) {
                bytes = std::move(retry);
                break;
            }
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

std::optional<flirt::FlirtXref>
DiscoveryFlirtContext::xref_from(std::uint64_t site_va) const {
    // vivisect resolves a reference through the instruction that contains the reference
    // offset (getLocation then getXrefsFrom)
    const auto loc = disc_->locations().get_location(site_va);
    if (!loc.has_value() || loc->type != LocType::kOp) {
        return std::nullopt;
    }
    const auto insn = read_(loc->va);
    if (!insn.has_value()) {
        return std::nullopt;
    }
    return resolve_xref(*insn);
}

std::optional<std::string_view>
DiscoveryFlirtContext::import_name(std::uint64_t /*va*/) const {
    // Reference validation resolves names through local library functions only,
    // never imports, so the discovery context does not surface import names
    return std::nullopt;
}

bool DiscoveryFlirtContext::is_function_entry(std::uint64_t va) const {
    return disc_->is_function(va);
}

FlirtDiscoveryAnalyzer::FlirtDiscoveryAnalyzer(
    std::vector<flirt::ModuleMatchFn> matchers,
    const flirt::FunctionContext& context, MakeFunction make_function,
    IsFunction is_function)
    : matchers_(std::move(matchers)),
      context_(&context),
      make_function_(std::move(make_function)),
      is_function_(std::move(is_function)) {}

void FlirtDiscoveryAnalyzer::apply_names(std::uint64_t             va,
                                         const flirt::FlirtModule& winner) {
    // Local names first, then public ones, so a public name takes precedence at an
    // address both kinds cover (viv_utils.flirt runs the loops in that order)
    for (const flirt::FlirtName& named : winner.names) {
        if (named.type != flirt::FlirtNameType::kLocal) {
            continue;
        }
        const std::uint64_t target = va + static_cast<std::uint64_t>(named.offset);
        if (!is_function_(target)) {
            make_function_(target);
        }
        if (is_function_(target)) {
            library_names_[target] = named.name;
        }
    }
    for (const flirt::FlirtName& named : winner.names) {
        if (named.type != flirt::FlirtNameType::kPublic) {
            continue;
        }
        const std::uint64_t target = va + static_cast<std::uint64_t>(named.offset);
        if (is_function_(target)) {
            library_names_[target] = named.name;
        }
    }
}

void FlirtDiscoveryAnalyzer::on_function(std::uint64_t va) {
    // A function an earlier signature already named is not re-matched, the
    // is_library_function short-circuit at the top of match_function_flirt_signatures
    if (library_names_.count(va) != 0) {
        return;
    }
    // capa registers one analyzer per signature file and they all run, in order, on
    // each function as it is made
    for (const flirt::ModuleMatchFn& matcher : matchers_) {
        if (library_names_.count(va) != 0) {
            break;
        }
        flirt::FlirtClassifier::Cache cache;
        const flirt::FlirtClassifier  classifier(
            matcher, *context_, cache,
            [this](std::uint64_t at, const flirt::FlirtModule& winner) {
                apply_names(at, winner);
            },
            [this](std::uint64_t at) -> std::optional<std::string> {
                const auto it = library_names_.find(at);
                if (it == library_names_.end()) {
                    return std::nullopt;
                }
                return it->second;
            });
        static_cast<void>(classifier.classify(va));
    }
}

}  // namespace papa::features::extractors::papa_native::viv
