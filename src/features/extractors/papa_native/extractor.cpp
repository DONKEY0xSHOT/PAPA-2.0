#include "papa/features/extractors/papa_native/extractor.h"

#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/features/extractors/pefile.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/basic_block.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/flirt/flirt_classifier.h"
#include "papa/features/extractors/papa_native/flirt/flirt_matcher.h"
#include "papa/features/extractors/papa_native/function.h"
#include "papa/features/extractors/papa_native/global_.h"
#include "papa/features/extractors/papa_native/insn.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace papa::features::extractors::papa_native {

namespace {

namespace base = ::papa::features::extractors;

// Recover the absolute VA from a public Address used by orchestrators
// Returns nullopt for non-VA addresses
// Orchestrators must never present FileOffsetAddress or NoAddress to
// per-scope extractors that look up real instructions or basic blocks
[[nodiscard]] std::optional<std::uint64_t>
absolute_va(const features::Address& addr) noexcept {
    if (const auto* a = std::get_if<features::AbsoluteVirtualAddress>(&addr)) {
        return a->v;
    }
    return std::nullopt;
}

// Lift a const Function* out of an opaque FunctionHandle.inner
// Throws PapaInvariantError when the handle did not originate from this backend
// because using a foreign handle indicates an orchestrator bug we want loud
[[nodiscard]] const Function&
function_from_handle(const base::FunctionHandle& fh) {
    if (fh.inner == nullptr) {
        throw ::papa::PapaInvariantError(
            "FunctionHandle.inner is null in PapaNativeStaticExtractor");
    }
    return *static_cast<const Function*>(fh.inner);
}

[[nodiscard]] const BasicBlock&
basic_block_from_handle(const base::BBHandle& bbh) {
    if (bbh.inner == nullptr) {
        throw ::papa::PapaInvariantError(
            "BBHandle.inner is null in PapaNativeStaticExtractor");
    }
    return *static_cast<const BasicBlock*>(bbh.inner);
}

[[nodiscard]] const DecodedInsn&
insn_from_handle(const base::InsnHandle& ih) {
    if (ih.inner == nullptr) {
        throw ::papa::PapaInvariantError(
            "InsnHandle.inner is null in PapaNativeStaticExtractor");
    }
    return *static_cast<const DecodedInsn*>(ih.inner);
}

[[nodiscard]] features::Address va_addr(std::uint64_t va) noexcept {
    return features::Address{features::AbsoluteVirtualAddress{va}};
}

}  // namespace

PapaNativeStaticExtractor::PapaNativeStaticExtractor(PapaNativeBackend backend)
    : backend_(std::move(backend)) {}

features::Address PapaNativeStaticExtractor::get_base_address() const {
    return va_addr(backend_.image().image_base());
}

std::vector<base::FeatureWithAddress>
PapaNativeStaticExtractor::extract_global_features() const {
    auto src = ::papa::features::extractors::papa_native::extract_global_features(
        backend_.image());
    std::vector<base::FeatureWithAddress> out;
    out.reserve(src.size());
    for (auto& fa : src) { out.push_back(std::move(fa)); }
    return out;
}

std::vector<base::FeatureWithAddress>
PapaNativeStaticExtractor::extract_file_features() const {
    auto src = ::papa::features::extractors::pefile::extract_file_features(
        backend_.image());
    std::vector<base::FeatureWithAddress> out;
    out.reserve(src.size());
    for (auto& fa : src) { out.push_back(std::move(fa)); }
    return out;
}

std::vector<base::FunctionHandle>
PapaNativeStaticExtractor::get_functions() const {
    const auto& funcs = backend_.functions();
    std::vector<base::FunctionHandle> out;
    out.reserve(funcs.size());
    for (const auto& fn : funcs) {
        base::FunctionHandle fh;
        fh.addr  = va_addr(fn.va);
        fh.inner = static_cast<const void*>(&fn);
        out.push_back(fh);
    }
    return out;
}

std::vector<base::FeatureWithAddress>
PapaNativeStaticExtractor::extract_function_features(
    const base::FunctionHandle& fh) const {
    const Function& fn = function_from_handle(fh);
    std::string symbol;
    if (auto va = absolute_va(fh.addr); va.has_value()) {
        if (auto it = function_names_.find(*va); it != function_names_.end()) {
            symbol = it->second;
        }
    }
    auto src = ::papa::features::extractors::papa_native::function_::
        extract_function_features(fn, symbol);
    std::vector<base::FeatureWithAddress> out;
    out.reserve(src.size());
    for (auto& fa : src) { out.push_back(std::move(fa)); }
    return out;
}

std::vector<base::BBHandle>
PapaNativeStaticExtractor::get_basic_blocks(const base::FunctionHandle& fh) const {
    const Function& fn = function_from_handle(fh);
    std::vector<base::BBHandle> out;
    out.reserve(fn.basic_blocks.size());
    for (const auto& bb : fn.basic_blocks) {
        base::BBHandle bbh;
        bbh.addr  = va_addr(bb.va);
        bbh.inner = static_cast<const void*>(&bb);
        out.push_back(bbh);
    }
    return out;
}

std::vector<base::FeatureWithAddress>
PapaNativeStaticExtractor::extract_basic_block_features(
    const base::FunctionHandle& /*fh*/,
    const base::BBHandle&       bbh) const {
    const BasicBlock& bb = basic_block_from_handle(bbh);
    auto src = ::papa::features::extractors::papa_native::basic_block::
        extract_basic_block_features(bb, backend_.image().is_64bit());
    std::vector<base::FeatureWithAddress> out;
    out.reserve(src.size());
    for (auto& fa : src) { out.push_back(std::move(fa)); }
    return out;
}

std::vector<base::InsnHandle>
PapaNativeStaticExtractor::get_instructions(const base::FunctionHandle& /*fh*/,
                                            const base::BBHandle&       bbh) const {
    const BasicBlock& bb = basic_block_from_handle(bbh);
    std::vector<base::InsnHandle> out;
    out.reserve(bb.instructions.size());
    for (const auto& ins : bb.instructions) {
        base::InsnHandle ih;
        ih.addr  = va_addr(ins.va);
        ih.inner = static_cast<const void*>(&ins);
        out.push_back(ih);
    }
    return out;
}

std::vector<base::FeatureWithAddress>
PapaNativeStaticExtractor::extract_insn_features(
    const base::FunctionHandle& fh,
    const base::BBHandle&       bbh,
    const base::InsnHandle&     ih) const {
    const Function&     fn       = function_from_handle(fh);
    const BasicBlock&   bb       = basic_block_from_handle(bbh);
    const DecodedInsn&  ins      = insn_from_handle(ih);
    const bool          is_64bit = backend_.image().is_64bit();

    std::vector<base::FeatureWithAddress> out;
    out.reserve(8U);

    // Per-scope extractors are aggregated here in a fixed order so output is
    // deterministic across runs
    // The engine itself does not depend on order, so this only affects rendering
    if (auto m = ::papa::features::extractors::papa_native::insn::extract_mnemonic(ins);
        m.has_value()) { out.push_back(std::move(*m)); }
    if (auto c = ::papa::features::extractors::papa_native::insn::extract_call_plus_5(ins);
        c.has_value()) { out.push_back(std::move(*c)); }
    if (auto i = ::papa::features::extractors::papa_native::insn::extract_indirect_call(ins);
        i.has_value()) { out.push_back(std::move(*i)); }
    {
        auto seg = ::papa::features::extractors::papa_native::insn::extract_segment_access(ins);
        for (auto& fa : seg) { out.push_back(std::move(fa)); }
    }
    if (auto p = ::papa::features::extractors::papa_native::insn::extract_peb_access(ins, is_64bit);
        p.has_value()) { out.push_back(std::move(*p)); }
    if (auto cs = ::papa::features::extractors::papa_native::insn::extract_cross_section_flow(
            ins, backend_.image(), backend_.imports());
        cs.has_value()) { out.push_back(std::move(*cs)); }
    if (auto nz = ::papa::features::extractors::papa_native::insn::extract_nzxor(
            fn, bb, ins, is_64bit);
        nz.has_value()) { out.push_back(std::move(*nz)); }
    {
        auto bytes = ::papa::features::extractors::papa_native::insn::extract_bytes(
            ins, backend_.image());
        for (auto& fa : bytes) { out.push_back(std::move(fa)); }
    }
    {
        auto nums = ::papa::features::extractors::papa_native::insn::extract_number(
            ins, backend_.image());
        for (auto& fa : nums) { out.push_back(std::move(fa)); }
    }
    {
        auto offs = ::papa::features::extractors::papa_native::insn::extract_offset(
            ins, backend_.image());
        for (auto& fa : offs) { out.push_back(std::move(fa)); }
    }
    {
        auto strs = ::papa::features::extractors::papa_native::insn::extract_string(
            ins, backend_.image());
        for (auto& fa : strs) { out.push_back(std::move(fa)); }
    }
    {
        auto apis = ::papa::features::extractors::papa_native::insn::extract_api_features(
            fn, bb, ins, backend_.image(), backend_.imports(), backend_.disassembler());
        for (auto& fa : apis) { out.push_back(std::move(fa)); }
    }
    {
        // capa also emits an api feature for a direct call to a statically-linked
        // library function FLIRT identified (e.g. _beginthreadex), which is not
        // an import. The lookup uses the same FLIRT classification as
        // is_library_function
        auto flirt_apis = ::papa::features::extractors::papa_native::insn::extract_flirt_call_api(
            ins, [this](std::uint64_t va) { return flirt_name_at(va); });
        for (auto& fa : flirt_apis) { out.push_back(std::move(fa)); }
    }
    return out;
}

bool PapaNativeStaticExtractor::is_library_function(
    const features::Address& addr) const {
    const auto va = absolute_va(addr);
    if (!va.has_value()) { return false; }

    // Locate the function carrying that VA
    const Function* fn = nullptr;
    for (const auto& f : backend_.functions()) {
        if (f.va == *va) { fn = &f; break; }
    }
    if (fn == nullptr) { return false; }

    // CFG-derived hint takes precedence when the recovery layer set it
    if (fn->likely_library) { return true; }

    // Structural thunks are library code regardless of any signature
    if (LibrarySignatureSet::is_thunk(*fn)) { return true; }

    // FLIRT identified the library functions during analysis, the way capa's
    // signature analyzers run as workspace modules while functions are made, so
    // this is a lookup into that result rather than a second matching pass
    return backend_.flirt_library_names().count(*va) != 0;
}

std::optional<std::string>
PapaNativeStaticExtractor::flirt_name_at(std::uint64_t va) const {
    const auto& names = backend_.flirt_library_names();
    const auto  it    = names.find(va);
    if (it == names.end()) { return std::nullopt; }
    return it->second;
}

std::optional<std::string>
PapaNativeStaticExtractor::get_function_name(const features::Address& addr) const {
    const auto va = absolute_va(addr);
    if (!va.has_value()) { return std::nullopt; }
    auto it = function_names_.find(*va);
    if (it == function_names_.end()) { return std::nullopt; }
    return it->second;
}

void PapaNativeStaticExtractor::set_function_name(std::uint64_t va, std::string name) {
    function_names_.insert_or_assign(va, std::move(name));
}

}  // namespace papa::features::extractors::papa_native
