#include "papa/features/extractors/papa_native/extractor.h"

#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/features/extractors/global_.h"
#include "papa/features/extractors/pefile.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/basic_block.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/function.h"
#include "papa/features/extractors/papa_native/insn.h"
#include "papa/features/extractors/papa_native/library_signatures.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace papa::features::extractors::papa_native {

namespace {

namespace base = ::papa::features::extractors;

// Recover the absolute VA from a public Address used by orchestrators. Returns nullopt
// for non-VA addresses
[[nodiscard]] std::optional<std::uint64_t>
absolute_va(const features::Address& addr) noexcept {
    if (const auto* a = std::get_if<features::AbsoluteVirtualAddress>(&addr)) {
        return a->v;
    }
    return std::nullopt;
}

// Lift a const Function* out of an opaque FunctionHandle.inner
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

// Move one optional feature, or a batch of features, onto the end of out
void append(std::vector<base::FeatureWithAddress>&   out,
            std::optional<base::FeatureWithAddress>&& one) {
    if (one.has_value()) { out.push_back(std::move(*one)); }
}

void append(std::vector<base::FeatureWithAddress>&  out,
            std::vector<base::FeatureWithAddress>&& many) {
    for (auto& fa : many) { out.push_back(std::move(fa)); }
}

}  // namespace

PapaNativeStaticExtractor::PapaNativeStaticExtractor(PapaNativeBackend backend)
    : backend_(std::move(backend)) {
    const auto& fns = backend_.functions();
    function_index_.reserve(fns.size());
    // Discovery drops repeat entries, so each entry VA is unique and maps to one position
    for (std::size_t i = 0; i < fns.size(); ++i) { function_index_.emplace(fns[i].va, i); }
}

features::Address PapaNativeStaticExtractor::get_base_address() const {
    return va_address(backend_.image().image_base());
}

std::vector<base::FeatureWithAddress>
PapaNativeStaticExtractor::extract_global_features() const {
    return base::extract_global_features(backend_.image());
}

std::vector<base::FeatureWithAddress>
PapaNativeStaticExtractor::extract_file_features() const {
    return pefile::extract_file_features(backend_.image());
}

std::vector<base::FunctionHandle>
PapaNativeStaticExtractor::get_functions() const {
    const auto& funcs = backend_.functions();
    std::vector<base::FunctionHandle> out;
    out.reserve(funcs.size());
    for (const auto& fn : funcs) {
        base::FunctionHandle fh;
        fh.addr  = va_address(fn.va);
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
    return function_::extract_function_features(fn, symbol);
}

std::vector<base::BBHandle>
PapaNativeStaticExtractor::get_basic_blocks(const base::FunctionHandle& fh) const {
    const Function& fn = function_from_handle(fh);
    std::vector<base::BBHandle> out;
    out.reserve(fn.basic_blocks.size());
    for (const auto& bb : fn.basic_blocks) {
        base::BBHandle bbh;
        bbh.addr  = va_address(bb.va);
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
    return basic_block::extract_basic_block_features(bb, backend_.image().is_64bit());
}

std::vector<base::InsnHandle>
PapaNativeStaticExtractor::get_instructions(const base::FunctionHandle& /*fh*/,
                                            const base::BBHandle&       bbh) const {
    const BasicBlock& bb = basic_block_from_handle(bbh);
    std::vector<base::InsnHandle> out;
    out.reserve(bb.instructions.size());
    for (const auto& ins : bb.instructions) {
        base::InsnHandle ih;
        ih.addr  = va_address(ins.va);
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
    const Function&            fn       = function_from_handle(fh);
    const BasicBlock&          bb       = basic_block_from_handle(bbh);
    const DecodedInsn&         ins      = insn_from_handle(ih);
    const ::papa::pe::PeImage& image    = backend_.image();
    const bool                 is_64bit = image.is_64bit();

    std::vector<base::FeatureWithAddress> out;
    out.reserve(8U);

    // Per-scope extractors are aggregated here in a fixed order so output is
    // deterministic across runs
    append(out, insn::extract_mnemonic(ins));
    append(out, insn::extract_call_plus_5(ins));
    append(out, insn::extract_indirect_call(ins));
    append(out, insn::extract_segment_access(ins));
    append(out, insn::extract_peb_access(ins, is_64bit));
    append(out, insn::extract_cross_section_flow(ins, image, backend_.imports()));
    append(out, insn::extract_nzxor(fn, bb, ins, is_64bit));
    append(out, insn::extract_bytes(ins, image));
    append(out, insn::extract_number(ins, image));
    append(out, insn::extract_offset(ins, image));
    append(out, insn::extract_string(ins, image));
    append(out, insn::extract_api_features(
        fn, ins, image, backend_.imports(), backend_.disassembler()));
    // capa also emits an api feature for a direct call to a statically linked library
    // function FLIRT identified, such as _beginthreadex, which is not an import
    append(out, insn::extract_flirt_call_api(
        ins, [this](std::uint64_t va) { return flirt_name_at(va); }));
    return out;
}

bool PapaNativeStaticExtractor::is_library_function(
    const features::Address& addr) const {
    const auto va = absolute_va(addr);
    if (!va.has_value()) { return false; }

    // Locate the function carrying that VA
    const auto it = function_index_.find(*va);
    if (it == function_index_.end()) { return false; }
    const Function& fn = backend_.functions()[it->second];

    // Structural thunks are library code regardless of any signature
    if (is_thunk(fn)) { return true; }

    // FLIRT identified the library functions during analysis, so this is a lookup into
    // that result rather than a second matching pass
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

}  // namespace papa::features::extractors::papa_native
