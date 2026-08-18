#pragma once

#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

// Lookup of import rows keyed by their IAT slot virtual address. Built once per image
// because hashing 10k+ entries on every API extraction would dominate runtime
struct ImportTable {
    std::unordered_map<std::uint64_t, const ::papa::pe::ParsedImport*> by_iat_va;
};

// Walk image.imports() once and produce an ImportTable
[[nodiscard]] ImportTable
build_import_table(const ::papa::pe::PeImage& image);

}  // namespace papa::features::extractors::papa_native

namespace papa::features::extractors::papa_native::insn {

// Pair returned by every extractor, the feature and the location it applies to. All
// are addressed by the absolute virtual address of the originating instruction
using FeatureWithAddress = std::pair<features::FeaturePtr, features::Address>;

// Always emit one Mnemonic feature per instruction. Throws nothing
[[nodiscard]] std::optional<FeatureWithAddress>
extract_mnemonic(const DecodedInsn& ins);

// Detect the "call $+5" pattern: a near-relative CALL whose target lands on the next
// instruction
[[nodiscard]] std::optional<FeatureWithAddress>
extract_call_plus_5(const DecodedInsn& ins);

// Detect indirect CALL: register, register+disp, or SIB operand
// PC-relative direct calls are not indirect even though they go via an offset
[[nodiscard]] std::optional<FeatureWithAddress>
extract_indirect_call(const DecodedInsn& ins);

// Detect FS-prefixed and GS-prefixed memory access. Both prefixes are emitted
// independently when present so rules can require either one alone or in combination
[[nodiscard]] std::vector<FeatureWithAddress>
extract_segment_access(const DecodedInsn& ins);

// Detect access to the PEB through the TIB. On x86 PEB lives at fs:0x30 and on x64 it
// lives at gs:0x60
[[nodiscard]] std::optional<FeatureWithAddress>
extract_peb_access(const DecodedInsn& ins, bool is_64bit);

// Extract Bytes features from operands whose targets point at readable memory. Up to
// kMaxBytesFeatureSize bytes are read per operand
[[nodiscard]] std::vector<FeatureWithAddress>
extract_bytes(const DecodedInsn& ins, const ::papa::pe::PeImage& image);

// Extract Number features from immediate operands
[[nodiscard]] std::vector<FeatureWithAddress>
extract_number(const DecodedInsn& ins, const ::papa::pe::PeImage& image);

// Extract Offset features from register-relative memory accesses
[[nodiscard]] std::vector<FeatureWithAddress>
extract_offset(const DecodedInsn& ins, const ::papa::pe::PeImage& image);

// Extract String features from operands whose targets read as printable text. ASCII is
// tried first and UTF-16LE second
[[nodiscard]] std::vector<FeatureWithAddress>
extract_string(const DecodedInsn& ins, const ::papa::pe::PeImage& image);

// True when ins is the security-cookie XOR emitted by /GS-protected MSVC code, which
// CAPA suppresses as noise rather than real nzxor evidence
[[nodiscard]] bool
is_security_cookie(const Function&    fn,
                   const BasicBlock&  bb,
                   const DecodedInsn& ins,
                   bool               is_64bit) noexcept;

// Detect non-zeroing XOR. Suppresses cases where both operands name the same register
// (xor eax, eax) and security-cookie XORs identified by is_security_cookie
[[nodiscard]] std::optional<FeatureWithAddress>
extract_nzxor(const Function&    fn,
              const BasicBlock&  bb,
              const DecodedInsn& ins,
              bool               is_64bit);

// Detect control flow that crosses PE section boundaries. CAPA flags this because
// legitimate code rarely branches across sections
[[nodiscard]] std::optional<FeatureWithAddress>
extract_cross_section_flow(const DecodedInsn&         ins,
                           const ::papa::pe::PeImage& image,
                           const ImportTable&         imports);

// Resolve the import a direct CALL or unconditional JMP targets, through the IAT or a
// thunk chain. Returns nullptr when the target is not an import
[[nodiscard]] const ::papa::pe::ParsedImport*
resolve_direct_call_import(const DecodedInsn&         ins,
                           const ::papa::pe::PeImage& image,
                           const ImportTable&         imports,
                           const Disassembler&        disasm);

/// Every API name a call or thunk-style jump implies
[[nodiscard]] std::vector<FeatureWithAddress>
extract_api_features(const Function&            fn,
                     const BasicBlock&          bb,
                     const DecodedInsn&         ins,
                     const ::papa::pe::PeImage& image,
                     const ImportTable&         imports,
                     const Disassembler&        disasm);

// Emit Api features for a direct call to a statically linked library function FLIRT
// identified. A leading-underscore name also yields its stripped form
[[nodiscard]] std::vector<FeatureWithAddress>
extract_flirt_call_api(
    const DecodedInsn& ins,
    const std::function<std::optional<std::string>(std::uint64_t)>& flirt_name);

}  // namespace papa::features::extractors::papa_native::insn
