#pragma once

#include "papa/features/address.h"
#include "papa/features/feature.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

// Lookup of import rows keyed by their IAT slot virtual address
// Built once per image because hashing 10k+ entries on every API extraction
// would dominate runtime
// The pointers reference rows owned by PeImage and must outlive ImportTable
struct ImportTable {
    std::unordered_map<std::uint64_t, const ::papa::pe::ParsedImport*> by_iat_va;
};

// Walk image.imports() once and produce an ImportTable
[[nodiscard]] ImportTable
build_import_table(const ::papa::pe::PeImage& image);

}  // namespace papa::features::extractors::papa_native

namespace papa::features::extractors::papa_native::insn {

// Pair returned by every extractor: the feature and the location it applies to
// All instruction-level features are addressed by the absolute virtual address
// of the originating instruction so callers can map back to the disassembly
using FeatureWithAddress = std::pair<features::FeaturePtr, features::Address>;

// Always emit one Mnemonic feature per instruction
// Throws nothing
// Returns an empty optional only when the mnemonic table lookup produced an
// empty string (which never happens in practice but lets callers loop without
// a separate validity check)
[[nodiscard]] std::optional<FeatureWithAddress>
extract_mnemonic(const DecodedInsn& ins);

// Detect the "call $+5" pattern: a near-relative CALL whose target lands on
// the next instruction. CAPA flags this because it corresponds to the
// position-independent code idiom used by some shellcode and packers
[[nodiscard]] std::optional<FeatureWithAddress>
extract_call_plus_5(const DecodedInsn& ins);

// Detect indirect CALL: register, register+disp, or SIB operand
// PC-relative direct calls are not indirect even though they go via an offset
[[nodiscard]] std::optional<FeatureWithAddress>
extract_indirect_call(const DecodedInsn& ins);

// Detect FS-prefixed and GS-prefixed memory access
// Both prefixes are emitted independently when present so rules can require
// either one alone or in combination
[[nodiscard]] std::vector<FeatureWithAddress>
extract_segment_access(const DecodedInsn& ins);

// Detect access to the PEB through the TIB
// On x86 PEB lives at fs:0x30 and on x64 it lives at gs:0x60
// The is_64bit flag selects the prefix and offset that together form a match
[[nodiscard]] std::optional<FeatureWithAddress>
extract_peb_access(const DecodedInsn& ins, bool is_64bit);

// Extract Bytes features from operands whose targets point at readable memory
// Up to kMaxBytesFeatureSize bytes are read per operand
// All-zero buffers and buffers that look like ASCII or UTF-16LE strings are
// suppressed because the latter are picked up by extract_string instead
// CALL operands are skipped because the target is code, not data
[[nodiscard]] std::vector<FeatureWithAddress>
extract_bytes(const DecodedInsn& ins, const ::papa::pe::PeImage& image);

// Extract Number features from immediate operands
// Stack-adjust patterns ("add esp, 4") and immediates that look like pointers
// to readable memory are suppressed because they reflect housekeeping rather
// than numeric semantics
// For "add reg, small_imm" patterns the value is also surfaced as an Offset
// because small positive immediates added to a register often represent struct
// offsets in MSVC-emitted code
[[nodiscard]] std::vector<FeatureWithAddress>
extract_number(const DecodedInsn& ins, const ::papa::pe::PeImage& image);

// Extract Offset features from register-relative memory accesses
// Stack-pointer and frame-pointer base registers are excluded because their
// displacements describe local-variable layout rather than struct geometry
[[nodiscard]] std::vector<FeatureWithAddress>
extract_offset(const DecodedInsn& ins, const ::papa::pe::PeImage& image);

// Extract String features from operands whose targets read as printable text
// ASCII is tried first and UTF-16LE second
// Runs shorter than kMinStringLength are suppressed to keep the false-positive
// rate manageable on real-world binaries
[[nodiscard]] std::vector<FeatureWithAddress>
extract_string(const DecodedInsn& ins, const ::papa::pe::PeImage& image);

// True when ins is the security-cookie XOR emitted by /GS-protected MSVC code
// CAPA must suppress these because they are noise rather than real nzxor evidence
// Match conditions follow viv/insn.py:352-377 verbatim:
//  - destination is a stack-pointer or frame-pointer register
//  - the instruction sits in the first prologue window of the entry block, or
//  - it sits in the last epilogue window of a returning block
[[nodiscard]] bool
is_security_cookie(const Function&    fn,
                   const BasicBlock&  bb,
                   const DecodedInsn& ins,
                   bool               is_64bit) noexcept;

// Detect non-zeroing XOR
// Suppresses cases where both operands name the same register (xor eax, eax)
// and security-cookie XORs identified by is_security_cookie
[[nodiscard]] std::optional<FeatureWithAddress>
extract_nzxor(const Function&    fn,
              const BasicBlock&  bb,
              const DecodedInsn& ins,
              bool               is_64bit);

// Detect control flow that crosses PE section boundaries
// CAPA flags this because legitimate code rarely branches across sections
// The pattern correlates with packers and shellcode loaders that decompress
// one section before transferring control to it
// Calls into the import table are excluded because every direct IAT call
// necessarily crosses sections
[[nodiscard]] std::optional<FeatureWithAddress>
extract_cross_section_flow(const DecodedInsn&         ins,
                           const ::papa::pe::PeImage& image,
                           const ImportTable&         imports);

// Resolve every API name implied by a CALL or thunk-style JMP instruction
//
// For direct IAT calls (kImmMem and kRipRel) the operand encodes the IAT slot
// directly and we look it up in imports.by_iat_va.
//
// For PC-relative calls (kPcRel) the target may be a thunk
// We follow up to kThunkChainDepthDelta levels of unconditional JMP/CALL with
// optional CET ENDBRANCH skipping, decoding through disasm at each step.
//
// For register-indirect calls (kReg) we backward-slice with find_definition
// from indirect_calls.h to learn the resolved value (if any) and look it up.
//
// Each emitted Api feature uses the symbol variants from generate_symbols so
// rules can match dotted, bare, or AW-stripped spellings interchangeably.
[[nodiscard]] std::vector<FeatureWithAddress>
extract_api_features(const Function&            fn,
                     const BasicBlock&          bb,
                     const DecodedInsn&         ins,
                     const ::papa::pe::PeImage& image,
                     const ImportTable&         imports,
                     const Disassembler&        disasm);

}  // namespace papa::features::extractors::papa_native::insn
