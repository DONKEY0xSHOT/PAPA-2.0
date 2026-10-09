#pragma once

#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <unordered_map>

namespace papa::features::extractors::papa_native {

// Lookup of import rows keyed by their IAT slot virtual address. Built once per image
// because hashing 10k+ entries on every API extraction would dominate runtime
struct ImportTable {
    std::unordered_map<std::uint64_t, const ::papa::pe::ParsedImport*> by_iat_va;
};

// Walk image.imports() once and produce an ImportTable
[[nodiscard]] ImportTable
build_import_table(const ::papa::pe::PeImage& image);

// Resolve the import a direct CALL or unconditional JMP targets, through the IAT or a
// thunk chain. Returns nullptr when the target is not an import
[[nodiscard]] const ::papa::pe::ParsedImport*
resolve_direct_call_import(const DecodedInsn&         ins,
                           const ::papa::pe::PeImage& image,
                           const ImportTable&         imports,
                           const Disassembler&        disasm);

}  // namespace papa::features::extractors::papa_native
