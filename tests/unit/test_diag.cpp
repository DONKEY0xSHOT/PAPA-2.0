#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/papa_native/indirect_calls.h"
#include "papa/features/extractors/papa_native/insn.h"
#include "papa/pe/pe_parser.h"

#include "fixture_paths.h"

#include <cstdint>
#include <optional>
#include <string>

namespace pn = papa::features::extractors::papa_native;

namespace {

// True when some instruction in the function entered at entry_va yields an api
// feature whose text contains needle
[[nodiscard]] bool function_emits_api(const pn::PapaNativeBackend& backend,
                                      std::uint64_t entry_va,
                                      const std::string& needle) {
    const auto& imports = backend.imports();
    const auto& disasm  = backend.disassembler();
    for (const auto& f : backend.functions()) {
        if (f.va != entry_va) { continue; }
        for (const auto& bb : f.basic_blocks) {
            for (const auto& ins : bb.instructions) {
                for (const auto& fa : pn::insn::extract_api_features(
                         f, bb, ins, backend.image(), imports, disasm)) {
                    if (fa.first->to_string().find(needle) != std::string::npos) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    return false;
}

}  // namespace

// Regression for the indirect-IAT resolution fixes against chrome.exe sha256
// 0cac3d17c4f4b83ad936cead2a7e79efcc2e0e39ee030a84477af95cffc2bc84
TEST_CASE("api: chrome resolves thunked and register-indirect imports") {
    const auto chrome = papa_tests::fixture_path("chrome.exe");
    if (!papa_tests::fixture_available(chrome)) {
        MESSAGE("chrome.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(chrome);
    REQUIRE(img.has_value());
    auto backend = pn::PapaNativeBackend::build(*img, pn::flirt::FlirtSignatureSet::embedded());
    REQUIRE(backend.has_value());

    // jmp [rip+slot] import thunks. MiniDumpWriteDump is called at 0x140213915, which
    // the pdata boundary places in the function entered at 0x1402136b0
    CHECK(function_emits_api(*backend, 0x1400630c0ULL, "GetFileVersionInfo"));
    CHECK(function_emits_api(*backend, 0x1402136b0ULL, "MiniDumpWriteDump"));
    // register loaded from the IAT in an earlier block
    CHECK(function_emits_api(*backend, 0x140243170ULL, "WinHttpWriteData"));
}
