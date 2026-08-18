#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/papa_native/flirt/flirt_crc16.h"
#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"
#include "papa/features/extractors/papa_native/indirect_calls.h"
#include "papa/features/extractors/papa_native/insn.h"
#include "papa/pe/pe_parser.h"

#include "fixture_paths.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pn = papa::features::extractors::papa_native;

namespace {

std::vector<std::uint64_t> parse_hex_csv(const std::string& csv) {
    std::vector<std::uint64_t> out;
    std::size_t i = 0;
    while (i < csv.size()) {
        std::size_t j = csv.find(',', i);
        if (j == std::string::npos) { j = csv.size(); }
        const std::string tok = csv.substr(i, j - i);
        if (!tok.empty()) {
            out.push_back(std::strtoull(tok.c_str(), nullptr, 16));
        }
        i = j + 1;
    }
    return out;
}

const pn::Function* find_function(const std::vector<pn::Function>& funcs,
                                  std::uint64_t va, bool& is_entry) {
    for (const auto& f : funcs) {
        if (f.va == va) { is_entry = true; return &f; }
    }
    for (const auto& f : funcs) {
        for (const auto& bb : f.basic_blocks) {
            for (const auto& ins : bb.instructions) {
                if (ins.va == va) { is_entry = false; return &f; }
            }
        }
    }
    return nullptr;
}

}  // namespace

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
    auto backend = pn::PapaNativeBackend::build(*img);
    REQUIRE(backend.has_value());

    // jmp [rip+slot] import thunks. MiniDumpWriteDump is called at 0x140213915, which
    // the pdata boundary places in the function entered at 0x1402136b0
    CHECK(function_emits_api(*backend, 0x1400630c0ULL, "GetFileVersionInfo"));
    CHECK(function_emits_api(*backend, 0x1402136b0ULL, "MiniDumpWriteDump"));
    // register loaded from the IAT in an earlier block
    CHECK(function_emits_api(*backend, 0x140243170ULL, "WinHttpWriteData"));
}

namespace {

namespace fl = papa::features::extractors::papa_native::flirt;

// Walks a FLIRT tree and prints every module whose pattern and CRC match, with its
// tail bytes and references, showing why a CRC-accepted candidate is rejected
void dump_flirt_node(const fl::FlirtNode& node, std::span<const std::uint8_t> fb) {
    if (!node.pattern.matches(fb)) { return; }
    for (const fl::FlirtModule& m : node.leaf_modules) {
        const std::size_t needed = 32U + static_cast<std::size_t>(m.tail_length);
        if (fb.size() < needed) { continue; }
        if (fl::flirt_crc16(fb.subspan(32U, m.tail_length)) != m.tail_crc16) { continue; }
        std::string name = "?";
        for (const auto& n : m.names) {
            if (n.type == fl::FlirtNameType::kPublic) { name = n.name; break; }
        }
        std::printf("  CRC-MATCH '%s' patlen=%u taillen=%u nnames=%zu ntb=%zu nref=%zu\n",
                    name.c_str(), node.pattern.length, m.tail_length,
                    m.names.size(), m.tail_bytes.size(), m.references.size());
        for (const auto& n : m.names) {
            std::printf("    name off=%lld type=%s '%s'\n",
                        static_cast<long long>(n.offset),
                        n.type == fl::FlirtNameType::kPublic ? "pub" : "loc",
                        n.name.c_str());
        }
        for (const auto& tb : m.tail_bytes) {
            // The tail-byte offset is relative to the end of the pattern+CRC
            // region, matching python-flirt's buf[byte_sig_size + crc_len + off]
            const std::size_t pos = 32U + m.tail_length + tb.offset;
            const bool in = pos < fb.size();
            std::printf("    tb off=%u pos=%zu exp=%02x act=%02x %s\n", tb.offset, pos,
                        static_cast<unsigned>(tb.value),
                        in ? static_cast<unsigned>(fb[pos]) : 0xFFFU,
                        (in && fb[pos] == tb.value) ? "OK" : "MISS");
        }
        for (const auto& r : m.references) {
            std::printf("    ref off=%u name='%s'\n", r.offset, r.name.c_str());
        }
    }
    for (const auto& c : node.children) {
        if (c) { dump_flirt_node(*c, fb); }
    }
}

}  // namespace
