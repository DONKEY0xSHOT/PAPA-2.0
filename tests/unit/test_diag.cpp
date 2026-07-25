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

// Diagnostic harness for parity investigations. It is a no-op unless
// PAPA_DIAG_BIN names a binary, so it never runs during a normal suite pass.
// For each requested VA it prints the recovered function that contains it (entry
// address, basic-block and instruction counts, the VA range actually covered,
// and the library flag) followed by every api / indirect-call / cross-section /
// offset / number / string / bytes feature the extractor produces inside that
// function. That is exactly the evidence needed to tell a CFG-coverage gap from
// a feature-extraction gap.
//   PAPA_DIAG_BIN=<path> PAPA_DIAG_VAS=<hex,hex,...> \
//       papa_unit_tests --test-case="diag: dump function features"
TEST_CASE("diag: dump function features") {
    const std::string bin = papa_tests::detail::read_env("PAPA_DIAG_BIN");
    if (bin.empty()) { return; }
    const auto vas = parse_hex_csv(papa_tests::detail::read_env("PAPA_DIAG_VAS"));

    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    auto backend = pn::PapaNativeBackend::build(*img);
    REQUIRE(backend.has_value());

    const auto& funcs   = backend->functions();
    const auto& imports = backend->imports();
    const auto& disasm  = backend->disassembler();

    for (const auto va : vas) {
        bool is_entry = false;
        const auto* f = find_function(funcs, va, is_entry);
        if (f == nullptr) {
            std::printf("VA %llx: NOT in any recovered function\n",
                        static_cast<unsigned long long>(va));
            continue;
        }
        std::size_t ninsn = 0;
        std::uint64_t maxva = 0;
        std::uint64_t minva = ~std::uint64_t{0};
        for (const auto& bb : f->basic_blocks) {
            for (const auto& ins : bb.instructions) {
                ninsn += 1;
                if (ins.va > maxva) { maxva = ins.va; }
                if (ins.va < minva) { minva = ins.va; }
            }
        }
        std::printf("VA %llx: func=%llx entry=%d bbs=%zu insns=%zu range=%llx..%llx lib=%d\n",
                    static_cast<unsigned long long>(va),
                    static_cast<unsigned long long>(f->va), is_entry ? 1 : 0,
                    f->basic_blocks.size(), ninsn,
                    static_cast<unsigned long long>(minva),
                    static_cast<unsigned long long>(maxva),
                    f->likely_library ? 1 : 0);
        std::size_t n_movzx = 0;
        std::size_t n_nzxor = 0;
        for (const auto& bb : f->basic_blocks) {
            for (const auto& ins : bb.instructions) {
                if (ins.zyd_mnem == ZYDIS_MNEMONIC_MOVZX) { n_movzx += 1; }
                if (pn::insn::extract_nzxor(*f, bb, ins, backend->image().is_64bit())) {
                    n_nzxor += 1;
                }
            }
        }
        std::printf("  counts: callees=%zu movzx=%zu nzxor=%zu\n",
                    f->callees.size(), n_movzx, n_nzxor);
        for (const auto& bb : f->basic_blocks) {
            std::printf("  --- BB %llx insns=%zu succ=%zu ---\n",
                        static_cast<unsigned long long>(bb.va),
                        bb.instructions.size(), bb.successors.size());
            for (const auto& ins : bb.instructions) {
                std::printf("    insn %llx %-8s J%d C%d R%d Ca%d FT%d tgt=%llx\n",
                            static_cast<unsigned long long>(ins.va),
                            std::string(ins.mnemonic_str).c_str(),
                            ins.is_jump ? 1 : 0, ins.is_conditional ? 1 : 0,
                            ins.is_return ? 1 : 0, ins.is_call ? 1 : 0,
                            ins.is_fallthrough ? 1 : 0,
                            ins.branch_target.has_value()
                                ? static_cast<unsigned long long>(*ins.branch_target) : 0ULL);
                for (const auto& fa : pn::insn::extract_api_features(
                         *f, bb, ins, backend->image(), imports, disasm)) {
                    std::printf("   api@%llx %s\n",
                                static_cast<unsigned long long>(ins.va),
                                fa.first->to_string().c_str());
                }
                if (pn::insn::extract_indirect_call(ins)) {
                    std::printf("   indirect_call@%llx\n",
                                static_cast<unsigned long long>(ins.va));
                }
                if (pn::insn::extract_cross_section_flow(ins, backend->image(), imports)) {
                    std::printf("   cross_section_flow@%llx\n",
                                static_cast<unsigned long long>(ins.va));
                }
                if (auto p = pn::insn::extract_peb_access(ins, backend->image().is_64bit())) {
                    std::printf("   %s@%llx\n", p->first->to_string().c_str(),
                                static_cast<unsigned long long>(ins.va));
                }
                for (const auto& fa : pn::insn::extract_segment_access(ins)) {
                    std::printf("   %s@%llx\n", fa.first->to_string().c_str(),
                                static_cast<unsigned long long>(ins.va));
                }
                for (const auto& fa : pn::insn::extract_offset(ins, backend->image())) {
                    std::printf("   %s@%llx\n", fa.first->to_string().c_str(),
                                static_cast<unsigned long long>(ins.va));
                }
                for (const auto& fa : pn::insn::extract_number(ins, backend->image())) {
                    std::printf("   %s@%llx [%s op0k=%d op1k=%d]\n",
                                fa.first->to_string().c_str(),
                                static_cast<unsigned long long>(ins.va),
                                std::string(ins.mnemonic_str).c_str(),
                                ins.operand_count > 0 ? static_cast<int>(ins.operands[0].kind) : -1,
                                ins.operand_count > 1 ? static_cast<int>(ins.operands[1].kind) : -1);
                }
                for (const auto& fa : pn::insn::extract_string(ins, backend->image())) {
                    std::printf("   %s@%llx\n", fa.first->to_string().c_str(),
                                static_cast<unsigned long long>(ins.va));
                }
                for (const auto& fa : pn::insn::extract_bytes(ins, backend->image())) {
                    std::printf("   %s@%llx\n", fa.first->to_string().c_str(),
                                static_cast<unsigned long long>(ins.va));
                }
            }
        }
    }
}

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

// Regression for the indirect-IAT resolution fixes against chrome.exe
//   sha256 0cac3d17c4f4b83ad936cead2a7e79efcc2e0e39ee030a84477af95cffc2bc84
// These imports are reached through an indirect memory thunk (jmp [rip+slot])
// and through a register loaded from the IAT in an earlier basic block. Before
// the fixes papa resolved neither, dropping api features capa relies on
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

    // jmp [rip+slot] import thunks. MiniDumpWriteDump is called at 0x140213915,
    // which the pdata boundary places in the function entered at 0x1402136b0 (the
    // function at 0x140213540 ends at the int3 padding before it)
    CHECK(function_emits_api(*backend, 0x1400630c0ULL, "GetFileVersionInfo"));
    CHECK(function_emits_api(*backend, 0x1402136b0ULL, "MiniDumpWriteDump"));
    // register loaded from the IAT in an earlier block
    CHECK(function_emits_api(*backend, 0x140243170ULL, "WinHttpWriteData"));
}

namespace {

namespace fl = papa::features::extractors::papa_native::flirt;

// Walks a FLIRT tree and, for every node whose pattern and a leaf module's CRC
// match function_bytes, prints that module's public name plus each tail byte's
// expected and actual value and each reference. Reveals why a candidate the CRC
// accepts is then rejected by the tail-byte or reference stage
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

// PAPA_FLIRT_BIN=<path> PAPA_FLIRT_VAS=<hex,hex> dumps the FLIRT candidates for
// each VA. No-op without the env var
TEST_CASE("diag: flirt match attempt") {
    const std::string bin = papa_tests::detail::read_env("PAPA_FLIRT_BIN");
    if (bin.empty()) { return; }
    const auto vas = parse_hex_csv(papa_tests::detail::read_env("PAPA_FLIRT_VAS"));

    auto img = papa::pe::PeParser::parse_file(bin);
    REQUIRE(img.has_value());
    const auto sigs = fl::FlirtSignatureSet::make_embedded();

    for (const auto va : vas) {
        std::printf("VA %llx:\n", static_cast<unsigned long long>(va));
        if (va < img->image_base()) { std::printf("  below base\n"); continue; }
        const std::uint64_t rva = va - img->image_base();
        auto bytes = img->read_at_rva(rva, 0x10000);
        if (!bytes) {
            for (std::size_t cap = 0x10000; cap > 0; cap >>= 1) {
                auto r = img->read_at_rva(rva, cap);
                if (r) { bytes = std::move(r); break; }
            }
        }
        if (!bytes) { std::printf("  unreadable\n"); continue; }
        std::vector<std::uint8_t> fb;
        fb.reserve(bytes->size());
        for (const std::byte b : *bytes) { fb.push_back(static_cast<std::uint8_t>(b)); }
        std::printf("  bytes:");
        for (std::size_t i = 0; i < 64 && i < fb.size(); ++i) {
            std::printf(" %02x", static_cast<unsigned>(fb[i]));
        }
        std::printf("  size=%zu\n", fb.size());
        for (const auto& tree : sigs.trees()) {
            if (tree.root() != nullptr) { dump_flirt_node(*tree.root(), fb); }
        }
    }
}
