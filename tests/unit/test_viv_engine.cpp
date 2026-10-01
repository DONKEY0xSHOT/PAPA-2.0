#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/papa_native/imports.h"
#include "papa/features/extractors/papa_native/viv/engine.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <vector>
#include "pe_builder.h"

namespace pn = papa::features::extractors::papa_native;

TEST_CASE("discovery engine: each seed source, direct call and i386 pass contributes its functions") {
    for (const bool x64 : {true, false}) {
        CAPTURE(x64);
        papa_tests::PeBuilder b;
        b.x64 = x64;
        // Every function but the last is placed without a .pdata row
        const auto place = [&b](const std::vector<std::uint8_t>& bytes) {
            const std::uint32_t at = b.add_function(bytes);
            b.pdata_functions.pop_back();
            return at;
        };
        const std::vector<std::uint8_t> leaf{0x33, 0xC0, 0xC3};  // xor eax, eax / ret
        const auto callee    = place(leaf);
        const auto exported  = place(leaf);
        const auto tls       = place(leaf);
        const auto relocated = place(leaf);
        const auto indirect  = place(leaf);
        // push ebp / mov ebp, esp / xor eax, eax / pop ebp / ret
        const auto prologue = place({0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3});
        // call callee / call callee / mov eax, indirect / call eax / ret, with movabs rax on x64
        std::vector<std::uint8_t> entry_code{0xE8, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0};
        if (x64) { entry_code.push_back(0x48); }
        entry_code.push_back(0xB8);
        entry_code.insert(entry_code.end(), x64 ? 8U : 4U, 0);
        entry_code.insert(entry_code.end(), {0xFF, 0xD0, 0xC3});
        const auto entry    = place(entry_code);
        // Two relocated pointer slots, the second holding a .data address
        const auto slot     = place(std::vector<std::uint8_t>(16, 0));
        const auto in_pdata = b.add_function(leaf);

        b.entry_offset       = entry;
        b.exports            = {{"exported", exported, ""}};
        b.tls_callbacks      = {tls};
        b.reloc_code_offsets = {slot, slot + 8U};
        b.data.assign(8, 0);
        for (const std::uint32_t call : {entry, entry + 5U}) {
            papa_tests::detail::poke(
                b.code, call + 1U,
                static_cast<std::int32_t>(b.code_va(callee) - b.code_va(call + 5U)));
        }
        if (x64) {
            papa_tests::detail::poke(b.code, entry + 12U, b.code_va(indirect));
            papa_tests::detail::poke(b.code, slot, b.code_va(relocated));
            papa_tests::detail::poke(b.code, slot + 8U, b.data_va(0));
        } else {
            papa_tests::detail::poke(b.code, entry + 11U,
                                     static_cast<std::uint32_t>(b.code_va(indirect)));
            papa_tests::detail::poke(b.code, slot,
                                     static_cast<std::uint32_t>(b.code_va(relocated)));
            papa_tests::detail::poke(b.code, slot + 8U,
                                     static_cast<std::uint32_t>(b.data_va(0)));
        }

        const auto img = papa::pe::PeParser::parse(b.build());
        REQUIRE(img.has_value());
        const pn::Disassembler             disasm(x64);
        const pn::flirt::FlirtSignatureSet no_sigs;
        const auto rec = pn::viv::discover_functions(*img, disasm, pn::build_import_table(*img),
                                                     no_sigs);

        // .pdata seeds only x64. The calling pass, which emulates the indirect call, and
        // the prologue scan run only on i386
        std::vector<std::uint32_t> want{callee, exported, tls, relocated, entry};
        const std::vector<std::uint32_t> only = x64 ? std::vector<std::uint32_t>{in_pdata}
                                                    : std::vector<std::uint32_t>{indirect, prologue};
        want.insert(want.end(), only.begin(), only.end());
        std::vector<std::uint64_t> want_va;
        for (const std::uint32_t at : want) { want_va.push_back(b.code_va(at)); }
        std::sort(want_va.begin(), want_va.end());

        std::vector<std::uint64_t>                              got_va;
        std::map<std::uint64_t, std::vector<std::uint64_t>> callers;
        for (const pn::Function& f : rec.functions) {
            got_va.push_back(f.va);
            if (!f.callers.empty()) { callers.emplace(f.va, f.callers); }
        }
        std::sort(got_va.begin(), got_va.end());
        CHECK(got_va == want_va);

        // The callee's two call sites count once, and no other function has a caller
        const std::map<std::uint64_t, std::vector<std::uint64_t>> want_callers{
            {b.code_va(callee), {b.code_va(entry)}}};
        CHECK(callers == want_callers);
    }
}
