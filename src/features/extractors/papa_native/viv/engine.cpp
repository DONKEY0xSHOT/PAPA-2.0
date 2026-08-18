#include "papa/features/extractors/papa_native/viv/engine.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>

#include "papa/constants.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/emu/emu_discovery.h"
#include "papa/features/extractors/papa_native/insn.h"
#include "papa/features/extractors/papa_native/jump_tables.h"
#include "papa/features/extractors/papa_native/flirt/flirt_matcher.h"
#include "papa/features/extractors/papa_native/library_signatures.h"
#include "papa/features/extractors/papa_native/noreturn.h"
#include "papa/features/extractors/papa_native/viv/discovery.h"
#include "papa/features/extractors/papa_native/viv/discovery_passes.h"
#include "papa/features/extractors/papa_native/viv/flirt_analysis.h"

namespace papa::features::extractors::papa_native::viv {

namespace {

constexpr std::uint16_t kRelBasedHighLow = 3;   // IMAGE_REL_BASED_HIGHLOW (32-bit)
constexpr std::uint16_t kRelBasedDir64   = 10;  // IMAGE_REL_BASED_DIR64 (64-bit)

// True when va lies in an executable section of the image
bool va_is_executable(const pe::PeImage& image, std::uint64_t va) {
    if (va < image.image_base()) {
        return false;
    }
    const auto* sec = image.section_containing_rva(va - image.image_base());
    return sec != nullptr &&
           (sec->characteristics & constants::kImageScnMemExecute) != 0;
}

// Read n little-endian bytes at a VA, or nullopt when the VA is unmapped
std::optional<std::uint64_t> read_le_va(const pe::PeImage& image,
                                        std::uint64_t va, std::size_t n) {
    if (va < image.image_base()) {
        return std::nullopt;
    }
    const auto bytes = image.read_at_rva(va - image.image_base(), n);
    if (!bytes || bytes->size() < n) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        v |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>((*bytes)[i]))
             << (8 * i);
    }
    return v;
}

// Resolve a switch dispatch straight from the image
std::optional<JumpTableTargets>
resolve_jump_table(const pe::PeImage& image, const Disassembler& disasm,
                   const emu::ImageMaps& maps,
                   std::span<const DecodedInsn> window) {
    if (window.empty()) {
        return std::nullopt;
    }
    const TableReader read_u32 =
        [&image](std::uint64_t va) -> std::optional<std::uint32_t> {
        if (va < image.image_base()) {
            return std::nullopt;
        }
        const auto b = image.read_at_rva(va - image.image_base(), 4);
        if (!b || b->size() < 4) {
            return std::nullopt;
        }
        std::uint32_t value = 0;
        std::memcpy(&value, b->data(), sizeof(value));
        return value;
    };

    const ByteReader read_u8 =
        [&image](std::uint64_t va) -> std::optional<std::uint8_t> {
        if (va < image.image_base()) {
            return std::nullopt;
        }
        const auto b = image.read_at_rva(va - image.image_base(), 1);
        if (!b || b->empty()) {
            return std::nullopt;
        }
        return std::to_integer<std::uint8_t>((*b)[0]);
    };

    const DecodedInsn&              jmp = window.back();
    std::optional<JumpTableTargets> jt;

    // The faithful x64 path: emulate the enclosing function to the dispatch, read the
    // base register there, then walk the image-base-relative offset table
    if (image.is_64bit() && !window.empty()) {
        SwitchEnv env;
        env.image_base = image.image_base();
        env.read_entry = read_u32;
        env.is_probably_code = [&image, &disasm](std::uint64_t va) {
            if (!va_is_executable(image, va)) {
                return false;
            }
            const auto bytes = image.read_at_rva(va - image.image_base(), 16);
            return bytes.has_value() && !bytes->empty() &&
                   disasm.decode(*bytes, va).has_value();
        };
        const std::uint64_t funcva = window.front().va;
        const std::uint64_t jmpva  = jmp.va;
        env.base_reg_value =
            [&maps, &disasm, funcva, jmpva](
                ZydisRegister reg) -> std::optional<std::uint64_t> {
            return emu::emulate_to_read_register(maps, disasm, funcva, jmpva, reg);
        };
        jt = resolve_switch_jump_table(window, image.is_64bit(), env);
    }

    if (!jt.has_value()) {
        if (const auto* sec =
                image.section_containing_rva(jmp.va - image.image_base());
            sec != nullptr &&
            (sec->characteristics & constants::kImageScnMemExecute) != 0) {
            const std::uint64_t sec_lo = image.image_base() + sec->virtual_address;
            const std::uint64_t sec_hi =
                sec_lo + std::max(sec->virtual_size, sec->raw_size);
            jt = resolve_memory_indirect_jump_table(jmp, sec_lo, sec_hi, read_u32);
        }
    }
    const std::uint64_t lo = image.image_base();
    const std::uint64_t hi = image.image_base() + image.size_of_image();
    // The two-level idiom is tried before the single-level, which would otherwise
    // mis-read its offset table with the un-remapped switch value
    if (!jt.has_value()) {
        jt = resolve_two_level_indexed_jump_table(window, image.is_64bit(), lo, hi,
                                                  read_u32, read_u8);
    }
    if (!jt.has_value()) {
        jt = resolve_indexed_jump_table(window, image.is_64bit(), lo, hi, read_u32);
    }
    return jt;
}

// The entrypoints-pass seeds: the PE entry, every non-forwarded export, each
// executable TLS callback, and the x64 .pdata function begins
std::vector<std::uint64_t> entrypoint_seeds(const pe::PeImage& image) {
    const std::uint64_t        base = image.image_base();
    std::vector<std::uint64_t> entries;
    if (image.entry_point_rva() != 0) {
        entries.push_back(base + image.entry_point_rva());
    }
    for (const auto& e : image.exports()) {
        if (!e.forwarder.has_value() && e.va != 0) {
            entries.push_back(e.va);
        }
    }
    for (const std::uint64_t cb : image.tls_callbacks_va()) {
        if (cb != 0 && va_is_executable(image, cb)) {
            entries.push_back(cb);
        }
    }
    for (const std::uint64_t begin : cfg::pdata_function_begins(image)) {
        entries.push_back(begin);
    }
    return entries;
}

// The relocation-pass sites: every HIGHLOW or DIR64 base-relocation address
std::vector<std::uint64_t> reloc_pointer_sites(const pe::PeImage& image) {
    const std::uint64_t        base = image.image_base();
    std::vector<std::uint64_t> sites;
    for (const auto& r : image.relocations()) {
        if (r.type == kRelBasedHighLow || r.type == kRelBasedDir64) {
            sites.push_back(base + r.rva);
        }
    }
    return sites;
}

}  // namespace

RecoveredImage
discover_functions(const pe::PeImage& image, const Disassembler& disasm) {
    const std::uint64_t ptr_size = image.is_64bit() ? 8U : 4U;
    const emu::ImageMaps maps    = emu::build_image_maps(image);
    const InsnReader     reader  = cfg::make_image_reader(image, disasm);

    // The API no-return oracle: a call whose resolved import is an exit/abort family
    // function does not return
    const ImportTable    imports = build_import_table(image);
    const NoReturnOracle api_no_return =
        [&image, &disasm, &imports](const DecodedInsn& ins) -> bool {
        if (!ins.is_call) {
            return false;
        }
        const pe::ParsedImport* row =
            insn::resolve_direct_call_import(ins, image, imports, disasm);
        return row != nullptr && is_noreturn_api(row->dll, row->name);
    };

    Discovery disc(
        reader,
        [&image](std::uint64_t va) { return va_is_executable(image, va); },
        [&image, &disasm, &maps](std::span<const DecodedInsn> window) {
            return resolve_jump_table(image, disasm, maps, window);
        },
        [&maps, &disasm](std::uint64_t va) {
            return emu::validate_candidate(maps, disasm, va);
        },
        [&image, ptr_size](std::uint64_t site) {
            return read_le_va(image, site, ptr_size);
        },
        ptr_size, api_no_return);

    // FLIRT runs as an analysis module, installed before any function is made so it
    // fires as each one is analyzed. This is the only FLIRT pass
    const LibrarySignatureSet   library_sigs = LibrarySignatureSet::make_default();
    const DiscoveryFlirtContext flirt_context(image, reader, disc);
    std::vector<flirt::ModuleMatchFn> matchers;
    for (const flirt::FlirtTree& tree : library_sigs.flirt().trees()) {
        matchers.emplace_back([&tree](std::span<const std::uint8_t> bytes) {
            return flirt::match_flirt_modules(tree, bytes);
        });
    }
    FlirtDiscoveryAnalyzer      flirt_analyzer(
        std::move(matchers), flirt_context,
        [&disc, &image](std::uint64_t target) {
            // makeFunction runs for a local-name offset only where the address is
            // undefined and executable
            if (!disc.locations().get_location(target).has_value() &&
                va_is_executable(image, target)) {
                disc.make_function(target);
            }
        },
        [&disc](std::uint64_t target) { return disc.is_function(target); });
    disc.set_flirt_fmod(
        [&flirt_analyzer](std::uint64_t va) { flirt_analyzer.on_function(va); });

    // The passes run in vivisect's amod order so a function another pass already
    // claimed is left alone, and codeblocks runs inline at each make
    run_entrypoints(disc, entrypoint_seeds(image));
    run_relocations(disc, reloc_pointer_sites(image));

    const std::vector<std::uint64_t> static_candidates =
        emu::find_pointer_candidates(image);
    run_emucode(disc, [&disc, &image, &reader, &static_candidates]() {
        std::vector<std::uint64_t> c = static_candidates;
        if (image.is_64bit()) {
            // On amd64 the only code-derived pointer is a RIP-relative lea target,
            // recomputed each pass as new functions expose their own lea sites
            disc.locations().for_each_location([&](const Location& loc) {
                if (loc.type != LocType::kOp) {
                    return;
                }
                const auto insn = reader(loc.va);
                if (!insn.has_value()) {
                    return;
                }
                if (const auto t = emu::riprel_lea_target(*insn);
                    t.has_value() && va_is_executable(image, *t)) {
                    c.push_back(*t);
                }
            });
        }
        return c;
    });

    // The calling and funcentries passes are i386-only, matching vivisect. On amd64
    // the pointer, lea and .pdata passes already reach the function set
    if (!image.is_64bit()) {
        // Calling: emulate each function and make a function of every indirect
        // call target it resolves
        run_calling(disc, [&maps, &disasm](std::uint64_t fva) {
            return emu::discover_call_targets(maps, disasm, fva);
        });

        // Funcentries: prologue-scan the .text gaps no earlier pass reached
        const pe::ParsedSection* text = nullptr;
        for (const auto& s : image.sections()) {
            if (s.name == ".text") {
                text = &s;
                break;
            }
        }
        if (text != nullptr) {
            const std::uint64_t text_base = image.image_base() + text->virtual_address;
            if (const auto raw =
                    image.read_at_rva(text->virtual_address, text->raw_size);
                raw.has_value()) {
                std::vector<std::uint8_t> code;
                code.reserve(raw->size());
                for (const std::byte b : *raw) {
                    code.push_back(static_cast<std::uint8_t>(b));
                }
                run_funcentries(disc, [&disc, text_base, code = std::move(code)]() {
                    std::vector<std::uint8_t> covered(code.size(), 0U);
                    disc.locations().for_each_location(
                        [&covered, text_base](const Location& loc) {
                            if (loc.type != LocType::kOp || loc.va < text_base) {
                                return;
                            }
                            const std::size_t off =
                                static_cast<std::size_t>(loc.va - text_base);
                            for (std::uint64_t k = 0;
                                 k < loc.size && off + k < covered.size(); ++k) {
                                covered[off + k] = 1U;
                            }
                        });
                    return cfg::find_function_prologues(code, text_base, covered);
                });
            }
        }
    }

    RecoveredImage out;
    out.functions     = disc.materialize_functions();
    out.library_names = flirt_analyzer.library_names();
    return out;
}

}  // namespace papa::features::extractors::papa_native::viv
