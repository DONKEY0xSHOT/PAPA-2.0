#include "papa/features/extractors/papa_native/emu/emu_discovery.h"

#include "papa/features/extractors/papa_native/emu/memory.h"
#include "papa/features/extractors/papa_native/emu/watcher.h"
#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"

#include <algorithm>
#include <cstddef>
#include <utility>

namespace papa::features::extractors::papa_native::emu {

namespace {

// PE section characteristics bits (winnt.h IMAGE_SCN_MEM_*).
constexpr std::uint32_t kScnMemExecute = 0x20000000U;
constexpr std::uint32_t kScnMemRead = 0x40000000U;
constexpr std::uint32_t kScnMemWrite = 0x80000000U;

// Base-relocation types that store an absolute pointer the loader fixes up.
constexpr std::uint16_t kRelBasedHighLow = 3;   // IMAGE_REL_BASED_HIGHLOW (32-bit)
constexpr std::uint16_t kRelBasedDir64 = 10;    // IMAGE_REL_BASED_DIR64 (64-bit)

// Assemble a little-endian unsigned value of the given width from a byte span.
[[nodiscard]] std::uint64_t read_le_uint(std::span<const std::byte> b,
                                         std::size_t width) noexcept {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < width && i < b.size(); ++i) {
        v |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(b[i])) << (8 * i);
    }
    return v;
}

}  // namespace

std::uint32_t section_perms(std::uint32_t characteristics) noexcept {
    std::uint32_t perms = 0;
    if ((characteristics & kScnMemRead) != 0) {
        perms |= kMemRead;
    }
    if ((characteristics & kScnMemWrite) != 0) {
        perms |= kMemWrite;
    }
    if ((characteristics & kScnMemExecute) != 0) {
        perms |= kMemExec;
    }
    return perms;
}

ImageMaps build_image_maps(const pe::PeImage& image) {
    ImageMaps maps;
    for (const pe::ParsedSection& s : image.sections()) {
        if (s.raw_size == 0) {
            continue;
        }
        auto raw = image.read_at_rva(s.virtual_address, s.raw_size);
        if (!raw) {
            continue;
        }
        std::vector<std::uint8_t> buf;
        buf.reserve(raw->size());
        for (const std::byte b : *raw) {
            buf.push_back(static_cast<std::uint8_t>(b));
        }
        maps.bytes.push_back(std::move(buf));
        maps.entries.push_back(ImageMaps::Entry{
            image.image_base() + s.virtual_address, section_perms(s.characteristics)});
    }
    return maps;
}

std::vector<std::uint64_t> find_pointer_candidates(const pe::PeImage& image) {
    // Executable VA ranges the candidate pointer values must target.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> exec_ranges;
    for (const pe::ParsedSection& s : image.sections()) {
        if ((s.characteristics & kScnMemExecute) != 0) {
            const std::uint64_t base = image.image_base() + s.virtual_address;
            exec_ranges.emplace_back(base, base + s.virtual_size);
        }
    }
    const auto in_exec = [&exec_ranges](std::uint64_t v) {
        for (const auto& [lo, hi] : exec_ranges) {
            if (v >= lo && v < hi) {
                return true;
            }
        }
        return false;
    };

    std::vector<std::uint64_t> targets;

    // Reloc-driven, section-agnostic (vivisect analysis/generic/relocations.py):
    // the loader fixes up every absolute pointer, so each HIGHLOW/DIR64 base
    // relocation marks a stored pointer to follow. The site can live anywhere,
    // including .text, which is where callback/vtable/island-entry pointers sit
    // and where the data-only scan never looks. Read the pointer at each site
    // and keep the values that target executable code.
    const std::size_t ptr_size = image.is_64bit() ? 8U : 4U;
    for (const pe::ParsedRelocation& r : image.relocations()) {
        std::size_t width = 0;
        if (r.type == kRelBasedHighLow) {
            width = 4;
        } else if (r.type == kRelBasedDir64) {
            width = 8;
        } else {
            continue;
        }
        auto bytes = image.read_at_rva(r.rva, width);
        if (!bytes) {
            continue;
        }
        const std::uint64_t v = read_le_uint(*bytes, width);
        if (in_exec(v)) {
            targets.push_back(v);
        }
    }

    // findPointers free-hanging scan (vivisect generic findPointers): aligned
    // slots in initialized data whose value points into code. The reloc scan is
    // authoritative for relocated binaries, but this also catches pointers in
    // images without a populated relocation table.
    for (const pe::ParsedSection& s : image.sections()) {
        if ((s.characteristics & kScnMemRead) == 0 ||
            (s.characteristics & kScnMemExecute) != 0) {
            continue;
        }
        auto raw = image.read_at_rva(s.virtual_address, s.raw_size);
        if (!raw) {
            continue;
        }
        const std::span<const std::byte> bytes = *raw;
        for (std::size_t off = 0; off + ptr_size <= bytes.size(); off += ptr_size) {
            const std::uint64_t v = read_le_uint(bytes.subspan(off, ptr_size), ptr_size);
            if (in_exec(v)) {
                targets.push_back(v);
            }
        }
    }

    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    return targets;
}

std::optional<std::uint64_t> riprel_lea_target(const DecodedInsn& insn) noexcept {
    if (insn.zyd_mnem != ZYDIS_MNEMONIC_LEA) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < insn.operand_count; ++i) {
        const DecodedOperand& op = insn.operands[i];
        if (op.kind == OperandKind::kRipRel) {
            // RIP addresses the next instruction, so the computed absolute is
            // va + length + disp (disp is signed).
            return insn.va + insn.length +
                   static_cast<std::uint64_t>(op.disp);
        }
    }
    return std::nullopt;
}

bool validate_candidate(const ImageMaps& maps, const Disassembler& disasm,
                        std::uint64_t va) {
    WorkspaceEmulator we(disasm);
    for (std::size_t i = 0; i < maps.entries.size(); ++i) {
        we.add_map(maps.entries[i].base, maps.entries[i].perms, maps.bytes[i]);
    }
    // emucode only emulates executable candidates.
    if (!we.emu().memory().probe(va, 1, kMemExec)) {
        return false;
    }
    we.prepare(va);
    Watcher watcher;
    we.run_function(va, &watcher, /*maxhit=*/1);
    return watcher.looks_good();
}

void AnalysisMonitor::apicall(WorkspaceEmulator& emu, const DecodedInsn& op,
                              std::uint64_t pc) {
    // vivisect AnalysisMonitor.apicall discovery tail (impemu/monitor.py).
    if (pc == funcva_) {
        return;  // recursive self-call
    }
    if (pc == op.va + op.length) {
        return;  // call-next / "call 0" construct
    }
    // Only concrete executable targets are functions. A taint sentinel sits in
    // the reserved high band and is not in any mapped section, so the exec probe
    // also rejects unresolved indirect calls.
    if (!emu.emu().memory().probe(pc, 1, kMemExec)) {
        return;
    }
    seeds_.insert(pc);
}

std::vector<std::uint64_t> AnalysisMonitor::seeds() const {
    std::vector<std::uint64_t> out(seeds_.begin(), seeds_.end());
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::uint64_t> discover_call_targets(const ImageMaps& maps,
                                                 const Disassembler& disasm,
                                                 std::uint64_t va) {
    WorkspaceEmulator we(disasm);
    for (std::size_t i = 0; i < maps.entries.size(); ++i) {
        we.add_map(maps.entries[i].base, maps.entries[i].perms, maps.bytes[i]);
    }
    if (!we.emu().memory().probe(va, 1, kMemExec)) {
        return {};
    }
    we.prepare(va);
    AnalysisMonitor monitor(va);
    we.run_function(va, &monitor, /*maxhit=*/1);
    return monitor.seeds();
}

}  // namespace papa::features::extractors::papa_native::emu
