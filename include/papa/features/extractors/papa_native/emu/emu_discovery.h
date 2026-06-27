#pragma once

#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <optional>
#include <unordered_set>
#include <vector>

namespace papa::features::extractors::papa_native::emu {

// The image sections copied once into emulator-owned byte buffers, reused as
// the read-only backing of every per-candidate emulation (each candidate gets
// its own register state and write overlay, but shares this backing). Building
// it once avoids copying the image per candidate.
struct ImageMaps {
    struct Entry {
        std::uint64_t base{0};
        std::uint32_t perms{0};
    };
    std::vector<std::vector<std::uint8_t>> bytes;    // one buffer per section
    std::vector<Entry>                     entries;  // parallel to bytes
};

// Translate PE section characteristics to emulator memory permissions.
[[nodiscard]] std::uint32_t section_perms(std::uint32_t characteristics) noexcept;

// Collect function-pointer candidate target VAs (deduplicated, sorted) the way
// vivisect's relocations.py and generic/pointers.py do: every HIGHLOW/DIR64
// base relocation marks a stored absolute pointer to follow (section-agnostic,
// so .text-resident callback/vtable/island-entry pointers are included), unioned
// with a findPointers scan of initialized data for aligned slots that point into
// code. Targets are validated behaviorally (validate_candidate) before being
// treated as functions, so raw noise here is filtered downstream.
[[nodiscard]] std::vector<std::uint64_t>
    find_pointer_candidates(const pe::PeImage& image);

// Copy each section's bytes into emulator-owned buffers with derived perms.
[[nodiscard]] ImageMaps build_image_maps(const pe::PeImage& image);

// The absolute pointer a RIP-relative `lea` computes (va + length + disp), or
// nullopt when the instruction is not a `lea` with a RIP-relative operand. This
// is vivisect's amd64 code-derived REF_PTR set: on amd64 the only code
// instruction that emits a REF_PTR is `lea reg, [rip + disp]`, whose operand is
// an address rather than a dereference. emucode treats these targets as function
// candidates. The caller filters them to undefined executable space.
[[nodiscard]] std::optional<std::uint64_t>
    riprel_lea_target(const DecodedInsn& insn) noexcept;

// Emulate from `va` over the image and report whether it behaves like a real
// function (analysis/generic/emucode.py: runFunction(maxhit=1) + watcher
// looks_good). Returns false if `va` is not in executable memory. This is the
// behavioral validator the discovery passes use to accept a candidate.
[[nodiscard]] bool validate_candidate(const ImageMaps& maps,
                                      const Disassembler& disasm,
                                      std::uint64_t va);

// Collects runtime-resolved indirect call targets as new function seeds during
// per-function emulation, a port of the discovery tail of vivisect's impemu
// AnalysisMonitor.apicall ("Emulation Found"). A target is seeded when it is
// concrete executable code, is not the function's own entry (recursion), and is
// not the fall-through immediately after the call.
class AnalysisMonitor : public EmulationMonitor {
public:
    explicit AnalysisMonitor(std::uint64_t funcva) noexcept : funcva_(funcva) {}

    void apicall(WorkspaceEmulator& emu, const DecodedInsn& op,
                 std::uint64_t pc) override;

    // The distinct seeds collected so far, sorted.
    [[nodiscard]] std::vector<std::uint64_t> seeds() const;

private:
    std::uint64_t                     funcva_;
    std::unordered_set<std::uint64_t> seeds_;
};

// Emulate from `va` (maxhit=1) and return the distinct executable indirect-call
// targets the emulation resolved (sorted). The per-function-emulation discovery
// primitive used by the i386 calling pass. Returns empty if `va` is not in
// executable memory.
[[nodiscard]] std::vector<std::uint64_t>
    discover_call_targets(const ImageMaps& maps, const Disassembler& disasm,
                          std::uint64_t va);

}  // namespace papa::features::extractors::papa_native::emu
