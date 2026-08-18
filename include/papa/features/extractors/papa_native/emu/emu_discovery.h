#pragma once

#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"
#include "papa/pe/pe_image.h"

#include <cstdint>
#include <optional>
#include <unordered_set>
#include <vector>

namespace papa::features::extractors::papa_native::emu {

// The image sections copied once into emulator-owned buffers, reused as the
// read-only backing of every per-candidate emulation
struct ImageMaps {
    struct Entry {
        std::uint64_t base{0};
        std::uint32_t perms{0};
    };
    std::vector<std::vector<std::uint8_t>> bytes;    // one buffer per section
    std::vector<Entry>                     entries;  // parallel to bytes
};

// Translate PE section characteristics to emulator memory permissions
[[nodiscard]] std::uint32_t section_perms(std::uint32_t characteristics) noexcept;

// Collect function-pointer candidate target VAs the way vivisect's relocations.py
// and generic/pointers.py do. Targets are validated behaviorally before use
[[nodiscard]] std::vector<std::uint64_t>
    find_pointer_candidates(const pe::PeImage& image);

// Copy each section's bytes into emulator-owned buffers with derived perms
[[nodiscard]] ImageMaps build_image_maps(const pe::PeImage& image);

// The absolute pointer a RIP-relative `lea` computes (va + length + disp), or nullopt
// when the instruction is not a `lea` with a RIP-relative operand
[[nodiscard]] std::optional<std::uint64_t>
    riprel_lea_target(const DecodedInsn& insn) noexcept;

// Emulate from `va` over the image and report whether it behaves like a real function
// (analysis/generic/emucode.py: runFunction(maxhit=1) + watcher looks_good)
[[nodiscard]] bool validate_candidate(const ImageMaps& maps,
                                      const Disassembler& disasm,
                                      std::uint64_t va);

// Collects runtime-resolved indirect call targets as new function seeds during per-
// function emulation, a port of the discovery tail of vivisect's impemu
class AnalysisMonitor : public EmulationMonitor {
public:
    explicit AnalysisMonitor(std::uint64_t funcva) noexcept : funcva_(funcva) {}

    void apicall(WorkspaceEmulator& emu, const DecodedInsn& op,
                 std::uint64_t pc) override;

    // The distinct seeds collected so far, sorted
    [[nodiscard]] std::vector<std::uint64_t> seeds() const;

private:
    std::uint64_t                     funcva_;
    std::unordered_set<std::uint64_t> seeds_;
};

// Emulate from `va` (maxhit=1) and return the distinct executable indirect-call targets
// the emulation resolved (sorted)
[[nodiscard]] std::vector<std::uint64_t>
    discover_call_targets(const ImageMaps& maps, const Disassembler& disasm,
                          std::uint64_t va);

// Emulate the function at funcva until execution first reaches target_va, then
// return the concrete value of reg there, or nullopt if it is never reached
[[nodiscard]] std::optional<std::uint64_t>
    emulate_to_read_register(const ImageMaps& maps, const Disassembler& disasm,
                             std::uint64_t funcva, std::uint64_t target_va,
                             ZydisRegister reg);

}  // namespace papa::features::extractors::papa_native::emu
