#pragma once

#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/intel_emulator.h"
#include "papa/features/extractors/papa_native/emu/taints.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace papa::features::extractors::papa_native::emu {

class WorkspaceEmulator;

// Hard caps that bound a single discovery emulation (DoS guards). All are
// constants and any breach ends the run cleanly, never the whole analysis
inline constexpr std::size_t   kMaxEmuSteps = 4096;     // total executed insns
inline constexpr std::size_t   kMaxTodoQueue = 4096;    // queued branch paths
inline constexpr std::uint32_t kDefaultMaxHit = 1;      // visits per address

// Total overlay entries the work queue may hold across every pending path.
// The queue length alone is not a memory bound, because each queued path
// carries the emulated writes made so far and the overlay is capped per
// snapshot rather than across the queue. A run that writes heavily and then
// branches repeatedly would otherwise multiply one large overlay by the queue
// length. Real functions write a few dozen stack bytes, so this never binds
inline constexpr std::size_t   kMaxQueuedOverlayEntries = 1U << 22;

// A hook called around each emulated instruction (impemu EmulationMonitor). The
// discovery watcher derives from this to observe the instruction stream and
// stop emulation when it has seen enough
class EmulationMonitor {
public:
    virtual ~EmulationMonitor() = default;

    // Called before an instruction executes. May call emu.stop_emu()
    virtual void prehook(WorkspaceEmulator& /*emu*/, const DecodedInsn& /*insn*/,
                         std::uint64_t /*eip*/) {}

    // Called after an instruction executes
    virtual void posthook(WorkspaceEmulator& /*emu*/, const DecodedInsn& /*insn*/,
                          std::uint64_t /*eip*/) {}

    // Called when an instruction faulted during execution (e.g. divide by
    // zero), the way vivisect routes such failures to logAnomaly. The watcher
    // uses this to mark a candidate as bad code
    virtual void log_anomaly(WorkspaceEmulator& /*emu*/, std::uint64_t /*eip*/) {}

    // Called when a call is intercepted, with the resolved call target pc (impemu
    // AnalysisMonitor.apicall). The discovery monitor uses this to seed runtime-
    // resolved indirect call targets as new functions. For an indirect call the
    // target is read from the emulated register or memory state
    virtual void apicall(WorkspaceEmulator& /*emu*/, const DecodedInsn& /*op*/,
                         std::uint64_t /*pc*/) {}
};

// A faithful port of vivisect's WorkspaceEmulator runFunction driver: it
// emulates inside one function over a bounded work-queue of (address, snapshot)
// paths, exploring both sides of conditional branches and resolving indirect
// flow from live state, without recursing into callees (their return value is
// tainted). It owns an IntelEmulator (register + sandboxed memory) and decodes
// instructions from that memory. Used by the discovery passes to validate and
// reach functions static descent misses
class WorkspaceEmulator {
public:
    explicit WorkspaceEmulator(const Disassembler& disasm) noexcept;

    [[nodiscard]] IntelEmulator& emu() noexcept { return emu_; }
    [[nodiscard]] const IntelEmulator& emu() const noexcept { return emu_; }
    [[nodiscard]] TaintRegistry& taints() noexcept { return taints_; }

    // Map an image section (or any backing bytes) into the emulated space
    void add_map(std::uint64_t base, std::uint32_t perms,
                 std::span<const std::uint8_t> bytes);

    // Set up the stack, stack-local taints and tainted entry registers, then
    // point the program counter at funcva (impemu __init__ + initStackMemory)
    void prepare(std::uint64_t funcva);

    void stop_emu() noexcept { emustop_ = true; }
    [[nodiscard]] bool stopped() const noexcept { return emustop_; }

    // Emulate inside the function at funcva. Returns the number of instructions
    // executed (bounded by kMaxEmuSteps). `monitor` may observe and stop the run
    std::size_t run_function(std::uint64_t funcva,
                             EmulationMonitor* monitor = nullptr,
                             std::uint32_t maxhit = kDefaultMaxHit);

private:
    struct Snapshot {
        RegisterFile::Snapshot  regs;
        SandboxMemory::Snapshot mem;
    };

    [[nodiscard]] Snapshot get_snap() const;
    void set_snap(const Snapshot& snap);
    [[nodiscard]] std::optional<DecodedInsn> decode_at(std::uint64_t va) const;

    // Intercept a call: do not recurse, taint the return value, continue after
    // the call (impemu checkCall, func_only). Notifies the monitor's apicall hook
    // with the resolved target. Returns true if it was a call
    bool check_call(const DecodedInsn& insn, EmulationMonitor* monitor);

    // Collect the branch targets to queue for a non-call instruction
    // (impemu checkBranches): distinct successors when there is more than one
    [[nodiscard]] std::vector<std::uint64_t> check_branches(const DecodedInsn& insn);

    const Disassembler& disasm_;
    IntelEmulator       emu_;
    TaintRegistry       taints_;
    bool                emustop_{false};
    bool                is_64bit_{false};
};

}  // namespace papa::features::extractors::papa_native::emu
