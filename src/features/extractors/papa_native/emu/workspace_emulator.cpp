#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace papa::features::extractors::papa_native::emu {

namespace {

// The general-purpose registers tainted at function entry (platarch/i386.py
// taintregs): every GP register except the stack pointer
constexpr std::array<std::uint32_t, 7> kTaintRegs = {
    kRegEax, kRegEcx, kRegEdx, kRegEbx, kRegEbp, kRegEsi, kRegEdi,
};

// The amd64 entry-tainted registers, being the GP registers that can carry an
// incoming argument
constexpr std::array<std::uint32_t, 9> kTaintRegs64 = {
    kRegRax, kRegRcx, kRegRdx, kRegRbx, kRegRbp, kRegRsi, kRegRdi, kRegR8, kRegR9,
};

constexpr std::size_t kFuncStackTaints = 20;
constexpr std::size_t kMaxInsnBytes = 15;

}  // namespace

WorkspaceEmulator::WorkspaceEmulator(const Disassembler& disasm) noexcept
    : disasm_(disasm),
      emu_(disasm.is_64bit()),
      is_64bit_(disasm.is_64bit()) {}

void WorkspaceEmulator::add_map(std::uint64_t base, std::uint32_t perms,
                                std::span<const std::uint8_t> bytes) {
    emu_.memory().add_map(base, perms, bytes);
}

void WorkspaceEmulator::prepare(std::uint64_t funcva) {
    // The stack base, slot size and entry-tainted registers all follow the arch, per
    // impemu initStackMemory and the platarch taintregs
    const std::size_t psize = is_64bit_ ? 8U : 4U;
    const std::uint64_t stack_base = is_64bit_ ? kStackBase64 : kStackBase;
    const std::uint64_t stack_top = is_64bit_ ? kStackTop64 : kStackTop;
    emu_.memory().init_stack(stack_base);

    // Pre-seed 20 stack-local taints at the top of the stack and point the stack
    // pointer at them (initStackMemory). The first stands for the saved return address
    const std::uint64_t sp = stack_top - kFuncStackTaints * psize;
    for (std::size_t i = 0; i < kFuncStackTaints; ++i) {
        const std::uint64_t t =
            taints_.allocate(TaintType::kFuncStack, i * psize);
        emu_.memory().write_value(sp + i * psize, t, psize);
    }
    emu_.regs().set_register(kRegEsp, sp);

    // Taint the entry registers so unknown inputs never drive control flow
    const std::span<const std::uint32_t> taintregs =
        is_64bit_ ? std::span<const std::uint32_t>(kTaintRegs64)
                  : std::span<const std::uint32_t>(kTaintRegs);
    for (const std::uint32_t reg : taintregs) {
        const std::uint64_t t = taints_.allocate(TaintType::kUninitReg, reg);
        emu_.regs().set_register(reg, t);
        emu_.regs().set_taint(reg, true);
    }

    emu_.set_program_counter(funcva);
}

WorkspaceEmulator::Snapshot WorkspaceEmulator::get_snap() const {
    return Snapshot{emu_.regs().snapshot(), emu_.memory().snapshot()};
}

void WorkspaceEmulator::set_snap(const Snapshot& snap) {
    emu_.regs().restore(snap.regs);
    emu_.memory().restore(snap.mem);
}

std::optional<DecodedInsn> WorkspaceEmulator::decode_at(std::uint64_t va) const {
    const std::vector<std::uint8_t> bytes =
        emu_.memory().read_code(va, kMaxInsnBytes);
    if (bytes.empty()) {
        return std::nullopt;
    }
    const std::span<const std::byte> code =
        std::as_bytes(std::span<const std::uint8_t>(bytes));
    Expected<DecodedInsn> decoded = disasm_.decode(code, va);
    if (!decoded.has_value()) {
        return std::nullopt;
    }
    return *decoded;
}

bool WorkspaceEmulator::check_call(const DecodedInsn& insn, EmulationMonitor* monitor) {
    if (!insn.is_call) {
        return false;
    }
    // The call target the operand resolved to. execute_opcode ran i_call and set the
    // program counter to it, as vivisect reads endeip before func_only rewinds
    const std::uint64_t pc = emu_.program_counter();
    // func_only: do not descend into the callee. Execution resumes at the
    // instruction after the call and the unknown return value taints EAX
    emu_.set_program_counter(insn.va + insn.length);
    const std::uint64_t ret = taints_.allocate(TaintType::kApiCall, insn.va);
    emu_.regs().set_register(kRegEax, ret);
    emu_.regs().set_taint(kRegEax, true);
    if (monitor != nullptr) {
        monitor->apicall(*this, insn, pc);
    }
    return true;
}

std::vector<std::uint64_t>
WorkspaceEmulator::check_branches(const DecodedInsn& insn) {
    std::vector<std::uint64_t> ret;
    const std::vector<Branch> branches = emu_.get_branches(insn);
    if (branches.size() <= 1) {
        return ret;
    }
    std::unordered_set<std::uint64_t> seen;
    for (const Branch& b : branches) {
        if (seen.insert(b.va).second) {
            ret.push_back(b.va);
        }
    }
    return ret;
}

std::size_t WorkspaceEmulator::run_function(std::uint64_t funcva,
                                            EmulationMonitor* monitor,
                                            std::uint32_t maxhit) {
    emustop_ = false;
    std::unordered_map<std::uint64_t, std::uint32_t> hits;
    // Paths share their snapshot rather than each deep-copying it, which is
    // observationally the same because a popped path only reads it
    std::vector<std::pair<std::uint64_t, std::shared_ptr<const Snapshot>>> todo;
    std::size_t queued_overlay = 0;
    const auto  push_path = [&todo, &queued_overlay](
                               std::uint64_t va,
                               const std::shared_ptr<const Snapshot>& snap) {
        const std::size_t cost = snap->mem.overlay.size();
        if (todo.size() >= kMaxTodoQueue ||
            queued_overlay + cost > kMaxQueuedOverlayEntries) {
            return false;
        }
        queued_overlay += cost;
        todo.emplace_back(va, snap);
        return true;
    };
    push_path(funcva, std::make_shared<const Snapshot>(get_snap()));

    std::size_t steps = 0;
    while (!todo.empty()) {
        auto [va, snap] = todo.back();
        todo.pop_back();
        queued_overlay -= snap->mem.overlay.size();
        set_snap(*snap);
        emu_.set_program_counter(va);

        while (steps < kMaxEmuSteps) {
            const std::uint64_t starteip = emu_.program_counter();
            if (!emu_.memory().is_valid_pointer(starteip)) {
                break;
            }
            const std::uint32_t hit = ++hits[starteip];
            if (hit > maxhit) {
                break;
            }

            const std::optional<DecodedInsn> op = decode_at(starteip);
            if (!op.has_value()) {
                break;
            }

            if (monitor != nullptr) {
                monitor->prehook(*this, *op, starteip);
                if (emustop_) {
                    return steps;
                }
            }

            const ExecResult result = emu_.execute_opcode(*op);
            ++steps;

            if (monitor != nullptr) {
                monitor->posthook(*this, *op, starteip);
                if (emustop_) {
                    return steps;
                }
            }

            // An execution fault (divide by zero) is an anomaly the watcher
            // treats as bad code (vivisect logAnomaly)
            if (result == ExecResult::kDivideByZero && monitor != nullptr) {
                monitor->log_anomaly(*this, starteip);
                if (emustop_) {
                    return steps;
                }
            }

            // Unsupported / privileged / trap: stop this path (strictops)
            if (result != ExecResult::kContinue) {
                break;
            }

            const bool iscall = check_call(*op, monitor);
            if (emustop_) {
                return steps;
            }

            if (!iscall) {
                const std::vector<std::uint64_t> blist = check_branches(*op);
                if (!blist.empty()) {
                    const auto branch_snap =
                        std::make_shared<const Snapshot>(get_snap());
                    for (const std::uint64_t bva : blist) {
                        if (!push_path(bva, branch_snap)) {
                            break;
                        }
                    }
                    break;
                }
            }

            if (op->is_return) {
                break;
            }
        }
    }
    return steps;
}

}  // namespace papa::features::extractors::papa_native::emu
