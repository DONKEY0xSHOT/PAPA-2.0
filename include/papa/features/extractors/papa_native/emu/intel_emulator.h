#pragma once

#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/emu/memory.h"
#include "papa/features/extractors/papa_native/emu/registers.h"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace papa::features::extractors::papa_native::emu {

// Map a Zydis register to our register-file index (real or meta-register lane),
// for i386 (default) or amd64. Returns nullopt for registers the discovery
// emulator does not model (SIMD, segment, control/debug, x87), which read as 0
// and ignore writes.
[[nodiscard]] std::optional<std::uint32_t>
reg_index_from_zydis(ZydisRegister reg, bool is_64bit = false) noexcept;

// Branch flags mirroring envi BR_* (envi/__init__.py).
inline constexpr std::uint32_t kBrProc = 1U << 0;   // call target
inline constexpr std::uint32_t kBrCond = 1U << 1;   // conditional edge
inline constexpr std::uint32_t kBrDeref = 1U << 2;  // target is dereferenced
inline constexpr std::uint32_t kBrTable = 1U << 3;  // base of a pointer table
inline constexpr std::uint32_t kBrFall = 1U << 4;   // fall-through edge

// One control-flow successor returned by get_branches.
struct Branch {
    std::uint64_t va{0};
    std::uint32_t flags{0};
};

// Outcome of executing one instruction. Mirrors the conditions vivisect raises
// as exceptions (BreakpointHit, BadOpcode, DivideByZero, UnsupportedInstruction)
// but reported as a value, per papa's no-exceptions-for-control-flow standard.
enum class ExecResult {
    kContinue,      // executed normally
    kUnsupported,   // no handler for this mnemonic
    kBreakpoint,    // int / int3
    kBadOpcode,     // ud0 / ud1 / ud2
    kDivideByZero,  // div / idiv by zero
    kOutInstruction,  // in / out (privileged i/o)
};

// A faithful port of envi's i386 IntelEmulator, holding the register file and
// the sandboxed memory and reproducing the operand-access and instruction
// semantics the discovery passes rely on. Provides the operand layer
// (getOperValue/setOperValue/getOperAddr) and the instruction handlers.
class IntelEmulator {
public:
    // Construct for i386 (default) or amd64. The arch selects the register
    // model, the program-counter register (eip/rip), the pointer size for
    // push/pop/call/ret, and whether addresses are masked to 32 bits.
    explicit IntelEmulator(bool is_64bit = false) noexcept
        : regs_(is_64bit), is_64bit_(is_64bit) {}

    [[nodiscard]] RegisterFile& regs() noexcept { return regs_; }
    [[nodiscard]] const RegisterFile& regs() const noexcept { return regs_; }
    [[nodiscard]] SandboxMemory& memory() noexcept { return mem_; }
    [[nodiscard]] const SandboxMemory& memory() const noexcept { return mem_; }

    [[nodiscard]] std::uint64_t program_counter() const noexcept {
        return regs_.get_register(pc_index());
    }
    void set_program_counter(std::uint64_t va) noexcept {
        regs_.set_register(pc_index(), va);
    }

    // Execute one decoded instruction (envi executeOpcode): set the program
    // counter to the instruction, dispatch on the mnemonic, then advance the
    // program counter to the next instruction or a branch target.
    ExecResult execute_opcode(const DecodedInsn& insn);

    // Read operand `idx`, reading register or memory state as needed
    // (disasm.py getOperValue). Deref operands read from sandboxed memory.
    [[nodiscard]] std::uint64_t
        get_oper_value(const DecodedInsn& insn, std::size_t idx) const;

    // Address a deref operand would read from (disasm.py getOperAddr), masked
    // to the 32-bit pointer size. Non-deref operands return 0.
    [[nodiscard]] std::uint64_t
        get_oper_addr(const DecodedInsn& insn, std::size_t idx) const;

    // Write `value` to operand `idx` (disasm.py setOperValue). Immediate and
    // pc-relative operands cannot be set and are ignored.
    void set_oper_value(const DecodedInsn& insn, std::size_t idx,
                        std::uint64_t value);

    // Enumerate the instruction's control-flow successors, resolving indirect
    // targets from current register/memory state (disasm.py getBranches(emu)).
    [[nodiscard]] std::vector<Branch> get_branches(const DecodedInsn& insn) const;

private:
    [[nodiscard]] std::uint64_t
        register_value(ZydisRegister reg) const noexcept;

    // Stack primitives (emu.py doPush/doPop). size defaults to the 4-byte
    // pointer width.
    void do_push(std::uint64_t value, std::size_t size = 4);
    [[nodiscard]] std::uint64_t do_pop(std::size_t size = 4);

    // Arithmetic cores shared by several handlers (emu.py intSubBase /
    // integerSubtraction / logicalAnd). Each sets EFLAGS and returns the result.
    [[nodiscard]] std::uint64_t
        int_sub_base(std::uint64_t src, std::uint64_t dst,
                     std::size_t ssize, std::size_t dsize);
    [[nodiscard]] std::uint64_t integer_subtraction(const DecodedInsn& insn);
    [[nodiscard]] std::uint64_t logical_and(const DecodedInsn& insn);

    // Evaluate a conditional-jump mnemonic against EFLAGS (emu.py cond_*).
    [[nodiscard]] bool condition_met(ZydisMnemonic mnem) const noexcept;

    // SSE/XMM operand byte access for the move handlers. read_simd_oper reads
    // the 16-byte value of an XMM-register operand, `width` bytes of a memory
    // deref, or a general-purpose register (the movd/movq reg form).
    // write_simd_oper writes `width` bytes back, zero-extending an XMM-register
    // destination (the upper bytes of a scalar load are cleared).
    [[nodiscard]] Xmm read_simd_oper(const DecodedInsn& insn, std::size_t idx,
                                     std::size_t width) const;
    void write_simd_oper(const DecodedInsn& insn, std::size_t idx,
                         const Xmm& value, std::size_t width);

    // Arch-derived constants (i386 vs amd64): the program-counter register,
    // the pointer size for push/pop/call/ret, and the address mask.
    [[nodiscard]] std::uint32_t pc_index() const noexcept {
        return is_64bit_ ? kRegRip : kRegEip;
    }
    [[nodiscard]] std::size_t ptr_size() const noexcept {
        return is_64bit_ ? 8U : 4U;
    }
    [[nodiscard]] std::uint64_t addr_mask() const noexcept {
        return is_64bit_ ? 0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFFULL;
    }

    RegisterFile  regs_;
    SandboxMemory mem_;
    bool          is_64bit_{false};
};

}  // namespace papa::features::extractors::papa_native::emu
