#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <array>
#include <cstdint>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// The WorkspaceEmulator runFunction driver, exercised over real 32-bit machine
// code placed in the sandboxed memory. Covers straight-line execution, branch
// exploration, no-recurse calls, and the DoS caps (maxhit, step cap).

namespace {

// Records every instruction address the emulator visits, and the EAX value at
// a chosen address.
class Recorder : public emu::EmulationMonitor {
public:
    std::vector<std::uint64_t> visited;
    std::uint64_t watch_eip{0};
    std::uint64_t eax_at_watch{0};
    bool watched{false};

    void prehook(emu::WorkspaceEmulator& e, const pn::DecodedInsn& /*insn*/,
                 std::uint64_t eip) override {
        visited.push_back(eip);
        if (eip == watch_eip) {
            eax_at_watch = e.emu().regs().get_register(emu::kRegEax);
            watched = true;
        }
    }

    [[nodiscard]] bool saw(std::uint64_t va) const {
        for (const std::uint64_t v : visited) {
            if (v == va) {
                return true;
            }
        }
        return false;
    }
};

// Records every intercepted call as (call-site va, resolved target pc), the way
// vivisect's AnalysisMonitor.apicall receives the resolved call target.
class ApiCallRecorder : public emu::EmulationMonitor {
public:
    struct Call {
        std::uint64_t site;
        std::uint64_t target;
    };
    std::vector<Call> calls;

    void apicall(emu::WorkspaceEmulator& /*e*/, const pn::DecodedInsn& op,
                 std::uint64_t pc) override {
        calls.push_back(Call{op.va, pc});
    }
};

constexpr std::uint64_t kBase = 0x00401000;

}  // namespace

TEST_CASE("emu workspace: prepare taints the entry registers and seeds the stack") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    we.prepare(kBase);
    // EAX is a taint sentinel, not a real pointer; ESP points into the stack.
    CHECK(we.emu().regs().is_tainted(emu::kRegEax));
    CHECK_FALSE(we.emu().memory().is_valid_pointer(
        we.emu().regs().get_register(emu::kRegEax)));
    CHECK(we.emu().memory().is_valid_pointer(we.emu().regs().get_register(emu::kRegEsp)));
}

TEST_CASE("emu workspace: a straight-line function runs to its ret") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // xor eax, eax ; ret
    static const std::array<std::uint8_t, 3> code = {0x31, 0xC0, 0xC3};
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);

    Recorder rec;
    const std::size_t steps = we.run_function(kBase, &rec);
    CHECK(rec.saw(kBase));          // xor
    CHECK(rec.saw(kBase + 2));      // ret
    CHECK(steps == 2);
}

TEST_CASE("emu workspace: a direct jmp is followed") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // jmp +0 (to the next instruction) ; ret
    static const std::array<std::uint8_t, 3> code = {0xEB, 0x00, 0xC3};
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);

    Recorder rec;
    we.run_function(kBase, &rec);
    CHECK(rec.saw(kBase));          // jmp
    CHECK(rec.saw(kBase + 2));      // ret
}

TEST_CASE("emu workspace: both sides of a conditional branch are explored") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // jz +1 ; ret (fall-through) ; ret (taken)
    static const std::array<std::uint8_t, 4> code = {0x74, 0x01, 0xC3, 0xC3};
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);

    Recorder rec;
    we.run_function(kBase, &rec);
    CHECK(rec.saw(kBase + 2));      // fall-through ret
    CHECK(rec.saw(kBase + 3));      // taken ret
}

TEST_CASE("emu workspace: a call does not recurse and taints the return value") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // call 0x402000 (unmapped target) ; ret
    // E8 imm32 where imm32 = 0x402000 - (0x401000 + 5) = 0x0FFB
    static const std::array<std::uint8_t, 6> code = {
        0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3};
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);

    Recorder rec;
    rec.watch_eip = kBase + 5;  // the ret, right after the call
    we.run_function(kBase, &rec);

    // Reaching the ret proves we did not jump into the unmapped callee.
    CHECK(rec.saw(kBase + 5));
    REQUIRE(rec.watched);
    const std::optional<emu::TaintInfo> t = we.taints().lookup(rec.eax_at_watch);
    REQUIRE(t.has_value());
    CHECK(t->type == emu::TaintType::kApiCall);
}

TEST_CASE("emu workspace: apicall reports the resolved indirect call target") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // mov eax, 0x00402000 ; call eax ; ret
    static const std::array<std::uint8_t, 8> code = {
        0xB8, 0x00, 0x20, 0x40, 0x00, 0xFF, 0xD0, 0xC3};
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);

    ApiCallRecorder rec;
    we.run_function(kBase, &rec);

    REQUIRE(rec.calls.size() == 1);
    CHECK(rec.calls[0].site == kBase + 5);       // the `call eax`
    CHECK(rec.calls[0].target == 0x00402000);    // resolved from the emulated eax
}

TEST_CASE("emu workspace: apicall reports a direct call target") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // call 0x402000 ; ret  (E8 imm32, imm32 = 0x402000 - (0x401000 + 5) = 0x0FFB)
    static const std::array<std::uint8_t, 6> code = {
        0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3};
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);

    ApiCallRecorder rec;
    we.run_function(kBase, &rec);

    REQUIRE(rec.calls.size() == 1);
    CHECK(rec.calls[0].site == kBase);
    CHECK(rec.calls[0].target == 0x00402000);
}

TEST_CASE("emu workspace: an infinite self-loop is bounded by maxhit") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // jmp -2 (to itself)
    static const std::array<std::uint8_t, 2> code = {0xEB, 0xFE};
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);

    const std::size_t steps = we.run_function(kBase, nullptr, /*maxhit=*/1);
    CHECK(steps == 1);  // executed once, second visit hit the cap
}

TEST_CASE("emu workspace: a long run is bounded by the step cap") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // A nop sled far longer than the step cap.
    static const std::array<std::uint8_t, 0x10000> sled = [] {
        std::array<std::uint8_t, 0x10000> a{};
        a.fill(0x90);
        return a;
    }();
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, sled);
    we.prepare(kBase);

    const std::size_t steps = we.run_function(kBase);
    CHECK(steps == emu::kMaxEmuSteps);
    CHECK(steps < sled.size());
}

// --- amd64: the workspace emulator must build the 64-bit register model, seed
// the 64-bit stack band, taint the amd64 entry registers (rax..r9), and run
// 64-bit code (platarch/amd64.py taintregs; impemu sign-extended stack base). ---

TEST_CASE("emu workspace amd64: prepare taints entry registers and seeds the 64-bit stack") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    emu::WorkspaceEmulator we(disasm);
    we.prepare(0x140001000ULL);
    CHECK(we.emu().regs().is_tainted(emu::kRegRax));
    CHECK(we.emu().regs().is_tainted(emu::kRegR9));   // r9 is an amd64 arg/taint reg
    const std::uint64_t rsp = we.emu().regs().get_register(emu::kRegRsp);
    CHECK(we.emu().memory().is_valid_pointer(rsp));   // rsp points into the stack
    CHECK(rsp > 0xFFFFFFFF00000000ULL);               // the sign-extended 64-bit band
}

TEST_CASE("emu workspace amd64: a 64-bit function runs to its ret") {
    const pn::Disassembler disasm(/*is_64bit=*/true);
    emu::WorkspaceEmulator we(disasm);
    // xor rax, rax ; ret  (REX.W 31 C0 ; C3)
    static const std::array<std::uint8_t, 4> code = {0x48, 0x31, 0xC0, 0xC3};
    const std::uint64_t base = 0x140001000ULL;
    we.add_map(base, emu::kMemRead | emu::kMemExec, code);
    we.prepare(base);
    Recorder rec;
    const std::size_t steps = we.run_function(base, &rec);
    CHECK(rec.saw(base));        // xor rax, rax
    CHECK(rec.saw(base + 3));    // ret
    CHECK(steps == 2);
}
