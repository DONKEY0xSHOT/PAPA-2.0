#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// The WorkspaceEmulator runFunction driver, exercised over real 32-bit machine code
// placed in the sandboxed memory

namespace {

// Records every instruction address the emulator visits, and the EAX value at
// a chosen address
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
// vivisect's AnalysisMonitor.apicall receives the resolved call target
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

TEST_CASE("emu workspace: prepare taints the entry registers and points the stack pointer into the stack") {
    struct Row {
        std::string_view           label;
        bool                       is_64bit;
        std::uint64_t              entry;
        std::vector<std::uint32_t> tainted;
        std::uint64_t              sp_above;
    };
    const std::vector<Row> rows{
        {"i386 taints EAX and seeds the stack", false, kBase, {emu::kRegEax}, emu::kStackBase - 1U},
        // r9 is an amd64 argument register, and the 64-bit stack sits in the sign-extended band
        {"amd64 taints RAX and R9 and seeds the 64-bit stack", true, 0x140001000ULL,
         {emu::kRegRax, emu::kRegR9}, 0xFFFFFFFF00000000ULL},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const pn::Disassembler disasm(row.is_64bit);
        emu::WorkspaceEmulator we(disasm);
        we.prepare(row.entry);
        // A tainted register holds a taint sentinel, which is never a real pointer
        for (const std::uint32_t r : row.tainted) {
            CAPTURE(r);
            CHECK(we.emu().regs().is_tainted(r));
            CHECK_FALSE(we.emu().memory().is_valid_pointer(we.emu().regs().get_register(r)));
        }
        const std::uint64_t sp = we.emu().regs().get_register(emu::kRegEsp);
        CHECK(we.emu().memory().is_valid_pointer(sp));
        CHECK(sp > row.sp_above);
    }
}

TEST_CASE("emu workspace: run_function follows straight lines, jumps and both sides of a branch to each ret") {
    struct Row {
        std::string_view           label;
        bool                       is_64bit;
        std::uint64_t              base;
        std::vector<std::uint8_t>  code;
        std::vector<std::uint64_t> visited;
        std::size_t                steps;
    };
    const std::vector<Row> rows{
        // xor eax, eax / ret
        {"a straight-line function runs to its ret", false, kBase, {0x31, 0xC0, 0xC3},
         {kBase, kBase + 2}, 2},
        // jmp +0 (to the next instruction) / ret
        {"a direct jmp is followed", false, kBase, {0xEB, 0x00, 0xC3}, {kBase, kBase + 2}, 2},
        // jz +1 / ret (fall-through) / ret (taken)
        {"both sides of a conditional branch are explored", false, kBase, {0x74, 0x01, 0xC3, 0xC3},
         {kBase + 2, kBase + 3}, 3},
        // xor rax, rax / ret (REX.W 31 C0 / C3)
        {"amd64 a 64-bit function runs to its ret", true, 0x140001000ULL, {0x48, 0x31, 0xC0, 0xC3},
         {0x140001000ULL, 0x140001003ULL}, 2},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const pn::Disassembler disasm(row.is_64bit);
        emu::WorkspaceEmulator we(disasm);
        we.add_map(row.base, emu::kMemRead | emu::kMemExec, row.code);
        we.prepare(row.base);
        Recorder rec;
        const std::size_t steps = we.run_function(row.base, &rec);
        for (const std::uint64_t va : row.visited) {
            CAPTURE(va);
            CHECK(rec.saw(va));
        }
        CHECK(steps == row.steps);
    }
}

TEST_CASE("emu workspace: a call does not recurse and taints the return value") {
    const pn::Disassembler disasm(/*is_64bit=*/false);
    emu::WorkspaceEmulator we(disasm);
    // call 0x402000 (unmapped target) / ret
    // E8 imm32 where imm32 = 0x402000 - (0x401000 + 5) = 0x0FFB
    static const std::array<std::uint8_t, 6> code = {
        0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3};
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);

    Recorder rec;
    rec.watch_eip = kBase + 5;  // the ret, right after the call
    we.run_function(kBase, &rec);

    // Reaching the ret proves we did not jump into the unmapped callee
    CHECK(rec.saw(kBase + 5));
    REQUIRE(rec.watched);
    const std::optional<emu::TaintInfo> t = we.taints().lookup(rec.eax_at_watch);
    REQUIRE(t.has_value());
    CHECK(t->type == emu::TaintType::kApiCall);
}

TEST_CASE("emu workspace: apicall reports the call site and the resolved direct or indirect target") {
    struct Row {
        std::string_view          label;
        std::vector<std::uint8_t> code;
        std::uint64_t             site;
    };
    const std::vector<Row> rows{
        // mov eax, 0x00402000 / call eax / ret
        {"an indirect call resolves its target from the emulated eax",
         {0xB8, 0x00, 0x20, 0x40, 0x00, 0xFF, 0xD0, 0xC3}, kBase + 5},
        // call 0x402000 / ret  (E8 imm32, imm32 = 0x402000 - (0x401000 + 5) = 0x0FFB)
        {"a direct call reports its target", {0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3}, kBase},
    };
    const pn::Disassembler disasm(/*is_64bit=*/false);
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::WorkspaceEmulator we(disasm);
        we.add_map(kBase, emu::kMemRead | emu::kMemExec, row.code);
        we.prepare(kBase);
        ApiCallRecorder rec;
        we.run_function(kBase, &rec);
        CHECK(rec.calls.size() == 1);
        if (rec.calls.size() != 1) { continue; }
        CHECK(rec.calls[0].site == row.site);
        CHECK(rec.calls[0].target == 0x00402000);
    }
}

TEST_CASE("emu workspace: maxhit and the step cap bound a run that would not end") {
    struct Row {
        std::string_view          label;
        std::vector<std::uint8_t> code;
        std::uint32_t             maxhit;
        std::size_t               steps;
    };
    const std::vector<Row> rows{
        // jmp -2 (to itself): executed once, and the second visit hits the cap
        {"an infinite self-loop is bounded by maxhit", {0xEB, 0xFE}, 1, 1},
        // A nop sled far longer than the step cap
        {"a long run is bounded by the step cap", std::vector<std::uint8_t>(0x10000, 0x90),
         emu::kDefaultMaxHit, emu::kMaxEmuSteps},
    };
    const pn::Disassembler disasm(/*is_64bit=*/false);
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::WorkspaceEmulator we(disasm);
        we.add_map(kBase, emu::kMemRead | emu::kMemExec, row.code);
        we.prepare(kBase);
        const std::size_t steps = we.run_function(kBase, nullptr, row.maxhit);
        CHECK(steps == row.steps);
        CHECK(steps < row.code.size());
    }
}
