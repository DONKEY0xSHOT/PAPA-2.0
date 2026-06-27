#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/watcher.h"
#include "papa/features/extractors/papa_native/emu/workspace_emulator.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <array>
#include <cstdint>

namespace emu = papa::features::extractors::papa_native::emu;
namespace pn = papa::features::extractors::papa_native;

// The watcher decides whether an emulated candidate looks like a real function:
// a faithful port of analysis/generic/emucode.py watcher. looks_good requires
// reaching a ret via varied, non-privileged, non-garbage instructions. Driven
// through run_function over real 32-bit code.

namespace {

constexpr std::uint64_t kBase = 0x00401000;

template <std::size_t N>
emu::Watcher run(const pn::Disassembler& disasm, const std::array<std::uint8_t, N>& code) {
    emu::WorkspaceEmulator we(disasm);
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);
    emu::Watcher watcher;
    we.run_function(kBase, &watcher);
    return watcher;
}

}  // namespace

TEST_CASE("emu watcher: a small function that reaches a ret looks good") {
    const pn::Disassembler disasm(false);
    // xor eax, eax ; add eax, 1 ; ret
    const std::array<std::uint8_t, 6> code = {0x31, 0xC0, 0x83, 0xC0, 0x01, 0xC3};
    const emu::Watcher w = run(disasm, code);
    CHECK(w.has_ret());
    CHECK(w.looks_good());
}

TEST_CASE("emu watcher: a body that never returns does not look good") {
    const pn::Disassembler disasm(false);
    // jmp -2 (infinite self-loop, never reaches a ret)
    const std::array<std::uint8_t, 2> code = {0xEB, 0xFE};
    const emu::Watcher w = run(disasm, code);
    CHECK_FALSE(w.has_ret());
    CHECK_FALSE(w.looks_good());
}

TEST_CASE("emu watcher: a stream dominated by one mnemonic does not look good") {
    const pn::Disassembler disasm(false);
    // six nops then ret: nop is 6/7 >= 0.67 of the instructions
    const std::array<std::uint8_t, 7> code = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3};
    const emu::Watcher w = run(disasm, code);
    CHECK(w.has_ret());            // it did reach the ret
    CHECK_FALSE(w.looks_good());   // but it is too repetitive
}

TEST_CASE("emu watcher: a varied function of several instructions looks good") {
    const pn::Disassembler disasm(false);
    // xor eax,eax ; add eax,1 ; sub eax,1 ; or eax,2 ; and eax,3 ; ret
    const std::array<std::uint8_t, 14> code = {
        0x31, 0xC0,        // xor eax, eax
        0x83, 0xC0, 0x01,  // add eax, 1
        0x83, 0xE8, 0x01,  // sub eax, 1
        0x83, 0xC8, 0x02,  // or  eax, 2
        0x83, 0xE0, 0x03,  // and eax, 3
    };
    // ret appended below to keep the array literal readable
    emu::WorkspaceEmulator we(disasm);
    std::array<std::uint8_t, 15> full{};
    for (std::size_t i = 0; i < code.size(); ++i) {
        full[i] = code[i];
    }
    full[14] = 0xC3;  // ret
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, full);
    we.prepare(kBase);
    emu::Watcher w;
    we.run_function(kBase, &w);
    CHECK(w.has_ret());
    CHECK(w.insn_count() > 4);
    CHECK(w.looks_good());
}

TEST_CASE("emu watcher: a divide by zero marks the candidate as bad code") {
    const pn::Disassembler disasm(false);
    // div ecx ; ret  (with ecx forced to 0)
    const std::array<std::uint8_t, 3> code = {0xF7, 0xF1, 0xC3};
    emu::WorkspaceEmulator we(disasm);
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, code);
    we.prepare(kBase);
    we.emu().regs().set_register(emu::kRegEcx, 0U);
    emu::Watcher w;
    we.run_function(kBase, &w);
    CHECK(w.bad_code());
    CHECK_FALSE(w.looks_good());
}

TEST_CASE("emu watcher: decoding through zero padding stops and does not look good") {
    const pn::Disassembler disasm(false);
    // all-zero bytes: the bad-op signature, not real code
    const std::array<std::uint8_t, 8> code = {0, 0, 0, 0, 0, 0, 0, 0};
    const emu::Watcher w = run(disasm, code);
    CHECK_FALSE(w.has_ret());
    CHECK_FALSE(w.looks_good());
}

TEST_CASE("emu watcher: is_code accepts a branch-terminated varied stream") {
    const pn::Disassembler disasm(false);
    // xor eax,eax ; add eax,1 ; jmp 0x402000 (unmapped, ends the path)
    // E9 imm32 where imm32 = 0x402000 - (0x401005 + 5) ... compute below
    emu::WorkspaceEmulator we(disasm);
    std::array<std::uint8_t, 10> full{};
    full[0] = 0x31; full[1] = 0xC0;              // xor eax, eax     @ 0x401000
    full[2] = 0x83; full[3] = 0xC0; full[4] = 0x01;  // add eax, 1   @ 0x401002
    full[5] = 0xE9;                              // jmp rel32        @ 0x401005
    const std::uint32_t imm = 0x402000U - (0x401005U + 5U);
    full[6] = static_cast<std::uint8_t>(imm & 0xFF);
    full[7] = static_cast<std::uint8_t>((imm >> 8) & 0xFF);
    full[8] = static_cast<std::uint8_t>((imm >> 16) & 0xFF);
    full[9] = static_cast<std::uint8_t>((imm >> 24) & 0xFF);
    we.add_map(kBase, emu::kMemRead | emu::kMemExec, full);
    we.prepare(kBase);
    emu::Watcher w;
    we.run_function(kBase, &w);
    CHECK_FALSE(w.has_ret());   // ends in a jump, not a ret
    CHECK(w.is_code());         // but it still looks like code
}
