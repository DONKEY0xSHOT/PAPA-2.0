#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/registers.h"

#include <array>
#include <cstdint>

namespace emu = papa::features::extractors::papa_native::emu;

// The register model is a faithful port of envi/registers.py. The indices, the
// meta-register encoding and the width masking on set are all load-bearing

TEST_CASE("emu RegisterFile: a general-purpose register round-trips a value") {
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x11223344U);
    CHECK(regs.get_register(emu::kRegEax) == 0x11223344U);
}

TEST_CASE("emu RegisterFile: a 32-bit register masks values to 32 bits") {
    // registers.py:380 -- vals[ridx] = value & masks[ridx]. A value wider than the
    // register wraps rather than overflowing
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x1'0000'0001ULL);
    CHECK(regs.get_register(emu::kRegEax) == 0x0000'0001U);
}

TEST_CASE("emu RegisterFile: registers are independent") {
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0xAAAAAAAAU);
    regs.set_register(emu::kRegEcx, 0xBBBBBBBBU);
    CHECK(regs.get_register(emu::kRegEax) == 0xAAAAAAAAU);
    CHECK(regs.get_register(emu::kRegEcx) == 0xBBBBBBBBU);
}

TEST_CASE("emu RegisterFile: an XMM register round-trips a 128-bit value") {
    emu::RegisterFile regs;
    std::array<std::uint8_t, 16> v{};
    for (std::size_t i = 0; i < v.size(); ++i) {
        v[i] = static_cast<std::uint8_t>(i + 1);
    }
    regs.set_xmm(0, v);
    CHECK(regs.get_xmm(0) == v);
    // XMM registers are independent and default to zero
    CHECK(regs.get_xmm(1) == std::array<std::uint8_t, 16>{});
}

TEST_CASE("emu RegisterFile: snapshot and restore preserve XMM state") {
    emu::RegisterFile regs;
    std::array<std::uint8_t, 16> v{};
    v[0] = 0xAB;
    v[15] = 0xCD;
    regs.set_xmm(3, v);
    const auto snap = regs.snapshot();
    regs.set_xmm(3, std::array<std::uint8_t, 16>{});
    CHECK(regs.get_xmm(3) == std::array<std::uint8_t, 16>{});
    regs.restore(snap);
    CHECK(regs.get_xmm(3) == v);
}

TEST_CASE("emu RegisterFile: AX reads the low 16 bits of EAX") {
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x11223344U);
    CHECK(regs.get_register(emu::kRegAx) == 0x3344U);
}

TEST_CASE("emu RegisterFile: AL reads the low 8 bits of EAX") {
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x11223344U);
    CHECK(regs.get_register(emu::kRegAl) == 0x44U);
}

TEST_CASE("emu RegisterFile: AH reads bits 8..15 of EAX") {
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x11223344U);
    CHECK(regs.get_register(emu::kRegAh) == 0x33U);
}

TEST_CASE("emu RegisterFile: writing AL splices into the low byte of EAX") {
    // _xlateToNativeReg (registers.py:340): the meta value is masked to its
    // width and shifted into place, the rest of the parent is preserved
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x11223344U);
    regs.set_register(emu::kRegAl, 0xFFU);
    CHECK(regs.get_register(emu::kRegEax) == 0x112233FFU);
}

TEST_CASE("emu RegisterFile: writing AH splices into bits 8..15 of EAX") {
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x11223344U);
    regs.set_register(emu::kRegAh, 0xFFU);
    CHECK(regs.get_register(emu::kRegEax) == 0x1122FF44U);
}

TEST_CASE("emu RegisterFile: writing AX splices into the low word of EAX") {
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x11223344U);
    regs.set_register(emu::kRegAx, 0xBEEFU);
    CHECK(regs.get_register(emu::kRegEax) == 0x1122BEEFU);
}

TEST_CASE("emu RegisterFile: writing AL only uses the low 8 bits of the value") {
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0x00000000U);
    regs.set_register(emu::kRegAl, 0xAB99U);  // only 0x99 is the byte
    CHECK(regs.get_register(emu::kRegEax) == 0x00000099U);
}

TEST_CASE("emu RegisterFile: a single EFLAGS bit sets and clears") {
    emu::RegisterFile regs;
    CHECK_FALSE(regs.get_flag(emu::kEflagsCf));
    regs.set_flag(emu::kEflagsCf, true);
    CHECK(regs.get_flag(emu::kEflagsCf));
    regs.set_flag(emu::kEflagsCf, false);
    CHECK_FALSE(regs.get_flag(emu::kEflagsCf));
}

TEST_CASE("emu RegisterFile: EFLAGS bits are independent") {
    emu::RegisterFile regs;
    regs.set_flag(emu::kEflagsZf, true);
    CHECK(regs.get_flag(emu::kEflagsZf));
    CHECK_FALSE(regs.get_flag(emu::kEflagsCf));
    CHECK_FALSE(regs.get_flag(emu::kEflagsSf));
    CHECK_FALSE(regs.get_flag(emu::kEflagsOf));
}

TEST_CASE("emu RegisterFile: a register defaults to untainted") {
    emu::RegisterFile regs;
    CHECK_FALSE(regs.is_tainted(emu::kRegEax));
}

TEST_CASE("emu RegisterFile: taint sets and clears per register") {
    emu::RegisterFile regs;
    regs.set_taint(emu::kRegEsi, true);
    CHECK(regs.is_tainted(emu::kRegEsi));
    CHECK_FALSE(regs.is_tainted(emu::kRegEdi));
    regs.set_taint(emu::kRegEsi, false);
    CHECK_FALSE(regs.is_tainted(emu::kRegEsi));
}

TEST_CASE("emu RegisterFile: snapshot and restore round-trip register state") {
    // registers.py:22 getRegisterSnap / setRegisterSnap underpin runFunction's
    // per-branch work-queue. Restoring must return values and taint exactly
    emu::RegisterFile regs;
    regs.set_register(emu::kRegEax, 0xCAFEBABEU);
    regs.set_taint(emu::kRegEbx, true);
    regs.set_flag(emu::kEflagsZf, true);

    const emu::RegisterFile::Snapshot snap = regs.snapshot();

    regs.set_register(emu::kRegEax, 0x00000000U);
    regs.set_taint(emu::kRegEbx, false);
    regs.set_flag(emu::kEflagsZf, false);

    regs.restore(snap);
    CHECK(regs.get_register(emu::kRegEax) == 0xCAFEBABEU);
    CHECK(regs.is_tainted(emu::kRegEbx));
    CHECK(regs.get_flag(emu::kEflagsZf));
}

// amd64 mode: the eight low GP slots become rax..rdi, r8..r15 are added, and writing
// a 32-bit lane zero-extends while 16 and 8-bit writes preserve the upper bits

TEST_CASE("emu RegisterFile amd64: a 64-bit GP register round-trips a full value") {
    emu::RegisterFile regs(/*is_64bit=*/true);
    regs.set_register(emu::kRegRax, 0x1122334455667788ULL);
    CHECK(regs.get_register(emu::kRegRax) == 0x1122334455667788ULL);
}

TEST_CASE("emu RegisterFile amd64: writing the 32-bit lane zero-extends into the full register") {
    emu::RegisterFile regs(/*is_64bit=*/true);
    regs.set_register(emu::kRegRax, 0x1122334455667788ULL);
    const std::uint32_t eax = emu::make_meta_reg(0, 32, emu::kRegRax);
    regs.set_register(eax, 0xDEADBEEFU);
    CHECK(regs.get_register(emu::kRegRax) == 0x00000000DEADBEEFULL);
}

TEST_CASE("emu RegisterFile amd64: writing AX preserves the upper 48 bits") {
    emu::RegisterFile regs(/*is_64bit=*/true);
    regs.set_register(emu::kRegRax, 0x1122334455667788ULL);
    regs.set_register(emu::kRegAx, 0xBEEFU);
    CHECK(regs.get_register(emu::kRegRax) == 0x112233445566BEEFULL);
}

TEST_CASE("emu RegisterFile amd64: writing AL preserves the upper 56 bits") {
    emu::RegisterFile regs(/*is_64bit=*/true);
    regs.set_register(emu::kRegRax, 0x1122334455667788ULL);
    regs.set_register(emu::kRegAl, 0x99U);
    CHECK(regs.get_register(emu::kRegRax) == 0x1122334455667799ULL);
}

TEST_CASE("emu RegisterFile amd64: R8 round-trips and R8D zero-extends it") {
    emu::RegisterFile regs(/*is_64bit=*/true);
    regs.set_register(emu::kRegR8, 0xAABBCCDDEEFF0011ULL);
    CHECK(regs.get_register(emu::kRegR8) == 0xAABBCCDDEEFF0011ULL);
    const std::uint32_t r8d = emu::make_meta_reg(0, 32, emu::kRegR8);
    regs.set_register(r8d, 0x12345678U);
    CHECK(regs.get_register(emu::kRegR8) == 0x0000000012345678ULL);
}

TEST_CASE("emu RegisterFile amd64: EFLAGS has its own slot, independent of the r-registers") {
    // In amd64 mode eflags must not collide with r9 (slot 9 is a GP register)
    emu::RegisterFile regs(/*is_64bit=*/true);
    regs.set_register(emu::kRegR9, 0ULL);
    regs.set_flag(emu::kEflagsZf, true);
    CHECK(regs.get_flag(emu::kEflagsZf));
    CHECK(regs.get_register(emu::kRegR9) == 0ULL);
}
