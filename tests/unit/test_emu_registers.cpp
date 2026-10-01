#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/emu/registers.h"

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

namespace emu = papa::features::extractors::papa_native::emu;

// The register model is a faithful port of envi/registers.py. The indices, the
// meta-register encoding and the width masking on set are all load-bearing

namespace {

// One register, flag or taint slot and the value written to it or read back from it
struct Access {
    enum class Kind { kRegister, kFlag, kTaint };
    Kind          kind;
    std::uint32_t id;
    std::uint64_t value;
};

Access r(std::uint32_t id, std::uint64_t value) { return {Access::Kind::kRegister, id, value}; }
Access flag(std::uint32_t mask, bool set) { return {Access::Kind::kFlag, mask, set ? 1U : 0U}; }
Access taint(std::uint32_t id, bool set) { return {Access::Kind::kTaint, id, set ? 1U : 0U}; }

// A fresh register file, the writes applied in order, then every read checked
struct Row {
    std::string_view    label;
    bool                is_64bit;
    std::vector<Access> writes;
    std::vector<Access> reads;
};

void check_rows(const std::vector<Row>& rows) {
    for (const Row& row : rows) {
        CAPTURE(row.label);
        emu::RegisterFile regs(row.is_64bit);
        for (const Access& w : row.writes) {
            switch (w.kind) {
                case Access::Kind::kRegister: regs.set_register(w.id, w.value); break;
                case Access::Kind::kFlag: regs.set_flag(w.id, w.value != 0); break;
                case Access::Kind::kTaint: regs.set_taint(w.id, w.value != 0); break;
            }
        }
        for (const Access& want : row.reads) {
            CAPTURE(want.id);
            const bool set = want.value != 0;
            switch (want.kind) {
                case Access::Kind::kRegister:
                    CHECK(regs.get_register(want.id) == want.value);
                    break;
                case Access::Kind::kFlag: CHECK(regs.get_flag(want.id) == set); break;
                case Access::Kind::kTaint: CHECK(regs.is_tainted(want.id) == set); break;
            }
        }
    }
}

constexpr bool k32 = false;
constexpr bool k64 = true;

}  // namespace

TEST_CASE("emu RegisterFile: registers and their lanes read back what was written, masked to width") {
    // In amd64 mode a 32-bit lane write zero-extends while 16 and 8-bit writes keep the
    // upper bits. registers.py:340 _xlateToNativeReg splices a meta value into its parent
    const std::uint32_t eax_of_rax = emu::make_meta_reg(0, 32, emu::kRegRax);
    const std::uint32_t r8d        = emu::make_meta_reg(0, 32, emu::kRegR8);
    check_rows({
        {"a general-purpose register round-trips a value", k32,
         {r(emu::kRegEax, 0x11223344U)}, {r(emu::kRegEax, 0x11223344U)}},
        {"a 32-bit register masks values to 32 bits (registers.py:380)", k32,
         {r(emu::kRegEax, 0x1'0000'0001ULL)}, {r(emu::kRegEax, 0x0000'0001U)}},
        {"registers are independent", k32,
         {r(emu::kRegEax, 0xAAAAAAAAU), r(emu::kRegEcx, 0xBBBBBBBBU)},
         {r(emu::kRegEax, 0xAAAAAAAAU), r(emu::kRegEcx, 0xBBBBBBBBU)}},
        {"AX reads the low 16 bits of EAX", k32,
         {r(emu::kRegEax, 0x11223344U)}, {r(emu::kRegAx, 0x3344U)}},
        {"AL reads the low 8 bits of EAX", k32,
         {r(emu::kRegEax, 0x11223344U)}, {r(emu::kRegAl, 0x44U)}},
        {"AH reads bits 8..15 of EAX", k32,
         {r(emu::kRegEax, 0x11223344U)}, {r(emu::kRegAh, 0x33U)}},
        {"writing AL splices into the low byte of EAX", k32,
         {r(emu::kRegEax, 0x11223344U), r(emu::kRegAl, 0xFFU)}, {r(emu::kRegEax, 0x112233FFU)}},
        {"writing AH splices into bits 8..15 of EAX", k32,
         {r(emu::kRegEax, 0x11223344U), r(emu::kRegAh, 0xFFU)}, {r(emu::kRegEax, 0x1122FF44U)}},
        {"writing AX splices into the low word of EAX", k32,
         {r(emu::kRegEax, 0x11223344U), r(emu::kRegAx, 0xBEEFU)}, {r(emu::kRegEax, 0x1122BEEFU)}},
        {"writing AL only uses the low 8 bits of the value", k32,
         {r(emu::kRegEax, 0x00000000U), r(emu::kRegAl, 0xAB99U)}, {r(emu::kRegEax, 0x00000099U)}},
        {"amd64 a 64-bit GP register round-trips a full value", k64,
         {r(emu::kRegRax, 0x1122334455667788ULL)}, {r(emu::kRegRax, 0x1122334455667788ULL)}},
        {"amd64 writing the 32-bit lane zero-extends into the full register", k64,
         {r(emu::kRegRax, 0x1122334455667788ULL), r(eax_of_rax, 0xDEADBEEFU)},
         {r(emu::kRegRax, 0x00000000DEADBEEFULL)}},
        {"amd64 writing AX preserves the upper 48 bits", k64,
         {r(emu::kRegRax, 0x1122334455667788ULL), r(emu::kRegAx, 0xBEEFU)},
         {r(emu::kRegRax, 0x112233445566BEEFULL)}},
        {"amd64 writing AL preserves the upper 56 bits", k64,
         {r(emu::kRegRax, 0x1122334455667788ULL), r(emu::kRegAl, 0x99U)},
         {r(emu::kRegRax, 0x1122334455667799ULL)}},
        {"amd64 R8 round-trips", k64,
         {r(emu::kRegR8, 0xAABBCCDDEEFF0011ULL)}, {r(emu::kRegR8, 0xAABBCCDDEEFF0011ULL)}},
        {"amd64 R8D zero-extends R8", k64,
         {r(emu::kRegR8, 0xAABBCCDDEEFF0011ULL), r(r8d, 0x12345678U)},
         {r(emu::kRegR8, 0x0000000012345678ULL)}},
    });
}

TEST_CASE("emu RegisterFile: EFLAGS bits default clear, set and clear independently, apart from the r-registers") {
    check_rows({
        {"a flag defaults clear", k32, {}, {flag(emu::kEflagsCf, false)}},
        {"a flag sets", k32, {flag(emu::kEflagsCf, true)}, {flag(emu::kEflagsCf, true)}},
        {"a set flag clears", k32,
         {flag(emu::kEflagsCf, true), flag(emu::kEflagsCf, false)}, {flag(emu::kEflagsCf, false)}},
        {"EFLAGS bits are independent", k32, {flag(emu::kEflagsZf, true)},
         {flag(emu::kEflagsZf, true), flag(emu::kEflagsCf, false), flag(emu::kEflagsSf, false),
          flag(emu::kEflagsOf, false)}},
        // In amd64 mode slot 9 is r9, a GP register, so eflags must not collide with it
        {"amd64 EFLAGS has its own slot, independent of the r-registers", k64,
         {r(emu::kRegR9, 0ULL), flag(emu::kEflagsZf, true)},
         {flag(emu::kEflagsZf, true), r(emu::kRegR9, 0ULL)}},
    });
}

TEST_CASE("emu RegisterFile: taint defaults clear and sets and clears per register") {
    check_rows({
        {"a register defaults to untainted", k32, {}, {taint(emu::kRegEax, false)}},
        {"taint sets on one register only", k32, {taint(emu::kRegEsi, true)},
         {taint(emu::kRegEsi, true), taint(emu::kRegEdi, false)}},
        {"taint clears", k32, {taint(emu::kRegEsi, true), taint(emu::kRegEsi, false)},
         {taint(emu::kRegEsi, false)}},
    });
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

TEST_CASE("emu RegisterFile: snapshot and restore round-trip values, taint, flags and XMM state") {
    // registers.py:22 getRegisterSnap / setRegisterSnap underpin runFunction's
    // per-branch work-queue. Restoring must return the state exactly
    emu::RegisterFile regs;
    std::array<std::uint8_t, 16> v{};
    v[0] = 0xAB;
    v[15] = 0xCD;
    regs.set_register(emu::kRegEax, 0xCAFEBABEU);
    regs.set_taint(emu::kRegEbx, true);
    regs.set_flag(emu::kEflagsZf, true);
    regs.set_xmm(3, v);

    const emu::RegisterFile::Snapshot snap = regs.snapshot();

    regs.set_register(emu::kRegEax, 0x00000000U);
    regs.set_taint(emu::kRegEbx, false);
    regs.set_flag(emu::kEflagsZf, false);
    regs.set_xmm(3, std::array<std::uint8_t, 16>{});
    CHECK(regs.get_xmm(3) == std::array<std::uint8_t, 16>{});

    regs.restore(snap);
    CHECK(regs.get_register(emu::kRegEax) == 0xCAFEBABEU);
    CHECK(regs.is_tainted(emu::kRegEbx));
    CHECK(regs.get_flag(emu::kEflagsZf));
    CHECK(regs.get_xmm(3) == v);
}
