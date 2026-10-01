#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/noreturn.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pn = papa::features::extractors::papa_native;

namespace {

// A terminator instruction with the branch-class flags noret cares about
pn::DecodedInsn term(std::uint64_t va, bool is_call, bool is_jump, bool is_cond, bool is_ret) {
    pn::DecodedInsn ins;
    ins.va             = va;
    ins.is_call        = is_call;
    ins.is_jump        = is_jump;
    ins.is_conditional = is_cond;
    ins.is_return      = is_ret;
    return ins;
}

pn::DecodedInsn ret_at(std::uint64_t va) { return term(va, false, false, false, true); }
pn::DecodedInsn call_at(std::uint64_t va) { return term(va, true, false, false, false); }

// One block holding only its terminator
pn::BasicBlock leaf(std::uint64_t va, const pn::DecodedInsn& terminator) {
    pn::BasicBlock bb;
    bb.va = va;
    bb.instructions.push_back(terminator);
    return bb;
}

// An entry at va that conditionally branches to two leaves at va+0x10 and va+0x20, so
// the entry is not itself a leaf
std::vector<pn::BasicBlock> fork(std::uint64_t va, const pn::DecodedInsn& first,
                                 const pn::DecodedInsn& second) {
    pn::BasicBlock entry = leaf(va, term(va, false, false, /*is_cond=*/true, false));
    entry.successors = {va + 0x10, va + 0x20};
    return {entry, leaf(va + 0x10, first), leaf(va + 0x20, second)};
}

// An oracle that treats every call as no-return, for the leaf-scan tests
const pn::NoReturnOracle kAllCallsNoReturn =
    [](const pn::DecodedInsn& ins) { return ins.is_call; };

}  // namespace

// norm_file_name is a faithful port of vivisect's normFileName, forming the library
// half of an import's identity
TEST_CASE("norm_file_name lowercases, strips the extension and joins the rest with underscores") {
    struct Row {
        std::string_view name;
        std::string_view expected;
    };
    const std::vector<Row> rows{
        {"kernel32.dll", "kernel32"},
        {"KERNEL32.DLL", "kernel32"},
        {"ntoskrnl.exe", "ntoskrnl"},
        {"kernel32", "kernel32"},
        // The api-ms-win CRT forwarder DLLs are the reason this matters: the dashes
        // become underscores so the no-return regexes match
        {"api-ms-win-crt-runtime-l1-1-0.dll", "api_ms_win_crt_runtime_l1_1_0"},
        {"foo.bar.dll", "foo_bar"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.name);
        CHECK(pn::norm_file_name(std::string(row.name)) == row.expected);
    }
}

TEST_CASE("is_noreturn_api matches the exact seeded APIs and each CRT family's regexes, nothing near them") {
    struct Row {
        std::string_view dll;
        std::string_view api;
        bool             noreturn;
    };
    const std::vector<Row> rows{
        // The exact seeded APIs
        {"kernel32.dll", "ExitProcess", true},
        {"KERNEL32.DLL", "ExitProcess", true},
        {"kernel32", "ExitThread", true},
        {"kernel32.dll", "FatalExit", true},
        {"ntdll.dll", "RtlExitUserThread", true},
        {"ntoskrnl.exe", "KeBugCheckEx", true},
        // The msvcr CRT regex family, case-insensitive
        {"msvcr120.dll", "abort", true},
        {"msvcr120.dll", "exit", true},
        {"msvcr120.dll", "_exit", true},
        {"msvcr120.dll", "quick_exit", true},
        {"msvcrt.dll", "exit", true},
        {"MSVCR110.DLL", "_CxxThrowException", true},
        // The api-ms-win CRT regex family
        {"api-ms-win-crt-runtime-l1-1-0.dll", "exit", true},
        {"api-ms-win-crt-runtime-l1-1-0.dll", "_exit", true},
        {"api-ms-win-crt-runtime-l1-1-0.dll", "_invalid_parameter_noinfo_noreturn", true},
        // An ordinary API, a prefix of an exact one and regexes outside their family
        {"kernel32.dll", "GetProcAddress", false},
        {"kernel32.dll", "ExitProcessEx", false},
        {"user32.dll", "abort", false},
        {"notmsvcr.dll", "exit", false},
        {"kernel32.dll", "exit", false},
    };
    for (const Row& row : rows) {
        CAPTURE(row.dll);
        CAPTURE(row.api);
        CHECK(pn::is_noreturn_api(std::string(row.dll), std::string(row.api)) == row.noreturn);
    }
}

// function_is_noreturn ports vivisect's leaf scan, where a function does not return
// when none of its terminal blocks ends in a ret or a dynamic branch
TEST_CASE("function_is_noreturn holds only when every leaf ends in a call that cannot return") {
    // Every row but the last treats every call as no-return
    const auto never = [](const pn::DecodedInsn&) { return false; };
    struct Row {
        std::string_view            label;
        std::uint64_t               va;
        std::vector<pn::BasicBlock> blocks;
        bool                        calls_noreturn;
        bool                        noreturn;
    };
    const std::vector<Row> rows{
        // vivisect noret.py bails when buildFunctionGraph throws (an empty or graph-build-
        // failed function), returning without addNoReturnVa
        {"a function with no blocks is not no-return", 0x1000, {}, true, false},
        {"a returning leaf means the function returns", 0x1000, {leaf(0x1000, ret_at(0x1000))},
         true, false},
        {"a sole no-return-call leaf makes it no-return", 0x2000, {leaf(0x2000, call_at(0x2000))},
         true, true},
        {"one returning leaf among no-return calls wins", 0x3000,
         fork(0x3000, ret_at(0x3010), call_at(0x3020)), true, false},
        // An unresolved indirect jump (no branch target) is a possible return path
        {"a dynamic-branch leaf means it may return", 0x4000,
         {leaf(0x4000, term(0x4000, false, /*is_jump=*/true, false, false))}, true, false},
        {"every leaf a no-return call makes it no-return", 0x5000,
         fork(0x5000, call_at(0x5010), call_at(0x5020)), true, true},
        // A leaf ending in a call not known to be no-return contributes no ret and no
        // branch, mirroring noret.py where a bare call is neither IF_RET nor IF_BRANCH
        {"an unflagged call leaf proves nothing but yields no ret either", 0x6000,
         {leaf(0x6000, call_at(0x6000))}, false, true},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        pn::Function fn;
        fn.va = row.va;
        fn.basic_blocks = row.blocks;
        const bool got = row.calls_noreturn ? pn::function_is_noreturn(fn, kAllCallsNoReturn)
                                            : pn::function_is_noreturn(fn, never);
        CHECK(got == row.noreturn);
    }
}
