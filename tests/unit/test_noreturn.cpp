#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/noreturn.h"

#include <string>

namespace pn = papa::features::extractors::papa_native;

namespace {

// Build a terminator instruction with the branch-class flags noret cares about
pn::DecodedInsn term(std::uint64_t va, bool is_call, bool is_jump,
                     bool is_cond, bool is_ret) {
    pn::DecodedInsn ins;
    ins.va             = va;
    ins.is_call        = is_call;
    ins.is_jump        = is_jump;
    ins.is_conditional = is_cond;
    ins.is_return      = is_ret;
    return ins;
}

pn::BasicBlock leaf(std::uint64_t va, const pn::DecodedInsn& terminator) {
    pn::BasicBlock bb;
    bb.va = va;
    bb.instructions.push_back(terminator);
    return bb;
}

// An oracle that treats every call as no-return, for the leaf-scan tests
const pn::NoReturnOracle kAllCallsNoReturn =
    [](const pn::DecodedInsn& ins) { return ins.is_call; };

}  // namespace

// norm_file_name is a faithful port of vivisect's normFileName, forming the library
// half of an import's identity
TEST_CASE("norm_file_name lowercases and strips the extension") {
    CHECK(pn::norm_file_name("kernel32.dll") == "kernel32");
    CHECK(pn::norm_file_name("KERNEL32.DLL") == "kernel32");
    CHECK(pn::norm_file_name("ntoskrnl.exe") == "ntoskrnl");
    CHECK(pn::norm_file_name("kernel32") == "kernel32");
}

TEST_CASE("norm_file_name replaces non-alphanumeric characters with underscore") {
    // The api-ms-win CRT forwarder DLLs are the reason this matters: the
    // dashes become underscores so the no-return regexes match
    CHECK(pn::norm_file_name("api-ms-win-crt-runtime-l1-1-0.dll") ==
          "api_ms_win_crt_runtime_l1_1_0");
}

TEST_CASE("norm_file_name joins earlier dotted parts with underscore") {
    CHECK(pn::norm_file_name("foo.bar.dll") == "foo_bar");
}

TEST_CASE("is_noreturn_api recognizes the exact seeded APIs") {
    CHECK(pn::is_noreturn_api("kernel32.dll", "ExitProcess"));
    CHECK(pn::is_noreturn_api("KERNEL32.DLL", "ExitProcess"));
    CHECK(pn::is_noreturn_api("kernel32", "ExitThread"));
    CHECK(pn::is_noreturn_api("kernel32.dll", "FatalExit"));
    CHECK(pn::is_noreturn_api("ntdll.dll", "RtlExitUserThread"));
    CHECK(pn::is_noreturn_api("ntoskrnl.exe", "KeBugCheckEx"));
}

TEST_CASE("is_noreturn_api recognizes the msvcr CRT regex family") {
    CHECK(pn::is_noreturn_api("msvcr120.dll", "abort"));
    CHECK(pn::is_noreturn_api("msvcr120.dll", "exit"));
    CHECK(pn::is_noreturn_api("msvcr120.dll", "_exit"));
    CHECK(pn::is_noreturn_api("msvcr120.dll", "quick_exit"));
    CHECK(pn::is_noreturn_api("msvcrt.dll", "exit"));
    // case-insensitive
    CHECK(pn::is_noreturn_api("MSVCR110.DLL", "_CxxThrowException"));
}

TEST_CASE("is_noreturn_api recognizes the api-ms-win CRT regex family") {
    CHECK(pn::is_noreturn_api("api-ms-win-crt-runtime-l1-1-0.dll", "exit"));
    CHECK(pn::is_noreturn_api("api-ms-win-crt-runtime-l1-1-0.dll", "_exit"));
    CHECK(pn::is_noreturn_api("api-ms-win-crt-runtime-l1-1-0.dll",
                              "_invalid_parameter_noinfo_noreturn"));
}

TEST_CASE("is_noreturn_api rejects ordinary and near-miss APIs") {
    CHECK_FALSE(pn::is_noreturn_api("kernel32.dll", "GetProcAddress"));
    // exact set requires a full match, not a prefix
    CHECK_FALSE(pn::is_noreturn_api("kernel32.dll", "ExitProcessEx"));
    // the regexes are anchored to their library family
    CHECK_FALSE(pn::is_noreturn_api("user32.dll", "abort"));
    CHECK_FALSE(pn::is_noreturn_api("notmsvcr.dll", "exit"));
    CHECK_FALSE(pn::is_noreturn_api("kernel32.dll", "exit"));
}

// function_is_noreturn ports vivisect's leaf scan, where a function does not return
// when none of its terminal blocks ends in a ret or a dynamic branch
TEST_CASE("function_is_noreturn: a function with no blocks is not no-return") {
    // vivisect noret.py bails when buildFunctionGraph throws (an empty or graph-build-
    // failed function), returning without addNoReturnVa
    pn::Function fn;
    fn.va = 0x1000;  // no basic blocks
    CHECK_FALSE(pn::function_is_noreturn(fn, kAllCallsNoReturn));
}

TEST_CASE("function_is_noreturn: a returning leaf means the function returns") {
    pn::Function fn;
    fn.va = 0x1000;
    fn.basic_blocks.push_back(
        leaf(0x1000, term(0x1000, false, false, false, /*ret=*/true)));
    CHECK_FALSE(pn::function_is_noreturn(fn, kAllCallsNoReturn));
}

TEST_CASE("function_is_noreturn: a sole no-return-call leaf makes it no-return") {
    pn::Function fn;
    fn.va = 0x2000;
    fn.basic_blocks.push_back(
        leaf(0x2000, term(0x2000, /*call=*/true, false, false, false)));
    CHECK(pn::function_is_noreturn(fn, kAllCallsNoReturn));
}

TEST_CASE("function_is_noreturn: one returning leaf among no-return calls wins") {
    pn::Function fn;
    fn.va = 0x3000;
    // entry conditionally branches to the two leaves, so it is not itself a leaf
    pn::BasicBlock entry;
    entry.va = 0x3000;
    entry.instructions.push_back(term(0x3000, false, false, /*cond=*/true, false));
    entry.successors = {0x3010, 0x3020};
    fn.basic_blocks.push_back(std::move(entry));
    fn.basic_blocks.push_back(
        leaf(0x3010, term(0x3010, false, false, false, /*ret=*/true)));
    fn.basic_blocks.push_back(
        leaf(0x3020, term(0x3020, /*call=*/true, false, false, false)));
    CHECK_FALSE(pn::function_is_noreturn(fn, kAllCallsNoReturn));
}

TEST_CASE("function_is_noreturn: a dynamic-branch leaf means it may return") {
    pn::Function fn;
    fn.va = 0x4000;
    // an unresolved indirect jump (no branch target) is a possible return path
    fn.basic_blocks.push_back(
        leaf(0x4000, term(0x4000, false, /*jump=*/true, false, false)));
    CHECK_FALSE(pn::function_is_noreturn(fn, kAllCallsNoReturn));
}

TEST_CASE("function_is_noreturn: every leaf a no-return call makes it no-return") {
    pn::Function fn;
    fn.va = 0x5000;
    pn::BasicBlock entry;
    entry.va = 0x5000;
    entry.instructions.push_back(term(0x5000, false, false, /*cond=*/true, false));
    entry.successors = {0x5010, 0x5020};
    fn.basic_blocks.push_back(std::move(entry));
    fn.basic_blocks.push_back(
        leaf(0x5010, term(0x5010, /*call=*/true, false, false, false)));
    fn.basic_blocks.push_back(
        leaf(0x5020, term(0x5020, /*call=*/true, false, false, false)));
    CHECK(pn::function_is_noreturn(fn, kAllCallsNoReturn));
}

TEST_CASE("function_is_noreturn: an ordinary (returning) call leaf does not "
          "by itself prove no-return but yields no ret either") {
    // A leaf ending in a call the oracle does not flag contributes no ret and no
    // branch, mirroring noret.py where a bare call is neither IF_RET nor. IF_BRANCH
    pn::Function fn;
    fn.va = 0x6000;
    pn::NoReturnOracle never = [](const pn::DecodedInsn&) { return false; };
    fn.basic_blocks.push_back(
        leaf(0x6000, term(0x6000, /*call=*/true, false, false, false)));
    CHECK(pn::function_is_noreturn(fn, never));
}
