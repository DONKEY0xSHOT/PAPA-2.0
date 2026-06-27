#include "papa/features/extractors/papa_native/noreturn.h"

#include "papa/util/string_utils.h"

#include <algorithm>
#include <array>
#include <regex>

namespace papa::features::extractors::papa_native {

std::string norm_file_name(std::string_view filename) {
    // os.path.basename: keep only the trailing path component
    if (const auto slash = filename.find_last_of("/\\");
        slash != std::string_view::npos) {
        filename = filename.substr(slash + 1U);
    }
    std::string name = ::papa::util::to_lower_ascii(filename);

    // Strip the final extension. vivisect splits on '.' and rejoins every part
    // but the last with '_', so an interior dot also collapses to '_'.
    if (const auto last_dot = name.find_last_of('.');
        last_dot != std::string::npos) {
        name.resize(last_dot);
        std::replace(name.begin(), name.end(), '.', '_');
    }

    // Replace every character outside [a-z0-9_] with '_' so the api-ms-win
    // forwarder dashes match the no-return regexes
    for (char& c : name) {
        const bool keep =
            (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!keep) {
            c = '_';
        }
    }
    return name;
}

namespace {

// The exact no-return imports vivisect seeds in parsers/pe.py, written as the
// lowercased "norm_file_name(lib).funcname" identity they reduce to
constexpr std::array<std::string_view, 5> kExactNoReturn = {
    std::string_view{"ntdll.rtlexituserthread"},
    std::string_view{"kernel32.exitprocess"},
    std::string_view{"kernel32.exitthread"},
    std::string_view{"kernel32.fatalexit"},
    std::string_view{"ntoskrnl.kebugcheckex"},
};

// The no-return regexes vivisect seeds for the MSVC CRT and the api-ms-win CRT
// forwarders. Matched case-insensitively against the joined identity.
const std::array<std::regex, 8>& noreturn_regexes() {
    static const std::array<std::regex, 8> kRegexes = {
        std::regex{R"(^msvcr.*\._CxxThrowException$)", std::regex::icase},
        std::regex{R"(^msvcr.*\.abort$)", std::regex::icase},
        std::regex{R"(^msvcr.*\.exit$)", std::regex::icase},
        std::regex{R"(^msvcr.*\._exit$)", std::regex::icase},
        std::regex{R"(^msvcr.*\.quick_exit$)", std::regex::icase},
        std::regex{R"(^api_ms_win_crt_runtime_.*\._invalid_parameter_noinfo_noreturn$)",
                   std::regex::icase},
        std::regex{R"(^api_ms_win_crt_runtime_.*\.exit$)", std::regex::icase},
        std::regex{R"(^api_ms_win_crt_runtime_.*\._exit$)", std::regex::icase},
    };
    return kRegexes;
}

}  // namespace

bool is_noreturn_api(std::string_view libname, std::string_view impname) {
    std::string key = norm_file_name(libname);
    key.push_back('.');
    key.append(impname);
    const std::string lower = ::papa::util::to_lower_ascii(key);

    for (const std::string_view exact : kExactNoReturn) {
        if (lower == exact) {
            return true;
        }
    }
    for (const std::regex& re : noreturn_regexes()) {
        if (std::regex_match(lower, re)) {
            return true;
        }
    }
    return false;
}

bool function_is_noreturn(const Function& fn, const NoReturnOracle& is_noreturn) {
    // Scan the terminal basic blocks (no intra-function successors). vivisect's
    // noret.py marks the function no-return when none of these can return.
    bool hasret = false;
    for (const BasicBlock& bb : fn.basic_blocks) {
        if (!bb.successors.empty()) { continue; }
        if (bb.instructions.empty()) { continue; }
        const DecodedInsn& term = bb.instructions.back();
        // A leaf ending in a no-return call does not count as a return path,
        // mirroring noret.py's isNoReturnVa(lva) skip.
        if (term.is_call && static_cast<bool>(is_noreturn) && is_noreturn(term)) {
            continue;
        }
        // A ret, or any branch (a tail jump or an unresolved dynamic branch we
        // could not follow), is a possible return, matching IF_RET / IF_BRANCH.
        if (term.is_return || term.is_jump || term.is_conditional) {
            hasret = true;
            break;
        }
    }
    return !hasret;
}

}  // namespace papa::features::extractors::papa_native
