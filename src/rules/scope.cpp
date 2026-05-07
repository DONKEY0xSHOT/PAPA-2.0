#include "papa/rules/scope.h"

#include <string_view>

namespace papa::rules {

std::string_view to_string(Scope s) noexcept {
    switch (s) {
        case Scope::kFile:         return "file";
        case Scope::kFunction:     return "function";
        case Scope::kBasicBlock:   return "basic block";
        case Scope::kInstruction:  return "instruction";
        case Scope::kGlobal:       return "global";
        case Scope::kProcess:      return "process";
        case Scope::kThread:       return "thread";
        case Scope::kCall:         return "call";
        case Scope::kSpanOfCalls:  return "span of calls";
    }
    return "unknown";
}

}  // namespace papa::rules
