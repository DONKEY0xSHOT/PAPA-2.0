#include "papa/exceptions.h"

#include <string>

namespace papa {

std::string_view to_string(ErrorKind kind) noexcept {
    switch (kind) {
        case ErrorKind::kOk:                 return "ok";
        case ErrorKind::kIoError:            return "io-error";
        case ErrorKind::kNotPe:              return "not-pe";
        case ErrorKind::kBadPe:              return "bad-pe";
        case ErrorKind::kOutOfBounds:        return "out-of-bounds";
        case ErrorKind::kDisassemblyFailed:  return "disassembly-failed";
        case ErrorKind::kInvalidRule:        return "invalid-rule";
        case ErrorKind::kRuleParseError:     return "rule-parse-error";
        case ErrorKind::kMissingDependency:  return "missing-dependency";
        case ErrorKind::kCycle:              return "cycle";
        case ErrorKind::kLimitation:         return "limitation";
        case ErrorKind::kUnsupportedFormat:  return "unsupported-format";
        case ErrorKind::kYamlParseError:     return "yaml-parse-error";
        case ErrorKind::kInternalInvariant:  return "internal-invariant";
    }
    return "unknown";
}

PapaError make_error(ErrorKind kind, std::string detail, std::source_location loc) {
    std::string where;
    where.reserve(64);
    where.append(loc.file_name());
    where.push_back(':');
    where.append(std::to_string(loc.line()));
    return PapaError{kind, std::move(detail), std::move(where)};
}

}  // namespace papa
