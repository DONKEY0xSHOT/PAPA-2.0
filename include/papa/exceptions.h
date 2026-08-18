#pragma once

#include "papa/util/expected.h"

#include <cstdint>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>

namespace papa {

enum class ErrorKind : std::uint8_t {
    kOk,
    kIoError,
    kNotPe,
    kBadPe,
    kOutOfBounds,
    kDisassemblyFailed,
    kInvalidRule,
    kRuleParseError,
    kMissingDependency,
    kCycle,
    kLimitation,
    kUnsupportedFormat,
    kYamlParseError,
    kInternalInvariant,
    kFlirtBadCompressedStream,
    kFlirtBadMagic,
    kFlirtUnsupportedVersion,
    kFlirtTruncated,
    kFlirtBadNode,
    kFlirtTooDeep,
};

[[nodiscard]] std::string_view to_string(ErrorKind kind) noexcept;

struct PapaError {
    ErrorKind   kind { ErrorKind::kOk };
    std::string detail;
    std::string source_location;
};

[[nodiscard]] PapaError make_error(
    ErrorKind kind,
    std::string detail,
    std::source_location loc = std::source_location::current());

template <typename T>
using Expected = ::papa::util::Expected<T, PapaError>;

using ::papa::util::BadExpectedAccess;
using ::papa::util::Unexpected;

class PapaInvariantError : public std::logic_error {
public:
    using std::logic_error::logic_error;
};

}  // namespace papa
