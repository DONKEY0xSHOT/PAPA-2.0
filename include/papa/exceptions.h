#pragma once

#include "papa/util/expected.h"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace papa {

enum class ErrorKind : std::uint8_t {
    kOk,
    kIoError,
    kNotPe,
    kBadPe,
    kOutOfBounds,
    kDisassemblyFailed,
    kInvalidRule,
    kCycle,
    kYamlParseError,
    kFlirtBadCompressedStream,
    kFlirtBadMagic,
    kFlirtUnsupportedVersion,
    kFlirtTruncated,
    kFlirtBadNode,
    kFlirtTooDeep,
};

struct PapaError {
    ErrorKind   kind { ErrorKind::kOk };
    std::string detail;
};

[[nodiscard]] PapaError make_error(ErrorKind kind, std::string detail);

template <typename T>
using Expected = ::papa::util::Expected<T, PapaError>;

using ::papa::util::BadExpectedAccess;
using ::papa::util::Unexpected;

class PapaInvariantError : public std::logic_error {
public:
    using std::logic_error::logic_error;
};

}  // namespace papa
