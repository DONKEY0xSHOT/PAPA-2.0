#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <variant>

namespace papa::features {

// Tag types distinguishing the address spaces CAPA rules and extractors speak
struct NoAddress {
    friend bool operator==(const NoAddress&, const NoAddress&) noexcept { return true; }
};

struct AbsoluteVirtualAddress {
    std::uint64_t v{0};
    friend bool operator==(const AbsoluteVirtualAddress&,
                           const AbsoluteVirtualAddress&) noexcept = default;
};

struct RelativeVirtualAddress {
    std::uint64_t v{0};
    friend bool operator==(const RelativeVirtualAddress&,
                           const RelativeVirtualAddress&) noexcept = default;
};

struct FileOffsetAddress {
    std::uint64_t v{0};
    friend bool operator==(const FileOffsetAddress&,
                           const FileOffsetAddress&) noexcept = default;
};

struct DnTokenAddress {
    std::uint64_t token{0};
    friend bool operator==(const DnTokenAddress&,
                           const DnTokenAddress&) noexcept = default;
};

struct DnTokenOffsetAddress {
    std::uint64_t token{0};
    std::uint64_t offset{0};
    friend bool operator==(const DnTokenOffsetAddress&,
                           const DnTokenOffsetAddress&) noexcept = default;
};

// Sum type used throughout the matcher to refer to a location in a binary
using Address = std::variant<
    NoAddress,
    AbsoluteVirtualAddress,
    RelativeVirtualAddress,
    FileOffsetAddress,
    DnTokenAddress,
    DnTokenOffsetAddress>;

[[nodiscard]] std::string    to_string(const Address& a);
[[nodiscard]] std::uint64_t  linearize(const Address& a) noexcept;

}  // namespace papa::features

// Specialize std::hash so Address can key unordered containers
template <>
struct std::hash<papa::features::Address> {
    std::size_t operator()(const papa::features::Address& a) const noexcept;
};
