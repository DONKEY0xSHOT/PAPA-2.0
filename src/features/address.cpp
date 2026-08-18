#include "papa/features/address.h"

#include "papa/util/hashing.h"

#include <cstdint>
#include <sstream>
#include <string>
#include <variant>

namespace papa::features {

namespace {

// Stable tag id used in hashes and linearization so identical variant
// alternatives with equal payloads never collide across address kinds
constexpr std::size_t tag_of(const Address& a) noexcept {
    return a.index();
}

}  // namespace

std::string to_string(const Address& a) {
    std::ostringstream os;
    std::visit(
        [&os](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, NoAddress>) {
                os << "none";
            } else if constexpr (std::is_same_v<T, AbsoluteVirtualAddress>) {
                os << "va:0x" << std::hex << v.v;
            } else if constexpr (std::is_same_v<T, RelativeVirtualAddress>) {
                os << "rva:0x" << std::hex << v.v;
            } else if constexpr (std::is_same_v<T, FileOffsetAddress>) {
                os << "off:0x" << std::hex << v.v;
            } else if constexpr (std::is_same_v<T, DnTokenAddress>) {
                os << "tok:0x" << std::hex << v.token;
            } else if constexpr (std::is_same_v<T, DnTokenOffsetAddress>) {
                os << "tok:0x" << std::hex << v.token << "+0x" << v.offset;
            }
        },
        a);
    return os.str();
}

std::uint64_t linearize(const Address& a) noexcept {
    // Mix the variant tag into the high byte so different address kinds
    // with identical payload bytes never land on the same linearized value
    const std::uint64_t tag = static_cast<std::uint64_t>(tag_of(a));
    std::uint64_t payload = 0;
    std::visit(
        [&payload](const auto& v) noexcept {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, NoAddress>) {
                payload = 0;
            } else if constexpr (std::is_same_v<T, DnTokenOffsetAddress>) {
                // Token and offset are independent spaces
                payload = v.token ^ (v.offset * util::hashing::kGoldenRatio64);
            } else if constexpr (std::is_same_v<T, DnTokenAddress>) {
                payload = v.token;
            } else {
                payload = v.v;
            }
        },
        a);
    return (tag << 56) ^ payload;
}

}  // namespace papa::features

std::size_t std::hash<papa::features::Address>::operator()(
    const papa::features::Address& a) const noexcept {
    return std::hash<std::uint64_t>{}(papa::features::linearize(a));
}
