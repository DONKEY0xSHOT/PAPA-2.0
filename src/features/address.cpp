#include "papa/features/address.h"

#include "papa/util/hashing.h"

#include <cstdint>
#include <variant>

namespace papa::features {

namespace {

// Stable tag id used in hashes and linearization so identical variant
// alternatives with equal payloads never collide across address kinds
constexpr std::size_t tag_of(const Address& a) noexcept {
    return a.index();
}

}  // namespace

std::uint64_t linearize(const Address& a) noexcept {
    // Mix the variant tag into the high byte so different address kinds
    // with identical payload bytes never land on the same linearized value
    const std::uint64_t tag = static_cast<std::uint64_t>(tag_of(a));
    std::uint64_t payload = 0;
    if (const auto* to = std::get_if<DnTokenOffsetAddress>(&a)) {
        // Token and offset are independent spaces
        payload = to->token ^ (to->offset * util::hashing::kGoldenRatio64);
    } else if (const auto* t = std::get_if<DnTokenAddress>(&a)) {
        payload = t->token;
    } else if (const auto* va = std::get_if<AbsoluteVirtualAddress>(&a)) {
        payload = va->v;
    } else if (const auto* rva = std::get_if<RelativeVirtualAddress>(&a)) {
        payload = rva->v;
    } else if (const auto* off = std::get_if<FileOffsetAddress>(&a)) {
        payload = off->v;
    }
    return (tag << 56) ^ payload;
}

}  // namespace papa::features

std::size_t std::hash<papa::features::Address>::operator()(
    const papa::features::Address& a) const noexcept {
    return std::hash<std::uint64_t>{}(papa::features::linearize(a));
}
