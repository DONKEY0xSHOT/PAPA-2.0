#include "papa/version.h"

#include <array>
#include <cstddef>

namespace papa::version {

namespace {

constexpr auto kBannerBuffer = [] {
    constexpr auto total_size = kProductName.size() + 1 + kVersionString.size() + 1;
    std::array<char, total_size> buf{};
    std::size_t i = 0;
    for (char c : kProductName) {
        buf[i++] = c;
    }
    buf[i++] = ' ';
    for (char c : kVersionString) {
        buf[i++] = c;
    }
    buf[i] = '\0';
    return buf;
}();

}  // namespace

std::string_view banner() noexcept {
    return std::string_view(kBannerBuffer.data(), kBannerBuffer.size() - 1);
}

}  // namespace papa::version
