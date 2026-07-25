#include "papa/features/extractors/papa_native/viv/location_db.h"

namespace papa::features::extractors::papa_native::viv {

void LocationDb::add_location(std::uint64_t va, std::uint64_t size, LocType type) {
    by_start_[va] = Location{va, size, type};
}

std::optional<Location> LocationDb::get_location(std::uint64_t va) const noexcept {
    // The candidate is the location with the greatest start not past va, so step
    // back from the first start strictly greater than va
    const auto after = by_start_.upper_bound(va);
    if (after == by_start_.begin()) {
        return std::nullopt;
    }
    const Location& loc = std::prev(after)->second;
    if (va >= loc.va && va < loc.va + loc.size) {
        return loc;
    }
    return std::nullopt;
}

bool LocationDb::is_location(std::uint64_t va) const noexcept {
    const auto loc = get_location(va);
    return loc.has_value() && loc->va == va;
}

std::optional<LocType> LocationDb::location_type(std::uint64_t va) const noexcept {
    if (const auto loc = get_location(va)) {
        return loc->type;
    }
    return std::nullopt;
}

void LocationDb::del_location(std::uint64_t va) noexcept {
    by_start_.erase(va);
}

void LocationDb::for_each_location(
    const std::function<void(const Location&)>& fn) const {
    for (const auto& [va, loc] : by_start_) {
        (void)va;
        fn(loc);
    }
}

}  // namespace papa::features::extractors::papa_native::viv
