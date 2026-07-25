#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>

namespace papa::features::extractors::papa_native::viv {

/// The kind of a defined location, a subset of vivisect's LOC_* constants
enum class LocType {
    kOp,
    kPointer,
    kString,
    kUnicode,
    kNumber,
    kPad,
    kImport,
};

/// One defined location covering the half-open byte range [va, va + size)
struct Location {
    std::uint64_t va{0};
    std::uint64_t size{0};
    LocType       type{LocType::kOp};
};

/// The shared location database every analysis pass consults and updates, a port
/// of vivisect's workspace location map
class LocationDb {
public:
    /// Define a location over the range starting at va
    void add_location(std::uint64_t va, std::uint64_t size, LocType type);

    /// The location whose byte range contains va, or nullopt when va is undefined
    [[nodiscard]] std::optional<Location> get_location(std::uint64_t va) const noexcept;

    /// True when a location begins exactly at va
    [[nodiscard]] bool is_location(std::uint64_t va) const noexcept;

    /// The type of the location containing va, or nullopt when undefined
    [[nodiscard]] std::optional<LocType> location_type(std::uint64_t va) const noexcept;

    /// Remove the location that begins exactly at va, if any
    void del_location(std::uint64_t va) noexcept;

    /// Visit every defined location in ascending start-address order. Used to
    /// build the covered-byte map the prologue gap scan needs
    void for_each_location(const std::function<void(const Location&)>& fn) const;

private:
    // Keyed by start VA so a range lookup is an upper_bound plus one step back
    std::map<std::uint64_t, Location> by_start_;
};

}  // namespace papa::features::extractors::papa_native::viv
