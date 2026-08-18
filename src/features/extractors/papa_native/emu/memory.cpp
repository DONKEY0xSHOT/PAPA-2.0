#include "papa/features/extractors/papa_native/emu/memory.h"

#include <algorithm>
#include <array>

namespace papa::features::extractors::papa_native::emu {

SandboxMemory::SandboxMemory(std::size_t overlay_cap) noexcept
    : overlay_cap_(overlay_cap) {}

void SandboxMemory::add_map(std::uint64_t base, std::uint32_t perms,
                            std::span<const std::uint8_t> bytes) {
    maps_.push_back(Map{base, static_cast<std::uint64_t>(bytes.size()), perms,
                        bytes, false});
}

void SandboxMemory::init_stack(std::uint64_t base) {
    // Inserted at the front so find_map reaches it before any image section
    maps_.insert(maps_.begin(),
                 Map{base, kStackSize, kMemRead | kMemWrite, {}, true});
}

const SandboxMemory::Map* SandboxMemory::find_map(std::uint64_t va) const noexcept {
    for (const Map& map : maps_) {
        if (va >= map.base && va < map.base + map.size) {
            return &map;
        }
    }
    return nullptr;
}

bool SandboxMemory::probe(std::uint64_t va, std::size_t size,
                          std::uint32_t perm) const noexcept {
    const Map* map = find_map(va);
    if (map == nullptr) {
        return false;
    }
    // The whole range must lie within this one map
    if (va + size > map->base + map->size) {
        return false;
    }
    return (map->perms & perm) == perm;
}

bool SandboxMemory::is_valid_pointer(std::uint64_t va) const noexcept {
    return find_map(va) != nullptr;
}

std::uint8_t SandboxMemory::backing_byte(const Map& map,
                                         std::uint64_t va) const noexcept {
    if (map.is_fill) {
        return kStackFill;
    }
    const std::uint64_t offset = va - map.base;
    if (offset < map.bytes.size()) {
        return map.bytes[static_cast<std::size_t>(offset)];
    }
    return kStackFill;
}

std::vector<std::uint8_t>
SandboxMemory::read_bytes(std::uint64_t va, std::size_t size) const {
    if (size == 0) {
        return {};
    }
    // Unreadable range -> taint fill (vivisect _safe_mem fallback)
    if (!probe(va, size, kMemRead)) {
        return std::vector<std::uint8_t>(size, kTaintByte);
    }
    const Map* map = find_map(va);
    std::vector<std::uint8_t> out(size);
    for (std::size_t i = 0; i < size; ++i) {
        const std::uint64_t addr = va + i;
        const auto it = overlay_.find(addr);
        if (it != overlay_.end()) {
            out[i] = it->second;
        } else {
            out[i] = backing_byte(*map, addr);
        }
    }
    return out;
}

std::vector<std::uint8_t>
SandboxMemory::read_code(std::uint64_t va, std::size_t max_len) const {
    const Map* map = find_map(va);
    if (map == nullptr || (map->perms & kMemRead) == 0) {
        return {};
    }
    const std::uint64_t available = map->base + map->size - va;
    const std::size_t n =
        static_cast<std::size_t>(std::min<std::uint64_t>(max_len, available));
    std::vector<std::uint8_t> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint64_t addr = va + i;
        const auto it = overlay_.find(addr);
        out[i] = it != overlay_.end() ? it->second : backing_byte(*map, addr);
    }
    return out;
}

std::uint64_t SandboxMemory::read_value(std::uint64_t va, std::size_t size) const {
    const std::vector<std::uint8_t> bytes = read_bytes(va, size);
    std::uint64_t value = 0;
    // Bounded to the width of the result
    const std::size_t limit = std::min<std::size_t>(bytes.size(), sizeof(value));
    for (std::size_t i = 0; i < limit; ++i) {
        value |= static_cast<std::uint64_t>(bytes[i]) << (8U * i);
    }
    return value;
}

void SandboxMemory::write(std::uint64_t va, std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return;
    }
    // Drop the whole write if the range is not writable (safe-mem)
    if (!probe(va, bytes.size(), kMemWrite)) {
        return;
    }
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const std::uint64_t addr = va + i;
        const auto it = overlay_.find(addr);
        if (it != overlay_.end()) {
            it->second = bytes[i];
            continue;
        }
        // DoS backstop: stop growing the overlay past the cap
        if (overlay_.size() >= overlay_cap_) {
            return;
        }
        overlay_.emplace(addr, bytes[i]);
    }
}

void SandboxMemory::write_value(std::uint64_t va, std::uint64_t value,
                                std::size_t size) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t i = 0; i < size && i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFULL);
    }
    write(va, std::span<const std::uint8_t>(bytes.data(), size));
}

SandboxMemory::Snapshot SandboxMemory::snapshot() const {
    return Snapshot{overlay_};
}

void SandboxMemory::restore(const Snapshot& snap) {
    overlay_ = snap.overlay;
}

}  // namespace papa::features::extractors::papa_native::emu
