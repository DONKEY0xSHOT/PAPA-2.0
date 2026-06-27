#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace papa::features::extractors::papa_native::flirt {

/// The six-byte ASCII magic that introduces every IDASGN file.
inline constexpr std::array<std::byte, 6> kIdasgnMagic = {
    std::byte{'I'}, std::byte{'D'}, std::byte{'A'},
    std::byte{'S'}, std::byte{'G'}, std::byte{'N'},
};

inline constexpr std::uint8_t  kMinSupportedVersion = 8;
inline constexpr std::uint8_t  kMaxSupportedVersion = 10;

/// Maximum FLAIR pattern length in bytes. Hard cap from the FLAIR SDK.
inline constexpr std::size_t   kMaxPatternLength    = 32;

/// Defensive cap on recursion depth when parsing the pattern tree.
inline constexpr std::size_t   kMaxTreeDepth        = 64;

/// Defensive cap on inflated body size; rejects decompression bombs.
inline constexpr std::size_t   kMaxDecompressedSize = std::size_t{64} << 20;

/// CRC16 polynomial used by FLAIR (reflected variant of 0x1021).
inline constexpr std::uint16_t kCrc16Polynomial     = 0x8408;

/// Returns true when v is an IDASGN version this reader can parse.
[[nodiscard]] constexpr bool is_supported_version(std::uint8_t v) noexcept {
    return v >= kMinSupportedVersion && v <= kMaxSupportedVersion;
}

/// Architecture tag from byte 6 of the header. We only act on x86/x64;
/// other values are accepted and ignored.
enum class FlirtArch : std::uint8_t {
    kAny    = 0,
    kX86    = 1,
    kX64    = 2,
    kOther  = 255,
};

/// Subset of FLAIR's SF_* feature-flag bits we care about. The
/// compression bit determines whether the body needs DEFLATE inflate.
enum class FlirtFeature : std::uint16_t {
    kStartup        = 0x0001,
    kCtype_crc      = 0x0002,
    k2byte_ctype    = 0x0004,
    kAlt_ctype_crc  = 0x0008,
    kCompressed     = 0x0010,
};

/// Parsed prefix of a .sig file. Mirrors the v8/v9/v10 header layout
/// per the FLAIR SDK; later fields are populated only when the version
/// is high enough.
struct FlirtHeader {
    std::uint8_t   version        {0};       // 8, 9, or 10
    FlirtArch      arch           {FlirtArch::kAny};
    std::uint32_t  file_types     {0};
    std::uint16_t  os_types       {0};
    std::uint16_t  app_types      {0};
    std::uint16_t  features       {0};       // bitmask of FlirtFeature
    std::uint16_t  old_n_functions{0};
    std::uint16_t  pattern_crc16  {0};
    std::array<char, 12> ctype    {};        // NUL-padded
    std::uint8_t   library_name_len{0};
    std::uint16_t  ctypes_crc16   {0};
    std::uint32_t  n_functions    {0};       // v9+
    std::uint16_t  pattern_size   {0};       // v10+
    std::uint16_t  unknown_v10    {0};       // v10+
    std::string    library_name;

    [[nodiscard]] constexpr bool is_compressed() const noexcept {
        return (features & static_cast<std::uint16_t>(FlirtFeature::kCompressed)) != 0;
    }
};

}  // namespace papa::features::extractors::papa_native::flirt
