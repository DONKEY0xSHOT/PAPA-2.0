#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace papa::constants {

// PE signatures
inline constexpr std::uint16_t kImageDosSignature       = 0x5A4D;       // "MZ"
inline constexpr std::uint32_t kImageNtSignature        = 0x00004550;   // "PE\0\0"
inline constexpr std::uint32_t kElfSignature            = 0x464C457F;   // "\x7FELF" LE

// PE header offsets
inline constexpr std::uint32_t kImageDosEofLfanewOffset = 0x3C;

// PE machine types
inline constexpr std::uint16_t kImageFileMachineI386    = 0x014C;
inline constexpr std::uint16_t kImageFileMachineAmd64   = 0x8664;
inline constexpr std::uint16_t kImageFileMachineArm64   = 0xAA64;

// Optional header magic
inline constexpr std::uint16_t kOptionalHeaderMagic32   = 0x010B;
inline constexpr std::uint16_t kOptionalHeaderMagic64   = 0x020B;

// Section table
inline constexpr std::size_t   kImageSizeofShortName    = 8;

// Data directory indices
inline constexpr std::uint32_t kImageDirectoryEntryExport        = 0;
inline constexpr std::uint32_t kImageDirectoryEntryImport        = 1;
inline constexpr std::uint32_t kImageDirectoryEntryResource      = 2;
inline constexpr std::uint32_t kImageDirectoryEntryException     = 3;
inline constexpr std::uint32_t kImageDirectoryEntryBaseReloc     = 5;
inline constexpr std::uint32_t kImageDirectoryEntryTls           = 9;
inline constexpr std::uint32_t kImageDirectoryEntryDelayImport   = 13;
inline constexpr std::uint32_t kImageNumberOfDirectoryEntries    = 16;

// Section characteristics
inline constexpr std::uint32_t kImageScnMemRead     = 0x40000000u;
inline constexpr std::uint32_t kImageScnMemWrite    = 0x80000000u;
inline constexpr std::uint32_t kImageScnMemExecute  = 0x20000000u;

// Import ordinal flags
inline constexpr std::uint32_t kImageOrdinalFlag32  = 0x80000000u;
inline constexpr std::uint64_t kImageOrdinalFlag64  = 0x8000000000000000ULL;

// DLL name normalization
// Suffixes stripped from imported DLL names before symbol matching
inline constexpr std::array<std::string_view, 3> kDllExtensions { ".dll", ".drv", ".so" };

// Feature extraction limits
// Forward-declared here and consumed by feature modules
inline constexpr std::size_t   kMaxBytesFeatureSize  = 0x100;
inline constexpr std::uint32_t kMaxStructureSize     = 0x10000;
inline constexpr std::size_t   kMaxOperandCount      = 5;
inline constexpr std::size_t   kMaxOperandIndex      = kMaxOperandCount - 1;
inline constexpr std::size_t   kMinStringLength      = 4;

// CFG recovery caps act as trip-wires against crafted inputs
inline constexpr std::size_t   kMaxInsnsPerFunction  = 1U << 15;   // 32k
inline constexpr std::size_t   kMaxFunctionsPerImage = 1U << 18;   // 256k
inline constexpr std::size_t   kMaxInsnBytes         = 15;         // x86 hard limit

// Table-size caps for counts a PE header declares. Each is also clamped to the
// bytes the image can supply, so these are the outer trip-wire rather than the
// primary bound. Real images stay far below both
inline constexpr std::size_t   kMaxExportsPerImage   = 1U << 20;   // 1M
inline constexpr std::size_t   kMaxPdataEntries      = 1U << 22;   // 4M

// String extraction
// kRepeatFillBytes lists bytes that, when filling a 4 KiB window, indicate
// padding rather than user data (CAPA strings.py:fill_bytes)
// kFillCheckSliceSize matches CAPA SLICE constant
inline constexpr std::array<std::uint8_t, 4> kRepeatFillBytes{0x00, 0xFE, 0xFF, 0x41};
inline constexpr std::size_t   kFillCheckSliceSize  = 4096;
inline constexpr std::size_t   kMinStackStringLen    = 8;

// Instruction-level feature constants
// Offsets into the TIB at which the PEB pointer lives, by bitness
// kCallPlus5Distance is the byte length of a near-relative CALL on x86/x64
// kSecurityCookieBytesDelta bounds the prologue/epilogue window where xor with
// the security cookie does not represent a real nzxor
// kThunkChainDepthDelta caps how many forwarder-thunks we follow during API
// resolution before giving up
inline constexpr std::uint32_t kPebOffsetX86            = 0x30;
inline constexpr std::uint32_t kPebOffsetX64            = 0x60;
inline constexpr std::uint64_t kCallPlus5Distance       = 5;
inline constexpr std::uint64_t kSecurityCookieBytesDelta = 0x40;
inline constexpr std::size_t   kThunkChainDepthDelta    = 5;

// CET ENDBRANCH leading bytes
// The full 4-byte instruction is endbr32/endbr64
// preceded by 0xF3 0x0F 0x1E and either 0xFB or 0xFA in the last position
// kEndbranchSkipLen is the count we advance past such a thunk prefix
inline constexpr std::array<std::uint8_t, 3> kEndbranchBytes{0xF3, 0x0F, 0x1E};
inline constexpr std::size_t   kEndbranchSkipLen        = 4;

// RUNTIME_FUNCTION record size (x64 .pdata entry)
inline constexpr std::size_t   kRuntimeFunctionSize  = 12;

// String constants used by the renderer to label per-image platform
// CAPA's report schema uses these literal lowercase tags
// Rules also match on them via the os/arch/format leaf features
namespace os_value {
inline constexpr std::string_view kWindows = "windows";
inline constexpr std::string_view kLinux   = "linux";
inline constexpr std::string_view kMacos   = "macos";
inline constexpr std::string_view kAndroid = "android";
inline constexpr std::string_view kAny     = "any";
inline constexpr std::string_view kAuto    = "auto";
}  // namespace os_value

namespace arch_value {
inline constexpr std::string_view kI386    = "i386";
inline constexpr std::string_view kAmd64   = "amd64";
inline constexpr std::string_view kAarch64 = "aarch64";
inline constexpr std::string_view kAny     = "any";
}  // namespace arch_value

namespace format_value {
inline constexpr std::string_view kPe      = "pe";
inline constexpr std::string_view kElf     = "elf";
inline constexpr std::string_view kDotnet  = "dotnet";
inline constexpr std::string_view kAuto    = "auto";
inline constexpr std::string_view kSc32    = "sc32";
inline constexpr std::string_view kSc64    = "sc64";
inline constexpr std::string_view kUnknown = "unknown";
}  // namespace format_value

}  // namespace papa::constants
