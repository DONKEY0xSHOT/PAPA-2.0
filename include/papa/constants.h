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

// CFG recovery caps act as trip-wires against crafted inputs. kMaxInsnsPerFunction
// bounds the memory one code flow holds, not the work it does
inline constexpr std::size_t   kMaxInsnsPerFunction  = 1U << 20;   // 1M
inline constexpr std::size_t   kMaxFunctionsPerImage = 1U << 18;   // 256k
inline constexpr std::size_t   kMaxInsnBytes         = 15;         // x86 hard limit

// Table-size caps for counts a PE header declares. Each is also clamped to the bytes
// the image can supply, so these are the outer trip-wire rather than the primary bound
inline constexpr std::size_t   kMaxExportsPerImage   = 1U << 20;   // 1M
inline constexpr std::size_t   kMaxPdataEntries      = 1U << 22;   // 4M
inline constexpr std::size_t   kMaxSectionsPerImage  = 1U << 12;   // 4k

// Import-table walks are terminated by a null entry the file supplies, so a table with
// no terminator inside a mapped region iterates until a read fails
inline constexpr std::size_t   kMaxImportDescriptors = 1U << 14;   // 16k DLLs
inline constexpr std::size_t   kMaxImportsPerDll     = 1U << 16;   // 64k symbols

// Base relocations expand roughly four-fold, each two-byte entry becoming an
// eight-byte record. Large images carry a few hundred thousand
inline constexpr std::size_t   kMaxRelocations       = 1U << 24;   // 16M

// Largest sample accepted, a trip-wire rather than a working limit
inline constexpr std::size_t   kMaxSampleBytes       = 1ULL << 31;  // 2G

// Most strings a single extraction pass will return
inline constexpr std::size_t   kMaxStringsPerPass    = 1U << 22;   // 4M

// Total bytes the discovery emulator will copy into its backing maps
inline constexpr std::size_t   kMaxEmuImageBytes     = 1U << 29;   // 512M

// String extraction. kRepeatFillBytes lists bytes that, filling a 4 KiB window,
// indicate padding rather than user data
inline constexpr std::array<std::uint8_t, 4> kRepeatFillBytes{0x00, 0xFE, 0xFF, 0x41};
inline constexpr std::size_t   kFillCheckSliceSize  = 4096;
inline constexpr std::size_t   kMinStackStringLen    = 8;

// Instruction-level feature constants
inline constexpr std::uint32_t kPebOffsetX86            = 0x30;
inline constexpr std::uint32_t kPebOffsetX64            = 0x60;
inline constexpr std::uint64_t kCallPlus5Distance       = 5;
inline constexpr std::uint64_t kSecurityCookieBytesDelta = 0x40;
inline constexpr std::size_t   kThunkChainDepthDelta    = 5;

// CET ENDBRANCH leading bytes. The full instruction is endbr32 or endbr64, and
// kEndbranchSkipLen is how far we advance past such a thunk prefix
inline constexpr std::array<std::uint8_t, 3> kEndbranchBytes{0xF3, 0x0F, 0x1E};
inline constexpr std::size_t   kEndbranchSkipLen        = 4;

// RUNTIME_FUNCTION record size (x64 .pdata entry)
inline constexpr std::size_t   kRuntimeFunctionSize  = 12;

// String constants used by the renderer to label per-image platform. CAPA's report
// schema uses these literal lowercase tags
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
