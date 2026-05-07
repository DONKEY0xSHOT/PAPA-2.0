#pragma once

#include <array>
#include <cstdint>

namespace papa::pe {

#pragma pack(push, 1)

struct ImageDosHeader {
    std::uint16_t e_magic;
    std::uint16_t e_cblp;
    std::uint16_t e_cp;
    std::uint16_t e_crlc;
    std::uint16_t e_cparhdr;
    std::uint16_t e_minalloc;
    std::uint16_t e_maxalloc;
    std::uint16_t e_ss;
    std::uint16_t e_sp;
    std::uint16_t e_csum;
    std::uint16_t e_ip;
    std::uint16_t e_cs;
    std::uint16_t e_lfarlc;
    std::uint16_t e_ovno;
    std::array<std::uint16_t, 4>  e_res;
    std::uint16_t e_oemid;
    std::uint16_t e_oeminfo;
    std::array<std::uint16_t, 10> e_res2;
    std::int32_t  e_lfanew;
};
static_assert(sizeof(ImageDosHeader) == 64);

struct ImageFileHeader {
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
};
static_assert(sizeof(ImageFileHeader) == 20);

struct ImageDataDirectory {
    std::uint32_t VirtualAddress;
    std::uint32_t Size;
};
static_assert(sizeof(ImageDataDirectory) == 8);

// Common optional-header fields shared by PE32 and PE32+
struct ImageOptionalHeaderCommon {
    std::uint16_t Magic;
    std::uint8_t  MajorLinkerVersion;
    std::uint8_t  MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
};
static_assert(sizeof(ImageOptionalHeaderCommon) == 24);

struct ImageOptionalHeader32 {
    ImageOptionalHeaderCommon Common;
    std::uint32_t BaseOfData;
    std::uint32_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint32_t SizeOfStackReserve;
    std::uint32_t SizeOfStackCommit;
    std::uint32_t SizeOfHeapReserve;
    std::uint32_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
};
static_assert(sizeof(ImageOptionalHeader32) == 96);

struct ImageOptionalHeader64 {
    ImageOptionalHeaderCommon Common;
    std::uint64_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint64_t SizeOfStackReserve;
    std::uint64_t SizeOfStackCommit;
    std::uint64_t SizeOfHeapReserve;
    std::uint64_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
};
static_assert(sizeof(ImageOptionalHeader64) == 112);

struct ImageSectionHeader {
    std::array<std::uint8_t, 8> Name;
    std::uint32_t VirtualSize;
    std::uint32_t VirtualAddress;
    std::uint32_t SizeOfRawData;
    std::uint32_t PointerToRawData;
    std::uint32_t PointerToRelocations;
    std::uint32_t PointerToLinenumbers;
    std::uint16_t NumberOfRelocations;
    std::uint16_t NumberOfLinenumbers;
    std::uint32_t Characteristics;
};
static_assert(sizeof(ImageSectionHeader) == 40);

struct ImageImportDescriptor {
    std::uint32_t OriginalFirstThunk;  // RVA of import lookup table
    std::uint32_t TimeDateStamp;
    std::uint32_t ForwarderChain;
    std::uint32_t Name;                // RVA of DLL name string
    std::uint32_t FirstThunk;          // RVA of IAT
};
static_assert(sizeof(ImageImportDescriptor) == 20);

struct ImageDelayImportDescriptor {
    std::uint32_t Attributes;
    std::uint32_t Name;
    std::uint32_t ModuleHandle;
    std::uint32_t DelayImportAddressTable;
    std::uint32_t DelayImportNameTable;
    std::uint32_t BoundDelayImportTable;
    std::uint32_t UnloadDelayImportTable;
    std::uint32_t TimeStamp;
};
static_assert(sizeof(ImageDelayImportDescriptor) == 32);

struct ImageExportDirectory {
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint32_t Name;
    std::uint32_t Base;
    std::uint32_t NumberOfFunctions;
    std::uint32_t NumberOfNames;
    std::uint32_t AddressOfFunctions;
    std::uint32_t AddressOfNames;
    std::uint32_t AddressOfNameOrdinals;
};
static_assert(sizeof(ImageExportDirectory) == 40);

struct ImageTlsDirectory32 {
    std::uint32_t StartAddressOfRawData;
    std::uint32_t EndAddressOfRawData;
    std::uint32_t AddressOfIndex;
    std::uint32_t AddressOfCallBacks;
    std::uint32_t SizeOfZeroFill;
    std::uint32_t Characteristics;
};
static_assert(sizeof(ImageTlsDirectory32) == 24);

struct ImageTlsDirectory64 {
    std::uint64_t StartAddressOfRawData;
    std::uint64_t EndAddressOfRawData;
    std::uint64_t AddressOfIndex;
    std::uint64_t AddressOfCallBacks;
    std::uint32_t SizeOfZeroFill;
    std::uint32_t Characteristics;
};
static_assert(sizeof(ImageTlsDirectory64) == 40);

#pragma pack(pop)

}  // namespace papa::pe
