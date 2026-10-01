#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/pefile.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/file.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include "pe_builder.h"
#include "test_support.h"

namespace pefile = papa::features::extractors::pefile;

using papa::features::Address;
using papa::features::Characteristic;
using papa::features::Export;
using papa::features::FileOffsetAddress;
using papa::features::Format;
using papa::features::Import;
using papa::features::NoAddress;
using papa::features::Section;
using papa::features::String;
using papa_tests::describe;
using papa_tests::feat;
using papa_tests::va;

namespace {

using Features = std::vector<papa::features::extractors::FeatureWithAddress>;

constexpr std::size_t kWideOffset = 0x10;  // the UTF-16 string in .data
constexpr std::size_t kPeOffset   = 0x40;  // the PE carried in .data

// An image with every kind of file feature: named, A/W-suffixed and ordinal imports,
// a plain and a forwarded export, an ASCII and a UTF-16 string, and a PE in .data
papa_tests::PeBuilder rich_builder() {
    papa_tests::PeBuilder b;
    b.code    = {0x33, 0xC0, 0xC3};  // xor eax, eax / ret
    b.imports = {{"KERNEL32.dll", {"CreateFileW", "ExitProcess"}},
                 {"ws2_32.dll", {"#6"}},
                 {"mydll.dll", {"#3"}}};
    b.exports = {{"DoWork", 0x00, ""}, {"HeapAlloc", 0x00, "NTDLL.RtlAllocateHeap"}};

    b.data.assign(kPeOffset + 0x44, 0);
    const std::string_view ascii = "hello world";
    std::copy(ascii.begin(), ascii.end(), b.data.begin());
    const std::string_view wide = "wide text";
    for (std::size_t i = 0; i < wide.size(); ++i) {
        b.data[kWideOffset + 2U * i] = static_cast<std::uint8_t>(wide[i]);
    }
    // The least a carver accepts: MZ, then e_lfanew pointing at the PE signature
    b.data[kPeOffset]      = 'M';
    b.data[kPeOffset + 1U] = 'Z';
    papa_tests::detail::poke<std::uint32_t>(b.data, kPeOffset + 0x3CU, 0x40U);
    papa_tests::detail::poke<std::uint32_t>(b.data, kPeOffset + 0x40U, 0x00004550U);
    return b;
}

[[nodiscard]] Address file_at(std::uint64_t offset) {
    return Address{FileOffsetAddress{offset}};
}

// File offset of the first copy of text in bytes
[[nodiscard]] std::uint64_t offset_of(const std::vector<std::byte>& bytes, std::string_view text) {
    const auto it = std::search(bytes.begin(), bytes.end(), text.begin(), text.end(),
                                [](std::byte b, char c) { return b == static_cast<std::byte>(c); });
    return static_cast<std::uint64_t>(it - bytes.begin());
}

}  // namespace

TEST_CASE("pefile: each file extractor yields exactly the features of the image") {
    const papa_tests::PeBuilder b     = rich_builder();
    const auto                  bytes = b.build();
    const auto                  img   = papa::pe::PeParser::parse(bytes);
    REQUIRE(img.has_value());
    const std::uint64_t base = img->image_base();
    const auto*         data = img->section_containing_rva(b.section_rva(".data"));
    REQUIRE(data != nullptr);

    CHECK(describe(pefile::extract_file_format(*img)) ==
          describe(Features{{feat<Format>("pe"), NoAddress{}}}));

    CHECK(describe(pefile::extract_file_section_names(*img)) ==
          describe(Features{
              {feat<Section>(".text"), va(base + b.section_rva(".text"))},
              {feat<Section>(".rdata"), va(base + b.section_rva(".rdata"))},
              {feat<Section>(".data"), va(base + b.section_rva(".data"))},
          }));

    // Each row yields its dotted and bare names, a W row also its A/W-stripped pair,
    // and an ordinal the table cannot name stays #N
    const auto iat = [&b](std::string_view dll, std::string_view fn) {
        return va(b.iat_va(dll, fn));
    };
    CHECK(describe(pefile::extract_file_import_names(*img)) ==
          describe(Features{
              {feat<Import>("kernel32.CreateFileW"), iat("KERNEL32.dll", "CreateFileW")},
              {feat<Import>("CreateFileW"), iat("KERNEL32.dll", "CreateFileW")},
              {feat<Import>("kernel32.CreateFile"), iat("KERNEL32.dll", "CreateFileW")},
              {feat<Import>("CreateFile"), iat("KERNEL32.dll", "CreateFileW")},
              {feat<Import>("kernel32.ExitProcess"), iat("KERNEL32.dll", "ExitProcess")},
              {feat<Import>("ExitProcess"), iat("KERNEL32.dll", "ExitProcess")},
              {feat<Import>("ws2_32.getsockname"), iat("ws2_32.dll", "#6")},
              {feat<Import>("getsockname"), iat("ws2_32.dll", "#6")},
              {feat<Import>("mydll.#3"), iat("mydll.dll", "#3")},
              {feat<Import>("#3"), iat("mydll.dll", "#3")},
          }));

    // A forwarded export has no address of its own, and adds the forwarded export
    // characteristic plus an import of its target with the module lowercased
    CHECK(describe(pefile::extract_file_export_names(*img)) ==
          describe(Features{
              {feat<Export>("DoWork"), va(b.code_va(0))},
              {feat<Export>("HeapAlloc"), va(0)},
              {feat<Characteristic>("forwarded export"), va(0)},
              {feat<Import>("ntdll.RtlAllocateHeap"), va(0)},
          }));

    // The host's own MZ at offset 0 is not reported
    CHECK(describe(pefile::extract_file_embedded_pe(*img)) ==
          describe(Features{
              {feat<Characteristic>("embedded pe"), file_at(data->raw_offset + kPeOffset)},
          }));

    // Past the headers every string is a name .rdata holds, then the two in .data, the
    // ASCII ones first
    Features strings;
    for (const auto& s : pefile::extract_file_strings(*img)) {
        const auto* at = std::get_if<FileOffsetAddress>(&s.second);
        REQUIRE(at != nullptr);
        if (at->v >= b.header_layout().size_of_headers) { strings.push_back(s); }
    }
    Features want;
    for (const std::string_view name : {"CreateFileW", "ExitProcess", "KERNEL32.dll", "ws2_32.dll",
                                        "mydll.dll", "DoWork", "HeapAlloc", "synthetic.exe",
                                        "NTDLL.RtlAllocateHeap"}) {
        want.emplace_back(feat<String>(std::string(name)), file_at(offset_of(bytes, name)));
    }
    want.emplace_back(feat<String>("hello world"), file_at(data->raw_offset));
    want.emplace_back(feat<String>("wide text"), file_at(data->raw_offset + kWideOffset));
    CHECK(describe(strings) == describe(want));
}

TEST_CASE("pefile: extract_file_features concatenates the extractors in a fixed order") {
    const auto img = papa::pe::PeParser::parse(rich_builder().build());
    REQUIRE(img.has_value());

    using Extract = Features (*)(const papa::pe::PeImage&);
    const std::array<Extract, 6> parts{
        &pefile::extract_file_format,      &pefile::extract_file_section_names,
        &pefile::extract_file_import_names, &pefile::extract_file_export_names,
        &pefile::extract_file_embedded_pe, &pefile::extract_file_strings,
    };
    Features want;
    for (const Extract part : parts) {
        const Features got = part(*img);
        CHECK_FALSE(got.empty());
        want.insert(want.end(), got.begin(), got.end());
    }
    CHECK(describe(pefile::extract_file_features(*img)) == describe(want));
}
