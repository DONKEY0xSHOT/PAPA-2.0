#include <ostream>

#include "doctest.h"

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/flirt/byte_cursor.h"
#include "papa/features/extractors/papa_native/flirt/flirt_format.h"
#include "papa/features/extractors/papa_native/flirt/flirt_reader.h"

#include "test_support.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

TEST_CASE("flirt_reader: empty buffer is truncated") {
    auto r = flirt::parse_header({});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == papa::ErrorKind::kFlirtTruncated);
}

TEST_CASE("flirt_reader: wrong magic is rejected") {
    std::vector<std::uint8_t> buf(64, 0);
    buf[0] = 'X';
    auto r = flirt::parse_header(buf);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == papa::ErrorKind::kFlirtBadMagic);
}

TEST_CASE("flirt_reader: unsupported versions are rejected") {
    for (std::uint8_t v : {std::uint8_t{0}, std::uint8_t{5}, std::uint8_t{7},
                            std::uint8_t{11}, std::uint8_t{255}}) {
        std::vector<std::uint8_t> buf(64, 0);
        std::memcpy(buf.data(), "IDASGN", 6);
        buf[6] = v;
        auto r = flirt::parse_header(buf);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == papa::ErrorKind::kFlirtUnsupportedVersion);
    }
}

TEST_CASE("flirt_reader: v10 minimal header parses every field") {
    const auto buf = papa_tests::sig_header(10);
    auto r = flirt::parse_header(buf);
    REQUIRE(r.has_value());
    CHECK(r->version          == 10U);
    CHECK(r->arch             == flirt::FlirtArch::kX86);
    CHECK(r->file_types       == 0x00000002U);
    CHECK(r->os_types         == 0x0003U);
    CHECK(r->app_types        == 0x0004U);
    CHECK(r->features         == 0x0010U);
    CHECK(r->is_compressed());
    CHECK(r->old_n_functions  == 0x0007U);
    CHECK(r->pattern_crc16    == 0xABCDU);
    CHECK(r->library_name_len == 0U);
    CHECK(r->ctypes_crc16     == 0x1234U);
    CHECK(r->n_functions      == 0x0000002AU);
    CHECK(r->pattern_size     == 0x0020U);
    CHECK(r->library_name.empty());
}

TEST_CASE("flirt_reader: v8 header does not populate v9+ fields") {
    const auto buf = papa_tests::sig_header(8);
    auto r = flirt::parse_header(buf);
    REQUIRE(r.has_value());
    CHECK(r->version      == 8U);
    CHECK(r->n_functions  == 0U);  // v9+ field, stays at default
    CHECK(r->pattern_size == 0U);  // v10+ field, stays at default
}

TEST_CASE("flirt_reader: v9 header does not populate v10+ fields") {
    const auto buf = papa_tests::sig_header(9);
    auto r = flirt::parse_header(buf);
    REQUIRE(r.has_value());
    CHECK(r->version      == 9U);
    CHECK(r->n_functions  == 0x0000002AU);
    CHECK(r->pattern_size == 0U);
}

TEST_CASE("flirt_reader: library name is read when length is non-zero") {
    const auto buf = papa_tests::sig_header(10, /*ln_len=*/5);
    auto r = flirt::parse_header(buf);
    REQUIRE(r.has_value());
    CHECK(r->library_name_len == 5U);
    CHECK(r->library_name == "abcde");
}

TEST_CASE("flirt_reader: truncated library name is rejected") {
    auto buf = papa_tests::sig_header(10, /*ln_len=*/5);
    buf.resize(buf.size() - 3);  // drop 3 of the 5 name bytes
    auto r = flirt::parse_header(buf);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == papa::ErrorKind::kFlirtTruncated);
}

TEST_CASE("flirt_reader: header consumed length matches version") {
    const auto v10 = papa_tests::sig_header(10);
    auto r = flirt::parse_header(v10);
    REQUIRE(r.has_value());
    CHECK(flirt::header_size_for_version(10) == 45U);
    CHECK(flirt::header_size_for_version(9)  == 41U);
    CHECK(flirt::header_size_for_version(8)  == 37U);
}

TEST_CASE("flirt_reader: read_vle16 one-byte form") {
    std::array<std::uint8_t, 1> data{0x7F};
    flirt::detail::ByteCursor cur{data};
    std::uint16_t out = 0xFFFF;
    REQUIRE(cur.read_vle16(out));
    CHECK(out == 0x7FU);
    CHECK(cur.offset() == 1U);
}

TEST_CASE("flirt_reader: read_vle16 two-byte form") {
    std::array<std::uint8_t, 2> data{0x92, 0x34};
    flirt::detail::ByteCursor cur{data};
    std::uint16_t out = 0;
    REQUIRE(cur.read_vle16(out));
    CHECK(out == 0x1234U);
    CHECK(cur.offset() == 2U);
}

TEST_CASE("flirt_reader: read_vle16 two-byte form reaches max value") {
    std::array<std::uint8_t, 2> data{0xFF, 0xFF};
    flirt::detail::ByteCursor cur{data};
    std::uint16_t out = 0;
    REQUIRE(cur.read_vle16(out));
    CHECK(out == 0x7FFFU);
    CHECK(cur.offset() == 2U);
}

TEST_CASE("flirt_reader: read_vle16 truncated two-byte form fails cleanly") {
    std::array<std::uint8_t, 1> data{0x92};
    flirt::detail::ByteCursor cur{data};
    std::uint16_t out = 0xABCD;
    REQUIRE_FALSE(cur.read_vle16(out));
    CHECK(out == 0xABCDU);     // out param untouched on failure
    CHECK(cur.offset() == 0U);  // cursor not advanced
}

TEST_CASE("flirt_reader: read_vle16 empty buffer fails") {
    std::array<std::uint8_t, 0> data{};
    flirt::detail::ByteCursor cur{data};
    std::uint16_t out = 0x1111;
    REQUIRE_FALSE(cur.read_vle16(out));
    CHECK(out == 0x1111U);
    CHECK(cur.offset() == 0U);
}

TEST_CASE("flirt_reader: read_vle32 one-byte form") {
    std::array<std::uint8_t, 1> data{0x7F};
    flirt::detail::ByteCursor cur{data};
    std::uint32_t out = 0xFFFFFFFF;
    REQUIRE(cur.read_vle32(out));
    CHECK(out == 0x7FU);
    CHECK(cur.offset() == 1U);
}

TEST_CASE("flirt_reader: read_vle32 two-byte form") {
    std::array<std::uint8_t, 2> data{0x81, 0x00};
    flirt::detail::ByteCursor cur{data};
    std::uint32_t out = 0;
    REQUIRE(cur.read_vle32(out));
    CHECK(out == 0x0100U);
    CHECK(cur.offset() == 2U);
}

TEST_CASE("flirt_reader: read_vle32 four-byte masked form") {
    std::array<std::uint8_t, 4> data{0xC0, 0x00, 0x80, 0x00};
    flirt::detail::ByteCursor cur{data};
    std::uint32_t out = 0;
    REQUIRE(cur.read_vle32(out));
    CHECK(out == 0x8000U);
    CHECK(cur.offset() == 4U);
}

TEST_CASE("flirt_reader: read_vle32 full five-byte form") {
    std::array<std::uint8_t, 5> data{0xFF, 0xDE, 0xAD, 0xBE, 0xEF};
    flirt::detail::ByteCursor cur{data};
    std::uint32_t out = 0;
    REQUIRE(cur.read_vle32(out));
    CHECK(out == 0xDEADBEEFU);
    CHECK(cur.offset() == 5U);
}

TEST_CASE("flirt_reader: read_vle32 truncated four-byte form fails cleanly") {
    std::array<std::uint8_t, 3> data{0xC0, 0x00, 0x80};
    flirt::detail::ByteCursor cur{data};
    std::uint32_t out = 0x12345678;
    REQUIRE_FALSE(cur.read_vle32(out));
    CHECK(out == 0x12345678U);  // out param untouched on failure
    CHECK(cur.offset() == 0U);   // cursor not advanced
}

TEST_CASE("flirt_reader: read_vle32 truncated five-byte form fails cleanly") {
    std::array<std::uint8_t, 4> data{0xFF, 0xDE, 0xAD, 0xBE};
    flirt::detail::ByteCursor cur{data};
    std::uint32_t out = 0x99999999;
    REQUIRE_FALSE(cur.read_vle32(out));
    CHECK(out == 0x99999999U);
    CHECK(cur.offset() == 0U);
}

TEST_CASE("flirt_reader: minimal uncompressed sig parses one module") {
    papa_tests::SigWriter body;
    body.vle16(1);                                   // root child count
    const std::array<std::uint8_t, 3> pat{0x55, 0x8B, 0xEC};
    body.child_pattern(pat);                         // child 0 pattern
    body.vle16(0);                                    // child 0 is a leaf
    body.u8(0x08);                                    // crc_len -> tail_length
    body.u16_be(0x1234);                           // crc16 -> tail_crc16 (BE on disk)
    body.module_body(0x10, "foo", 0x00);              // one module, no continuation

    const auto sig = papa_tests::sig_with_body(body.buf);
    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE(r.has_value());
    CHECK(r->module_count() == 1U);

    const flirt::FlirtNode* root = r->root();
    REQUIRE(root != nullptr);
    REQUIRE(root->children.size() == 1U);
    const flirt::FlirtNode* child = root->children.front().get();
    REQUIRE(child != nullptr);
    CHECK(child->pattern.length == 3U);
    CHECK(child->pattern.bytes[0] == 0x55U);
    CHECK(child->pattern.bytes[1] == 0x8BU);
    CHECK(child->pattern.bytes[2] == 0xECU);
    CHECK_FALSE(child->pattern.wildcard.any());
    REQUIRE(child->leaf_modules.size() == 1U);
    CHECK(child->leaf_modules.front().tail_length == 0x08U);
    CHECK(child->leaf_modules.front().tail_crc16 == 0x1234U);
}

TEST_CASE("flirt_reader: two-children root sums module counts") {
    papa_tests::SigWriter body;
    body.vle16(2);                                    // root child count

    const std::array<std::uint8_t, 2> pat_a{0x55, 0x8B};
    body.child_pattern(pat_a);
    body.vle16(0);                                    // leaf
    body.u8(0x04);
    body.u16_be(0xAAAA);
    body.module_body(0x20, "aaa", 0x00);

    const std::array<std::uint8_t, 4> pat_b{0x90, 0x90, 0x90, 0x90};
    body.child_pattern(pat_b);
    body.vle16(0);                                    // leaf
    body.u8(0x06);
    body.u16_be(0xBBBB);
    body.module_body(0x30, "bbb", 0x00);

    const auto sig = papa_tests::sig_with_body(body.buf);
    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE(r.has_value());
    CHECK(r->module_count() == 2U);

    const flirt::FlirtNode* root = r->root();
    REQUIRE(root != nullptr);
    REQUIRE(root->children.size() == 2U);
    CHECK(root->children[0]->pattern.length == 2U);
    CHECK(root->children[1]->pattern.length == 4U);
    CHECK(root->children[0]->leaf_modules.size() == 1U);
    CHECK(root->children[1]->leaf_modules.size() == 1U);
}

TEST_CASE("flirt_reader: leaf with two colliding modules") {
    papa_tests::SigWriter body;
    body.vle16(1);
    const std::array<std::uint8_t, 3> pat{0x55, 0x8B, 0xEC};
    body.child_pattern(pat);
    body.vle16(0);                                    // leaf
    body.u8(0x08);
    body.u16_be(0x1234);
    // First module sets MORE_MODULES_WITH_SAME_CRC (0x08) so a second
    // module follows under the same crc without a fresh crc header
    body.module_body(0x10, "foo", 0x08);
    body.module_body(0x18, "bar", 0x00);

    const auto sig = papa_tests::sig_with_body(body.buf);
    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE(r.has_value());
    CHECK(r->module_count() == 2U);

    const flirt::FlirtNode* child = r->root()->children.front().get();
    REQUIRE(child->leaf_modules.size() == 2U);
    CHECK(child->leaf_modules[0].tail_length == 0x08U);
    CHECK(child->leaf_modules[0].tail_crc16 == 0x1234U);
    CHECK(child->leaf_modules[1].tail_length == 0x08U);
    CHECK(child->leaf_modules[1].tail_crc16 == 0x1234U);
}

TEST_CASE("flirt_reader: truncated body returns truncated error") {
    papa_tests::SigWriter body;
    body.vle16(1);
    const std::array<std::uint8_t, 3> pat{0x55, 0x8B, 0xEC};
    body.child_pattern(pat);
    body.vle16(0);                                    // leaf
    body.u8(0x08);
    body.u16_be(0x1234);
    body.module_body(0x10, "foo", 0x00);

    auto sig = papa_tests::sig_with_body(body.buf);
    sig.resize(sig.size() - 2);  // drop the trailing flags and last name byte

    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == papa::ErrorKind::kFlirtTruncated);
}

TEST_CASE("flirt_reader: pattern longer than cap is a bad node") {
    papa_tests::SigWriter body;
    body.vle16(1);
    // kMaxPatternLength is 32. Encode a 33-byte pattern length
    body.vle16(33);
    body.vle16(0);  // empty variant mask
    body.buf.insert(body.buf.end(), 33, std::uint8_t{0x90});

    const auto sig = papa_tests::sig_with_body(body.buf);
    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == papa::ErrorKind::kFlirtBadNode);
}

TEST_CASE("flirt_reader: variant mask marks wildcard positions") {
    papa_tests::SigWriter body;
    body.vle16(1);  // root child count
    // A 3-byte segment with the middle position wildcarded. A wildcard at local
    // position 1 sets mask bit (length - 1 - 1) = bit 1
    const std::array<std::uint8_t, 2> literals{0x55, 0xEC};
    body.child_pattern_masked(3, 0x02, literals);
    body.vle16(0);  // leaf
    body.u8(0x04);
    body.u16_be(0x1234);
    body.module_body(0x10, "foo", 0x00);

    const auto sig = papa_tests::sig_with_body(body.buf);
    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE(r.has_value());
    const flirt::FlirtNode* child = r->root()->children.front().get();
    REQUIRE(child != nullptr);
    CHECK(child->pattern.length == 3U);
    CHECK(child->pattern.bytes[0] == 0x55U);
    CHECK_FALSE(child->pattern.wildcard.test(0));
    CHECK(child->pattern.wildcard.test(1));
    CHECK_FALSE(child->pattern.wildcard.test(2));
    CHECK(child->pattern.bytes[2] == 0xECU);
}

TEST_CASE("flirt_reader: nested nodes accumulate the pattern prefix") {
    papa_tests::SigWriter body;
    body.vle16(1);  // root has one child A
    const std::array<std::uint8_t, 1> pat_a{0x55};
    body.child_pattern(pat_a);  // A pattern, length 1
    body.vle16(1);  // A is internal with one child B
    const std::array<std::uint8_t, 2> pat_b{0x8B, 0xEC};
    body.child_pattern(pat_b);  // B pattern, length 2
    body.vle16(0);  // B is a leaf
    body.u8(0x05);
    body.u16_be(0xCAFE);
    body.module_body(0x10, "foo", 0x00);

    const auto sig = papa_tests::sig_with_body(body.buf);
    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE(r.has_value());
    CHECK(r->module_count() == 1U);

    const flirt::FlirtNode* a = r->root()->children.front().get();
    REQUIRE(a != nullptr);
    CHECK(a->pattern.length == 1U);
    CHECK(a->pattern.bytes[0] == 0x55U);
    REQUIRE(a->children.size() == 1U);
    const flirt::FlirtNode* b = a->children.front().get();
    REQUIRE(b != nullptr);
    CHECK(b->pattern.length == 3U);  // inherited prefix of 1 plus segment of 2
    CHECK(b->pattern.bytes[0] == 0x55U);
    CHECK(b->pattern.bytes[1] == 0x8BU);
    CHECK(b->pattern.bytes[2] == 0xECU);
    REQUIRE(b->leaf_modules.size() == 1U);
    CHECK(b->leaf_modules.front().tail_crc16 == 0xCAFEU);
}

TEST_CASE("flirt_reader: a module retains names, tail bytes, and references") {
    using flirt::FlirtNameType;
    papa_tests::SigWriter body;
    body.vle16(1);                               // root child count
    const std::array<std::uint8_t, 3> pat{0x55, 0x8B, 0xEC};
    body.child_pattern(pat);
    body.vle16(0);                                // leaf
    body.u8(0x08);                                // crc_len
    body.u16_be(0x1234);                          // crc16

    body.vle16(0x40);                             // function_size
    // Three names: public foo @rel 0, local bar @rel +5, public baz @rel +3.
    // Delta accumulation yields absolute offsets 0, 5, 8 (8 != 3 proves delta)
    constexpr std::uint8_t kMorePublicNames = 0x01;
    constexpr std::uint8_t kLocalFlag       = 0x02;
    constexpr std::uint8_t kTailAndRefs     = 0x02 | 0x04;
    body.name_record(0, 0,          "foo", kMorePublicNames);
    body.name_record(5, kLocalFlag, "bar", kMorePublicNames);
    body.name_record(3, 0,          "baz", kTailAndRefs);
    // Tail bytes: count 1, absolute offset 0x20, value 0xAB
    body.vle16(1);
    body.vle16(0x20);
    body.u8(0xAB);
    // Referenced functions: count 1, absolute offset 0x10, name "malloc"
    body.vle16(1);
    body.vle16(0x10);
    body.u8(6);
    for (const char c : std::string_view{"malloc"}) {
        body.u8(static_cast<std::uint8_t>(c));
    }

    const auto sig = papa_tests::sig_with_body(body.buf);
    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE(r.has_value());
    const flirt::FlirtNode* child = r->root()->children.front().get();
    REQUIRE(child != nullptr);
    REQUIRE(child->leaf_modules.size() == 1U);
    const flirt::FlirtModule& m = child->leaf_modules.front();

    CHECK(m.function_size == 0x40U);
    REQUIRE(m.names.size() == 3U);
    CHECK(m.names[0].offset == 0);
    CHECK(m.names[0].name == "foo");
    CHECK(m.names[0].type == FlirtNameType::kPublic);
    CHECK(m.names[1].offset == 5);
    CHECK(m.names[1].name == "bar");
    CHECK(m.names[1].type == FlirtNameType::kLocal);
    CHECK(m.names[2].offset == 8);
    CHECK(m.names[2].name == "baz");
    CHECK(m.names[2].type == FlirtNameType::kPublic);
    REQUIRE(m.tail_bytes.size() == 1U);
    CHECK(m.tail_bytes[0].offset == 0x20U);
    CHECK(m.tail_bytes[0].value == 0xABU);
    REQUIRE(m.references.size() == 1U);
    CHECK(m.references[0].offset == 0x10U);
    CHECK(m.references[0].name == "malloc");
}

TEST_CASE("flirt_reader: leaf with two distinct-crc module groups") {
    papa_tests::SigWriter body;
    body.vle16(1);
    const std::array<std::uint8_t, 3> pat{0x55, 0x8B, 0xEC};
    body.child_pattern(pat);
    body.vle16(0);  // leaf
    // First group sets MORE_MODULES (0x10) so a second group with its own
    // crc header follows
    body.u8(0x08);
    body.u16_be(0xAAAA);
    body.module_body(0x10, "foo", 0x10);
    body.u8(0x0C);
    body.u16_be(0xBBBB);
    body.module_body(0x20, "bar", 0x00);

    const auto sig = papa_tests::sig_with_body(body.buf);
    auto r = flirt::parse_sig_buffer(sig);
    REQUIRE(r.has_value());
    CHECK(r->module_count() == 2U);
    const flirt::FlirtNode* child = r->root()->children.front().get();
    REQUIRE(child->leaf_modules.size() == 2U);
    CHECK(child->leaf_modules[0].tail_crc16 == 0xAAAAU);
    CHECK(child->leaf_modules[0].tail_length == 0x08U);
    CHECK(child->leaf_modules[1].tail_crc16 == 0xBBBBU);
    CHECK(child->leaf_modules[1].tail_length == 0x0CU);
}
