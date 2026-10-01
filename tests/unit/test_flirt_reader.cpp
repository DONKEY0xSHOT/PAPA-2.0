#include <ostream>

#include "doctest.h"

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/flirt/byte_cursor.h"
#include "papa/features/extractors/papa_native/flirt/flirt_format.h"
#include "papa/features/extractors/papa_native/flirt/flirt_reader.h"

#include "test_support.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

namespace {

// One module with three names, a tail byte and a referenced function. Its last name ends
// with last_flags, which mark the tail bytes and references and may chain more modules
void rich_module(papa_tests::SigWriter& body, std::uint8_t last_flags) {
    body.vle16(0x40);  // function_size
    // Three names: public foo @rel 0, local bar @rel +5, public baz @rel +3.
    // Delta accumulation yields absolute offsets 0, 5, 8 (8 != 3 proves delta)
    constexpr std::uint8_t kMorePublicNames = 0x01;
    constexpr std::uint8_t kLocalFlag       = 0x02;
    body.name_record(0, 0,          "foo", kMorePublicNames);
    body.name_record(5, kLocalFlag, "bar", kMorePublicNames);
    body.name_record(3, 0,          "baz", last_flags);
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
}

// The trailing flags that announce tail bytes and referenced functions
constexpr std::uint8_t kTailAndRefs = 0x02 | 0x04;

// A sig of the given version with compression cleared, followed by body
[[nodiscard]] std::vector<std::uint8_t> plain_sig(std::uint8_t version,
                                                  std::span<const std::uint8_t> body) {
    auto sig = papa_tests::sig_header(version);
    papa_tests::clear_compression_bit(sig);
    sig.insert(sig.end(), body.begin(), body.end());
    return sig;
}

}  // namespace

TEST_CASE("flirt_reader: parse_header rejects a short buffer, a wrong magic, an unsupported version and a cut library name") {
    const auto with_version = [](std::uint8_t v) {
        std::vector<std::uint8_t> buf(64, 0);
        std::memcpy(buf.data(), "IDASGN", 6);
        buf[6] = v;
        return buf;
    };
    std::vector<std::uint8_t> wrong_magic(64, 0);
    wrong_magic[0] = 'X';
    // Drop 3 of the 5 name bytes
    auto cut_name = papa_tests::sig_header(10, /*ln_len=*/5);
    cut_name.resize(cut_name.size() - 3);
    struct Row {
        std::string_view          label;
        std::vector<std::uint8_t> buf;
        papa::ErrorKind           kind;
    };
    const std::vector<Row> rows{
        {"an empty buffer", {}, papa::ErrorKind::kFlirtTruncated},
        {"a wrong magic", wrong_magic, papa::ErrorKind::kFlirtBadMagic},
        {"version 0", with_version(0), papa::ErrorKind::kFlirtUnsupportedVersion},
        {"version 5", with_version(5), papa::ErrorKind::kFlirtUnsupportedVersion},
        {"version 7", with_version(7), papa::ErrorKind::kFlirtUnsupportedVersion},
        {"version 11", with_version(11), papa::ErrorKind::kFlirtUnsupportedVersion},
        {"version 255", with_version(255), papa::ErrorKind::kFlirtUnsupportedVersion},
        {"a truncated library name", cut_name, papa::ErrorKind::kFlirtTruncated},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = flirt::parse_header(row.buf);
        CHECK_FALSE(r.has_value());
        if (!r.has_value()) { CHECK(r.error().kind == row.kind); }
    }
}

TEST_CASE("flirt_reader: parse_header reads every field its version carries and leaves the later ones at their defaults") {
    struct Row {
        std::string_view label;
        std::uint8_t     version;
        std::uint8_t     ln_len;
        std::uint32_t    n_functions;
        std::uint16_t    pattern_size;
        std::string_view library_name;
        std::size_t      header_size;
    };
    const std::vector<Row> rows{
        {"a minimal v10 header", 10, 0, 0x0000002AU, 0x0020U, "", 45},
        {"a v9 header leaves the v10 pattern size at its default", 9, 0, 0x0000002AU, 0, "", 41},
        {"a v8 header leaves the v9 and v10 fields at their defaults", 8, 0, 0, 0, "", 37},
        {"a v10 header with a library name of 5 letters", 10, 5, 0x0000002AU, 0x0020U, "abcde",
         45},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = flirt::parse_header(papa_tests::sig_header(row.version, row.ln_len));
        REQUIRE(r.has_value());
        CHECK(r->version          == row.version);
        CHECK(r->arch             == flirt::FlirtArch::kX86);
        CHECK(r->file_types       == 0x00000002U);
        CHECK(r->os_types         == 0x0003U);
        CHECK(r->app_types        == 0x0004U);
        CHECK(r->features         == 0x0010U);
        CHECK(r->is_compressed());
        CHECK(r->old_n_functions  == 0x0007U);
        CHECK(r->pattern_crc16    == 0xABCDU);
        CHECK(r->library_name_len == row.ln_len);
        CHECK(r->ctypes_crc16     == 0x1234U);
        CHECK(r->n_functions      == row.n_functions);
        CHECK(r->pattern_size     == row.pattern_size);
        CHECK(r->library_name     == row.library_name);
        CHECK(flirt::header_size_for_version(row.version) == row.header_size);
    }
}

TEST_CASE("flirt_reader: read_vle16 and read_vle32 decode each length form and leave the cursor and value on a short read") {
    // The value a failed read must leave untouched
    constexpr std::uint32_t kUntouched = 0x5A5A5A5AU;
    struct Row {
        std::string_view          label;
        int                       width;
        std::vector<std::uint8_t> data;
        bool                      ok;
        std::uint32_t             value;
        std::size_t               consumed;
    };
    const std::vector<Row> rows{
        {"vle16 one-byte form", 16, {0x7F}, true, 0x7FU, 1},
        {"vle16 two-byte form", 16, {0x92, 0x34}, true, 0x1234U, 2},
        {"vle16 two-byte form reaches max value", 16, {0xFF, 0xFF}, true, 0x7FFFU, 2},
        {"vle16 truncated two-byte form fails cleanly", 16, {0x92}, false, kUntouched & 0xFFFFU, 0},
        {"vle16 empty buffer fails", 16, {}, false, kUntouched & 0xFFFFU, 0},
        {"vle32 one-byte form", 32, {0x7F}, true, 0x7FU, 1},
        {"vle32 two-byte form", 32, {0x81, 0x00}, true, 0x0100U, 2},
        {"vle32 four-byte masked form", 32, {0xC0, 0x00, 0x80, 0x00}, true, 0x8000U, 4},
        {"vle32 full five-byte form", 32, {0xFF, 0xDE, 0xAD, 0xBE, 0xEF}, true, 0xDEADBEEFU, 5},
        {"vle32 truncated four-byte form fails cleanly", 32, {0xC0, 0x00, 0x80}, false, kUntouched,
         0},
        {"vle32 truncated five-byte form fails cleanly", 32, {0xFF, 0xDE, 0xAD, 0xBE}, false,
         kUntouched, 0},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        flirt::detail::ByteCursor cur{row.data};
        bool          ok    = false;
        std::uint32_t value = 0;
        if (row.width == 16) {
            auto out = static_cast<std::uint16_t>(kUntouched);
            ok = cur.read_vle16(out);
            value = out;
        } else {
            std::uint32_t out = kUntouched;
            ok = cur.read_vle32(out);
            value = out;
        }
        CHECK(ok == row.ok);
        CHECK(value == row.value);
        CHECK(cur.offset() == row.consumed);
    }
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

TEST_CASE("flirt_reader: parse_sig_buffer rejects a cut body, an over-long pattern, a tree past the depth cap and a bad compressed body") {
    papa_tests::SigWriter one_module;
    one_module.vle16(1);
    const std::array<std::uint8_t, 3> pat{0x55, 0x8B, 0xEC};
    one_module.child_pattern(pat);
    one_module.vle16(0);  // leaf
    one_module.u8(0x08);
    one_module.u16_be(0x1234);
    one_module.module_body(0x10, "foo", 0x00);

    // kMaxPatternLength is 32, so a pattern length of 33 is one too many
    papa_tests::SigWriter long_pattern;
    long_pattern.vle16(1);
    long_pattern.vle16(33);
    long_pattern.vle16(0);  // empty variant mask
    long_pattern.buf.insert(long_pattern.buf.end(), 33, std::uint8_t{0x90});

    // A chain of nodes with one child each and an empty pattern, so a level is the two
    // bytes 0x01 0x00 and carries no mask or pattern bytes
    const auto chain = [](std::size_t levels) {
        std::vector<std::uint8_t> body;
        for (std::size_t i = 0; i < levels; ++i) {
            body.push_back(0x01);
            body.push_back(0x00);
        }
        return papa_tests::sig_with_body(body);
    };
    const auto cut = [](std::vector<std::uint8_t> sig, std::size_t drop) {
        sig.resize(sig.size() - drop);
        return sig;
    };
    // The header keeps its compressed bit, and the body is no zlib stream
    auto not_zlib = papa_tests::sig_header(10);
    not_zlib.insert(not_zlib.end(), {0x01, 0x02, 0x03});

    struct Row {
        std::string_view          label;
        std::vector<std::uint8_t> sig;
        papa::ErrorKind           kind;
    };
    const std::vector<Row> rows{
        // Dropping 2 bytes cuts the trailing flags and the last name byte
        {"a body cut short", cut(papa_tests::sig_with_body(one_module.buf), 2),
         papa::ErrorKind::kFlirtTruncated},
        {"a pattern longer than the cap is a bad node", papa_tests::sig_with_body(long_pattern.buf),
         papa::ErrorKind::kFlirtBadNode},
        {"a chain two levels past the depth cap", chain(flirt::kMaxTreeDepth + 2U),
         papa::ErrorKind::kFlirtTooDeep},
        {"a chain one level past the depth cap", chain(flirt::kMaxTreeDepth + 1U),
         papa::ErrorKind::kFlirtTooDeep},
        // Its last node sits at the cap and finds no child count to read
        {"a chain that reaches the depth cap is only cut short", chain(flirt::kMaxTreeDepth),
         papa::ErrorKind::kFlirtTruncated},
        {"a compressed body that is no zlib stream", not_zlib,
         papa::ErrorKind::kFlirtBadCompressedStream},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        const auto r = flirt::parse_sig_buffer(row.sig);
        CHECK_FALSE(r.has_value());
        if (!r.has_value()) { CHECK(r.error().kind == row.kind); }
    }
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
    rich_module(body, kTailAndRefs);

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

TEST_CASE("flirt_reader: every cut of a rich sig is truncated at versions 8, 9 and 10") {
    // Two root children. The first has a masked pattern over an internal node whose leaf
    // holds the rich module, one sharing its crc and a second crc group
    papa_tests::SigWriter body;
    body.vle16(2);
    const std::array<std::uint8_t, 2> masked{0x55, 0xEC};
    body.child_pattern_masked(3, 0x02, masked);
    body.vle16(1);  // internal, one child
    const std::array<std::uint8_t, 2> inner{0x8B, 0xEC};
    body.child_pattern(inner);
    body.vle16(0);  // leaf
    body.u8(0x08);
    body.u16_be(0x1234);
    rich_module(body, kTailAndRefs | 0x08);  // a module with the same crc follows
    body.module_body(0x18, "same", 0x10);    // then a second crc group
    body.u8(0x0C);
    body.u16_be(0xBBBB);
    body.module_body(0x20, "group", 0x00);
    // The second child is a plain leaf whose reference spells its name length as a vint
    const std::array<std::uint8_t, 1> plain{0x90};
    body.child_pattern(plain);
    body.vle16(0);  // leaf
    body.u8(0x04);
    body.u16_be(0xCCCC);
    body.vle16(0x10);  // function_size
    body.name_record(0, 0, "last", 0x04);
    body.vle16(1);     // one reference
    body.vle16(0x08);
    body.u8(0);        // the length follows as a vint
    body.vle16(3);
    for (const char c : std::string_view{"abc"}) {
        body.u8(static_cast<std::uint8_t>(c));
    }

    // Every value is below 0x80, so the same bytes read alike under each version's widths
    for (const std::uint8_t version : {std::uint8_t{8}, std::uint8_t{9}, std::uint8_t{10}}) {
        CAPTURE(static_cast<int>(version));
        const auto sig   = plain_sig(version, body.buf);
        const auto whole = flirt::parse_sig_buffer(sig);
        REQUIRE(whole.has_value());
        CHECK(whole->module_count() == 4U);
        REQUIRE(whole->root() != nullptr);
        CHECK(whole->root()->children.size() == 2U);

        const std::size_t header        = flirt::header_size_for_version(version);
        std::size_t       problem_count = 0;
        std::string       problems;
        for (std::size_t n = 0; n < sig.size(); ++n) {
            const auto r = flirt::parse_sig_buffer(std::span<const std::uint8_t>(sig.data(), n));
            std::string problem;
            if (r.has_value()) {
                problem = "parsed";
            } else if (r.error().kind != papa::ErrorKind::kFlirtTruncated &&
                       (n >= header || r.error().kind != papa::ErrorKind::kFlirtBadMagic)) {
                problem = "an unexpected error kind, " + r.error().detail;
            }
            // The first few problems name their prefix, and the rest are only counted
            if (!problem.empty() && ++problem_count <= 8U) {
                problems.append(std::to_string(n)).append(" bytes: ").append(problem).append("\n");
            }
        }
        CHECK(problems == "");
        CHECK(problem_count == 0U);
    }
}
