#include <ostream>

#include "doctest.h"

#include "papa/util/hash.h"

#include "test_support.h"

#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using papa_tests::text_bytes;

TEST_CASE("hash: SHA-256 and SHA-1 NIST and MD5 RFC test vectors") {
    using Hex = std::string (*)(std::span<const std::byte>);
    const Hex sha256 = [](std::span<const std::byte> b) {
        return papa::util::hex_digest(papa::util::sha256(b));
    };
    const Hex sha1 = [](std::span<const std::byte> b) {
        return papa::util::hex_digest(papa::util::sha1(b));
    };
    const Hex md5 = [](std::span<const std::byte> b) {
        return papa::util::hex_digest(papa::util::md5(b));
    };
    constexpr std::string_view kTwoBlocks =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    struct Row {
        std::string_view label;
        Hex              hash;
        std::string_view input;
        std::string_view hex;
    };
    const std::vector<Row> rows{
        {"SHA-256 of nothing", sha256, "",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"SHA-256 of abc", sha256, "abc",
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"SHA-256 of two blocks", sha256, kTwoBlocks,
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"SHA-1 of nothing", sha1, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"SHA-1 of abc", sha1, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"SHA-1 of two blocks", sha1, kTwoBlocks, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {"MD5 of nothing", md5, "", "d41d8cd98f00b204e9800998ecf8427e"},
        {"MD5 of a", md5, "a", "0cc175b9c0f1b6a831c399e269772661"},
        {"MD5 of abc", md5, "abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"MD5 of message digest", md5, "message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"MD5 of the alphabet", md5, "abcdefghijklmnopqrstuvwxyz",
         "c3fcd3d76192e4007dfb496cca67e13b"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        CHECK(row.hash(text_bytes(row.input)) == row.hex);
    }
}

TEST_CASE("hash: SHA-256 streaming matches one-shot for chunked input") {
    using papa::util::Sha256;
    using papa::util::hex_digest;
    using papa::util::sha256;

    std::vector<std::byte> data(1024);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = std::byte{static_cast<std::uint8_t>((i * 31U) & 0xFFU)};
    }
    const auto one_shot = sha256(data);

    Sha256 h;
    // Feed in irregular chunk sizes to exercise the partial-buffer path
    constexpr std::size_t kChunks[] = {1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29};
    std::size_t off = 0;
    std::size_t i   = 0;
    while (off < data.size()) {
        const std::size_t want = kChunks[i % (sizeof(kChunks) / sizeof(kChunks[0]))];
        const std::size_t take = (off + want > data.size()) ? data.size() - off : want;
        h.update(std::span<const std::byte>(&data[off], take));
        off += take;
        ++i;
    }
    CHECK(hex_digest(h.finalize()) == hex_digest(one_shot));
}

TEST_CASE("hash: hex_digest produces fixed-width lowercase output") {
    const auto buf = papa_tests::bytes(0x00, 0xFF, 0xAB, 0x10);
    CHECK(papa::util::hex_digest(buf) == "00ffab10");
}
