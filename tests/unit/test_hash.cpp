#include <ostream>

#include "doctest.h"

#include "papa/util/hash.h"

#include <array>
#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

// View a string literal as a span<const std::byte> for hashing input
[[nodiscard]] std::span<const std::byte> bytes_of(std::string_view s) noexcept {
    return std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(s.data()), s.size());
}

}  // namespace

TEST_CASE("hash: SHA-256 NIST test vectors") {
    using papa::util::hex_digest;
    using papa::util::sha256;

    CHECK(hex_digest(sha256(bytes_of(""))) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hex_digest(sha256(bytes_of("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(hex_digest(sha256(bytes_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
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

TEST_CASE("hash: SHA-1 NIST test vectors") {
    using papa::util::hex_digest;
    using papa::util::sha1;

    CHECK(hex_digest(sha1(bytes_of(""))) ==
          "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    CHECK(hex_digest(sha1(bytes_of("abc"))) ==
          "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(hex_digest(sha1(bytes_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
          "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

TEST_CASE("hash: MD5 RFC test vectors") {
    using papa::util::hex_digest;
    using papa::util::md5;

    CHECK(hex_digest(md5(bytes_of(""))) ==
          "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(hex_digest(md5(bytes_of("a"))) ==
          "0cc175b9c0f1b6a831c399e269772661");
    CHECK(hex_digest(md5(bytes_of("abc"))) ==
          "900150983cd24fb0d6963f7d28e17f72");
    CHECK(hex_digest(md5(bytes_of("message digest"))) ==
          "f96b697d7cb7938d525a2f31aaf161d0");
    CHECK(hex_digest(md5(bytes_of("abcdefghijklmnopqrstuvwxyz"))) ==
          "c3fcd3d76192e4007dfb496cca67e13b");
}

TEST_CASE("hash: hex_digest produces fixed-width lowercase output") {
    std::array<std::byte, 4> buf{
        std::byte{0x00}, std::byte{0xFF},
        std::byte{0xAB}, std::byte{0x10}
    };
    CHECK(papa::util::hex_digest(buf) == "00ffab10");
}
