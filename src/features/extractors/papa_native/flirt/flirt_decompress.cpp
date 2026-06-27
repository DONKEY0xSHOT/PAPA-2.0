#include "papa/features/extractors/papa_native/flirt/flirt_decompress.h"

#include "papa/features/extractors/papa_native/flirt/flirt_format.h"

#include "miniz.h"

#include <cstring>

namespace papa::features::extractors::papa_native::flirt {

namespace {

struct InflateSink {
    std::vector<std::uint8_t>* out;
    bool                       overflowed;
};

int put_buf_cb(const void* buf, int len, void* user) noexcept {
    auto* sink = static_cast<InflateSink*>(user);
    if (len < 0) {
        return 0;
    }
    const auto chunk = static_cast<std::size_t>(len);
    if (sink->out->size() + chunk > kMaxDecompressedSize) {
        sink->overflowed = true;
        return 0;
    }
    const auto prev = sink->out->size();
    sink->out->resize(prev + chunk);
    std::memcpy(sink->out->data() + prev, buf, chunk);
    return 1;
}

}  // namespace

Expected<std::vector<std::uint8_t>> decompress_inflate(
    std::span<const std::uint8_t> compressed) noexcept {
    if (compressed.empty()) {
        return Unexpected{make_error(
            ErrorKind::kFlirtBadCompressedStream, "empty input")};
    }

    std::vector<std::uint8_t> out;
    out.reserve(compressed.size() * 2U);
    InflateSink sink{&out, false};

    std::size_t in_size = compressed.size();
    const int flags = TINFL_FLAG_PARSE_ZLIB_HEADER;

    const auto status = tinfl_decompress_mem_to_callback(
        compressed.data(),
        &in_size,
        &put_buf_cb,
        &sink,
        flags);

    if (status == 0) {
        if (sink.overflowed) {
            return Unexpected{make_error(
                ErrorKind::kFlirtBadCompressedStream, "output exceeded size cap")};
        }
        return Unexpected{make_error(
            ErrorKind::kFlirtBadCompressedStream, "inflate failed")};
    }
    return out;
}

}  // namespace papa::features::extractors::papa_native::flirt
