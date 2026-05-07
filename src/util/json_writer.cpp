#include "papa/util/json_writer.h"

#include "papa/exceptions.h"

#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <system_error>

namespace papa::util::json {

namespace {

constexpr int kIndentSpaces = 2;

[[noreturn]] void invariant_violation(const char* msg) {
    throw ::papa::PapaInvariantError(std::string{"json::Writer: "}.append(msg));
}

}  // namespace

Writer::Writer(std::ostream& out, bool pretty)
    : out_(&out), pretty_(pretty) {
    stack_.reserve(8);
    stack_.push_back(Context::kRoot);
}

void Writer::newline_and_indent() {
    if (!pretty_) { return; }
    out_->put('\n');
    for (int i = 0; i < depth_ * kIndentSpaces; ++i) { out_->put(' '); }
}

void Writer::emit_separator_for_value() {
    // The value about to be written follows either:
    //   - the start of a container (no separator)
    //   - a key inside an object (already emitted ":" and optional space)
    //   - a previous value or container in the same parent (need ",")
    // awaiting_value_ short-circuits the comma path because key() handles its own separator
    if (awaiting_value_) {
        awaiting_value_ = false;
        return;
    }
    if (need_comma_) {
        out_->put(',');
        newline_and_indent();
    } else if (stack_.back() != Context::kRoot) {
        // First element in a container: indent only, no comma
        newline_and_indent();
    }
}

void Writer::start_value() {
    // Validate: a value at root level can only appear once
    // For object context the previous emission must be a key (awaiting_value_ true)
    if (stack_.back() == Context::kObject && !awaiting_value_) {
        invariant_violation("expected key before value inside object");
    }
    emit_separator_for_value();
}

void Writer::begin_object() {
    start_value();
    out_->put('{');
    stack_.push_back(Context::kObject);
    ++depth_;
    need_comma_ = false;
}

void Writer::end_object() {
    if (stack_.size() < 2 || stack_.back() != Context::kObject) {
        invariant_violation("end_object without matching begin_object");
    }
    if (awaiting_value_) {
        invariant_violation("end_object after key with no value");
    }
    --depth_;
    // Add trailing newline+indent only when the object had content
    if (need_comma_ && pretty_) { newline_and_indent(); }
    out_->put('}');
    stack_.pop_back();
    need_comma_ = true;
}

void Writer::begin_array() {
    start_value();
    out_->put('[');
    stack_.push_back(Context::kArray);
    ++depth_;
    need_comma_ = false;
}

void Writer::end_array() {
    if (stack_.size() < 2 || stack_.back() != Context::kArray) {
        invariant_violation("end_array without matching begin_array");
    }
    --depth_;
    if (need_comma_ && pretty_) { newline_and_indent(); }
    out_->put(']');
    stack_.pop_back();
    need_comma_ = true;
}

void Writer::key(std::string_view k) {
    if (stack_.back() != Context::kObject) {
        invariant_violation("key emitted outside an object");
    }
    if (awaiting_value_) {
        invariant_violation("two consecutive keys without an intervening value");
    }
    if (need_comma_) {
        out_->put(',');
        newline_and_indent();
    } else {
        // First key in object: just indent
        newline_and_indent();
    }
    emit_escaped_string(k);
    out_->put(':');
    if (pretty_) { out_->put(' '); }
    awaiting_value_ = true;
}

void Writer::value_string(std::string_view v) {
    start_value();
    emit_escaped_string(v);
    need_comma_ = true;
}

void Writer::value_int(std::int64_t v) {
    start_value();
    std::array<char, 32> buf{};
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), v);
    if (ec != std::errc{}) {
        invariant_violation("value_int formatting failed");
    }
    out_->write(buf.data(), ptr - buf.data());
    need_comma_ = true;
}

void Writer::value_uint(std::uint64_t v) {
    start_value();
    std::array<char, 32> buf{};
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), v);
    if (ec != std::errc{}) {
        invariant_violation("value_uint formatting failed");
    }
    out_->write(buf.data(), ptr - buf.data());
    need_comma_ = true;
}

void Writer::value_double(double v) {
    start_value();
    if (!std::isfinite(v)) {
        // JSON has no representation for NaN or +/-inf
        // Emit null and let the reader treat it as "no value"
        // This matches CAPA's behavior on degenerate inputs
        out_->write("null", 4);
        need_comma_ = true;
        return;
    }
    std::array<char, 64> buf{};
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), v);
    if (ec != std::errc{}) {
        invariant_violation("value_double formatting failed");
    }
    out_->write(buf.data(), ptr - buf.data());
    need_comma_ = true;
}

void Writer::value_bool(bool v) {
    start_value();
    if (v) { out_->write("true", 4); }
    else   { out_->write("false", 5); }
    need_comma_ = true;
}

void Writer::value_null() {
    start_value();
    out_->write("null", 4);
    need_comma_ = true;
}

void Writer::emit_escaped_string(std::string_view s) {
    static constexpr char kHex[] = "0123456789abcdef";
    out_->put('"');
    for (char c : s) {
        const auto u = static_cast<std::uint8_t>(c);
        switch (c) {
            case '"':  out_->write("\\\"", 2); break;
            case '\\': out_->write("\\\\", 2); break;
            case '\b': out_->write("\\b",  2); break;
            case '\f': out_->write("\\f",  2); break;
            case '\n': out_->write("\\n",  2); break;
            case '\r': out_->write("\\r",  2); break;
            case '\t': out_->write("\\t",  2); break;
            default:
                if (u < 0x20U) {
                    // Mandatory \u00XX escape for control bytes
                    char esc[6] = {'\\', 'u', '0', '0', kHex[(u >> 4) & 0xFU], kHex[u & 0xFU]};
                    out_->write(esc, 6);
                } else {
                    // Pass UTF-8 bytes through unchanged
                    // CAPA feature values are already UTF-8 by construction
                    out_->put(c);
                }
                break;
        }
    }
    out_->put('"');
}

}  // namespace papa::util::json
