#include <ostream>

#include "doctest.h"

#include "papa/util/json_writer.h"

#include "papa/exceptions.h"

#include <cmath>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>

using papa::PapaInvariantError;
using papa::util::json::Writer;

namespace {

[[nodiscard]] std::string emit(auto&& fn, bool pretty = false) {
    std::ostringstream oss;
    Writer w(oss, pretty);
    fn(w);
    return oss.str();
}

}  // namespace

TEST_CASE("json_writer: empty object") {
    CHECK(emit([](Writer& w) {
        w.begin_object();
        w.end_object();
    }) == "{}");
}

TEST_CASE("json_writer: empty array") {
    CHECK(emit([](Writer& w) {
        w.begin_array();
        w.end_array();
    }) == "[]");
}

TEST_CASE("json_writer: object with mixed scalar values") {
    const auto out = emit([](Writer& w) {
        w.begin_object();
        w.key("name");      w.value_string("PAPA");
        w.key("version");   w.value_uint(1U);
        w.key("ready");     w.value_bool(true);
        w.key("missing");   w.value_null();
        w.key("count");     w.value_int(-7);
        w.end_object();
    });
    CHECK(out == "{\"name\":\"PAPA\",\"version\":1,\"ready\":true,\"missing\":null,\"count\":-7}");
}

TEST_CASE("json_writer: nested arrays and objects") {
    const auto out = emit([](Writer& w) {
        w.begin_object();
        w.key("items");
        w.begin_array();
        w.begin_object();
            w.key("id");
            w.value_uint(1U);
        w.end_object();
        w.begin_object();
            w.key("id");
            w.value_uint(2U);
        w.end_object();
        w.end_array();
        w.end_object();
    });
    CHECK(out == R"({"items":[{"id":1},{"id":2}]})");
}

TEST_CASE("json_writer: pretty mode produces newline-indented output") {
    const auto out = emit([](Writer& w) {
        w.begin_object();
        w.key("a"); w.value_uint(1U);
        w.key("b");
        w.begin_array();
        w.value_uint(2U);
        w.value_uint(3U);
        w.end_array();
        w.end_object();
    }, /*pretty=*/true);
    CHECK(out ==
        "{\n"
        "  \"a\": 1,\n"
        "  \"b\": [\n"
        "    2,\n"
        "    3\n"
        "  ]\n"
        "}");
}

TEST_CASE("json_writer: control bytes and quotes are escaped") {
    const auto out = emit([](Writer& w) {
        w.value_string("a\"b\\c\nd\te\x01");
    });
    // Build the expected JSON form via explicit char concatenation
    // The string contains literal backslashes followed by escape characters,
    // not the escape sequences themselves
    // Building it with std::string ops
    // sidesteps the multiple-level escaping headaches of nested string literals
    std::string expected;
    expected.push_back('"');
    expected.append("a");
    expected.append("\\\"");      // JSON escape for quote
    expected.append("b");
    expected.append("\\\\");      // JSON escape for backslash
    expected.append("c");
    expected.append("\\n");       // JSON escape for newline
    expected.append("d");
    expected.append("\\t");       // JSON escape for tab
    expected.append("e");
    expected.append("\\u0001");   // JSON unicode escape for SOH
    expected.push_back('"');
    CHECK(out == expected);
}

TEST_CASE("json_writer: NaN and infinity are emitted as null") {
    const auto out = emit([](Writer& w) {
        w.begin_array();
        w.value_double(std::numeric_limits<double>::quiet_NaN());
        w.value_double(std::numeric_limits<double>::infinity());
        w.value_double(-std::numeric_limits<double>::infinity());
        w.end_array();
    });
    CHECK(out == "[null,null,null]");
}

TEST_CASE("json_writer: protocol violations throw PapaInvariantError") {
    SUBCASE("two keys without an intervening value") {
        std::ostringstream oss;
        Writer w(oss);
        w.begin_object();
        w.key("a");
        CHECK_THROWS_AS(w.key("b"), PapaInvariantError);
    }
    SUBCASE("end_object inside an array") {
        std::ostringstream oss;
        Writer w(oss);
        w.begin_array();
        CHECK_THROWS_AS(w.end_object(), PapaInvariantError);
    }
    SUBCASE("value inside object without a preceding key") {
        std::ostringstream oss;
        Writer w(oss);
        w.begin_object();
        CHECK_THROWS_AS(w.value_uint(1U), PapaInvariantError);
    }
}
