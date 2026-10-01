#include <ostream>

#include "doctest.h"

#include "papa/util/json_writer.h"

#include "papa/exceptions.h"

#include <cmath>
#include <functional>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using papa::PapaInvariantError;
using papa::util::json::Writer;

TEST_CASE("json_writer: each document shape serializes to its exact compact or pretty text") {
    // The escaped form of a"b\c<newline>d<tab>e<SOH>, built by concatenation because a raw
    // string literal cannot hold the escapes and the quotes together
    std::string escaped;
    escaped.push_back('"');
    escaped.append("a");
    escaped.append("\\\"");      // JSON escape for quote
    escaped.append("b");
    escaped.append("\\\\");      // JSON escape for backslash
    escaped.append("c");
    escaped.append("\\n");       // JSON escape for newline
    escaped.append("d");
    escaped.append("\\t");       // JSON escape for tab
    escaped.append("e");
    escaped.append("\\u0001");   // JSON unicode escape for SOH
    escaped.push_back('"');

    struct Row {
        std::string_view               label;
        bool                           pretty;
        std::function<void(Writer& w)> build;
        std::string                    expected;
    };
    const std::vector<Row> rows{
        {"an empty object", false, [](Writer& w) { w.begin_object(); w.end_object(); }, "{}"},
        {"an empty array", false, [](Writer& w) { w.begin_array(); w.end_array(); }, "[]"},
        {"an object with mixed scalar values", false,
         [](Writer& w) {
             w.begin_object();
             w.key("name");      w.value_string("PAPA");
             w.key("version");   w.value_uint(1U);
             w.key("ready");     w.value_bool(true);
             w.key("missing");   w.value_null();
             w.key("count");     w.value_int(-7);
             w.end_object();
         },
         "{\"name\":\"PAPA\",\"version\":1,\"ready\":true,\"missing\":null,\"count\":-7}"},
        {"nested arrays and objects", false,
         [](Writer& w) {
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
         },
         R"({"items":[{"id":1},{"id":2}]})"},
        {"pretty mode indents each nested line", true,
         [](Writer& w) {
             w.begin_object();
             w.key("a"); w.value_uint(1U);
             w.key("b");
             w.begin_array();
             w.value_uint(2U);
             w.value_uint(3U);
             w.end_array();
             w.end_object();
         },
         "{\n"
         "  \"a\": 1,\n"
         "  \"b\": [\n"
         "    2,\n"
         "    3\n"
         "  ]\n"
         "}"},
        {"control bytes and quotes are escaped", false,
         [](Writer& w) { w.value_string("a\"b\\c\nd\te\x01"); }, escaped},
        {"NaN and infinity are emitted as null", false,
         [](Writer& w) {
             w.begin_array();
             w.value_double(std::numeric_limits<double>::quiet_NaN());
             w.value_double(std::numeric_limits<double>::infinity());
             w.value_double(-std::numeric_limits<double>::infinity());
             w.end_array();
         },
         "[null,null,null]"},
    };
    for (const Row& row : rows) {
        CAPTURE(row.label);
        std::ostringstream oss;
        Writer w(oss, row.pretty);
        row.build(w);
        CHECK(oss.str() == row.expected);
    }
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
