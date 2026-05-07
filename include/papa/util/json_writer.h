#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace papa::util::json {

class Writer {
public:
    explicit Writer(std::ostream& out, bool pretty = false);

    // Container management
    // Each begin must be paired with the matching end on the same nesting level
    void begin_object();
    void end_object();
    void begin_array();
    void end_array();

    // Object key, must be followed by exactly one value or container
    void key(std::string_view k);

    // Scalars
    void value_string(std::string_view v);
    void value_int   (std::int64_t v);
    void value_uint  (std::uint64_t v);
    void value_double(double v);
    void value_bool  (bool v);
    void value_null();

private:
    enum class Context : std::uint8_t {
        kRoot,
        kObject,
        kArray,
    };

    void start_value();
    void emit_separator_for_value();
    void newline_and_indent();
    void emit_escaped_string(std::string_view s);

    std::ostream*           out_;
    bool                    pretty_;
    std::vector<Context>    stack_;
    bool                    need_comma_{false};   // true if next value needs a leading comma
    bool                    awaiting_value_{false};  // true after key(), suppresses comma
    int                     depth_{0};
};

}  // namespace papa::util::json
