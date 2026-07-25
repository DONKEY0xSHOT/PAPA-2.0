#include "papa/render/spec.h"

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace papa::render {

namespace {

// Split "A::B::C [id]" into ({A, B, C}, id), faithful to capa's parse_parts_id.
// The trailing identifier is peeled off the last part at its final space
[[nodiscard]] std::pair<std::vector<std::string>, std::string>
parse_parts_id(const std::string& s) {
    std::vector<std::string> parts;
    std::size_t pos = 0;
    while (true) {
        const std::size_t sep = s.find("::", pos);
        if (sep == std::string::npos) {
            parts.push_back(s.substr(pos));
            break;
        }
        parts.push_back(s.substr(pos, sep - pos));
        pos = sep + 2;
    }

    std::string id;
    if (!parts.empty()) {
        const std::string last = parts.back();
        parts.pop_back();

        // rpartition on the final space: no space means an empty head and the
        // whole part as the identifier, matching Python's str.rpartition
        std::string head;
        std::string tail = last;
        if (const std::size_t sp = last.rfind(' '); sp != std::string::npos) {
            head = last.substr(0, sp);
            tail = last.substr(sp + 1);
        }

        const std::size_t a = tail.find_first_not_of('[');
        const std::size_t b = tail.find_last_not_of(']');
        id = (a == std::string::npos) ? std::string{} : tail.substr(a, b - a + 1);
        parts.push_back(head);
    }
    return {std::move(parts), std::move(id)};
}

[[nodiscard]] std::string part_at(const std::vector<std::string>& parts, std::size_t i) {
    return i < parts.size() ? parts[i] : std::string{};
}

}  // namespace

AttackSpec attack_from_string(const std::string& s) {
    auto [parts, id] = parse_parts_id(s);
    AttackSpec spec;
    spec.tactic       = part_at(parts, 0);
    spec.technique    = part_at(parts, 1);
    spec.subtechnique = part_at(parts, 2);
    spec.id           = std::move(id);
    spec.parts        = std::move(parts);
    return spec;
}

MbcSpec mbc_from_string(const std::string& s) {
    auto [parts, id] = parse_parts_id(s);
    MbcSpec spec;
    spec.objective = part_at(parts, 0);
    spec.behavior  = part_at(parts, 1);
    spec.method    = part_at(parts, 2);
    spec.id        = std::move(id);
    spec.parts     = std::move(parts);
    return spec;
}

}  // namespace papa::render
