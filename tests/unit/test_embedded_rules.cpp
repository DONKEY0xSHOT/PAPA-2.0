#include <ostream>

#include "doctest.h"

#include "papa/rules/embedded.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"
#include "papa/rules/scope.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

using papa::rules::embedded_rules;
using papa::rules::RuleSet;
using papa::rules::Scope;

namespace {

constexpr std::array kAllScopes{
    Scope::kFile,   Scope::kFunction, Scope::kBasicBlock,  Scope::kInstruction,
    Scope::kGlobal, Scope::kProcess,  Scope::kThread,      Scope::kCall,
    Scope::kSpanOfCalls,
};

std::vector<std::string> sorted_names(const RuleSet& rs) {
    std::vector<std::string> out;
    for (const auto& rule : rs.all_rules()) { out.push_back(rule->name()); }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> topo_names(const RuleSet& rs, Scope scope) {
    std::vector<std::string> out;
    for (const auto* rule : rs.rules_by_scope(scope)) { out.push_back(rule->name()); }
    return out;
}

// The vendored corpus, relative to the repository root the tests run from
const fs::path kRulesDir = "third_party/capa-rules";

bool has_hidden_component(std::string_view path) {
    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t end = std::min(path.find('/', start), path.size());
        if (end > start && path[start] == '.') { return true; }
        start = end + 1;
    }
    return false;
}

// Forward-slash UTF-8 path, built from u8 so MSVC never converts to the ANSI code page
std::string relative_utf8(const fs::path& p) {
    std::string out;
    for (const char8_t c : p.lexically_relative(kRulesDir).generic_u8string()) {
        out.push_back(static_cast<char>(c));
    }
    return out;
}

std::string read_bytes(const fs::path& p) {
    std::string out(static_cast<std::size_t>(fs::file_size(p)), '\0');
    std::ifstream in(p, std::ios::binary);
    in.read(out.data(), static_cast<std::streamsize>(out.size()));
    return out;
}

// Every .yml file on disk keyed by relative path, skipping hidden entries like the loader
std::map<std::string, fs::path> rules_on_disk() {
    std::map<std::string, fs::path> out;
    for (auto it = fs::recursive_directory_iterator(kRulesDir);
         it != fs::recursive_directory_iterator(); ++it) {
        if (it->path().filename().generic_u8string().starts_with(u8".")) {
            if (it->is_directory()) { it.disable_recursion_pending(); }
            continue;
        }
        if (it->is_regular_file() && it->path().extension() == ".yml") {
            out.emplace(relative_utf8(it->path()), it->path());
        }
    }
    return out;
}

}  // namespace

TEST_CASE("embedded_rules: the table is non-empty and strictly sorted by path") {
    const auto rules = embedded_rules();
    REQUIRE_FALSE(rules.empty());
    for (std::size_t i = 1; i < rules.size(); ++i) {
        CHECK(rules[i - 1].path < rules[i].path);
    }
}

TEST_CASE("embedded_rules: every path is a .yml file with no hidden component") {
    for (const auto& rule : embedded_rules()) {
        CHECK(rule.path.ends_with(".yml"));
        CHECK_FALSE(has_hidden_component(rule.path));
    }
}

TEST_CASE("embedded_rules: the table matches the vendored files byte for byte") {
    REQUIRE_MESSAGE(fs::is_directory(kRulesDir),
        "third_party/capa-rules not found, run the tests from the repository root");
    const auto on_disk = rules_on_disk();
    CHECK(embedded_rules().size() == on_disk.size());
    for (const auto& rule : embedded_rules()) {
        const auto it = on_disk.find(std::string(rule.path));
        REQUIRE_MESSAGE(it != on_disk.end(), "not on disk: ", rule.path);
        CHECK_MESSAGE(rule.text == read_bytes(it->second), "differs from disk: ", rule.path);
    }
}

TEST_CASE("embedded_rules: RuleSet::from_embedded loads the same rules as the vendored files") {
    REQUIRE_MESSAGE(fs::is_directory(kRulesDir),
        "third_party/capa-rules not found, run the tests from the repository root");
    const auto embedded = RuleSet::from_embedded();
    const auto on_disk  = RuleSet::from_directory(kRulesDir);
    REQUIRE(embedded);
    REQUIRE(on_disk);
    CHECK(embedded->size() == on_disk->size());
    CHECK(sorted_names(*embedded) == sorted_names(*on_disk));
    for (const Scope scope : kAllScopes) {
        CHECK_MESSAGE(topo_names(*embedded, scope) == topo_names(*on_disk, scope),
                      "topological order differs at scope ", to_string(scope));
    }
}
