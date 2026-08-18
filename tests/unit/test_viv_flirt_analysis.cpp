#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/viv/flirt_analysis.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;
namespace viv   = papa::features::extractors::papa_native::viv;

namespace {

// A scriptable FunctionContext standing in for the in-progress workspace
class MockContext : public flirt::FunctionContext {
public:
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> code;
    std::unordered_map<std::uint64_t, flirt::FlirtXref>          xrefs;
    std::unordered_set<std::uint64_t>                            functions;

    [[nodiscard]] std::span<const std::uint8_t>
    code_at(std::uint64_t va, std::size_t max_len) const override {
        const auto it = code.find(va);
        if (it == code.end()) {
            return {};
        }
        return std::span<const std::uint8_t>(
            it->second.data(), std::min(max_len, it->second.size()));
    }

    [[nodiscard]] std::optional<flirt::FlirtXref>
    xref_from(std::uint64_t site_va) const override {
        const auto it = xrefs.find(site_va);
        return it == xrefs.end() ? std::nullopt
                                 : std::optional<flirt::FlirtXref>{it->second};
    }

    [[nodiscard]] std::optional<std::string_view>
    import_name(std::uint64_t) const override {
        return std::nullopt;
    }

    [[nodiscard]] bool is_function_entry(std::uint64_t va) const override {
        return functions.count(va) != 0;
    }
};

// A matcher yielding the modules whose key byte leads the buffer
flirt::ModuleMatchFn byte_dispatch(
    std::unordered_map<std::uint8_t, std::vector<const flirt::FlirtModule*>> table) {
    return [table = std::move(table)](std::span<const std::uint8_t> b)
               -> std::vector<const flirt::FlirtModule*> {
        if (b.empty()) {
            return {};
        }
        const auto it = table.find(b[0]);
        return it == table.end() ? std::vector<const flirt::FlirtModule*>{}
                                 : it->second;
    };
}

flirt::FlirtModule public_module(std::string name) {
    flirt::FlirtModule m;
    m.names.push_back({0, std::move(name), flirt::FlirtNameType::kPublic});
    return m;
}

}  // namespace

TEST_CASE("flirt analysis: a local name creates its function and names it library") {
    MockContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0x11U, 0x00U, 0x00U};

    // The winner names itself at offset 0 and a local helper at 0x40. capa's local-
    // names loop makeFunctions the helper, so it becomes its own library function
    flirt::FlirtModule outer = public_module("outer");
    outer.names.push_back({0x40, "helper", flirt::FlirtNameType::kLocal});

    std::vector<std::uint64_t> made;
    viv::FlirtDiscoveryAnalyzer analyzer(
        {byte_dispatch({{0x11U, {&outer}}})}, ctx,
        [&made, &ctx](std::uint64_t va) {
            made.push_back(va);
            ctx.functions.insert(va);  // makeFunction completes it
        },
        [&ctx](std::uint64_t va) { return ctx.functions.count(va) != 0; });

    analyzer.on_function(0x1000U);

    REQUIRE(made.size() == 1);
    CHECK(made[0] == 0x1040U);
    const auto& names = analyzer.library_names();
    CHECK(names.at(0x1000U) == "outer");
    CHECK(names.at(0x1040U) == "helper");
}

TEST_CASE("flirt analysis: a public name never creates a function") {
    MockContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0x12U, 0x00U, 0x00U};

    // viv_utils.flirt only calls makeFunction in the local-names loop, so a public
    // sibling at an address that is not a function is left alone and carries no name
    flirt::FlirtModule outer = public_module("outer");
    outer.names.push_back({0x80, "pub_sibling", flirt::FlirtNameType::kPublic});

    std::vector<std::uint64_t> made;
    viv::FlirtDiscoveryAnalyzer analyzer(
        {byte_dispatch({{0x12U, {&outer}}})}, ctx,
        [&made](std::uint64_t va) { made.push_back(va); },
        [&ctx](std::uint64_t va) { return ctx.functions.count(va) != 0; });

    analyzer.on_function(0x1000U);

    CHECK(made.empty());
    CHECK(analyzer.library_names().count(0x1080U) == 0);
    CHECK(analyzer.library_names().at(0x1000U) == "outer");
}

TEST_CASE("flirt analysis: a function an earlier tree named is skipped by later trees") {
    MockContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0x13U, 0x00U, 0x00U};

    const flirt::FlirtModule first  = public_module("from_first_tree");
    const flirt::FlirtModule second = public_module("from_second_tree");

    int second_tree_calls = 0;
    // The second matcher records whether it was consulted at all
    const flirt::ModuleMatchFn counting =
        [&second_tree_calls, &second](std::span<const std::uint8_t>) {
            ++second_tree_calls;
            return std::vector<const flirt::FlirtModule*>{&second};
        };

    viv::FlirtDiscoveryAnalyzer analyzer(
        {byte_dispatch({{0x13U, {&first}}}), counting}, ctx,
        [](std::uint64_t) {},
        [&ctx](std::uint64_t va) { return ctx.functions.count(va) != 0; });

    analyzer.on_function(0x1000U);

    // The first tree named it, so the is_library_function short-circuit stops
    // the second tree from matching and renaming it
    CHECK(analyzer.library_names().at(0x1000U) == "from_first_tree");
    CHECK(second_tree_calls == 0);
}

TEST_CASE("flirt analysis: an unmatched function is named by a later tree") {
    MockContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0x14U, 0x00U, 0x00U};

    const flirt::FlirtModule second = public_module("from_second_tree");

    viv::FlirtDiscoveryAnalyzer analyzer(
        {byte_dispatch({{0x99U, {}}}), byte_dispatch({{0x14U, {&second}}})}, ctx,
        [](std::uint64_t) {},
        [&ctx](std::uint64_t va) { return ctx.functions.count(va) != 0; });

    analyzer.on_function(0x1000U);

    CHECK(analyzer.library_names().at(0x1000U) == "from_second_tree");
}
