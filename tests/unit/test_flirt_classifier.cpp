#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_classifier.h"
#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

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

namespace {

// A scriptable FunctionContext. The maps stand in for the recovered functions,
// their instruction xrefs, the import table, and the function-entry set, so the
// classifier can be exercised without any binary, CFG, or disassembler.
class MockContext : public flirt::FunctionContext {
public:
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> code;
    std::unordered_map<std::uint64_t, flirt::FlirtXref>          xrefs;
    std::unordered_map<std::uint64_t, std::string>              imports;
    std::unordered_set<std::uint64_t>                          functions;

    [[nodiscard]] std::span<const std::uint8_t>
    code_at(std::uint64_t va, std::size_t max_len) const override {
        const auto it = code.find(va);
        if (it == code.end()) {
            return {};
        }
        const std::size_t n = std::min(max_len, it->second.size());
        return std::span<const std::uint8_t>(it->second.data(), n);
    }

    [[nodiscard]] std::optional<flirt::FlirtXref>
    xref_from(std::uint64_t site_va) const override {
        const auto it = xrefs.find(site_va);
        if (it == xrefs.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] std::optional<std::string_view>
    import_name(std::uint64_t va) const override {
        const auto it = imports.find(va);
        if (it == imports.end()) {
            return std::nullopt;
        }
        return std::string_view(it->second);
    }

    [[nodiscard]] bool is_function_entry(std::uint64_t va) const override {
        return functions.find(va) != functions.end();
    }
};

// A module carrying one public symbol at offset 0.
flirt::FlirtModule public_module(std::string name) {
    flirt::FlirtModule m;
    m.names.push_back({0, std::move(name), flirt::FlirtNameType::kPublic});
    return m;
}

// A module carrying one local symbol at offset 0, as a statically linked
// library helper does.
flirt::FlirtModule local_module(std::string name) {
    flirt::FlirtModule m;
    m.names.push_back({0, std::move(name), flirt::FlirtNameType::kLocal});
    return m;
}

// Returns a matcher that yields the modules whose key byte leads the buffer.
flirt::ModuleMatchFn
byte_dispatch(std::unordered_map<std::uint8_t, std::vector<const flirt::FlirtModule*>> table) {
    return [table = std::move(table)](std::span<const std::uint8_t> b)
               -> std::vector<const flirt::FlirtModule*> {
        if (b.empty()) {
            return {};
        }
        const auto it = table.find(b[0]);
        return it == table.end() ? std::vector<const flirt::FlirtModule*>{} : it->second;
    };
}

}  // namespace

TEST_CASE("flirt_classifier: a reference-free match marks the function library") {
    MockContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0xDDU, 0x00U, 0x00U};

    const flirt::FlirtModule plain = public_module("plain");
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xDDU, {&plain}}}), ctx, cache);

    const auto name = classifier.classify(0x1000U);
    REQUIRE(name.has_value());
    CHECK(*name == "plain");
}

TEST_CASE("flirt_classifier: a local name at offset zero still names the function") {
    MockContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0xDDU, 0x00U, 0x00U};

    // A statically linked helper (e.g. _check_managed_app) carries only a local
    // name at offset 0. viv_utils.flirt.get_match_name takes the offset-0 name
    // regardless of kind, so the function is still a library match.
    const flirt::FlirtModule helper = local_module("_check_managed_app");
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xDDU, {&helper}}}), ctx, cache);

    const auto name = classifier.classify(0x1000U);
    REQUIRE(name.has_value());
    CHECK(*name == "_check_managed_app");
}

TEST_CASE("flirt_classifier: a name only at a non-zero offset names nothing") {
    MockContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0xDEU, 0x00U, 0x00U};

    // No name sits at offset 0, so get_match_name yields nothing and the match
    // confers no identity. A name only at a non-zero offset is a sibling marker,
    // not this function's name.
    flirt::FlirtModule m;
    m.names.push_back({0x40, "sibling", flirt::FlirtNameType::kPublic});
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xDEU, {&m}}}), ctx, cache);

    CHECK_FALSE(classifier.classify(0x1000U).has_value());
}

TEST_CASE("flirt_classifier: a reference to an import is rejected") {
    MockContext ctx;
    ctx.functions.insert(0x2000U);
    ctx.code[0x2000U] = {0xAAU, 0x00U, 0x00U};
    ctx.xrefs[0x2010U] = {0x9000U, /*is_code=*/true};
    ctx.imports[0x9000U] = "malloc";

    flirt::FlirtModule foo = public_module("foo");
    foo.references.push_back({0x10U, "malloc"});
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xAAU, {&foo}}}), ctx, cache);

    // capa satisfies a named reference only via a local matched library function,
    // not an import, so a candidate whose only reference resolves to an imported
    // API is rejected (this is why ___crtTlsAlloc@4 does not match).
    CHECK_FALSE(classifier.classify(0x2000U).has_value());
}

TEST_CASE("flirt_classifier: an unsatisfied reference rejects the match") {
    MockContext ctx;
    ctx.functions.insert(0x2000U);
    ctx.code[0x2000U] = {0xAAU, 0x00U, 0x00U};
    ctx.xrefs[0x2010U] = {0x9000U, /*is_code=*/true};
    ctx.imports[0x9000U] = "free";  // the reference names "malloc", not "free"

    flirt::FlirtModule foo = public_module("foo");
    foo.references.push_back({0x10U, "malloc"});
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xAAU, {&foo}}}), ctx, cache);

    CHECK_FALSE(classifier.classify(0x2000U).has_value());
}

TEST_CASE("flirt_classifier: a reference resolved by recursion is accepted") {
    MockContext ctx;
    ctx.functions.insert(0x2000U);
    ctx.functions.insert(0x3000U);
    ctx.code[0x2000U] = {0xAAU, 0x00U, 0x00U};  // foo, references malloc
    ctx.code[0x3000U] = {0xBBU, 0x00U, 0x00U};  // malloc, no references
    ctx.xrefs[0x2010U] = {0x3000U, /*is_code=*/true};  // target is a function, not an import

    flirt::FlirtModule foo = public_module("foo");
    foo.references.push_back({0x10U, "malloc"});
    const flirt::FlirtModule malloc_mod = public_module("malloc");
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(
        byte_dispatch({{0xAAU, {&foo}}, {0xBBU, {&malloc_mod}}}), ctx, cache);

    const auto name = classifier.classify(0x2000U);
    REQUIRE(name.has_value());
    CHECK(*name == "foo");
}

TEST_CASE("flirt_classifier: a data reference requires a data xref") {
    flirt::FlirtModule mod = public_module("d");
    mod.references.push_back({0x08U, "."});

    // A data xref satisfies the "." reference.
    {
        MockContext ctx;
        ctx.functions.insert(0x6000U);
        ctx.code[0x6000U] = {0xEEU, 0x00U, 0x00U};
        ctx.xrefs[0x6008U] = {0x7000U, /*is_code=*/false};
        flirt::FlirtClassifier::Cache cache;
        const flirt::FlirtClassifier classifier(byte_dispatch({{0xEEU, {&mod}}}), ctx, cache);
        const auto name = classifier.classify(0x6000U);
        REQUIRE(name.has_value());
        CHECK(*name == "d");
    }

    // A code xref does not satisfy a "." data reference.
    {
        MockContext ctx;
        ctx.functions.insert(0x6000U);
        ctx.code[0x6000U] = {0xEEU, 0x00U, 0x00U};
        ctx.xrefs[0x6008U] = {0x7000U, /*is_code=*/true};
        flirt::FlirtClassifier::Cache cache;
        const flirt::FlirtClassifier classifier(byte_dispatch({{0xEEU, {&mod}}}), ctx, cache);
        CHECK_FALSE(classifier.classify(0x6000U).has_value());
    }
}

TEST_CASE("flirt_classifier: candidates with conflicting names are ambiguous") {
    MockContext ctx;
    ctx.functions.insert(0x4000U);
    ctx.code[0x4000U] = {0xCCU, 0x00U, 0x00U};

    const flirt::FlirtModule foo = public_module("foo");
    const flirt::FlirtModule bar = public_module("bar");
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xCCU, {&foo, &bar}}}), ctx, cache);

    CHECK_FALSE(classifier.classify(0x4000U).has_value());
}

TEST_CASE("flirt_classifier: names at non-zero offsets mark sibling functions library") {
    MockContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0x11U, 0x00U, 0x00U};

    // A module that names itself at offset 0 and a sibling at offset 0x40.
    flirt::FlirtModule outer = public_module("outer");
    outer.names.push_back({0x40, "inner", flirt::FlirtNameType::kPublic});

    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0x11U, {&outer}}}), ctx, cache);

    REQUIRE(classifier.classify(0x1000U).has_value());
    // The name at offset 0x40 marks 0x1040 as the library function "inner".
    const auto it = cache.find(0x1040U);
    REQUIRE(it != cache.end());
    REQUIRE(it->second.has_value());
    CHECK(*it->second == "inner");
}

TEST_CASE("flirt_classifier: a virtual address that is not a function is never library") {
    MockContext ctx;  // empty: 0x5000 is not a function entry
    const flirt::FlirtModule foo = public_module("foo");
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0x00U, {&foo}}}), ctx, cache);
    CHECK_FALSE(classifier.classify(0x5000U).has_value());
}
