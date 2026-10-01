#include <ostream>

#include "doctest.h"

#include "papa/features/extractors/papa_native/flirt/flirt_classifier.h"
#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"

#include "test_support.h"

#include <cstdint>
#include <string>
#include <vector>

namespace flirt = papa::features::extractors::papa_native::flirt;

using papa_tests::byte_dispatch;
using papa_tests::MockFlirtContext;
using papa_tests::public_module;

namespace {

// A module carrying one local symbol at offset 0, as a statically linked
// library helper does
flirt::FlirtModule local_module(std::string name) {
    flirt::FlirtModule m;
    m.names.push_back({0, std::move(name), flirt::FlirtNameType::kLocal});
    return m;
}

}  // namespace

TEST_CASE("flirt_classifier: a reference-free match marks the function library") {
    MockFlirtContext ctx;
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
    MockFlirtContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0xDDU, 0x00U, 0x00U};

    // A statically linked helper (e.g. _check_managed_app) carries only a local name at
    // offset 0
    const flirt::FlirtModule helper = local_module("_check_managed_app");
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xDDU, {&helper}}}), ctx, cache);

    const auto name = classifier.classify(0x1000U);
    REQUIRE(name.has_value());
    CHECK(*name == "_check_managed_app");
}

TEST_CASE("flirt_classifier: a name only at a non-zero offset names nothing") {
    MockFlirtContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0xDEU, 0x00U, 0x00U};

    // No name sits at offset 0, so get_match_name yields nothing and the match confers
    // no identity
    flirt::FlirtModule m;
    m.names.push_back({0x40, "sibling", flirt::FlirtNameType::kPublic});
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xDEU, {&m}}}), ctx, cache);

    CHECK_FALSE(classifier.classify(0x1000U).has_value());
}

TEST_CASE("flirt_classifier: a reference to an import is rejected") {
    MockFlirtContext ctx;
    ctx.functions.insert(0x2000U);
    ctx.code[0x2000U] = {0xAAU, 0x00U, 0x00U};
    ctx.xrefs[0x2010U] = {0x9000U, /*is_code=*/true};
    ctx.imports[0x9000U] = "malloc";

    flirt::FlirtModule foo = public_module("foo");
    foo.references.push_back({0x10U, "malloc"});
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xAAU, {&foo}}}), ctx, cache);

    // capa satisfies a named reference only via a local matched library function, not
    // an import, so a candidate whose only reference resolves to an imported
    CHECK_FALSE(classifier.classify(0x2000U).has_value());
}

TEST_CASE("flirt_classifier: an unsatisfied reference rejects the match") {
    MockFlirtContext ctx;
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
    MockFlirtContext ctx;
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

    // A data xref satisfies the "." reference
    {
        MockFlirtContext ctx;
        ctx.functions.insert(0x6000U);
        ctx.code[0x6000U] = {0xEEU, 0x00U, 0x00U};
        ctx.xrefs[0x6008U] = {0x7000U, /*is_code=*/false};
        flirt::FlirtClassifier::Cache cache;
        const flirt::FlirtClassifier classifier(byte_dispatch({{0xEEU, {&mod}}}), ctx, cache);
        const auto name = classifier.classify(0x6000U);
        REQUIRE(name.has_value());
        CHECK(*name == "d");
    }

    // A code xref does not satisfy a "." data reference
    {
        MockFlirtContext ctx;
        ctx.functions.insert(0x6000U);
        ctx.code[0x6000U] = {0xEEU, 0x00U, 0x00U};
        ctx.xrefs[0x6008U] = {0x7000U, /*is_code=*/true};
        flirt::FlirtClassifier::Cache cache;
        const flirt::FlirtClassifier classifier(byte_dispatch({{0xEEU, {&mod}}}), ctx, cache);
        CHECK_FALSE(classifier.classify(0x6000U).has_value());
    }
}

TEST_CASE("flirt_classifier: candidates with conflicting names are ambiguous") {
    MockFlirtContext ctx;
    ctx.functions.insert(0x4000U);
    ctx.code[0x4000U] = {0xCCU, 0x00U, 0x00U};

    const flirt::FlirtModule foo = public_module("foo");
    const flirt::FlirtModule bar = public_module("bar");
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0xCCU, {&foo, &bar}}}), ctx, cache);

    CHECK_FALSE(classifier.classify(0x4000U).has_value());
}

TEST_CASE("flirt_classifier: names at non-zero offsets mark sibling functions library") {
    MockFlirtContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0x11U, 0x00U, 0x00U};

    // A module that names itself at offset 0 and a sibling at offset 0x40
    flirt::FlirtModule outer = public_module("outer");
    outer.names.push_back({0x40, "inner", flirt::FlirtNameType::kPublic});

    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0x11U, {&outer}}}), ctx, cache);

    REQUIRE(classifier.classify(0x1000U).has_value());
    // The name at offset 0x40 marks 0x1040 as the library function "inner"
    const auto it = cache.find(0x1040U);
    REQUIRE(it != cache.end());
    REQUIRE(it->second.has_value());
    CHECK(*it->second == "inner");
}

TEST_CASE("flirt_classifier: an accepted match reports the winning module") {
    MockFlirtContext ctx;
    ctx.functions.insert(0x1000U);
    ctx.code[0x1000U] = {0x22U, 0x00U, 0x00U};

    // A module that names itself at offset 0 and carries a local and a public sibling
    flirt::FlirtModule outer = public_module("outer");
    outer.names.push_back({0x40, "inner_local", flirt::FlirtNameType::kLocal});
    outer.names.push_back({0x80, "inner_public", flirt::FlirtNameType::kPublic});

    std::vector<std::uint64_t>            match_vas;
    std::vector<const flirt::FlirtModule*> winners;
    const auto on_match = [&](std::uint64_t va, const flirt::FlirtModule& w) {
        match_vas.push_back(va);
        winners.push_back(&w);
    };

    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier  classifier(byte_dispatch({{0x22U, {&outer}}}), ctx,
                                             cache, on_match);

    REQUIRE(classifier.classify(0x1000U).has_value());
    REQUIRE(match_vas.size() == 1);
    CHECK(match_vas[0] == 0x1000U);
    REQUIRE(winners.size() == 1);
    CHECK(winners[0] == &outer);
    CHECK(winners[0]->names.size() == 3U);
}

TEST_CASE("flirt_classifier: a rejected candidate reports no match") {
    MockFlirtContext ctx;
    ctx.functions.insert(0x2000U);
    ctx.code[0x2000U] = {0xAAU, 0x00U, 0x00U};
    ctx.xrefs[0x2010U] = {0x9000U, /*is_code=*/true};  // resolves to nothing named

    flirt::FlirtModule foo = public_module("foo");
    foo.references.push_back({0x10U, "malloc"});

    bool       fired = false;
    const auto on_match = [&fired](std::uint64_t, const flirt::FlirtModule&) {
        fired = true;
    };

    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier  classifier(byte_dispatch({{0xAAU, {&foo}}}), ctx,
                                             cache, on_match);

    CHECK_FALSE(classifier.classify(0x2000U).has_value());
    CHECK_FALSE(fired);
}

TEST_CASE("flirt_classifier: a virtual address that is not a function is never library") {
    MockFlirtContext ctx;  // empty: 0x5000 is not a function entry
    const flirt::FlirtModule foo = public_module("foo");
    flirt::FlirtClassifier::Cache cache;
    const flirt::FlirtClassifier classifier(byte_dispatch({{0x00U, {&foo}}}), ctx, cache);
    CHECK_FALSE(classifier.classify(0x5000U).has_value());
}
