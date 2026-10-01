#include <ostream>

#include "doctest.h"

#include "papa/capabilities/static_.h"
#include "papa/features/address.h"
#include "papa/features/insn.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/extractor.h"
#include "papa/loader.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"
#include "papa/render/json.h"
#include "papa/render/result_document.h"
#include "papa/render/text.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"
#include "papa/version.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>
#include "fixture_paths.h"
#include "pe_builder.h"
#include "test_support.h"

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");

}  // namespace

TEST_CASE("render: build_document filters synthetic subscope rules") {
    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: parent-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - basic block:\n"
        "      - characteristic: tight loop\n"
    });

    // Forge a MatchResults that contains both the parent and the synthetic
    papa::engine::MatchResults matches;
    for (const auto& r : rs.all_rules()) {
        matches[r->name()].emplace_back(
            papa::features::Address{papa::features::AbsoluteVirtualAddress{0x1000}},
            papa::engine::Result{});
    }

    papa::Metadata meta;
    auto doc = papa::render::build_document(std::move(meta), rs, matches);
    CHECK(doc.rules.count("parent-rule") == 1);
    // Every synthetic rule has the parent's name as a "/N" prefix
    for (const auto& [name, _rep] : doc.rules) {
        CHECK(name.find('/') == std::string::npos);
    }
}

TEST_CASE("render: JSON output is well-formed for an empty match result") {
    papa::Metadata meta;
    meta.version = "9.4.0";
    meta.argv    = {"papa.exe", "sample.exe"};
    meta.timestamp = "2026-05-02T00:00:00Z";
    meta.sample_path = "sample.exe";
    meta.sample_size_bytes = 12U;
    meta.hashes.md5    = "00000000000000000000000000000000";
    meta.hashes.sha1   = "0000000000000000000000000000000000000000";
    meta.hashes.sha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    meta.analysis.os = "windows";
    meta.analysis.arch = "amd64";
    meta.analysis.format = "pe";
    meta.analysis.extractor = "papa_native";

    papa::render::ResultDocument doc;
    doc.meta = std::move(meta);
    const auto out = papa::render::json::render_to_string(doc, /*pretty=*/false);
    // Spot check: starts with object brace, contains the version, ends in brace
    CHECK(out.front() == '{');
    CHECK(out.back()  == '}');
    CHECK(out.find("\"version\":\"9.4.0\"") != std::string::npos);
    CHECK(out.find("\"rules\":{}")          != std::string::npos);
}

TEST_CASE("render: text default lists capabilities in capa's table format") {
    papa::Metadata meta;
    meta.version = "9.4.0";
    meta.sample_path = "x.exe";
    meta.sample_size_bytes = 0U;
    meta.hashes.md5 = meta.hashes.sha1 = meta.hashes.sha256 = "0";
    meta.analysis.os = "windows";
    meta.analysis.arch = "amd64";
    meta.analysis.format = "pe";

    papa::render::ResultDocument doc;
    doc.meta = std::move(meta);

    papa::render::RuleReport rep;
    rep.meta.name = "decode-base64";
    rep.meta.namespace_ = "data-manipulation/encoding/base64";
    rep.addresses.push_back(papa::features::Address{
        papa::features::AbsoluteVirtualAddress{0x401000U}});
    rep.match_count = 1;
    doc.rules.emplace("decode-base64", std::move(rep));

    const auto out = papa::render::text::render_to_string(
        doc, papa::render::text::Verbosity::kDefault);
    CHECK(out.find("decode-base64") != std::string::npos);
    CHECK(out.find("data-manipulation/encoding/base64") != std::string::npos);
    // capa shows the bare rule name for a single match, with no count suffix
    CHECK(out.find("matches)") == std::string::npos);
    CHECK(out.find("[1 match]") == std::string::npos);
    // The capabilities and meta tables carry capa's column and field labels
    CHECK(out.find("Capability") != std::string::npos);
    CHECK(out.find("Namespace") != std::string::npos);
    CHECK(out.find("analysis") != std::string::npos);
}

TEST_CASE("render: text hides library rules but JSON keeps them, matching capa") {
    papa::Metadata meta;
    meta.version = "9.4.0";
    meta.sample_path = "x.exe";
    meta.sample_size_bytes = 0U;
    meta.hashes.md5 = meta.hashes.sha1 = meta.hashes.sha256 = "0";
    meta.analysis.os = "windows";
    meta.analysis.arch = "amd64";
    meta.analysis.format = "pe";

    papa::render::ResultDocument doc;
    doc.meta = std::move(meta);

    papa::render::RuleReport capability;
    capability.meta.name = "send-data";
    capability.meta.namespace_ = "communication";
    capability.addresses.push_back(papa::features::Address{
        papa::features::AbsoluteVirtualAddress{0x401000U}});
    capability.match_count = 1;
    doc.rules.emplace("send-data", std::move(capability));

    papa::render::RuleReport library;
    library.meta.name = "calculate-modulo-256-via-x86-assembly";
    library.meta.namespace_ = "lib";
    library.meta.lib = true;
    library.addresses.push_back(papa::features::Address{
        papa::features::AbsoluteVirtualAddress{0x402000U}});
    doc.rules.emplace("calculate-modulo-256-via-x86-assembly", std::move(library));

    // Text report shows the capability but hides the library rule (capa does
    // not list lib rules among capabilities)
    const auto text = papa::render::text::render_to_string(
        doc, papa::render::text::Verbosity::kDefault);
    CHECK(text.find("send-data") != std::string::npos);
    CHECK(text.find("calculate-modulo-256-via-x86-assembly") == std::string::npos);

    // JSON keeps the library rule (capa's --json includes lib rules), so
    // schema-consuming tooling sees the same rule set
    const auto js = papa::render::json::render_to_string(doc, /*pretty=*/false);
    CHECK(js.find("calculate-modulo-256-via-x86-assembly") != std::string::npos);
}

TEST_CASE("render: json emits capa's meta and match-tree schema") {
    papa::Metadata meta;
    meta.version           = "9.4.0";
    meta.sample_path       = "x.exe";
    meta.argv              = {"papa.exe", "x.exe"};
    meta.hashes.md5        = "aa";
    meta.hashes.sha1       = "bb";
    meta.hashes.sha256     = "cc";
    meta.analysis.os       = "windows";
    meta.analysis.arch     = "amd64";
    meta.analysis.format   = "pe";
    meta.analysis.extractor = "papa_native";
    meta.analysis.base_address = 0x140000000ULL;

    papa::render::ResultDocument doc;
    doc.meta = std::move(meta);

    // The feature must outlive render because MatchNode points into rule memory
    const papa::features::Api api("CreateFileA");
    const papa::features::Address loc{papa::features::AbsoluteVirtualAddress{0x401000U}};

    papa::render::MatchNode leaf;
    leaf.success    = true;
    leaf.is_feature = true;
    leaf.feature    = &api;
    leaf.locations  = {loc};

    papa::render::MatchNode root;
    root.success        = true;
    root.statement_type = "and";
    root.children.push_back(leaf);

    papa::render::RuleReport rep;
    rep.meta.name      = "create file";
    rep.meta.namespace_ = "host-interaction/file-system";
    rep.match_count    = 1;
    rep.matches.emplace_back(loc, root);
    doc.rules.emplace("create file", std::move(rep));

    const auto js = papa::render::json::render_to_string(doc, /*pretty=*/false);

    // Meta block follows capa's schema and field order
    CHECK(js.find("\"flavor\":\"static\"") != std::string::npos);
    CHECK(js.find("\"argv\":[\"papa.exe\",\"x.exe\"]") != std::string::npos);
    CHECK(js.find("\"sample\":{\"md5\":\"aa\",\"sha1\":\"bb\",\"sha256\":\"cc\",\"path\":")
          != std::string::npos);
    CHECK(js.find("\"base_address\":{\"type\":\"absolute\",\"value\":5368709120}")
          != std::string::npos);

    // Match tree uses capa's recursive node model and freeze feature format
    CHECK(js.find("\"node\":{\"type\":\"statement\",\"statement\":{\"type\":\"and\"}}")
          != std::string::npos);
    CHECK(js.find("\"node\":{\"type\":\"feature\",\"feature\":{\"type\":\"api\",\"api\":\"CreateFileA\"}}")
          != std::string::npos);
    CHECK(js.find("\"captures\":{}") != std::string::npos);
}

TEST_CASE("render: end-to-end JSON over notepad produces parseable output") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());
    auto backend = papa::features::extractors::papa_native::PapaNativeBackend::build(
        *img, papa_tests::shared_flirt_sigs());
    REQUIRE(backend);
    papa::features::extractors::papa_native::PapaNativeStaticExtractor extractor(
        std::move(*backend));

    const auto rs = papa_tests::ruleset({
        "rule:\n"
        "  meta:\n"
        "    name: has-text\n"
        "    scope: file\n"
        "  features:\n"
        "    - section: .text\n"
    });

    auto caps = papa::capabilities::static_::find_static_capabilities(rs, extractor);
    REQUIRE(caps);

    auto meta = papa::collect_metadata(
        kNotepad,
        std::vector<std::string>{"papa.exe", "notepad.exe"},
        std::vector<std::string>{},
        *img,
        *caps);

    auto doc = papa::render::build_document(std::move(meta), rs, caps->all_matches);
    const auto json_out = papa::render::json::render_to_string(doc, /*pretty=*/false);
    CHECK(json_out.find("\"sha256\":\"") != std::string::npos);
    CHECK(json_out.find("has-text")     != std::string::npos);
}

TEST_CASE("collect_metadata: the report version is capa's release so the JSON can match capa") {
    papa_tests::PeBuilder b;
    b.code = {0xC3};
    auto img = papa::pe::PeParser::parse(b.build());
    REQUIRE(img.has_value());

    const auto meta = papa::collect_metadata(
        "x.exe", {}, {}, *img, papa::capabilities::static_::StaticCapabilities{});
    CHECK(meta.version == "9.4.0");
}

TEST_CASE("collect_metadata: the arch names i386 and amd64 and falls back to aarch64 or unknown") {
    struct Row {
        std::uint16_t machine;
        const char*   arch;
    };
    constexpr std::array<Row, 4> kRows = {{
        {0x014C, "i386"}, {0x8664, "amd64"}, {0xAA64, "aarch64"}, {0x01C4, "unknown"},
    }};
    for (const Row& row : kRows) {
        CAPTURE(row.arch);
        papa_tests::PeBuilder b;
        b.code = {0xC3};
        auto bytes = b.build();
        // The COFF Machine field follows the four byte PE signature that e_lfanew points at
        std::uint32_t lfanew = 0;
        std::memcpy(&lfanew, bytes.data() + 0x3C, sizeof lfanew);
        std::memcpy(bytes.data() + lfanew + 4U, &row.machine, sizeof row.machine);
        auto img = papa::pe::PeParser::parse(bytes);
        REQUIRE(img.has_value());

        const auto meta = papa::collect_metadata(
            "x.exe", {}, {}, *img, papa::capabilities::static_::StaticCapabilities{});
        CHECK(meta.analysis.arch == row.arch);
    }
}

TEST_CASE("render: the verbose header names PAPA's own version rather than the report's") {
    papa::render::ResultDocument doc;
    doc.meta.version = "9.4.0";
    const auto out = papa::render::text::render_to_string(
        doc, papa::render::text::Verbosity::kVerbose);
    const std::string first_line =
        "PAPA " + std::string(papa::version::version()) + "\n";
    CHECK(out.rfind(first_line, 0) == 0);
    CHECK(out.find("9.4.0") == std::string::npos);
}
