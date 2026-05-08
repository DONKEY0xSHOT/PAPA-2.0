#include <ostream>

#include "doctest.h"

#include "papa/capabilities/static_.h"
#include "papa/features/extractors/papa_native/backend.h"
#include "papa/features/extractors/papa_native/extractor.h"
#include "papa/loader.h"
#include "papa/pe/pe_image.h"
#include "papa/pe/pe_parser.h"
#include "papa/render/json.h"
#include "papa/render/result_document.h"
#include "papa/render/text.h"
#include "papa/rules/parser.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"

#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
#include "fixture_paths.h"

namespace {

const auto kNotepad = papa_tests::fixture_path("notepad.exe");

[[nodiscard]] std::unique_ptr<papa::rules::Rule> parse_rule(std::string_view yaml) {
    auto r = papa::rules::RuleParser::parse(yaml, "test.yml");
    REQUIRE(r);
    return std::move(*r);
}

}  // namespace

TEST_CASE("render: build_document filters synthetic subscope rules") {
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(
        "rule:\n"
        "  meta:\n"
        "    name: parent-rule\n"
        "    scope: function\n"
        "  features:\n"
        "    - basic block:\n"
        "      - characteristic: tight loop\n"));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    // Forge a MatchResults that contains both the parent and the synthetic
    papa::engine::MatchResults matches;
    for (const auto& r : rs->all_rules()) {
        matches[r->name()].emplace_back(
            papa::features::Address{papa::features::AbsoluteVirtualAddress{0x1000}},
            papa::engine::Result{});
    }

    papa::Metadata meta;
    auto doc = papa::render::build_document(std::move(meta), *rs, matches);
    CHECK(doc.rules.count("parent-rule") == 1);
    // Every synthetic rule has the parent's name as a "/N" prefix
    for (const auto& [name, _rep] : doc.rules) {
        CHECK(name.find('/') == std::string::npos);
    }
}

TEST_CASE("render: JSON output is well-formed for an empty match result") {
    papa::Metadata meta;
    meta.version = "0.1.0";
    meta.argv    = "papa.exe sample.exe";
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
    CHECK(out.find("\"version\":\"0.1.0\"") != std::string::npos);
    CHECK(out.find("\"rules\":{}")          != std::string::npos);
}

TEST_CASE("render: text default lists rule names grouped by namespace") {
    papa::Metadata meta;
    meta.version = "0.1.0";
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
    doc.rules.emplace("decode-base64", std::move(rep));

    const auto out = papa::render::text::render_to_string(
        doc, papa::render::text::Verbosity::kDefault);
    CHECK(out.find("decode-base64") != std::string::npos);
    CHECK(out.find("data-manipulation/encoding/base64") != std::string::npos);
    CHECK(out.find("[1 match]") != std::string::npos);
}

TEST_CASE("render: end-to-end JSON over notepad produces parseable output") {
    if (!std::filesystem::exists(kNotepad)) {
        MESSAGE("notepad.exe fixture missing, skipping");
        return;
    }
    auto img = papa::pe::PeParser::parse_file(kNotepad);
    REQUIRE(img.has_value());
    auto backend = papa::features::extractors::papa_native::PapaNativeBackend::build(*img);
    REQUIRE(backend);
    papa::features::extractors::papa_native::PapaNativeStaticExtractor extractor(
        std::move(*backend));

    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    rules.push_back(parse_rule(
        "rule:\n"
        "  meta:\n"
        "    name: has-text\n"
        "    scope: file\n"
        "  features:\n"
        "    - section: .text\n"));
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);

    auto caps = papa::capabilities::static_::find_static_capabilities(*rs, extractor);
    REQUIRE(caps);

    // Slurp the sample bytes manually because PeParser only exposes parse_file
    std::vector<std::byte> raw_bytes;
    {
        std::error_code ec;
        const auto sz = std::filesystem::file_size(kNotepad, ec);
        REQUIRE_FALSE(ec);
        raw_bytes.resize(static_cast<std::size_t>(sz));
        std::ifstream ifs(std::filesystem::path(kNotepad), std::ios::binary);
        REQUIRE(ifs);
        ifs.read(reinterpret_cast<char*>(raw_bytes.data()),
                 static_cast<std::streamsize>(raw_bytes.size()));
        REQUIRE(ifs.gcount() == static_cast<std::streamsize>(raw_bytes.size()));
    }

    auto meta = papa::collect_metadata(
        std::span<const std::byte>(raw_bytes),
        kNotepad,
        std::string("papa.exe notepad.exe"),
        std::vector<std::string>{},
        *img,
        *caps,
        extractor);

    auto doc = papa::render::build_document(std::move(meta), *rs, caps->all_matches);
    const auto json_out = papa::render::json::render_to_string(doc, /*pretty=*/false);
    CHECK(json_out.find("\"sha256\":\"") != std::string::npos);
    CHECK(json_out.find("has-text")     != std::string::npos);
}
