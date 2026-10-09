// The four report modes end to end through the CLI, compared with checked-in goldens.
// PAPA_UPDATE_GOLDENS=1 rewrites the goldens instead of comparing

#include <ostream>

#include "doctest.h"

#include "papa/main_driver.h"
#include "papa/render/result_document.h"
#include "papa/version.h"

#include "pe_builder.h"
#include "test_support.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

const fs::path kGoldenDir = "tests/unit/golden";

// Makes dir the working directory while it lives, so the reports carry relative paths
class CwdGuard {
public:
    explicit CwdGuard(const fs::path& dir) : old_(fs::current_path()) { fs::current_path(dir); }
    ~CwdGuard() {
        std::error_code ec;
        fs::current_path(old_, ec);
    }
    CwdGuard(const CwdGuard&)            = delete;
    CwdGuard& operator=(const CwdGuard&) = delete;
    CwdGuard(CwdGuard&&)                 = delete;
    CwdGuard& operator=(CwdGuard&&)      = delete;

private:
    fs::path old_;
};

// An x64 sample with an import thunk, a function that opens and writes a file with a
// string argument, an xor loop and a function that loads one constant twice
[[nodiscard]] std::vector<std::byte> golden_sample() {
    papa_tests::PeBuilder b;
    b.x64     = true;
    b.imports = {{"kernel32.dll", {"CreateFileA", "WriteFile", "ExitProcess"}}};
    const std::string_view text = "hello world";
    b.data.assign(0x20, 0);
    std::copy(text.begin(), text.end(), b.data.begin());

    // jmp [rip+ExitProcess]
    const std::uint32_t thunk = b.add_function({0xFF, 0x25, 0, 0, 0, 0});
    // sub rsp, 0x28 | lea rdx, [rip+text] | call [rip+CreateFileA] | call [rip+WriteFile]
    // | add rsp, 0x28 | ret
    const std::uint32_t writer = b.add_function(
        {0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x15, 0, 0, 0, 0, 0xFF, 0x15, 0, 0, 0, 0,
         0xFF, 0x15, 0, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3});
    // mov eax, 3 | L: dec eax | xor ecx, edx | jnz L | ret
    b.add_function({0xB8, 0x03, 0, 0, 0, 0xFF, 0xC8, 0x33, 0xCA, 0x75, 0xFA, 0xC3});
    // mov eax, 0x10 | mov ecx, 0x10 | ret
    b.add_function({0xB8, 0x10, 0, 0, 0, 0xB9, 0x10, 0, 0, 0, 0xC3});

    // Each rip-relative displacement counts from the end of its instruction
    const auto rel = [&b](std::uint32_t disp_at, std::uint32_t end, std::uint64_t target) {
        papa_tests::detail::poke(b.code, disp_at,
                                 static_cast<std::int32_t>(target - b.code_va(end)));
    };
    rel(thunk + 2U, thunk + 6U, b.iat_va("kernel32.dll", "ExitProcess"));
    rel(writer + 7U, writer + 11U, b.data_va(0));
    rel(writer + 13U, writer + 17U, b.iat_va("kernel32.dll", "CreateFileA"));
    rel(writer + 19U, writer + 23U, b.iat_va("kernel32.dll", "WriteFile"));
    return b.build();
}

// One rule file
struct RuleFile {
    std::string_view path;
    std::string_view yaml;
};

// A lib rule, a match by name and by namespace, a subscope, a count and both
// ATT&CK and MBC metadata, across the instruction, function and file scopes
constexpr RuleFile kRules[] = {
    {"lib/open-file.yml", R"(rule:
  meta:
    name: open file
    namespace: host-interaction/file-system/open
    lib: true
    scopes:
      static: instruction
      dynamic: unsupported
  features:
    - api: CreateFileA
)"},
    {"host-interaction/file-system/write/write-file.yml", R"(rule:
  meta:
    name: write file
    namespace: host-interaction/file-system/write
    description: opens a file and writes a string to it
    scopes:
      static: function
      dynamic: unsupported
    mbc:
      - File System::Writes File [C0052]
  features:
    - and:
      - match: open file
      - api: WriteFile
      - string: hello world
)"},
    {"data-manipulation/encoding/xor/xor-loop.yml", R"(rule:
  meta:
    name: encode data using xor in a loop
    namespace: data-manipulation/encoding/xor
    scopes:
      static: function
      dynamic: unsupported
    att&ck:
      - Defense Evasion::Obfuscated Files or Information [T1027]
    mbc:
      - Defense Evasion::Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]
  features:
    - and:
      - basic block:
        - and:
          - characteristic: tight loop
          - characteristic: nzxor
)"},
    {"data-manipulation/constant/repeated-constant.yml", R"(rule:
  meta:
    name: reference a constant twice
    namespace: data-manipulation/constant
    scopes:
      static: function
      dynamic: unsupported
  features:
    - count(number(0x10)): 2 or more
)"},
    {"executable/pe/section/text-section.yml", R"(rule:
  meta:
    name: contain a text section
    namespace: executable/pe/section
    scopes:
      static: file
      dynamic: unsupported
  features:
    - section: .text
)"},
    {"collection/write-encoded.yml", R"(rule:
  meta:
    name: write and encode data
    namespace: collection
    scopes:
      static: file
      dynamic: unsupported
    att&ck:
      - Collection::Data Staged [T1074]
  features:
    - and:
      - match: write file
      - match: data-manipulation/encoding/xor
)"},
};

// The report with its run-specific parts replaced: the analysis time, the absolute
// sample path, PAPA's own version in the verbose header and any console color
[[nodiscard]] std::string normalize(std::string text, const std::string& sample_path) {
    static const std::regex kTimestamp(R"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)");
    static const std::regex kColor("\x1b\\[[0-9;]*m");
    // The table may truncate or wrap the path, so its whole row is replaced
    const std::string       bar = "\xE2\x94\x82";
    static const std::regex kPathRow(bar + " path     " + bar + "[^\n]*\n(?:" + bar +
                                     "          " + bar + "[^\n]*\n)*");
    text = std::regex_replace(text, kTimestamp, "<timestamp>");
    text = std::regex_replace(text, kColor, "");
    text = std::regex_replace(text, kPathRow, bar + " path     " + bar + " <sample path>\n");
    for (auto at = text.find(sample_path); at != std::string::npos;
         at = text.find(sample_path, at)) {
        text.replace(at, sample_path.size(), "<sample path>");
    }
    const std::string header = "PAPA " + std::string(papa::version::version()) + "\n";
    if (text.rfind(header, 0) == 0) { text.replace(0, header.size(), "PAPA <version>\n"); }
    return text;
}

// The file's bytes with carriage returns dropped, so a checkout that converts line
// endings still compares equal
[[nodiscard]] std::string read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::string   out(static_cast<std::size_t>(fs::file_size(path)), '\0');
    in.read(out.data(), static_cast<std::streamsize>(out.size()));
    std::erase(out, '\r');
    return out;
}

}  // namespace

TEST_CASE("golden: the default, verbose, very verbose and json reports match their goldens") {
    const bool update = !papa_tests::read_env("PAPA_UPDATE_GOLDENS").empty();
    REQUIRE_MESSAGE((update || fs::is_directory(kGoldenDir)),
                    "tests/unit/golden not found, run the tests from the repository root");
    const fs::path golden_dir = fs::absolute(kGoldenDir);

    const papa_tests::TempDir dir;
    papa_tests::write_file(dir.path() / "sample.exe", golden_sample());
    for (const RuleFile& rule : kRules) {
        papa_tests::write_file(dir.path() / "rules" / rule.path, rule.yaml);
    }
    const CwdGuard    cwd(dir.path());
    const std::string sample_path = papa::render::posix_path("sample.exe");

    struct Row {
        std::string_view         golden;
        std::vector<const char*> argv;
    };
    const std::vector<Row> rows{
        {"default.txt", {"sample.exe", "-r", "rules"}},
        {"verbose.txt", {"-v", "sample.exe", "-r", "rules"}},
        {"vverbose.txt", {"-vv", "sample.exe", "-r", "rules"}},
        {"json.json", {"-j", "sample.exe", "-r", "rules"}},
    };
    for (const Row& row : rows) {
        CAPTURE(row.golden);
        const auto parsed =
            papa::cli::parse_args(static_cast<int>(row.argv.size()), row.argv.data());
        REQUIRE(parsed.error.empty());

        const papa_tests::StreamCapture out(std::cout);
        const papa_tests::StreamCapture err(std::cerr);
        CHECK(papa::cli::run(parsed.args) == papa::cli::kExitOk);
        CHECK(err.text().empty());
        const std::string report = normalize(out.text(), sample_path);

        const fs::path golden = golden_dir / row.golden;
        if (update) {
            papa_tests::write_file(golden, report);
            continue;
        }
        REQUIRE_MESSAGE(fs::exists(golden), "missing golden ", golden.string());
        CHECK(report == read_text(golden));
    }
}

TEST_CASE("golden: without -r the embedded rules load and the report names them as capa does") {
    const papa_tests::TempDir dir;
    papa_tests::write_file(dir.path() / "sample.exe", golden_sample());
    const CwdGuard cwd(dir.path());

    const std::vector<const char*> argv{"-j", "sample.exe"};
    const auto parsed = papa::cli::parse_args(static_cast<int>(argv.size()), argv.data());
    REQUIRE(parsed.error.empty());
    const papa_tests::StreamCapture out(std::cout);
    CHECK(papa::cli::run(parsed.args) == papa::cli::kExitOk);
    CHECK(out.text().find(R"json("rules":["(embedded rules)"])json") != std::string::npos);
}
