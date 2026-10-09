#pragma once

#include <ostream>

#include "doctest.h"

#include "papa/constants.h"
#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/feature.h"
#include "papa/features/insn.h"
#include "papa/features/extractors/base_extractor.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/features/extractors/papa_native/flirt/flirt_classifier.h"
#include "papa/features/extractors/papa_native/flirt/flirt_tree.h"
#include "papa/rules/parser.h"
#include "papa/rules/rule.h"
#include "papa/rules/ruleset.h"
#include "papa/rules/scope.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

/// Helpers shared by the unit tests
namespace papa_tests {

/// The listed values as a std::array of std::byte
template <typename... B>
[[nodiscard]] constexpr std::array<std::byte, sizeof...(B)> bytes(B... values) {
    return std::array<std::byte, sizeof...(B)>{std::byte{static_cast<std::uint8_t>(values)}...};
}

/// The listed values as a std::vector of std::byte
[[nodiscard]] inline std::vector<std::byte> byte_vec(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (const std::uint8_t b : values) { out.push_back(std::byte{b}); }
    return out;
}

/// The characters of text viewed as bytes. The text must outlive the span
[[nodiscard]] inline std::span<const std::byte> text_bytes(std::string_view text) noexcept {
    return std::as_bytes(std::span<const char>(text.data(), text.size()));
}

/// A register operand
[[nodiscard]] inline papa::features::extractors::papa_native::DecodedOperand
reg(ZydisRegister r, std::size_t width) {
    papa::features::extractors::papa_native::DecodedOperand op;
    op.kind        = papa::features::extractors::papa_native::OperandKind::kReg;
    op.base_reg    = r;
    op.width_bytes = width;
    return op;
}

/// An immediate operand
[[nodiscard]] inline papa::features::extractors::papa_native::DecodedOperand
imm(std::uint64_t value, std::size_t width) {
    papa::features::extractors::papa_native::DecodedOperand op;
    op.kind        = papa::features::extractors::papa_native::OperandKind::kImm;
    op.imm         = value;
    op.width_bytes = width;
    return op;
}

/// A [base + disp] memory operand
[[nodiscard]] inline papa::features::extractors::papa_native::DecodedOperand
mem(ZydisRegister base, std::int64_t disp, std::size_t width) {
    papa::features::extractors::papa_native::DecodedOperand op;
    op.kind        = papa::features::extractors::papa_native::OperandKind::kRegMem;
    op.base_reg    = base;
    op.disp        = disp;
    op.width_bytes = width;
    return op;
}

/// A two-byte instruction at 0x1000 with the given mnemonic and operands
template <typename... Ops>
[[nodiscard]] papa::features::extractors::papa_native::DecodedInsn
insn(ZydisMnemonic mnemonic, const Ops&... ops) {
    static_assert(sizeof...(Ops) <= papa::constants::kMaxOperandCount);
    const std::array<papa::features::extractors::papa_native::DecodedOperand, sizeof...(Ops)>
        list{ops...};
    papa::features::extractors::papa_native::DecodedInsn out;
    out.va       = 0x1000;
    out.length   = 2;
    out.zyd_mnem = mnemonic;
    std::copy(list.begin(), list.end(), out.operands.begin());
    out.operand_count = list.size();
    return out;
}

/// A function whose entry is the first block, made of the blocks in order
[[nodiscard]] inline papa::features::extractors::papa_native::Function
function(std::vector<papa::features::extractors::papa_native::BasicBlock> blocks) {
    papa::features::extractors::papa_native::Function fn;
    fn.va           = blocks.empty() ? 0U : blocks.front().va;
    fn.basic_blocks = std::move(blocks);
    return fn;
}

/// A function of one block holding insns, both starting at the first instruction
[[nodiscard]] inline papa::features::extractors::papa_native::Function
single_block_function(std::vector<papa::features::extractors::papa_native::DecodedInsn> insns) {
    const std::uint64_t entry = insns.empty() ? 0U : insns.front().va;
    return function({{entry, std::move(insns)}});
}

/// The absolute virtual address v
[[nodiscard]] inline papa::features::Address va(std::uint64_t v) {
    return papa::features::Address{papa::features::AbsoluteVirtualAddress{v}};
}

/// A shared feature of type T built from args
template <typename T, typename... Args>
[[nodiscard]] papa::features::FeaturePtr feat(Args&&... args) {
    return std::make_shared<const T>(std::forward<Args>(args)...);
}

/// A FeatureSet holding each feature at its address
[[nodiscard]] inline papa::features::FeatureSet feature_set(
    std::initializer_list<std::pair<papa::features::FeaturePtr, papa::features::Address>> items) {
    papa::features::FeatureSet out;
    for (const auto& [f, a] : items) { out.add(f, a); }
    return out;
}

/// One line naming a feature, its value and its address. Comparing these compares
/// extractor output exactly, and a failed check prints both sides readably
[[nodiscard]] inline std::string describe(const papa::features::extractors::FeatureWithAddress& fa) {
    namespace pf = papa::features;
    static constexpr std::array<std::string_view, 23> kTags{
        "string", "substring", "regex", "bytes", "number", "offset", "mnemonic", "api",
        "import", "export", "section", "function-name", "class", "namespace", "property",
        "characteristic", "match", "os", "arch", "format", "operand number",
        "operand offset", "basic block"};
    std::ostringstream out;
    const auto number = [&out](const pf::Number::Value& v) {
        if (const auto* u = std::get_if<std::uint64_t>(&v)) {
            out << " 0x" << std::hex << *u << std::dec;
        } else if (const auto* i = std::get_if<std::int64_t>(&v)) {
            out << " int " << *i;
        } else {
            out << " double " << std::get<double>(v);
        }
    };

    const pf::Feature& f = *fa.first;
    out << kTags.at(static_cast<std::size_t>(f.tag()));
    switch (f.tag()) {
        case pf::FeatureTag::kBytes:
            out << ' ' << std::hex;
            for (const std::byte b : static_cast<const pf::Bytes&>(f).value()) {
                out << (std::to_integer<unsigned>(b) >> 4U) << (std::to_integer<unsigned>(b) & 0xFU);
            }
            out << std::dec;
            break;
        case pf::FeatureTag::kNumber:
            number(static_cast<const pf::Number&>(f).value());
            break;
        case pf::FeatureTag::kOperandNumber:
            out << ' ' << static_cast<const pf::OperandNumber&>(f).index();
            number(static_cast<const pf::OperandNumber&>(f).value());
            break;
        case pf::FeatureTag::kOffset:
            out << ' ' << static_cast<const pf::Offset&>(f).value();
            break;
        case pf::FeatureTag::kOperandOffset:
            out << ' ' << static_cast<const pf::OperandOffset&>(f).index() << ' '
                << static_cast<const pf::OperandOffset&>(f).value();
            break;
        case pf::FeatureTag::kProperty:
            out << ' ' << static_cast<const pf::Property&>(f).value() << ' '
                << static_cast<int>(static_cast<const pf::Property&>(f).access());
            break;
        case pf::FeatureTag::kBasicBlock:
            break;
        default:
            out << ' ' << static_cast<const pf::ValueFeature&>(f).value();
            break;
    }

    out << " @ " << std::hex;
    if (const auto* v = std::get_if<pf::AbsoluteVirtualAddress>(&fa.second)) {
        out << "va 0x" << v->v;
    } else if (const auto* o = std::get_if<pf::FileOffsetAddress>(&fa.second)) {
        out << "file 0x" << o->v;
    } else if (const auto* r = std::get_if<pf::RelativeVirtualAddress>(&fa.second)) {
        out << "rva 0x" << r->v;
    } else if (std::holds_alternative<pf::NoAddress>(fa.second)) {
        out << "none";
    } else {
        out << "token 0x" << pf::linearize(fa.second);
    }
    return out.str();
}

/// The describe() line of every entry, in order
[[nodiscard]] inline std::string
describe(const std::vector<papa::features::extractors::FeatureWithAddress>& list) {
    std::string out;
    for (const auto& fa : list) { out.append(describe(fa)).append("\n"); }
    return out;
}

/// A statement that holds when f is present
[[nodiscard]] inline std::unique_ptr<papa::engine::Statement> leaf(papa::features::FeaturePtr f) {
    return std::make_unique<papa::engine::FeatureStatement>(std::move(f));
}

namespace detail {

[[nodiscard]] inline std::unique_ptr<papa::engine::Statement>
node(std::unique_ptr<papa::engine::Statement> st) {
    return st;
}

[[nodiscard]] inline std::unique_ptr<papa::engine::Statement>
node(const papa::features::FeaturePtr& f) {
    return leaf(f);
}

template <typename... Kids>
[[nodiscard]] std::vector<std::unique_ptr<papa::engine::Statement>> kids(Kids&&... k) {
    std::vector<std::unique_ptr<papa::engine::Statement>> out;
    (out.push_back(node(std::forward<Kids>(k))), ...);
    return out;
}

}  // namespace detail

/// An and: over the children, each a statement or a feature. Named after the rule
/// keyword rather than all_of, which ADL would resolve to the std algorithm
template <typename... Kids>
[[nodiscard]] std::unique_ptr<papa::engine::Statement> all(Kids&&... k) {
    return std::make_unique<papa::engine::And>(detail::kids(std::forward<Kids>(k)...));
}

/// An or: over the children, each a statement or a feature
template <typename... Kids>
[[nodiscard]] std::unique_ptr<papa::engine::Statement> any(Kids&&... k) {
    return std::make_unique<papa::engine::Or>(detail::kids(std::forward<Kids>(k)...));
}

/// An "n or more" over the children, each a statement or a feature
template <typename... Kids>
[[nodiscard]] std::unique_ptr<papa::engine::Statement> at_least(std::size_t n, Kids&&... k) {
    return std::make_unique<papa::engine::Some>(n, detail::kids(std::forward<Kids>(k)...));
}

/// An optional: block over the children, each a statement or a feature
template <typename... Kids>
[[nodiscard]] std::unique_ptr<papa::engine::Statement> opt(Kids&&... k) {
    return at_least(0, std::forward<Kids>(k)...);
}

/// A not: around one child, a statement or a feature
template <typename Kid>
[[nodiscard]] std::unique_ptr<papa::engine::Statement> negate(Kid&& k) {
    return std::make_unique<papa::engine::Not>(detail::node(std::forward<Kid>(k)));
}

/// A count(f) of at least min with no upper bound
[[nodiscard]] inline std::unique_ptr<papa::engine::Statement>
count(const papa::features::FeaturePtr& f, std::size_t min) {
    return std::make_unique<papa::engine::Range>(f, min, std::numeric_limits<std::size_t>::max());
}

/// The rule parsed from yaml, which must parse
[[nodiscard]] inline std::unique_ptr<papa::rules::Rule> rule(std::string_view yaml) {
    auto r = papa::rules::RuleParser::parse(yaml, "test.yml");
    REQUIRE(r);
    return std::move(*r);
}

/// The RuleSet of the rules parsed from yamls, which must parse and link
[[nodiscard]] inline papa::rules::RuleSet ruleset(std::initializer_list<std::string_view> yamls) {
    std::vector<std::unique_ptr<papa::rules::Rule>> rules;
    for (const std::string_view yaml : yamls) { rules.push_back(rule(yaml)); }
    auto rs = papa::rules::RuleSet::from_rules(std::move(rules));
    REQUIRE(rs);
    return std::move(*rs);
}

/// The YAML of a rule with one static scope, a feature list of one entry per line and
/// an optional namespace
[[nodiscard]] inline std::string rule_yaml(std::string_view name, std::string_view scope,
                                           const std::vector<std::string>& features,
                                           std::string_view ns = {}) {
    std::string out = "rule:\n  meta:\n    name: ";
    out.append(name);
    if (!ns.empty()) { out.append("\n    namespace: ").append(ns); }
    out.append("\n    scopes:\n      static: ").append(scope);
    out.append("\n      dynamic: unsupported\n  features:\n");
    for (const std::string& f : features) { out.append("    - ").append(f).append("\n"); }
    return out;
}

/// A rule around stmt with only its name, namespace and static scope set
[[nodiscard]] inline std::unique_ptr<papa::rules::Rule>
make_rule(std::string                               name,
          std::optional<std::string>                ns,
          papa::rules::Scope                        scope,
          std::unique_ptr<papa::engine::Statement>  stmt) {
    papa::rules::RuleMeta meta;
    meta.name                = std::move(name);
    meta.namespace_          = std::move(ns);
    meta.scopes.static_scope = scope;
    return std::make_unique<papa::rules::Rule>(std::move(meta), std::move(stmt), std::string{});
}

/// The embedded FLIRT signatures, decoded once per test process and shared
[[nodiscard]] inline const papa::features::extractors::papa_native::flirt::FlirtSignatureSet&
shared_flirt_sigs() {
    static const auto set =
        papa::features::extractors::papa_native::flirt::FlirtSignatureSet::make_embedded();
    return set;
}

/// An InsnReader over a contiguous region starting at base_va. The region and disasm
/// must outlive the returned reader
[[nodiscard]] inline papa::features::extractors::papa_native::InsnReader
make_span_reader(std::span<const std::byte> region, std::uint64_t base_va,
                 const papa::features::extractors::papa_native::Disassembler& disasm) {
    using papa::features::extractors::papa_native::DecodedInsn;
    const auto* dis = &disasm;
    return [region, base_va, dis](std::uint64_t va) -> papa::Expected<DecodedInsn> {
        if (va < base_va) {
            return papa::Unexpected{
                papa::make_error(papa::ErrorKind::kOutOfBounds, "va below region base")};
        }
        const std::uint64_t off = va - base_va;
        if (off >= region.size()) {
            return papa::Unexpected{
                papa::make_error(papa::ErrorKind::kOutOfBounds, "va past region end")};
        }
        const std::size_t avail = std::min<std::size_t>(
            papa::constants::kMaxInsnBytes, region.size() - static_cast<std::size_t>(off));
        return dis->decode(region.subspan(static_cast<std::size_t>(off), avail), va);
    };
}

/// Builds FLIRT .sig bytes one field at a time, each in its on-disk encoding
class SigWriter {
public:
    std::vector<std::uint8_t> buf;

    void u8(std::uint8_t v) { buf.push_back(v); }

    void u16_le(std::uint16_t v) {
        buf.push_back(static_cast<std::uint8_t>(v & 0xFFU));
        buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    }

    /// Big-endian, the encoding of the module CRC16
    void u16_be(std::uint16_t v) {
        buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
        buf.push_back(static_cast<std::uint8_t>(v & 0xFFU));
    }

    void u32_le(std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            buf.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFU));
        }
    }

    void zeroes(std::size_t n) { buf.insert(buf.end(), n, std::uint8_t{0}); }

    /// FLAIR vint16. Values below 0x80 take one byte, larger ones two with the lead
    /// byte's high bit set
    void vle16(std::uint16_t v) {
        if (v < 0x80U) {
            buf.push_back(static_cast<std::uint8_t>(v));
            return;
        }
        buf.push_back(static_cast<std::uint8_t>(0x80U | ((v >> 8) & 0x7FU)));
        buf.push_back(static_cast<std::uint8_t>(v & 0xFFU));
    }

    /// A node child header with no wildcards: the length, a clear variant mask, then
    /// the literal bytes
    void child_pattern(std::span<const std::uint8_t> pattern_bytes) {
        vle16(static_cast<std::uint16_t>(pattern_bytes.size()));
        vle16(0);
        buf.insert(buf.end(), pattern_bytes.begin(), pattern_bytes.end());
    }

    /// A node child header with wildcards. Mask bit (length-1-i) marks position i
    void child_pattern_masked(std::uint16_t length, std::uint16_t mask,
                              std::span<const std::uint8_t> literals) {
        vle16(length);
        vle16(mask);
        buf.insert(buf.end(), literals.begin(), literals.end());
    }

    /// A module body without its crc_len and crc16: the function size, one name at
    /// relative offset zero, then the trailing flags byte
    void module_body(std::uint32_t function_size, std::string_view name,
                     std::uint8_t trailing_flags) {
        vle16(static_cast<std::uint16_t>(function_size));
        vle16(0);
        for (const char c : name) { buf.push_back(static_cast<std::uint8_t>(c)); }
        u8(trailing_flags);
    }

    /// A name record: the relative offset, a name-flag byte when non-zero, the name,
    /// then the trailing flags byte that ends it
    void name_record(std::uint16_t relative_offset, std::uint8_t name_flags,
                     std::string_view name, std::uint8_t trailing_flags) {
        vle16(relative_offset);
        if (name_flags != 0U) { u8(name_flags); }
        for (const char c : name) { buf.push_back(static_cast<std::uint8_t>(c)); }
        u8(trailing_flags);
    }
};

/// Offset of the little-endian features word inside every .sig header
inline constexpr std::size_t kSigFeaturesOffset = 16;

/// A minimal well-formed .sig header of the given version, marked compressed, with a
/// library name of ln_len letters
[[nodiscard]] inline std::vector<std::uint8_t> sig_header(std::uint8_t version,
                                                          std::uint8_t ln_len = 0) {
    SigWriter w;
    w.buf = {'I', 'D', 'A', 'S', 'G', 'N'};
    w.u8(version);
    w.u8(0x01);             // arch x86
    w.u32_le(0x00000002U);  // file_types
    w.u16_le(0x0003U);      // os_types
    w.u16_le(0x0004U);      // app_types
    w.u16_le(0x0010U);      // features, compressed is 0x10
    w.u16_le(0x0007U);      // old_n_functions
    w.u16_le(0xABCDU);      // pattern_crc16
    w.zeroes(12);           // ctype
    w.u8(ln_len);
    w.u16_le(0x1234U);      // ctypes_crc16
    if (version >= 9) {
        w.u32_le(0x0000002AU);  // n_functions
    }
    if (version >= 10) {
        w.u16_le(0x0020U);  // pattern_size
        w.u16_le(0x0000U);  // unknown
    }
    for (std::uint8_t i = 0; i < ln_len; ++i) {
        w.buf.push_back(static_cast<std::uint8_t>('a' + (i % 26)));
    }
    return w.buf;
}

/// Clears the compression bit so the body that follows reads as plain tree bytes
inline void clear_compression_bit(std::vector<std::uint8_t>& header) {
    header[kSigFeaturesOffset] =
        static_cast<std::uint8_t>(header[kSigFeaturesOffset] & ~0x10U);
}

/// A v10 header with compression cleared, followed by body
[[nodiscard]] inline std::vector<std::uint8_t> sig_with_body(std::span<const std::uint8_t> body) {
    auto sig = sig_header(10);
    clear_compression_bit(sig);
    sig.insert(sig.end(), body.begin(), body.end());
    return sig;
}

/// A FlirtPattern from a byte list starting at offset 0. A negative entry is a wildcard
[[nodiscard]] inline papa::features::extractors::papa_native::flirt::FlirtPattern
pattern(std::initializer_list<int> values) {
    papa::features::extractors::papa_native::flirt::FlirtPattern pat;
    pat.length = 0;
    for (const int b : values) {
        if (b < 0) {
            pat.wildcard.set(pat.length);
        } else {
            pat.bytes[pat.length] = static_cast<std::uint8_t>(b);
        }
        pat.length = static_cast<std::uint8_t>(pat.length + 1U);
    }
    return pat;
}

/// A scriptable FLIRT FunctionContext. Each answer comes from the matching map
class MockFlirtContext : public papa::features::extractors::papa_native::flirt::FunctionContext {
public:
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> code;
    std::unordered_map<std::uint64_t,
                       papa::features::extractors::papa_native::flirt::FlirtXref> xrefs;
    std::unordered_map<std::uint64_t, std::string> imports;
    std::unordered_set<std::uint64_t>              functions;

    [[nodiscard]] std::span<const std::uint8_t>
    code_at(std::uint64_t va, std::size_t max_len) const override {
        const auto it = code.find(va);
        if (it == code.end()) {
            return {};
        }
        return std::span<const std::uint8_t>(it->second.data(),
                                              std::min(max_len, it->second.size()));
    }

    [[nodiscard]] std::optional<papa::features::extractors::papa_native::flirt::FlirtXref>
    xref_from(std::uint64_t site_va) const override {
        const auto it = xrefs.find(site_va);
        if (it == xrefs.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] std::optional<std::string_view> import_name(std::uint64_t va) const override {
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

/// A FLIRT module carrying one public name at offset 0
[[nodiscard]] inline papa::features::extractors::papa_native::flirt::FlirtModule
public_module(std::string name) {
    papa::features::extractors::papa_native::flirt::FlirtModule m;
    m.names.push_back(
        {0, std::move(name), papa::features::extractors::papa_native::flirt::FlirtNameType::kPublic});
    return m;
}

/// A module matcher that yields the modules keyed by the first byte of the buffer
[[nodiscard]] inline papa::features::extractors::papa_native::flirt::ModuleMatchFn byte_dispatch(
    std::unordered_map<std::uint8_t,
                       std::vector<const papa::features::extractors::papa_native::flirt::FlirtModule*>>
        table) {
    using papa::features::extractors::papa_native::flirt::FlirtModule;
    return [table = std::move(table)](std::span<const std::uint8_t> b)
               -> std::vector<const FlirtModule*> {
        if (b.empty()) {
            return {};
        }
        const auto it = table.find(b[0]);
        return it == table.end() ? std::vector<const FlirtModule*>{} : it->second;
    };
}

/// A StaticFeatureExtractor that yields the features it was given. File features sit
/// at the base 0x400000, and function i at 0x401000 + 0x10 * i with no basic blocks
class FakeExtractor : public papa::features::extractors::StaticFeatureExtractor {
public:
    static constexpr std::uint64_t kBase          = 0x400000;
    static constexpr std::uint64_t kFirstFunction = 0x401000;

    explicit FakeExtractor(
        std::vector<papa::features::FeaturePtr>              file_features,
        std::vector<std::vector<papa::features::FeaturePtr>> function_features = {})
        : file_features_(std::move(file_features)),
          function_features_(std::move(function_features)) {}

    [[nodiscard]] papa::features::Address get_base_address() const override { return va(kBase); }

    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_global_features() const override { return {}; }

    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_file_features() const override {
        return at(file_features_, va(kBase));
    }

    [[nodiscard]] std::vector<papa::features::extractors::FunctionHandle>
    get_functions() const override {
        std::vector<papa::features::extractors::FunctionHandle> out;
        for (std::size_t i = 0; i < function_features_.size(); ++i) {
            out.push_back({va(kFirstFunction + 0x10U * i), &function_features_[i]});
        }
        return out;
    }

    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_function_features(const papa::features::extractors::FunctionHandle& fh) const override {
        return at(*static_cast<const std::vector<papa::features::FeaturePtr>*>(fh.inner), fh.addr);
    }

    [[nodiscard]] std::vector<papa::features::extractors::BBHandle>
    get_basic_blocks(const papa::features::extractors::FunctionHandle&) const override {
        return {};
    }

    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_basic_block_features(const papa::features::extractors::FunctionHandle&,
                                 const papa::features::extractors::BBHandle&) const override {
        return {};
    }

    [[nodiscard]] std::vector<papa::features::extractors::InsnHandle>
    get_instructions(const papa::features::extractors::FunctionHandle&,
                     const papa::features::extractors::BBHandle&) const override {
        return {};
    }

    [[nodiscard]] std::vector<papa::features::extractors::FeatureWithAddress>
    extract_insn_features(const papa::features::extractors::FunctionHandle&,
                          const papa::features::extractors::BBHandle&,
                          const papa::features::extractors::InsnHandle&) const override {
        return {};
    }

private:
    [[nodiscard]] static std::vector<papa::features::extractors::FeatureWithAddress>
    at(const std::vector<papa::features::FeaturePtr>& feats, const papa::features::Address& a) {
        std::vector<papa::features::extractors::FeatureWithAddress> out;
        out.reserve(feats.size());
        for (const auto& f : feats) { out.emplace_back(f, a); }
        return out;
    }

    std::vector<papa::features::FeaturePtr>              file_features_;
    std::vector<std::vector<papa::features::FeaturePtr>> function_features_;
};

/// The value of an environment variable, empty when it is unset. MSVC rejects
/// std::getenv under /W4 /WX
[[nodiscard]] inline std::string read_env(const char* name) {
#if defined(_MSC_VER)
    std::size_t required = 0;
    if (getenv_s(&required, nullptr, 0, name) != 0 || required == 0) {
        return {};
    }
    std::string buf(required, '\0');
    if (getenv_s(&required, buf.data(), buf.size(), name) != 0) {
        return {};
    }
    // getenv_s writes a trailing NUL inside the buffer
    if (!buf.empty() && buf.back() == '\0') { buf.pop_back(); }
    return buf;
#else
    const char* v = std::getenv(name);
    return v != nullptr ? std::string(v) : std::string{};
#endif
}

/// A fresh directory under the system temp directory, removed with its contents when
/// the guard goes out of scope, including when a check fails and the case unwinds
class TempDir {
public:
    TempDir() {
        const auto         base = std::filesystem::temp_directory_path();
        std::random_device seed;
        for (int attempt = 0; attempt < 16 && path_.empty(); ++attempt) {
            auto            candidate = base / ("papa_unit_" + std::to_string(seed()));
            std::error_code ec;
            if (std::filesystem::create_directory(candidate, ec)) { path_ = std::move(candidate); }
        }
        REQUIRE_FALSE(path_.empty());
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    TempDir(const TempDir&)            = delete;
    TempDir& operator=(const TempDir&) = delete;
    TempDir(TempDir&&)                 = delete;
    TempDir& operator=(TempDir&&)      = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

/// Redirects a stream into a buffer while it lives
class StreamCapture {
public:
    explicit StreamCapture(std::ostream& stream)
        : stream_(stream), old_(stream.rdbuf(buf_.rdbuf())) {}
    ~StreamCapture() { stream_.rdbuf(old_); }
    StreamCapture(const StreamCapture&)            = delete;
    StreamCapture& operator=(const StreamCapture&) = delete;
    StreamCapture(StreamCapture&&)                 = delete;
    StreamCapture& operator=(StreamCapture&&)      = delete;

    [[nodiscard]] std::string text() const { return buf_.str(); }

private:
    std::ostringstream buf_;
    std::ostream&      stream_;
    std::streambuf*    old_ = nullptr;
};

/// Writes bytes to path, creating its parent directories
inline void write_file(const std::filesystem::path& path, std::span<const std::byte> data) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    REQUIRE(out.good());
}

/// Writes text to path byte for byte, creating its parent directories
inline void write_file(const std::filesystem::path& path, std::string_view text) {
    write_file(path, text_bytes(text));
}

}  // namespace papa_tests
