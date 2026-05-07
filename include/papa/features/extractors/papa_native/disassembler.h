#pragma once

#include "papa/constants.h"
#include "papa/exceptions.h"

#include <Zydis/Zydis.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace papa::features::extractors::papa_native {

// Taxonomy mirroring vivisect operand classes used by CAPA
enum class OperandKind : std::uint8_t {
    kImm,      // immediate literal, not a branch target
    kImmMem,   // [abs32] with no base/index
    kPcRel,    // relative branch target
    kRipRel,   // [rip+disp] on x64
    kReg,      // register
    kRegMem,   // [base + disp]
    kSib,      // [base + index*scale + disp]
    kUnknown,
};

// One decoded operand
// Payload fields are valid only for the kinds that carry them
struct DecodedOperand {
    OperandKind   kind          { OperandKind::kUnknown };
    ZydisRegister base_reg      { ZYDIS_REGISTER_NONE };
    ZydisRegister index_reg     { ZYDIS_REGISTER_NONE };
    std::uint8_t  scale         { 0 };
    std::int64_t  disp          { 0 };
    std::uint64_t imm           { 0 };
    bool          is_signed_imm { false };
    std::size_t   width_bytes   { 0 };
};

// One fully-decoded instruction with derived branch metadata
struct DecodedInsn {
    std::uint64_t va            { 0 };
    std::size_t   length        { 0 };
    ZydisMnemonic zyd_mnem      { ZYDIS_MNEMONIC_INVALID };
    std::string_view mnemonic_str;
    std::array<DecodedOperand, constants::kMaxOperandCount> operands {};
    std::size_t   operand_count { 0 };
    bool          has_prefix_fs { false };
    bool          has_prefix_gs { false };
    std::span<const std::byte> raw_bytes;

    bool          is_call        { false };
    bool          is_jump        { false };
    bool          is_conditional { false };
    bool          is_return      { false };
    std::optional<std::uint64_t> branch_target;
    bool          is_fallthrough { true };
};

// One Disassembler instance is not thread-safe
// Use one instance per thread when running in parallel
class Disassembler {
public:
    explicit Disassembler(bool is_64bit);

    // Decode one instruction
    // Length is capped by bytes.size() so Zydis cannot over-read
    [[nodiscard]] Expected<DecodedInsn>
        decode(std::span<const std::byte> bytes, std::uint64_t va) const;

    [[nodiscard]] bool is_64bit() const noexcept { return is_64bit_; }

    // Pure CAPA-compatible per-operand classification
    [[nodiscard]] static OperandKind
        classify(const ZydisDecodedOperand& op, ZydisMachineMode mode) noexcept;

    [[nodiscard]] static std::string_view
        mnemonic_to_string(ZydisMnemonic m) noexcept;

    // ESP/EBP or RSP/RBP per width
    // Used to suppress stack-frame false positives in feature extraction
    [[nodiscard]] std::span<const ZydisRegister>
        stack_registers() const noexcept;

private:
    ZydisDecoder decoder_ {};
    bool         is_64bit_ { false };
};

}  // namespace papa::features::extractors::papa_native
