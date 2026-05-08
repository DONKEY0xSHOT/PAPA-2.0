#include "papa/features/extractors/papa_native/library_signatures.h"

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

namespace {

/// Hex-character to nibble; std::nullopt for non-hex characters.
[[nodiscard]] std::optional<std::uint8_t> hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') { return static_cast<std::uint8_t>(c - '0'); }
    if (c >= 'a' && c <= 'f') { return static_cast<std::uint8_t>(10 + (c - 'a')); }
    if (c >= 'A' && c <= 'F') { return static_cast<std::uint8_t>(10 + (c - 'A')); }
    return std::nullopt;
}

/// Bundled MSVC CRT prologue signatures.
///
/// Each entry is a (name, byte-pattern) pair. Wildcards mark every byte that
/// the linker may rewrite (32-bit RIP-relative displacements following lea/mov,
/// 32-bit branch displacements following call/jmp). Patterns capture enough
/// distinct opcode bytes to be specific without depending on absolute layout.
///
/// Coverage focuses on the helpers that surface in CAPA's parity allow-list:
/// the security-cookie initializer, the SEH common-main wrapper, _initterm,
/// the TLS init helper, and a few short stubs that wrap CRT entry points.
constexpr std::array<std::pair<std::string_view, std::string_view>, 18>
kBundledSignatures = {{
    // __security_init_cookie x64
    // sub rsp,28; lea rax,[rip+disp]; mov rcx,[rax]; ...
    { "msvc_security_init_cookie_x64",
      "48 83 EC 28 48 8D 05 ?? ?? ?? ?? 48 8B 08 48 B8 ?? ?? ?? ?? ?? ?? ?? ??" },

    // __scrt_common_main_seh prologue x64
    // mov [rsp+8],rbx; mov [rsp+10h],rsi; push rdi; sub rsp,N
    { "msvc_scrt_common_main_seh_x64_v1",
      "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 33 ?? E8 ?? ?? ?? ??" },

    // __scrt_common_main_seh prologue x64 alternate (MSVC 2017+)
    { "msvc_scrt_common_main_seh_x64_v2",
      "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 33 ED" },

    // _initterm x64
    // mov [rsp+8],rbx; mov [rsp+10h],rsi; push rdi; sub rsp,20h
    { "msvc_initterm_x64",
      "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B F2 48 8B D9 48 3B D1" },

    // _initterm_e x64 (signed variant)
    { "msvc_initterm_e_x64",
      "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B FA 48 8B D9 48 3B FA" },

    // __scrt_initialize_default_local_stdio_options
    { "msvc_scrt_init_stdio_options_x64",
      "48 83 EC 28 48 8D 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ??" },

    // __scrt_initialize_thread_safe_statics
    { "msvc_scrt_init_thread_safe_statics_x64",
      "48 83 EC 28 E8 ?? ?? ?? ?? 33 C0 48 83 C4 28 C3" },

    // __scrt_acquire_startup_lock prologue
    { "msvc_scrt_acquire_startup_lock_x64",
      "B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 87 05 ?? ?? ?? ?? 83 F8 ?? 75 ??" },

    // __scrt_release_startup_lock prologue
    { "msvc_scrt_release_startup_lock_x64",
      "83 3D ?? ?? ?? ?? ?? 75 ?? B9 ?? ?? ?? ?? E9 ?? ?? ?? ??" },

    // __vcrt_thread_attach helper (TLS dispatcher)
    { "msvc_vcrt_thread_attach_x64",
      "40 53 48 83 EC 20 48 83 3D ?? ?? ?? ?? ?? B3 01 75" },

    // __scrt_dllmain_crt_thread_attach
    { "msvc_scrt_dllmain_crt_thread_attach_x64",
      "40 53 48 83 EC 20 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??" },

    // __scrt_unhandled_exception_filter
    { "msvc_scrt_unhandled_exception_filter_x64",
      "48 83 EC 28 48 8B 41 ?? 81 38 ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ??" },

    // __vcrt_initialize_locks variant
    // mov [rsp+8],rbx; push rdi; sub rsp,20h; mov rbx,rdx; lea r9,[rip+...];
    // mov edi,ecx; lea rdx,[rip+...]; mov ecx,3
    { "msvc_vcrt_initialize_locks_x64",
      "48 89 5C 24 08 57 48 83 EC 20 48 8B DA 4C 8D 0D ?? ?? ?? ?? 8B F9 48 8D 15 ?? ?? ?? ?? B9 03 00 00 00" },

    // __dllonexit / module-exit registration helper
    // push rbx; sub rsp,20h; cmp byte ptr [rip+...],0; mov ebx,ecx; jne ...;
    // cmp ecx,1; ja ...; call ...
    { "msvc_dllonexit_registration_x64",
      "40 53 48 83 EC 20 80 3D ?? ?? ?? ?? 00 8B D9 75 ?? 83 F9 01 77 ?? E8 ?? ?? ?? ??" },

    // PE header validator (CRT module-image check)
    // sub rsp,18h; mov r8,rcx; mov eax,4D5Ah; cmp word ptr [rip+...],ax; jne ...;
    // movsxd rcx,dword ptr [rip+...]; lea rdx,[rip+...]; add rcx,rdx;
    // cmp dword ptr [rcx],4550h
    { "msvc_crt_module_image_validator_x64",
      "48 83 EC 18 4C 8B C1 B8 4D 5A 00 00 66 39 05 ?? ?? ?? ?? 75 ?? 48 63 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 03 CA 81 39 50 45 00 00" },

    // Inline CRC32 / checksum loop body (CRT integrity helper variant)
    // xor ecx,dword ptr [rsi]; movzx eax,cl; shr ecx,8; mov r13,[rsp+...];
    // xor ecx,dword ptr [r9+rax*4+...]
    { "msvc_crt_checksum_loop_a_x64",
      "33 0E 0F B6 C1 C1 E9 08 4C 8B 6C 24 ?? 41 33 8C 81 ?? ?? ?? ??" },

    // Inline CRC32 loop variant b
    // cmp rbp,8; jb ...; mov r8,rbp; shr r8,3; imul rax,r8,FFFFFFF8h;
    // add rbp,rax
    { "msvc_crt_checksum_loop_b_x64",
      "48 83 FD 08 0F 82 ?? ?? ?? ?? 4C 8B C5 49 C1 E8 03 49 6B C0 F8 48 03 E8" },

    // CRT module-image section walker
    // movsxd r8,[rcx+3Ch]; xor r9d,r9d; add r8,rcx; mov r10,rdx;
    // movzx eax,word ptr [r8+14h]; movzx r11d,word ptr [rax+6]; add rax,18h;
    // add rax,r8; test r11d,r11d
    { "msvc_crt_module_section_walker_x64",
      "4C 63 41 3C 45 33 C9 4C 03 C1 4C 8B D2 41 0F B7 40 14 45 0F B7 58 06 48 83 C0 18 49 03 C0 45 85 DB" },
}};

}  // namespace

std::optional<PrologueSignature>
parse_signature_entry(std::string_view name, std::string_view byte_pattern) {
    PrologueSignature out;
    out.name.assign(name);
    out.bytes.reserve(byte_pattern.size() / 3 + 1);

    std::size_t i = 0;
    while (i < byte_pattern.size()) {
        // Skip ASCII whitespace between bytes
        if (byte_pattern[i] == ' ' || byte_pattern[i] == '\t') { ++i; continue; }
        if (i + 1 >= byte_pattern.size()) { return std::nullopt; }

        const char hi = byte_pattern[i];
        const char lo = byte_pattern[i + 1];
        if (hi == '?' && lo == '?') {
            out.bytes.push_back(std::nullopt);
        } else {
            const auto h = hex_nibble(hi);
            const auto l = hex_nibble(lo);
            if (!h.has_value() || !l.has_value()) { return std::nullopt; }
            out.bytes.push_back(static_cast<std::uint8_t>((*h << 4) | *l));
        }
        i += 2;
    }
    if (out.bytes.empty()) { return std::nullopt; }
    return out;
}

LibrarySignatureSet LibrarySignatureSet::make_default() {
    LibrarySignatureSet set;
    set.signatures_.reserve(kBundledSignatures.size());
    for (const auto& [name, pattern] : kBundledSignatures) {
        if (auto sig = parse_signature_entry(name, pattern); sig.has_value()) {
            set.signatures_.push_back(std::move(*sig));
        }
    }
    return set;
}

void LibrarySignatureSet::set_signatures(std::vector<PrologueSignature> sigs) noexcept {
    signatures_ = std::move(sigs);
}

bool LibrarySignatureSet::is_thunk(const Function& fn) noexcept {
    // A thunk is a single basic block that contains exactly one instruction
    // and that instruction is an unconditional jmp or call through memory
    if (fn.basic_blocks.size() != 1) { return false; }
    const auto& bb = fn.basic_blocks.front();
    if (bb.instructions.size() != 1) { return false; }

    const auto& ins = bb.instructions.front();
    const bool is_uncond_branch =
        (ins.is_jump || ins.is_call) && !ins.is_conditional;
    if (!is_uncond_branch) { return false; }
    if (ins.operand_count == 0) { return false; }

    const auto& op0 = ins.operands.front();
    // kImmMem is x86 absolute "[disp32]"
    // kRipRel is x64 RIP-relative "[rip+disp]"
    // Both encode a memory operand whose target is an IAT slot in normal thunks
    return op0.kind == OperandKind::kImmMem || op0.kind == OperandKind::kRipRel;
}

bool LibrarySignatureSet::matches_signature(
    std::span<const std::uint8_t> prologue_bytes) const noexcept {
    for (const auto& sig : signatures_) {
        if (prologue_bytes.size() < sig.bytes.size()) { continue; }
        bool ok = true;
        for (std::size_t i = 0; i < sig.bytes.size(); ++i) {
            const auto& expected = sig.bytes[i];
            if (!expected.has_value()) { continue; }
            if (prologue_bytes[i] != *expected) { ok = false; break; }
        }
        if (ok) { return true; }
    }
    return false;
}

bool LibrarySignatureSet::classify_as_library(
    const Function&                fn,
    std::span<const std::uint8_t>  prologue_bytes) const noexcept {
    if (is_thunk(fn))                              { return true; }
    if (matches_signature(prologue_bytes))         { return true; }
    return false;
}

}  // namespace papa::features::extractors::papa_native
