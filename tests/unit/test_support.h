#pragma once

#include "papa/constants.h"
#include "papa/engine.h"
#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/flirt/flirt.h"
#include "papa/rules/rule.h"
#include "papa/rules/scope.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

/// Helpers shared by the unit tests
namespace papa_tests {

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

}  // namespace papa_tests
