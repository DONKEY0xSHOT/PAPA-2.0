#pragma once

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "papa/features/extractors/papa_native/viv/br_flags.h"

namespace papa::features::extractors::papa_native::viv {

/// One REF_CODE cross-reference: a code edge from one instruction to another,
/// carrying the envi BR_* branch flags vivisect stores on the xref
struct CodeXref {
    std::uint64_t from_va{0};
    std::uint64_t to_va{0};
    std::uint16_t branch_flags{0};
};

/// The global REF_CODE cross-reference store, the read model codeblocks walks
/// through code_xrefs_from and has_code_xref_to. A faithful stand-in for the
/// code portion of vivisect's xref database (getXrefsFrom / getXrefsTo over
/// REF_CODE)
class XrefDb {
public:
    /// Record a code edge from from_va to to_va. A repeated (from, to) is not
    /// duplicated, its branch flags accumulate, matching vivisect addXref
    void add_code_xref(std::uint64_t from_va, std::uint64_t to_va,
                       std::uint16_t branch_flags);

    /// The outgoing code edges of an instruction, or an empty list when it has
    /// none
    [[nodiscard]] const std::vector<CodeXref>&
    code_xrefs_from(std::uint64_t va) const;

    /// True when any recorded code edge targets va, codeblocks' block-join test
    [[nodiscard]] bool has_code_xref_to(std::uint64_t va) const noexcept;

private:
    std::unordered_map<std::uint64_t, std::vector<CodeXref>> from_;
    std::unordered_set<std::uint64_t>                        to_;
};

}  // namespace papa::features::extractors::papa_native::viv
