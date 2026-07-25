#include "papa/features/extractors/papa_native/viv/xref_db.h"

namespace papa::features::extractors::papa_native::viv {

void XrefDb::add_code_xref(std::uint64_t from_va, std::uint64_t to_va,
                           std::uint16_t branch_flags) {
    std::vector<CodeXref>& edges = from_[from_va];
    for (CodeXref& existing : edges) {
        if (existing.to_va == to_va) {
            existing.branch_flags |= branch_flags;
            return;
        }
    }
    edges.push_back(CodeXref{from_va, to_va, branch_flags});
    to_.insert(to_va);
}

const std::vector<CodeXref>& XrefDb::code_xrefs_from(std::uint64_t va) const {
    static const std::vector<CodeXref> kEmpty;
    const auto it = from_.find(va);
    return it == from_.end() ? kEmpty : it->second;
}

bool XrefDb::has_code_xref_to(std::uint64_t va) const noexcept {
    return to_.count(va) != 0;
}

}  // namespace papa::features::extractors::papa_native::viv
