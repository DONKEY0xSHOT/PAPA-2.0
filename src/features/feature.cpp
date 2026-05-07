#include "papa/features/feature.h"

#include "papa/engine.h"

#include <memory>
#include <string_view>

namespace papa::features {

std::string_view to_string(FeatureTag t) noexcept {
    switch (t) {
        case FeatureTag::kString:         return "string";
        case FeatureTag::kSubstring:      return "substring";
        case FeatureTag::kRegex:          return "regex";
        case FeatureTag::kBytes:          return "bytes";
        case FeatureTag::kNumber:         return "number";
        case FeatureTag::kOffset:         return "offset";
        case FeatureTag::kMnemonic:       return "mnemonic";
        case FeatureTag::kApi:            return "api";
        case FeatureTag::kImport:         return "import";
        case FeatureTag::kExport:         return "export";
        case FeatureTag::kSection:        return "section";
        case FeatureTag::kFunctionName:   return "function-name";
        case FeatureTag::kClass:          return "class";
        case FeatureTag::kNamespace:      return "namespace";
        case FeatureTag::kProperty:       return "property";
        case FeatureTag::kCharacteristic: return "characteristic";
        case FeatureTag::kMatchedRule:    return "match";
        case FeatureTag::kOs:             return "os";
        case FeatureTag::kArch:           return "arch";
        case FeatureTag::kFormat:         return "format";
        case FeatureTag::kOperandNumber:  return "operand.number";
        case FeatureTag::kOperandOffset:  return "operand.offset";
        case FeatureTag::kBasicBlock:     return "basic block";
    }
    return "unknown";
}

std::size_t FeatureHashKey::operator()(const FeaturePtr& p) const noexcept {
    return p ? p->hash() : 0;
}

bool FeatureEqKey::operator()(const FeaturePtr& a, const FeaturePtr& b) const noexcept {
    if (a.get() == b.get()) { return true; }
    if (!a || !b)           { return false; }
    return a->equals(*b);
}

engine::Result Feature::evaluate(const FeatureSet& fs, bool /*short_circuit*/) const {
    // Build an aliasing shared_ptr that does not own *this so we can probe the map
    // without allocating a new Feature or transferring ownership
    const FeaturePtr probe(std::shared_ptr<const Feature>{}, this);
    engine::Result r;
    r.node = this;
    auto it = fs.find(probe);
    if (it != fs.end()) {
        r.success = true;
        r.locations.insert(it->second.begin(), it->second.end());
    }
    return r;
}

void FeatureSet::add(FeaturePtr f, const Address& a) {
    if (!f) { return; }
    const FeatureTag tag = f->tag();
    auto [it, inserted] = this->try_emplace(f);
    it->second.insert(a);
    if (inserted) {
        // Maintain tag-specific indices for scanning evaluators
        if (tag == FeatureTag::kString) {
            strings_.push_back(it->first);
        } else if (tag == FeatureTag::kBytes) {
            bytes_.push_back(it->first);
        }
    }
}

void FeatureSet::merge_in(const FeatureSet& other) {
    for (const auto& [f, locs] : other) {
        const FeatureTag tag = f->tag();
        auto [it, inserted] = this->try_emplace(f);
        it->second.insert(locs.begin(), locs.end());
        if (inserted) {
            if (tag == FeatureTag::kString) {
                strings_.push_back(it->first);
            } else if (tag == FeatureTag::kBytes) {
                bytes_.push_back(it->first);
            }
        }
    }
}

}  // namespace papa::features
