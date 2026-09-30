#include "papa/features/feature.h"

#include "papa/engine.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

namespace papa::features {

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

bool Feature::matches(const FeatureSet& fs) const {
    const FeaturePtr probe(std::shared_ptr<const Feature>{}, this);
    return fs.find(probe) != fs.end();
}

std::size_t ValueFeature::hash() const noexcept {
    return mix_tag(tag_, std::hash<std::string>{}(value_));
}

bool ValueFeature::equals(const Feature& o) const noexcept {
    // A matching tag implies the same concrete type, and every such type is a ValueFeature
    return o.tag() == tag_ && value_ == static_cast<const ValueFeature&>(o).value_;
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
