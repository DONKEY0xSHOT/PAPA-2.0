#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/flirt/flirt_classifier.h"

namespace papa::pe {
class PeImage;
}

namespace papa::features::extractors::papa_native::viv {

class Discovery;

/// A FunctionContext over a Discovery's live analysis state plus the image bytes,
/// so FLIRT can run as an interleaved discovery fmod rather than a post-hoc pass.
/// code_at reads the image, xref_from decodes the instruction containing an
/// address and resolves its static reference from the live location map, and
/// is_function_entry consults the functions made so far, so FLIRT sees the
/// in-progress workspace its analyzer sees during vw.analyze
class DiscoveryFlirtContext : public flirt::FunctionContext {
public:
    DiscoveryFlirtContext(const pe::PeImage& image, InsnReader read,
                          const Discovery& disc);

    [[nodiscard]] std::span<const std::uint8_t>
        code_at(std::uint64_t va, std::size_t max_len) const override;
    [[nodiscard]] std::optional<flirt::FlirtXref>
        xref_from(std::uint64_t site_va) const override;
    [[nodiscard]] std::optional<std::string_view>
        import_name(std::uint64_t va) const override;
    [[nodiscard]] bool is_function_entry(std::uint64_t va) const override;

private:
    const pe::PeImage*                image_;
    InsnReader                        read_;
    const Discovery*                  disc_;
    mutable std::vector<std::uint8_t> scratch_;
};

/// The FLIRT analysis module, a port of the analyzers
/// viv_utils.flirt.register_flirt_signature_analyzers adds to the workspace. As
/// each function is made it is matched against every signature tree in registry
/// order, and an accepted match applies viv_utils.flirt's two name loops: a
/// local name at a non-zero offset whose address is undefined and executable
/// becomes its own function, and every named address that is a function is
/// marked a library function under that name. This is the single FLIRT pass, so
/// both the sub-function creation and the library naming the report uses come
/// from here, exactly as capa does it during vw.analyze
class FlirtDiscoveryAnalyzer {
public:
    /// Creates a function at va during discovery, the makeFunction the local-name
    /// loop performs. The driver applies the undefined and executable gate
    using MakeFunction = std::function<void(std::uint64_t va)>;
    /// True when va is a function whose analysis has completed (vw.isFunction)
    using IsFunction = std::function<bool(std::uint64_t va)>;

    /// matchers are the loaded signature trees in registry order, one matcher
    /// each, mirroring capa's one analyzer per .sig file
    FlirtDiscoveryAnalyzer(std::vector<flirt::ModuleMatchFn> matchers,
                           const flirt::FunctionContext&     context,
                           MakeFunction make_function, IsFunction is_function);

    /// Run the FLIRT analyzers on the function at va
    void on_function(std::uint64_t va);

    /// Every address a match marked a library function, with its assigned name.
    /// This is the workspace's library state, what is_library_function reads
    [[nodiscard]] const std::unordered_map<std::uint64_t, std::string>&
    library_names() const noexcept {
        return library_names_;
    }

private:
    // Apply viv_utils.flirt's local-name then public-name loops for a winner
    void apply_names(std::uint64_t va, const flirt::FlirtModule& winner);

    std::vector<flirt::ModuleMatchFn> matchers_;
    const flirt::FunctionContext*     context_;
    MakeFunction                      make_function_;
    IsFunction                        is_function_;
    // The library functions found so far, keyed by address. A function already in
    // here is skipped by later trees, the is_library_function short-circuit at the
    // top of match_function_flirt_signatures
    std::unordered_map<std::uint64_t, std::string> library_names_;
};

}  // namespace papa::features::extractors::papa_native::viv
