#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <unordered_set>
#include <vector>

#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/jump_tables.h"
#include "papa/features/extractors/papa_native/noreturn.h"
#include "papa/features/extractors/papa_native/viv/cf_context.h"
#include "papa/features/extractors/papa_native/viv/codeblocks.h"
#include "papa/features/extractors/papa_native/viv/location_db.h"
#include "papa/features/extractors/papa_native/viv/xref_db.h"

namespace papa::features::extractors::papa_native::viv {

/// The VivWorkspace-analog driver. It owns the shared location, cross-reference,
/// and block state, and runs vivisect's function analysis: a CodeFlowContext
/// discovers a function's code, defining a location and recording code
/// cross-references for each instruction as it goes, and the codeblocks fmod runs
/// inline the moment a function's flow completes. Building each function's blocks
/// against the state visible at that instant is what reproduces vivisect's
/// order-dependent, shared-block attribution
class Discovery {
public:
    /// Reads the pointer-sized value stored at an address, or nullopt when it is
    /// unreadable. Stands in for vivisect castPointer
    using ReadPtr = std::function<std::optional<std::uint64_t>(std::uint64_t site)>;
    /// True when an undefined address emulates like the start of a function, the
    /// emucode behavioral verdict (vivisect isProbablyCode via the emulator)
    using IsProbablyCode = std::function<bool(std::uint64_t va)>;

    Discovery(InsnReader read, std::function<bool(std::uint64_t)> is_exec,
              JumpTableResolver resolve_jt = {},
              IsProbablyCode is_probably_code = {}, ReadPtr read_ptr = {},
              std::uint64_t ptr_size = 4, NoReturnOracle api_no_return = {});

    /// Analyze va as a function entry: flow its code, then build its blocks
    void make_function(std::uint64_t va);

    /// True when va is a function whose analysis has completed, matching
    /// vivisect's isFunction (funcmeta set at _cb_function). A function still
    /// being flowed is not yet one
    [[nodiscard]] bool is_function(std::uint64_t va) const {
        return analyzed_.count(va) != 0;
    }

    /// Install the FLIRT analysis fmod, run at the end of each function's
    /// analysis (after codeblocks and noret, the order vivisect registers the
    /// FLIRT analyzers). It may call make_function to create the library
    /// sub-functions a signature names, which is what lets an enclosing function
    /// collapse the way vivisect's FLIRT-driven analysis does. Empty by default,
    /// so the shipped path does no FLIRT-driven creation
    void set_flirt_fmod(std::function<void(std::uint64_t va)> fmod) {
        flirt_fmod_ = std::move(fmod);
    }

    /// The location kind a pointer target should become, or nullopt when va is
    /// already defined or does not look like code. Ports vivisect analyzePointer
    [[nodiscard]] std::optional<LocType> analyze_pointer(std::uint64_t va) const;

    /// Define a pointer location at site and, when follow is set, make its stored
    /// target a function if that target is undefined code. Ports vivisect
    /// makePointer, the relocations pass primitive
    void make_pointer(std::uint64_t site, bool follow);

    [[nodiscard]] const CodeBlockStore& blocks() const noexcept { return blocks_; }
    [[nodiscard]] const LocationDb& locations() const noexcept { return locations_; }
    [[nodiscard]] const XrefDb& xrefs() const noexcept { return xrefs_; }
    /// Every function made so far, in completion (post-order) order
    [[nodiscard]] const std::vector<std::uint64_t>& function_entries() const noexcept {
        return function_entries_;
    }

    /// Materialize every recovered function as a full Function: its basic blocks
    /// with instructions, intra-function successors and predecessors, and its
    /// callees. This is the recovered CFG the feature extractor consumes
    [[nodiscard]] std::vector<Function> materialize_functions() const;

private:
    // Decode-once gate: an address already holding any location is claimed, so a
    // later flow over it decodes nothing (base.py _cb_opcode stops on any loc)
    [[nodiscard]] bool is_defined(std::uint64_t va) const;
    // True when the instruction at va does not fall through (envi IF_NOFALL)
    [[nodiscard]] bool is_no_fall(std::uint64_t va) const;
    // Make va's undefined-code pointer target a function (vivisect followPointer)
    void follow_pointer(std::uint64_t target);
    // Define va as code and record its non-fall code cross-references
    void on_opcode(std::uint64_t va, const DecodedInsn& op,
                   std::span<const CfBranch> branches);
    // Run the codeblocks and noret fmods for the completed function va
    void on_function(std::uint64_t va);
    // True when a call does not return: a call to a no-return import (the API
    // oracle) or to a function already proven no-return. Ports the combined
    // oracle vivisect's noret pass builds over the import seeds
    [[nodiscard]] bool is_no_return_call(const DecodedInsn& op) const;
    // Assemble a Function (blocks with instructions and intra-function
    // successors) from the recovered block state, so the shared function_is_noreturn
    // leaf scan can run over it
    [[nodiscard]] Function materialize_function(std::uint64_t fva) const;

    InsnReader                        read_;
    LocationDb                        locations_;
    XrefDb                            xrefs_;
    CodeBlockStore                    blocks_;
    std::unordered_set<std::uint64_t> no_fall_;
    std::unordered_set<std::uint64_t> analyzed_;  // on_function already ran, base.py:838
    std::unordered_set<std::uint64_t> no_return_functions_;  // proven no-return
    std::vector<std::uint64_t>        function_entries_;
    IsProbablyCode                    is_probably_code_;
    ReadPtr                           read_ptr_;
    NoReturnOracle                    api_no_return_;
    std::function<void(std::uint64_t)> flirt_fmod_;  // FLIRT discovery fmod, opt-in
    std::uint64_t                     ptr_size_{4};
    // Declared last so its this-capturing callbacks see the state above already
    // constructed
    CodeFlowContext cf_;
};

}  // namespace papa::features::extractors::papa_native::viv
