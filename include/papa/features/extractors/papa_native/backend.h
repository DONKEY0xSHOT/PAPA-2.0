#pragma once

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/insn.h"
#include "papa/pe/pe_image.h"

#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

class PapaNativeBackend {
public:
    // Construct a backend from a parsed image
    // Internally: build a Disassembler, recover the CFG, and index the IAT
    // Returns ErrorKind::kDisassemblyFailed when CFG recovery fails outright
    // Partial recovery is preserved on success so a handful of unparseable
    // functions do not abort the whole image
    [[nodiscard]] static Expected<PapaNativeBackend>
    build(const ::papa::pe::PeImage& image);

    PapaNativeBackend(PapaNativeBackend&&) noexcept;
    PapaNativeBackend& operator=(PapaNativeBackend&&) noexcept;
    PapaNativeBackend(const PapaNativeBackend&)            = delete;
    PapaNativeBackend& operator=(const PapaNativeBackend&) = delete;
    ~PapaNativeBackend();

    [[nodiscard]] const ::papa::pe::PeImage&    image()        const noexcept;
    [[nodiscard]] const Disassembler&           disassembler() const noexcept;
    [[nodiscard]] const std::vector<Function>&  functions()    const noexcept;
    [[nodiscard]] const ImportTable&            imports()      const noexcept;

private:
    PapaNativeBackend(const ::papa::pe::PeImage& image,
                      Disassembler               disasm,
                      std::vector<Function>      funcs,
                      ImportTable                imps);

    const ::papa::pe::PeImage* image_{nullptr};
    Disassembler               disasm_;
    std::vector<Function>      functions_;
    ImportTable                imports_;
};

}  // namespace papa::features::extractors::papa_native
