#include "papa/features/extractors/papa_native/backend.h"

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/features/extractors/papa_native/insn.h"
#include "papa/pe/pe_image.h"

#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native {

PapaNativeBackend::PapaNativeBackend(const ::papa::pe::PeImage& image,
                                     Disassembler               disasm,
                                     std::vector<Function>      funcs,
                                     ImportTable                imps)
    : image_(&image),
      disasm_(std::move(disasm)),
      functions_(std::move(funcs)),
      imports_(std::move(imps)) {}

PapaNativeBackend::~PapaNativeBackend()                                   = default;
PapaNativeBackend::PapaNativeBackend(PapaNativeBackend&&) noexcept        = default;
PapaNativeBackend& PapaNativeBackend::operator=(PapaNativeBackend&&) noexcept = default;

::papa::Expected<PapaNativeBackend>
PapaNativeBackend::build(const ::papa::pe::PeImage& image) {
    // The disassembler is constructed first because every downstream artifact
    // depends on its bitness and decoded operand semantics
    Disassembler disasm(image.is_64bit());

    auto cfg_result = Cfg::recover(image, disasm);
    if (!cfg_result) {
        return ::papa::Unexpected{cfg_result.error()};
    }

    ImportTable imports = build_import_table(image);
    return PapaNativeBackend(image,
                             std::move(disasm),
                             std::move(*cfg_result),
                             std::move(imports));
}

const ::papa::pe::PeImage& PapaNativeBackend::image() const noexcept {
    // The pointer is non-null after construction
    // build() either returns by value or fails outright so dereferencing
    // here is always safe
    return *image_;
}

const Disassembler& PapaNativeBackend::disassembler() const noexcept {
    return disasm_;
}

const std::vector<Function>& PapaNativeBackend::functions() const noexcept {
    return functions_;
}

const ImportTable& PapaNativeBackend::imports() const noexcept {
    return imports_;
}

}  // namespace papa::features::extractors::papa_native
