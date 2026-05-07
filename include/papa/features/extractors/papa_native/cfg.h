#pragma once

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/disassembler.h"
#include "papa/pe/pe_image.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace papa::features::extractors::papa_native {

// One straight-line run of instructions with no branches inside
struct BasicBlock {
    std::uint64_t              va{0};
    std::vector<DecodedInsn>   instructions;
    std::vector<std::uint64_t> successors;
    std::vector<std::uint64_t> predecessors;
};

// One function recovered by CFG analysis
struct Function {
    std::uint64_t              va{0};
    std::vector<BasicBlock>    basic_blocks;
    std::vector<std::uint64_t> callers;
    std::vector<std::uint64_t> callees;
    bool                       likely_library{false};
};

// Callback returning a decoded instruction at a given VA
// Errors are fatal to the single function being recovered, not to the image
using InsnReader =
    std::function<Expected<DecodedInsn>(std::uint64_t va)>;

class Cfg {
public:
    // Top-level: seed from entry/exports/TLS/pdata, worklist across new call targets
    [[nodiscard]] static Expected<std::vector<Function>>
        recover(const pe::PeImage& image, const Disassembler& disasm);

    // Recover one function given an instruction reader
    // Shared by production callers and unit tests
    [[nodiscard]] static Expected<Function>
        recover_one(const InsnReader& read, std::uint64_t start_va);

    // Build an InsnReader that decodes through a PE image
    [[nodiscard]] static InsnReader
        make_image_reader(const pe::PeImage& image, const Disassembler& disasm);

    // Build an InsnReader over a contiguous region starting at base_va
    [[nodiscard]] static InsnReader
        make_span_reader(std::span<const std::byte> region,
                         std::uint64_t base_va,
                         const Disassembler& disasm);
};

}  // namespace papa::features::extractors::papa_native
