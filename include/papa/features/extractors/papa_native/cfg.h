#pragma once

#include "papa/exceptions.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
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
};

// What one analysis run recovers: the functions, plus the library functions FLIRT
// identified along the way with the name it assigned each
struct RecoveredImage {
    std::vector<Function>                          functions;
    std::unordered_map<std::uint64_t, std::string> library_names;
};

// Callback returning a decoded instruction at a given VA
// Errors are fatal to the single function being recovered, not to the image
using InsnReader = std::function<Expected<DecodedInsn>(std::uint64_t va)>;

}  // namespace papa::features::extractors::papa_native
