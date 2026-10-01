#include "papa/features/extractors/papa_native/function.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/file.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace papa::features::extractors::papa_native::function_ {

namespace {

constexpr const char* kCharLoop          = "loop";
constexpr const char* kCharCallsFrom     = "calls from";
constexpr const char* kCharCallsTo       = "calls to";
constexpr const char* kCharRecursiveCall = "recursive call";

// True when the block graph has a cycle, which is capa's loop test once self-loops are dropped
// Kahn's peel is iterative, so a crafted chain of blocks cannot exhaust the native stack
[[nodiscard]] bool has_cycle(const std::vector<std::vector<std::size_t>>& succ) {
    std::vector<std::size_t> in_degree(succ.size(), 0);
    for (const auto& targets : succ) {
        for (const std::size_t w : targets) { ++in_degree[w]; }
    }
    std::vector<std::size_t> ready;
    for (std::size_t v = 0; v < succ.size(); ++v) {
        if (in_degree[v] == 0) { ready.push_back(v); }
    }
    std::size_t peeled = 0;
    while (!ready.empty()) {
        const std::size_t v = ready.back();
        ready.pop_back();
        ++peeled;
        for (const std::size_t w : succ[v]) {
            if (--in_degree[w] == 0) { ready.push_back(w); }
        }
    }
    return peeled != succ.size();
}

}  // namespace

std::optional<FeatureWithAddress>
extract_loop(const Function& fn) {
    const std::size_t n = fn.basic_blocks.size();
    if (n < 2) { return std::nullopt; }

    // Build a VA -> index map so we can resolve successors as graph nodes
    std::unordered_map<std::uint64_t, std::size_t> bb_index;
    bb_index.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        bb_index.emplace(fn.basic_blocks[i].va, i);
    }

    std::vector<std::vector<std::size_t>> succ(n);
    for (std::size_t i = 0; i < n; ++i) {
        for (const std::uint64_t s : fn.basic_blocks[i].successors) {
            const auto it = bb_index.find(s);
            // A self-loop alone is a size-one component, which capa does not count
            if (it == bb_index.end() || it->second == i) { continue; }
            succ[i].push_back(it->second);
        }
    }

    if (!has_cycle(succ)) { return std::nullopt; }
    return make_characteristic(kCharLoop, fn.va);
}

std::vector<FeatureWithAddress>
extract_calls_from(const Function& fn) {
    std::vector<FeatureWithAddress> out;
    for (const auto& bb : fn.basic_blocks) {
        for (const auto& ins : bb.instructions) {
            if (!ins.is_call)                      { continue; }
            if (!ins.branch_target.has_value())    { continue; }
            out.push_back(make_characteristic(kCharCallsFrom, ins.va));
        }
    }
    return out;
}

std::vector<FeatureWithAddress>
extract_calls_to(const Function& fn) {
    std::vector<FeatureWithAddress> out;
    out.reserve(fn.callers.size());
    for (const std::uint64_t caller_va : fn.callers) {
        out.push_back(make_characteristic(kCharCallsTo, caller_va));
    }
    return out;
}

std::optional<FeatureWithAddress>
extract_recursive_call(const Function& fn) {
    for (const auto& bb : fn.basic_blocks) {
        for (const auto& ins : bb.instructions) {
            if (!ins.is_call)                      { continue; }
            if (!ins.branch_target.has_value())    { continue; }
            if (*ins.branch_target == fn.va) {
                return make_characteristic(kCharRecursiveCall, ins.va);
            }
        }
    }
    return std::nullopt;
}

std::optional<FeatureWithAddress>
extract_function_name(const Function& fn, std::string_view symbol) {
    if (symbol.empty()) { return std::nullopt; }
    return FeatureWithAddress{
        std::make_shared<const features::FunctionName>(std::string(symbol)),
        va_address(fn.va)
    };
}

std::vector<FeatureWithAddress>
extract_function_features(const Function& fn, std::string_view symbol) {
    std::vector<FeatureWithAddress> out;
    if (auto loop = extract_loop(fn); loop.has_value()) {
        out.push_back(std::move(*loop));
    }
    {
        auto cf = extract_calls_from(fn);
        out.reserve(out.size() + cf.size());
        for (auto& f : cf) { out.push_back(std::move(f)); }
    }
    {
        auto ct = extract_calls_to(fn);
        out.reserve(out.size() + ct.size());
        for (auto& f : ct) { out.push_back(std::move(f)); }
    }
    if (auto rec = extract_recursive_call(fn); rec.has_value()) {
        out.push_back(std::move(*rec));
    }
    if (auto name = extract_function_name(fn, symbol); name.has_value()) {
        out.push_back(std::move(*name));
    }
    return out;
}

bool is_thunk(const Function& fn) noexcept {
    // A thunk is a single basic block that contains exactly one instruction
    // and that instruction is an unconditional jmp or call through memory
    if (fn.basic_blocks.size() != 1) { return false; }
    const auto& bb = fn.basic_blocks.front();
    if (bb.instructions.size() != 1) { return false; }

    const auto& ins = bb.instructions.front();
    const bool is_uncond_branch =
        (ins.is_jump || ins.is_call) && !ins.is_conditional;
    if (!is_uncond_branch) { return false; }
    if (ins.operand_count == 0) { return false; }

    const auto& op0 = ins.operands.front();
    // kImmMem is x86 absolute "[disp32]" and kRipRel is x64 RIP-relative "[rip+disp]",
    // both memory operands whose target is an IAT slot in normal thunks
    return op0.kind == OperandKind::kImmMem || op0.kind == OperandKind::kRipRel;
}

}  // namespace papa::features::extractors::papa_native::function_
