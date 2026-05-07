#include "papa/features/extractors/papa_native/function.h"

#include "papa/features/address.h"
#include "papa/features/common.h"
#include "papa/features/file.h"
#include "papa/features/extractors/papa_native/cfg.h"
#include "papa/features/extractors/papa_native/disassembler.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stack>
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

[[nodiscard]] features::Address va_addr(std::uint64_t va) noexcept {
    return features::Address{features::AbsoluteVirtualAddress{va}};
}

[[nodiscard]] FeatureWithAddress
make_characteristic(const char* name, std::uint64_t va) {
    return { std::make_shared<const features::Characteristic>(std::string(name)),
             va_addr(va) };
}

// State for one Tarjan-SCC iteration over a function's BB graph
// The algorithm runs on indices into fn.basic_blocks because that gives
// constant-time successor lookups via bb_index map
struct TarjanState {
    std::vector<int>          index_of;            // -1 means unvisited
    std::vector<int>          lowlink;
    std::vector<bool>         on_stack;
    std::stack<std::size_t>   work_stack;
    int                       next_index{0};
    bool                      found_cycle{false};
};

// Recursive Tarjan strongconnect
// Depth is bounded by the number of basic blocks in fn, which is itself capped
// by kMaxFunctionsPerImage during CFG recovery. Synthetic functions used in
// unit tests are tiny, so the recursion depth here is not a concern in practice
void strongconnect(std::size_t                                                v,
                   const std::vector<std::vector<std::size_t>>&               succ,
                   TarjanState&                                                state) {
    if (state.found_cycle) { return; }
    state.index_of[v] = state.next_index;
    state.lowlink[v]  = state.next_index;
    ++state.next_index;
    state.work_stack.push(v);
    state.on_stack[v] = true;

    for (const std::size_t w : succ[v]) {
        if (state.index_of[w] == -1) {
            strongconnect(w, succ, state);
            state.lowlink[v] = std::min(state.lowlink[v], state.lowlink[w]);
        } else if (state.on_stack[w]) {
            state.lowlink[v] = std::min(state.lowlink[v], state.index_of[w]);
        }
    }

    if (state.lowlink[v] == state.index_of[v]) {
        // Pop the entire SCC
        // Non-trivial means size >= 2 in CAPA's loop characteristic
        std::size_t component_size = 0;
        while (!state.work_stack.empty()) {
            const std::size_t w = state.work_stack.top();
            state.work_stack.pop();
            state.on_stack[w] = false;
            ++component_size;
            if (w == v) { break; }
        }
        if (component_size >= 2) { state.found_cycle = true; }
    }
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
            if (it == bb_index.end()) { continue; }
            succ[i].push_back(it->second);
        }
    }

    TarjanState state;
    state.index_of.assign(n, -1);
    state.lowlink.assign(n, -1);
    state.on_stack.assign(n, false);

    for (std::size_t i = 0; i < n && !state.found_cycle; ++i) {
        if (state.index_of[i] == -1) { strongconnect(i, succ, state); }
    }
    if (!state.found_cycle) { return std::nullopt; }
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
        va_addr(fn.va)
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

}  // namespace papa::features::extractors::papa_native::function_
