#ifndef BITCOIN_SCRIPT_ECX_ACTIVATION_ANNEX_H
#define BITCOIN_SCRIPT_ECX_ACTIVATION_ANNEX_H

#include <script/script.h>
#include <uint256.h>
#include <haskell/bridge.h>
#include <algorithm>
#include <array>
#include <cstdint>
extern "C" {
#include <simplicity/elements/env.h>
}

namespace ecx {
// Static simplicity_analyseBounds result for the exact CMR below with the
// unchanged frozen catalogue: 1,002,635,231 milliWU, rounded up to WU.
// This is a consensus allowance, not a measured runtime. No other program gets
// this credit, even if a different activation CMR is configured later.
#include <haskell/activation_constants.h>

inline bool ParseActivationAnnex(const std::vector<std::vector<unsigned char>>& stack,
    std::array<unsigned char, 32>& program, std::array<unsigned char, 364>& values)
{
    if (!drivechain::haskell::ActivationShape([&](uint32_t step) -> int64_t {
        switch (step) {
        case 0: return stack.size();
        case 1: return stack.at(2).size();
        case 2: return stack.at(4).size();
        case 3: return stack.at(4).at(0);
        case 4: return stack.at(3).size();
        case 5: return stack.at(3).at(0);
        default: throw std::logic_error("unknown activation shape fact");
        }
    })) return false;
    std::array<unsigned char, 32> digest{};
    return simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        stack[4].data() + 1, stack[4].size() - 1,
        program.data(), digest.data(), values.data());
}

inline int64_t ActivationExecutionBudget(int64_t ordinary, unsigned int input,
    const std::vector<std::vector<unsigned char>>& stack, const uint256* frozen_cmr,
    const uint256* frozen_program)
{
    std::array<unsigned char, 32> program{};
    std::array<unsigned char, 364> values{};
    // The interpreter already verified the Taproot leaf commitment. Its unchanged
    // CMR commits to the full program and proof/identity checks.
    return drivechain::haskell::ActivationBudget(ordinary, input, [&](uint32_t step) {
        switch (step) {
        case 0: return frozen_cmr != nullptr;
        case 1: return frozen_program != nullptr;
        case 2: return !frozen_program->IsNull();
        case 3: return std::equal(ACTIVATION_BUDGET_CMR.begin(), ACTIVATION_BUDGET_CMR.end(), frozen_cmr->begin());
        case 4: return ParseActivationAnnex(stack, program, values);
        case 5: return std::equal(stack.at(2).begin(), stack.at(2).end(), frozen_cmr->begin());
        case 6: return std::equal(program.begin(), program.end(), frozen_program->begin());
        default: throw std::logic_error("unknown activation credit fact");
        }
    });
}
} // namespace ecx
#endif
