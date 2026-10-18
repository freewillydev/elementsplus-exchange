#pragma once
#include <usdd_sp1_resources.h>
#include <simplicity/elements/primitiveJetCost.inc>
#include <simplicity/limitations.h>

namespace usdd_reference {
using namespace usdd;
inline bool NativeAnnexNamespace(Span<const unsigned char> annex)
{
    static constexpr std::array<unsigned char, 5> prefix{{0x50, 'U', 'S', 'D', 'D'}};
    return annex.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), annex.begin());
}

// Frozen legacy budget reference; no production callers remain.
/**
 * The exact frozen controller receives its exact analysed execution budget.
 *
 * Simplicity budgets are expressed in whole WU while generated jet costs are
 * milliWU. The ordinary witness-derived base budget is bounded by the reserved
 * proof-transaction lane. The host gate has already pinned the script CMR, and
 * Simplicity independently recomputes that CMR from the decoded 6,155-byte
 * program before execution. Therefore the exact controller program, rather
 * than a generic budget heuristic, is the structural invariant that fixes how
 * many verifier nodes can execute.
 *
 * The pinned cost below is the result of decoding that exact program with the
 * frozen Elements jet catalogue and running Simplicity's static bound analysis.
 * Granting less rejects the canonical controller before cryptographic proof
 * verification; granting more is unnecessary. A generic program containing a
 * duplicated verifier remains outside the exact CMR-gated lane.
 */
static constexpr uint64_t SP1_VERIFIER_JET_COST_MWU{
    SIMPLICITY_VERIFY_SP1_COMPRESSED_SHA256_COST_MWU};
static_assert(SP1_VERIFIER_JET_COST_MWU ==
              ElementsDrivechainIdentity::VERIFY_SP1_COMPRESSED_SHA256_JET_COST_MWU);
static constexpr uint64_t SP1_CONTROLLER_PROGRAM_COST_MWU{3'532'580'406ULL};
static constexpr int64_t SP1_CONTROLLER_PROGRAM_BUDGET_WU{
    static_cast<int64_t>((SP1_CONTROLLER_PROGRAM_COST_MWU + 999U) / 1000U)};
static constexpr int64_t SP1_VERIFIER_BASE_BUDGET_MAX_WU{
    ElementsDrivechainIdentity::USDD_SP1_PROOF_TX_MAX_WEIGHT};
static_assert(
    static_cast<uint64_t>(SP1_CONTROLLER_PROGRAM_BUDGET_WU - 1) * 1000U <
        SP1_CONTROLLER_PROGRAM_COST_MWU,
    "USDD controller budget must be the minimum whole-WU execution ceiling");
static_assert(
    static_cast<uint64_t>(SP1_CONTROLLER_PROGRAM_BUDGET_WU) * 1000U >=
        SP1_CONTROLLER_PROGRAM_COST_MWU,
    "USDD controller execution must fit its whole-WU budget");
static_assert(SP1_CONTROLLER_PROGRAM_BUDGET_WU <= BUDGET_MAX,
              "USDD controller execution must fit Simplicity's global budget");
static_assert(SP1_VERIFIER_BASE_BUDGET_MAX_WU <
                  SP1_CONTROLLER_PROGRAM_BUDGET_WU,
              "proof-lane base budget must remain below controller execution budget");

inline bool ComputeUsddSp1VerifierBudget(const int64_t base_budget_wu,
                                         int64_t& credited_budget_wu)
{
    if (base_budget_wu < 0 ||
        base_budget_wu > SP1_VERIFIER_BASE_BUDGET_MAX_WU) {
        return false;
    }
    if constexpr (ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
        // V11 has no global controller CMR/program pin. Consequently neither
        // an annex nor a mutable configuration may grant reserved execution
        // weight to an arbitrary leaf. Parameterized leaves must fit the
        // ordinary witness-derived budget and Simplicity's BUDGET_MAX.
        credited_budget_wu = base_budget_wu;
    } else {
        credited_budget_wu = SP1_CONTROLLER_PROGRAM_BUDGET_WU;
    }
    return true;
}

inline Sp1AnnexResourceUsage NativeResourceUsage(const CTransaction& tx)
{
    Sp1AnnexResourceUsage usage;
    for (const auto& input_witness : tx.witness.vtxinwit) {
        const auto& stack = input_witness.scriptWitness.stack;
        if (stack.size() < 2 ||
            !NativeAnnexNamespace(stack.back())) {
            continue;
        }
        ++usage.namespace_annexes;
        usage.oversized |= stack.back().size() > SP1_ANNEX_MAX_SIZE;

        Sp1ProofAnnexView parsed;
        const Sp1AnnexError parse_error =
            ParseUsddSp1ProofAnnex(stack.back(), parsed);
        switch (parse_error) {
        case Sp1AnnexError::OK:
            break;
        case Sp1AnnexError::PUBLIC_VALUES_TOO_LARGE:
            // Preserve rejection while reporting the precise bounded-field
            // violation. All other parser failures remain malformed-envelope
            // errors, including V11 zero or wrong-width public values.
            usage.malformed_public_values = true;
            continue;
        case Sp1AnnexError::NOT_USDD:
        case Sp1AnnexError::TOO_LARGE:
        case Sp1AnnexError::TRUNCATED:
        case Sp1AnnexError::BAD_MAGIC:
        case Sp1AnnexError::BAD_VERSION:
        case Sp1AnnexError::BAD_PROOF_SYSTEM:
        case Sp1AnnexError::BAD_STATEMENT_KIND:
        case Sp1AnnexError::BAD_DIGEST_MODE:
        case Sp1AnnexError::BAD_FLAGS:
        case Sp1AnnexError::EMPTY_PUBLIC_VALUES:
        case Sp1AnnexError::INVALID_STRONG_EXECUTION_PUBLIC_VALUES:
        case Sp1AnnexError::EMPTY_PROOF:
        case Sp1AnnexError::ZERO_GUEST_PROGRAM_ID:
        case Sp1AnnexError::LENGTH_MISMATCH:
            usage.malformed = true;
            continue;
        }

        if constexpr (ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
            if (parsed.statement_kind !=
                Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2) {
                usage.malformed = true;
                continue;
            }
        }

        // A reserved proof annex is valid only on the exact structural form
        // of a Tapsimplicity script-path spend:
        //
        //   witness, program, script CMR, control block, annex
        //
        // UTXO commitment and program/CMR equality remain script-consensus
        // checks. This context-free rule also compares the carried CMR and
        // annex guest ID to the frozen pair, preventing any other key path,
        // Tapscript, or Tapsimplicity program from occupying the proof lane.
        if (stack.size() != SP1_TAPSIMPLICITY_WITNESS_ITEMS ||
            stack[2].size() != 32) {
            usage.wrong_spend_shape = true;
            continue;
        }
        const auto& control = stack[3];
        const bool wrong_spend_shape =
            control.size() < SP1_TAPROOT_CONTROL_BASE_SIZE ||
            control.size() > SP1_TAPROOT_CONTROL_MAX_SIZE ||
            (control.size() - SP1_TAPROOT_CONTROL_BASE_SIZE) %
                    SP1_TAPROOT_CONTROL_NODE_SIZE !=
                0 ||
            (control[0] & SP1_TAPROOT_LEAF_MASK) !=
                SP1_TAPSIMPLICITY_LEAF_VERSION;
        usage.wrong_spend_shape |= wrong_spend_shape;
        if (wrong_spend_shape) continue;

        if constexpr (ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
            continue;
        }

        switch (CheckUsddSp1ProofIdentity(
            stack[2], parsed.guest_program_id, parsed.public_values)) {
        case Sp1ProofIdentityResult::MATCH:
            break;
        case Sp1ProofIdentityResult::WRONG_CONTROLLER_CMR:
            usage.wrong_controller_cmr = true;
            break;
        case Sp1ProofIdentityResult::WRONG_GUEST_PROGRAM_ID:
            usage.wrong_guest_program_id = true;
            break;
        case Sp1ProofIdentityResult::MALFORMED_PUBLIC_VALUES:
            usage.malformed_public_values = true;
            break;
        case Sp1ProofIdentityResult::DEPLOYMENT_UNCONFIGURED:
            usage.deployment_unconfigured = true;
            break;
        case Sp1ProofIdentityResult::WRONG_INBOUND_MINT_DOMAIN:
            usage.wrong_inbound_mint_domain = true;
            break;
        }
    }
    return usage;
}
}
