// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_USDD_SP1_RESOURCES_H
#define BITCOIN_USDD_SP1_RESOURCES_H

#include <primitives/transaction.h>
#include <script/usdd_sp1_annex.h>
#include <simplicity/elements/env.h>

#include <cstddef>
#include <cstdint>

namespace usdd {

static_assert(SP1_ANNEX_MAX_SIZE ==
                  SIMPLICITY_ELEMENTS_MAX_OWNED_ANNEX_SIZE,
              "SP1 consensus and Simplicity owned-annex limits must match");

/** One deterministic proof-verification lane is available in each block. */
static constexpr std::size_t SP1_ANNEXES_PER_BLOCK{
    ElementsDrivechainIdentity::USDD_SP1_ANNEXES_PER_BLOCK};
/** Consensus and policy ceiling for the transaction occupying that lane. */
static constexpr uint64_t SP1_PROOF_TX_MAX_WEIGHT{
    ElementsDrivechainIdentity::USDD_SP1_PROOF_TX_MAX_WEIGHT};
static_assert(SP1_PROOF_TX_MAX_WEIGHT * 4U <=
              ElementsDrivechainIdentity::CONSENSUS_MAX_BLOCK_WEIGHT,
              "one proof transaction must consume at most 25% of a block");
static_assert(
    ElementsDrivechainIdentity::USDD_SP1_MAX_ANNEX_WEIGHT <
        SP1_PROOF_TX_MAX_WEIGHT,
    "maximum annex must leave deterministic transaction headroom");

struct Sp1AnnexResourceUsage {
    std::size_t namespace_annexes{0};
    bool oversized{false};
    bool malformed{false};
    bool wrong_spend_shape{false};
    bool wrong_controller_cmr{false};
    bool wrong_guest_program_id{false};
    bool malformed_public_values{false};
    bool deployment_unconfigured{false};
    bool wrong_inbound_mint_domain{false};

    uint32_t Flags() const
    {
        return (oversized << 1) | (malformed << 2) | (wrong_spend_shape << 3) |
               (wrong_controller_cmr << 4) | (wrong_guest_program_id << 5) |
               (malformed_public_values << 6) | (deployment_unconfigured << 7) |
               (wrong_inbound_mint_domain << 8);
    }
};

static constexpr std::size_t SP1_TAPSIMPLICITY_WITNESS_ITEMS{5};
static constexpr std::size_t SP1_TAPROOT_CONTROL_BASE_SIZE{33};
static constexpr std::size_t SP1_TAPROOT_CONTROL_NODE_SIZE{32};
static constexpr std::size_t SP1_TAPROOT_CONTROL_MAX_SIZE{
    SP1_TAPROOT_CONTROL_BASE_SIZE + 128 * SP1_TAPROOT_CONTROL_NODE_SIZE};
static constexpr unsigned char SP1_TAPROOT_LEAF_MASK{0xfe};
static constexpr unsigned char SP1_TAPSIMPLICITY_LEAF_VERSION{0xbe};

inline bool ExceedsUsddSp1AnnexLane(const std::size_t current,
                                    const std::size_t additional)
{
    static_assert(SP1_ANNEXES_PER_BLOCK <= UINT32_MAX);
    return drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::LANE_EXCEEDED,
        SP1_ANNEXES_PER_BLOCK, 0, current, additional);
}

/**
 * Count BIP341-shaped annexes in the reserved 0x50 || "USDD" namespace.
 *
 * Count the raw namespace before parsing it, so malformed members consume the
 * same deterministic lane and cannot evade the cap. V11 performs only
 * structural/resource admission here. Authorization belongs exclusively to
 * successful execution of the configuration-bound Simplicity leaf and its
 * verifier jet. Historical profiles retain their frozen-pair prefilter.
 */
class ResourceReader {
    const CTransaction* m_tx{nullptr};
public:
    uint64_t Select(const CTransaction& tx) {
        m_tx = &tx;
        return tx.witness.vtxinwit.size();
    }
    drivechain::haskell::UsddResourceSource Source() const {
        using namespace ElementsDrivechainIdentity;
        return {{{ {}, HISTORICAL_V8_CONTROLLER_CMR, {}, USDD_SP1_GUEST_PROGRAM_ID, {}, USDD_SP1_INBOUND_MINT_DOMAIN_ID, {} }},
            {USDD_SP1_DEPLOYMENT_BINDING_VERSION, USDD_SP1_ANNEX_DIGEST_MODE, USDD_SP1_ANNEX_STATEMENT_KIND,
             USDD_SP1_ANNEX_ENVELOPE_VERSION, USDD_SP1_ANNEX_PROOF_SYSTEM},
            SP1_ANNEX_MAX_SIZE,V11_PARAMETERIZED_CONTROLLER_PROFILE,[this](uint64_t index) {
            if (!m_tx) throw std::logic_error("USDD resource transaction not selected");
            const auto& stack = m_tx->witness.vtxinwit.at(index).scriptWitness.stack;
            using Bytes = std::span<const unsigned char>;
            return drivechain::haskell::UsddWitness{stack.empty() ? Bytes{} : Bytes{stack.back()},
                stack.size()>2 ? Bytes{stack[2]} : Bytes{}, stack.size()>3 ? Bytes{stack[3]} : Bytes{},stack.size()};
        }};
    }
};

inline Sp1AnnexResourceUsage GetUsddSp1AnnexResourceUsage(const CTransaction& tx)
{
    Sp1AnnexResourceUsage usage;
    ResourceReader reader;
    const auto witnesses = reader.Select(tx);
    // With no witnesses there are no rows to classify.
    if (!witnesses) return usage;
    const auto source = reader.Source();
    const auto [flags,count] = drivechain::haskell::UsddResources(witnesses,source.fields,source.profile,
        source.limit,source.parameterized,source.read);
    usage.namespace_annexes = count;
    usage.oversized = flags & 2;
    usage.malformed = flags & 4;
    usage.wrong_spend_shape = flags & 8;
    usage.wrong_controller_cmr = flags & 16;
    usage.wrong_guest_program_id = flags & 32;
    usage.malformed_public_values = flags & 64;
    usage.deployment_unconfigured = flags & 128;
    usage.wrong_inbound_mint_domain = flags & 256;
    return usage;
}

} // namespace usdd

#endif // BITCOIN_USDD_SP1_RESOURCES_H
