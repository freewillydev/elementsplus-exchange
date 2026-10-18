// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_BMM_H
#define BITCOIN_DRIVECHAIN_BMM_H

#include <primitives/block.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <uint256.h>
#include <haskell/bmm_constants.h>

#include <cstdint>
#include <string>
#include <vector>

class CBlockIndex;
class CCoinsView;
class CCoinsViewCache;
namespace Sidechain::Bitcoin { class CTransaction; struct CMutableTransaction; class CBlockHeader; class CTxOut; }

namespace drivechain {

class BitcoinSignetSignatureChecker final : public BaseSignatureChecker
{
public:
    enum class Mode { BMM, PARENT };
    // PARENT requires input zero of the constructed, nonempty synthetic transaction.
    BitcoinSignetSignatureChecker(const Sidechain::Bitcoin::CTransaction& transaction,
        unsigned int index, Mode mode = Mode::BMM)
        : m_transaction(transaction), m_input_index(index), m_mode(mode) {}
    bool CheckECDSASignature(const std::vector<unsigned char>& signature,
        const std::vector<unsigned char>& key, const CScript& script,
        SigVersion version, unsigned int flags) const override;
private:
    const Sidechain::Bitcoin::CTransaction& m_transaction;
    const unsigned int m_input_index;
    const Mode m_mode;
};

int BitcoinWitnessCommitmentIndex(const std::vector<Sidechain::Bitcoin::CTxOut>& outputs);
bool ExtractTaggedParentCommitment(const std::vector<CTxOut>& outputs, uint256& parent, std::string& error);
// Call with fresh transactions; native serialization follows Haskell action plans.
void BuildBitcoinSignetTransactions(const CScript& challenge,
    Sidechain::Bitcoin::CMutableTransaction& spend, Sidechain::Bitcoin::CMutableTransaction& sign);
std::vector<unsigned char> BitcoinSignetBlockData(const Sidechain::Bitcoin::CBlockHeader& header,
    const uint256& modified_merkle_root);

// Bitcoin witness-v0 preimage for the zero-valued synthetic signet spend.
// The caller must supply an existing input index.
uint256 BitcoinWitnessV0SignatureHash(const CScript& script_code,
    const Sidechain::Bitcoin::CTransaction& transaction, unsigned int input_index, int hash_type);

struct BmmL1State
{
    uint256 block_hash;
    uint32_t height{0};
    uint32_t block_time{0};
    uint32_t n_bits{0};
    uint32_t period_start_height{0};
    uint32_t period_start_time{0};
    std::vector<uint32_t> recent_times;

    SERIALIZE_METHODS(BmmL1State, obj)
    {
        READWRITE(
            obj.block_hash,
            obj.height,
            obj.block_time,
            obj.n_bits,
            obj.period_start_height,
            obj.period_start_time,
            obj.recent_times);
    }

    bool operator==(const BmmL1State&) const = default;
};

/**
 * Fail-closed clock context derived from an authenticated BMM chainstate.
 * Values are widened to the u64 representation consumed by ECX public values.
 */
struct BmmParentContext
{
    uint256 block_hash;
    uint64_t height{0};
    uint64_t median_time_past{0};
};

struct BmmProofEntry
{
    std::vector<unsigned char> coinbase_tx;
    std::vector<unsigned char> coinbase_proof;

    SERIALIZE_METHODS(BmmProofEntry, obj)
    {
        READWRITE(obj.coinbase_tx, obj.coinbase_proof);
    }
};

struct BmmProof
{
    uint8_t version{BMM_PROOF_SCHEMA_VERSION};
    BmmL1State previous_state;
    std::vector<BmmProofEntry> entries;

    SERIALIZE_METHODS(BmmProof, obj)
    {
        READWRITE(obj.version, obj.previous_state, obj.entries);
    }
};

struct BmmConsensus
{
    uint256 pow_limit;
    int64_t target_timespan{BMM_TARGET_TIMESPAN};
    int64_t target_spacing{BMM_TARGET_SPACING};
    CScript signet_challenge;
    int sidechain_slot{BMM_SIDECHAIN_SLOT};
    size_t max_entries{MAX_BMM_PROOF_ENTRIES};
    size_t max_proof_bytes{MAX_BMM_PROOF_BYTES};
    // Appended so legacy seven-field aggregate initializers retain their
    // original field mapping and safely default to public signet validation.
    bool require_signet_solution{BMM_REQUIRE_SIGNET_SOLUTION};

    int64_t DifficultyAdjustmentInterval() const;
};

/** Fixed LayerTwoLabs public-signet consensus values and immutable bootstrap. */
const BmmConsensus& LayerTwoLabsBmmConsensus();
const BmmL1State& LayerTwoLabsInitialBmmState();
const uint256& LayerTwoLabsPublicSidechainBlock1();
const uint256& LayerTwoLabsPublicSidechainBlock2();

/** Canonical identity of every selected BMM rule/bootstrap constant. */
uint256 RuntimeBmmConsensusFingerprint();

/** Detect a connected BMM tracker while first-binding a legacy datadir. */
bool HasPersistedBmmConsensusState(const CCoinsView& view);

/** Prevent transactions from naming the synthetic BMM chainstate record. */
bool IsBmmStateInternalOutpoint(const COutPoint& outpoint);

/** Header activation and critical-hash rules for the public slot-24 branch. */
bool BmmProofRequiredAfter(const CBlockIndex* previous);
bool CheckBmmHeader(
    const CBlockHeader& block,
    const CBlockIndex* previous,
    std::string& error,
    bool allow_incomplete_candidate = false);

/** Revalidate the BMM commitments of an already-persisted block-index entry. */
bool CheckBmmIndexHeader(
    const CBlockIndex& index,
    std::string& error);

/** Canonical proof encoding and header commitment. */
bool SerializeBmmProof(const BmmProof& proof, std::vector<unsigned char>& bytes, std::string& error);
bool DeserializeBmmProof(const std::vector<unsigned char>& bytes, BmmProof& proof, std::string& error);
uint256 BmmProofCommitment(const std::vector<unsigned char>& bytes);
bool AttachBmmProof(CBlock& block, const BmmProof& proof, std::string& error);
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
/** Build one valid synthetic parent successor for explicit private regtest only. */
bool BuildPrivateE2eBmmProof(
    const BmmL1State& previous,
    const uint256& critical_hash,
    BmmProof& proof,
    std::string& error);
#endif

/** Deterministic proof verification, with injectable parameters for focused tests. */
bool VerifyBmmProof(
    const CBlock& block,
    const BmmL1State& expected_previous,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus);
bool VerifyBmmProofEntries(
    const BmmProof& proof,
    const uint256& expected_critical_hash,
    const uint256& expected_parent_hash,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus);

/** Persist and undo the authenticated parent-chain tip in chainstate. */
bool GetBmmState(const CCoinsViewCache& view, BmmL1State& state, std::string* error = nullptr);
bool GetBmmParentContext(
    const BmmL1State& state,
    BmmParentContext& context,
    std::string& error);
bool GetEffectiveBmmState(
    const CCoinsViewCache& view,
    const CBlockIndex* previous,
    BmmL1State& state,
    std::string& error);
bool ConnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    int height,
    bool allow_incomplete_candidate,
    std::string& error);
bool DisconnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    int height,
    std::string& error);

} // namespace drivechain

#endif // BITCOIN_DRIVECHAIN_BMM_H
