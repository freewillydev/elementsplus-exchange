// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signet.h>

#include <common/system.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <drivechain_bmm.h>
#include <hash.h>
#include <haskell/bridge.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/bitcoin/block.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <span.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};

static constexpr unsigned int BLOCK_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY;

namespace Bitcoin = Sidechain::Bitcoin;

static bool FetchAndClearCommitmentSection(const Span<const uint8_t> header, CScript& witness_commitment, std::vector<uint8_t>& result)
{
    CScript replacement;
    bool found_header = false;
    result.clear();

    opcodetype opcode;
    CScript::const_iterator pc = witness_commitment.begin();
    std::vector<uint8_t> pushdata;
    while (witness_commitment.GetOp(pc, opcode, pushdata)) {
        if (pushdata.size() > 0) {
            if (!found_header && pushdata.size() > header.size() && std::ranges::equal(Span{pushdata}.first(header.size()), header)) {
                // pushdata only counts if it has the header _and_ some data
                result.insert(result.end(), pushdata.begin() + header.size(), pushdata.end());
                pushdata.erase(pushdata.begin() + header.size(), pushdata.end());
                found_header = true;
            }
            replacement << pushdata;
        } else {
            replacement << opcode;
        }
    }

    if (found_header) witness_commitment = replacement;
    return found_header;
}

static uint256 ComputeModifiedMerkleRoot(const CMutableTransaction& cb, const CBlock& block)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    leaves[0] = cb.GetHash();
    for (size_t s = 1; s < block.vtx.size(); ++s) {
        leaves[s] = block.vtx[s]->GetHash();
    }
    return ComputeMerkleRoot(std::move(leaves));
}

std::optional<SignetTxs> SignetTxs::Create(const CBlock& block, const CScript& challenge)
{
    CMutableTransaction tx_to_spend;
    tx_to_spend.version = 0;
    tx_to_spend.nLockTime = 0;
    tx_to_spend.vin.emplace_back(COutPoint(), CScript(OP_0), 0);
    tx_to_spend.vout.emplace_back(CAsset(), 0, challenge);

    CMutableTransaction tx_spending;
    tx_spending.version = 0;
    tx_spending.nLockTime = 0;
    tx_spending.vin.emplace_back(COutPoint(), CScript(), 0);
    tx_spending.witness.vtxinwit.resize(1);
    tx_spending.vout.emplace_back(CAsset(), 0, CScript(OP_RETURN));

    // can't fill any other fields before extracting signet
    // responses from block coinbase tx

    // find and delete signet signature
    if (block.vtx.empty()) return std::nullopt; // no coinbase tx in block; invalid
    CMutableTransaction modified_cb(*block.vtx.at(0));

    const int cidx = GetWitnessCommitmentIndex(block);
    if (cidx == NO_WITNESS_COMMITMENT) {
        return std::nullopt; // require a witness commitment
    }

    CScript& witness_commitment = modified_cb.vout.at(cidx).scriptPubKey;

    std::vector<uint8_t> signet_solution;
    if (!FetchAndClearCommitmentSection(SIGNET_HEADER, witness_commitment, signet_solution)) {
        // no signet solution -- allow this to support OP_TRUE as trivial block challenge
    } else {
        try {
            SpanReader v{signet_solution};
            v >> tx_spending.vin[0].scriptSig;
            v >> tx_spending.witness.vtxinwit[0].scriptWitness.stack;
            if (!v.empty()) return std::nullopt; // extraneous data encountered
        } catch (const std::exception&) {
            return std::nullopt; // parsing error
        }
    }
    uint256 signet_merkle = ComputeModifiedMerkleRoot(modified_cb, block);

    std::vector<uint8_t> block_data;
    VectorWriter writer{block_data, 0};
    writer << block.nVersion;
    writer << block.hashPrevBlock;
    writer << signet_merkle;
    writer << block.nTime;
    tx_to_spend.vin[0].scriptSig << block_data;
    tx_spending.vin[0].prevout = COutPoint(tx_to_spend.GetHash(), 0);

    return SignetTxs{tx_to_spend, tx_spending};
}

// Signet block solution checker
bool CheckSignetBlockSolution(const CBlock& block, const Consensus::Params& consensusParams)
{
    if (block.GetHash() == consensusParams.hashGenesisBlock) {
        // genesis block solution is always valid
        return true;
    }

    const CScript challenge(consensusParams.signet_challenge.begin(), consensusParams.signet_challenge.end());
    const std::optional<SignetTxs> signet_txs = SignetTxs::Create(block, challenge);

    if (!signet_txs) {
        LogDebug(BCLog::VALIDATION, "CheckSignetBlockSolution: Errors in block (block solution parse failure)\n");
        return false;
    }

    const CScript& scriptSig = signet_txs->m_to_sign.vin[0].scriptSig;
    const CScriptWitness& witness = signet_txs->m_to_sign.witness.vtxinwit[0].scriptWitness;

    PrecomputedTransactionData txdata;
    txdata.Init(signet_txs->m_to_sign, {signet_txs->m_to_spend.vout[0]});
    TransactionSignatureChecker sigcheck(&signet_txs->m_to_sign, /* nInIn= */ 0, /* amountIn= */ signet_txs->m_to_spend.vout[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL);

    if (!VerifyScript(scriptSig, signet_txs->m_to_spend.vout[0].scriptPubKey, &witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)) {
        LogDebug(BCLog::VALIDATION, "CheckSignetBlockSolution: Errors in block (block solution invalid)\n");
        return false;
    }
    return true;
}

uint256 ComputeBitcoinModifiedMerkleRoot(const Bitcoin::CMutableTransaction& coinbase,
                                         const Bitcoin::CBlock& block)
{
    std::vector<uint256> leaves;
    size_t index{0};
    uint256 root;
    namespace hs = drivechain::haskell;
    hs::ParentReplayStore(hs::ReplayStoreFlow::SIGNET_MERKLE, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: leaves.reserve(block.vtx.size()); return 1;
        case 2: leaves.push_back(coinbase.GetHash()); return 1;
        case 3: index = 1; return 1;
        case 4: return hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, index, block.vtx.size());
        case 5: leaves.push_back(block.vtx[index]->GetHash()); return 1;
        case 6: ++index; return 1;
        case 7: root = ComputeMerkleRoot(std::move(leaves)); return 1;
        default: throw std::logic_error("invalid parent signet Merkle action");
        }
    });
    return root;
}

namespace {
bool SetSignetError(std::string* error, const std::string& message)
{
    if (error) *error = message;
    return false;
}

} // namespace

bool CheckBitcoinSignetBlockSolution(const Bitcoin::CBlock& block,
                                     const CScript& challenge,
                                     const uint256& genesis_hash,
                                     std::string* error)
{
    namespace hs = drivechain::haskell;
    int commitment_index{-1};
    std::optional<Bitcoin::CMutableTransaction> modified_coinbase, spend, sign;
    std::optional<Bitcoin::CTransaction> immutable;
    std::vector<uint8_t> solution, block_data;
    uint256 merkle;
    ScriptError script_error{SCRIPT_ERR_OK};
    return hs::ParentReplayStore(hs::ReplayStoreFlow::PARENT_SIGNET, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return block.GetHash() == genesis_hash;
        case 2: return block.vtx.empty();
        case 3: return block.vtx[0]->IsCoinBase();
        case 4: return SetSignetError(error, "parent signet block has no coinbase transaction");
        case 5:
            commitment_index = drivechain::BitcoinWitnessCommitmentIndex(block.vtx[0]->vout);
            return commitment_index >= 0;
        case 6: return SetSignetError(error, "parent signet block has no witness commitment");
        case 7: modified_coinbase.emplace(*block.vtx[0]); return 1;
        case 8:
            FetchAndClearCommitmentSection(SIGNET_HEADER, modified_coinbase->vout[commitment_index].scriptPubKey, solution);
            return 1;
        case 9:
            spend.emplace();
            sign.emplace();
            drivechain::BuildBitcoinSignetTransactions(challenge, *spend, *sign);
            return 1;
        case 10: return solution.empty();
        case 11:
            try {
                SpanReader reader{solution};
                return hs::ParentReplayStore(hs::ReplayStoreFlow::RAW_DECODE, [&](uint32_t step) -> uint32_t {
                    switch (step) {
                    case 1: reader >> sign->vin[0].scriptSig; return 1;
                    case 2: reader >> sign->vin[0].scriptWitness.stack; return 1;
                    case 3: return !reader.empty();
                    case 4: return SetSignetError(error, "parent signet solution has trailing bytes");
                    default: throw std::logic_error("invalid signet decode action");
                    }
                });
            } catch (const std::exception&) {
                return SetSignetError(error, "parent signet solution is not canonically encoded");
            }
        case 12: merkle = ComputeBitcoinModifiedMerkleRoot(*modified_coinbase, block); return 1;
        case 13: block_data = drivechain::BitcoinSignetBlockData(block, merkle); return 1;
        case 14:
            spend->vin[0].scriptSig << block_data;
            sign->vin[0].prevout = Bitcoin::COutPoint(spend->GetHash(), 0);
            return 1;
        case 15: immutable.emplace(std::move(*sign)); return 1;
        case 16: {
            const drivechain::BitcoinSignetSignatureChecker checker{*immutable, 0,
                drivechain::BitcoinSignetSignatureChecker::Mode::PARENT};
            return VerifyScript(immutable->vin[0].scriptSig, challenge,
                &immutable->vin[0].scriptWitness, BLOCK_SCRIPT_VERIFY_FLAGS, checker, &script_error);
        }
        case 17: return SetSignetError(error, strprintf("parent signet solution failed challenge validation: %s", ScriptErrorString(script_error)));
        default: throw std::logic_error("invalid parent signet action");
        }
    }) == 1;
}
