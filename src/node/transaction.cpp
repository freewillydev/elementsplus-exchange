// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <index/txindex.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/types.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>
#include <node/transaction.h>

#include <future>

namespace node {
static TransactionError HandleATMPError(const TxValidationState& state, std::string& err_string_out)
{
    err_string_out = state.ToString();
    if (state.IsInvalid()) {
        if (state.GetResult() == TxValidationResult::TX_MISSING_INPUTS) {
            return TransactionError::MISSING_INPUTS;
        }
        return TransactionError::MEMPOOL_REJECTED;
    } else {
        return TransactionError::MEMPOOL_ERROR;
    }
}

TransactionError BroadcastTransaction(NodeContext& node, const CTransactionRef tx, std::string& err_string, const CAmount& max_tx_fee, bool relay, bool wait_callback)
{
    // BroadcastTransaction can be called by RPC or by the wallet.
    // chainman, mempool and peerman are initialized before the RPC server and wallet are started
    // and reset after the RPC sever and wallet are stopped.
    assert(node.chainman);
    assert(node.mempool);
    assert(node.peerman);

    std::promise<void> promise;
    Txid txid = tx->GetHash();
    uint256 wtxid = tx->GetWitnessHash();
    bool callback_set = false;

    {
        LOCK(cs_main);

        // If the transaction is already confirmed in the chain, don't do anything
        // and return early.
        CCoinsViewCache &view = node.chainman->ActiveChainstate().CoinsTip();
        for (size_t o = 0; o < tx->vout.size(); o++) {
            const Coin& existingCoin = view.AccessCoin(COutPoint(txid, o));
            // IsSpent doesn't mean the coin is spent, it means the output doesn't exist.
            // So if the output does exist, then this transaction exists in the chain.
            if (!existingCoin.IsSpent()) return TransactionError::ALREADY_IN_UTXO_SET;
        }

        if (auto mempool_tx = node.mempool->get(txid); mempool_tx) {
            // There's already a transaction in the mempool with this txid. Don't
            // try to submit this transaction to the mempool (since it'll be
            // rejected as a TX_CONFLICT), but do attempt to reannounce the mempool
            // transaction if relay=true.
            //
            // The mempool transaction may have the same or different witness (and
            // wtxid) as this transaction. Use the mempool's wtxid for reannouncement.
            wtxid = mempool_tx->GetWitnessHash();
        } else {
            // Transaction is not already in the mempool.
            if (max_tx_fee > 0) {
                // First, call ATMP with test_accept and check the fee. If ATMP
                // fails here, return error immediately.
                const MempoolAcceptResult result = node.chainman->ProcessTransaction(tx, /*test_accept=*/ true);
                if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
                    return HandleATMPError(result.m_state, err_string);
                } else if (result.m_base_fees.value() > max_tx_fee) {
                    return TransactionError::MAX_FEE_EXCEEDED;
                }
            }
            // Try to submit the transaction to the mempool.
            const MempoolAcceptResult result = node.chainman->ProcessTransaction(tx, /*test_accept=*/ false);
            if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
                return HandleATMPError(result.m_state, err_string);
            }

            // Transaction was accepted to the mempool.

            if (relay) {
                // the mempool tracks locally submitted transactions to make a
                // best-effort of initial broadcast
                node.mempool->AddUnbroadcastTx(txid);
            }

            if (wait_callback && node.validation_signals) {
                // For transactions broadcast from outside the wallet, make sure
                // that the wallet has been notified of the transaction before
                // continuing.
                //
                // This prevents a race where a user might call sendrawtransaction
                // with a transaction to/from their wallet, immediately call some
                // wallet RPC, and get a stale result because callbacks have not
                // yet been processed.
                node.validation_signals->CallFunctionInValidationInterfaceQueue([&promise] {
                    promise.set_value();
                });
                callback_set = true;
            }
        }
    } // cs_main

    if (callback_set) {
        // Wait until Validation Interface clients have been notified of the
        // transaction entering the mempool.
        promise.get_future().wait();
    }

    if (relay) {
        node.peerman->RelayTransaction(txid, wtxid);
    }

    return TransactionError::OK;
}

CTransactionRef GetTransaction(const CBlockIndex* const block_index, const CTxMemPool* const mempool, const uint256& hash, uint256& hashBlock, const BlockManager& blockman)
{
    if (mempool && !block_index) {
        CTransactionRef ptx = mempool->get(hash);
        if (ptx) return ptx;
    }
    if (g_txindex) {
        CTransactionRef tx;
        uint256 block_hash;
        if (g_txindex->FindTx(hash, block_hash, tx)) {
            if (!block_index || block_index->GetBlockHash() == block_hash) {
                // Don't return the transaction if the provided block hash doesn't match.
                // The case where a transaction appears in multiple blocks (e.g. reorgs or
                // BIP30) is handled by the block lookup below.
                hashBlock = block_hash;
                return tx;
            }
        }
    }
    if (block_index) {
        CBlock block;
        if (blockman.ReadBlock(block, *block_index)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    hashBlock = block_index->GetBlockHash();
                    return tx;
                }
            }
        }
    }
    return nullptr;
}
} // namespace node

// Fork-specific node/drivechain_deposits adapters.
// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#include <node/drivechain_deposits.h>

#include <common/args.h>
#include <logging.h>
#include <mainchainrpc.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/types.h>
#include <pegins.h>
#include <txmempool.h>
#include <validation.h>

namespace node {
void AutoImportDrivechainDeposits(NodeContext& node,
    std::optional<Sidechain::Bitcoin::COutPoint>& cursor)
{
    if (!node.args->GetBoolArg("-drivechainautodeposit", true) ||
        !Params().GetConsensus().drivechain_slot || !node.mempool || !node.chainman) return;
    DrivechainParentValidationBudget budget(true);
    try {
        const int height = WITH_LOCK(cs_main, return node.chainman->ActiveChain().Height() + 1);
        std::vector<DrivechainMintableDeposit> deposits;
        std::optional<Sidechain::Bitcoin::COutPoint> next;
        std::string error;
        if (!ListDrivechainDepositCandidates(cursor, height, deposits, next, &error)) {
            LogDebug(BCLog::VALIDATION, "Automatic deposit scan waiting: %s\n", error);
            return;
        }
        unsigned attempts{0};
        for (const auto& deposit : deposits) {
            CScript recipient;
            CAmount committed_fee{0};
            if (!DecodeDrivechainDepositDestination(std::string(deposit.address.begin(), deposit.address.end()),
                recipient, committed_fee) || deposit.value <= committed_fee) continue;
            const auto tx = CreateNativeDrivechainDeposit(deposit);
            {
                LOCK2(cs_main, node.mempool->cs);
                CCoinsViewMemPool view(&node.chainman->ActiveChainstate().CoinsTip(), *node.mempool);
                if (view.IsPeginSpent(GetPeginSpentKey(tx->witness.vtxinwit[0].m_pegin_witness, tx->vin[0].prevout))) continue;
            }
            // Never skip the normal parent proof/depth, replay and mempool checks.
            // No wallet, key, fee input or external enforcer assertion is used.
            const auto result = BroadcastTransaction(node, tx, error, /*max_tx_fee=*/0,
                /*relay=*/true, /*wait_callback=*/false);
            if (result == TransactionError::OK)
                LogPrintf("Automatically imported drivechain deposit %s:%u as %s (committed fee %d)\n",
                    deposit.outpoint.hash.ToString(), deposit.outpoint.n, tx->GetHash().ToString(), committed_fee);
            else
                LogDebug(BCLog::VALIDATION, "Automatic deposit %s:%u deferred: %s\n",
                    deposit.outpoint.hash.ToString(), deposit.outpoint.n, error);
            if (++attempts == 8) { cursor = deposit.outpoint; return; }
        }
        cursor = next;
    } catch (const std::exception& error) {
        // Retain the cursor on faults, so unavailable/reorged evidence is retried.
        LogDebug(BCLog::VALIDATION, "Automatic deposit scan deferred: %s\n", error.what());
    }
}
}

// Fork-specific node/drivechain_withdrawal_journal adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/drivechain_withdrawal_journal.h>

#include <crypto/common.h>
#include <hash.h>
#include <haskell/bridge.h>
#include <haskell/journal_constants.h>
#include <logging.h>
#include <random.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/fs_helpers.h>

#include <cstdio>
#include <algorithm>

namespace node {

namespace {
//! File name of the journal inside the network data directory.
const char* const JOURNAL_FILENAME{drivechain::WITHDRAWAL_JOURNAL_FILENAME};

//! Distinguishes this file from any other serialized blob if one is ever
//! pointed at the wrong path.
const std::string JOURNAL_MAGIC{drivechain::WITHDRAWAL_JOURNAL_MAGIC};

std::vector<unsigned char> JournalScalar(uint64_t value)
{
    std::vector<unsigned char> bytes(8);
    WriteLE64(bytes.data(), value);
    return bytes;
}

std::vector<unsigned char> JournalObservation(const WithdrawalJournalEntry& entry,
    std::string& error, uint32_t step, uint64_t index, std::span<const unsigned char> input)
{
    if (index || (!input.empty() && step != 0 && step != 103 && step != 105))
        throw std::logic_error("Invalid Haskell withdrawal journal request");
    switch (step) {
    case 0: throw std::runtime_error(std::string(input.begin(), input.end()));
    case 101: {
        error.clear();
        const uint8_t facts = (entry.m6id.IsNull() || entry.sidechain_txid.IsNull()) |
            (entry.destination.empty() << 1) | (entry.payout_script.empty() << 2) |
            (entry.payout_script.IsUnspendable() << 3) | (entry.bundle_bytes.empty() << 4);
        std::array<unsigned char,7> prefix{};
        const auto prefix_size = std::min(prefix.size(), entry.bundle_bytes.size());
        std::copy_n(entry.bundle_bytes.begin(), prefix_size, prefix.begin());
        DataStream facts_bytes;
        facts_bytes << entry.version << entry.state << entry.amount << entry.mainchain_fee
                    << entry.sidechain_slot << entry.created_time << facts << uint8_t(prefix_size) << prefix
                    << entry.m6id;
        const auto* data = reinterpret_cast<const unsigned char*>(facts_bytes.data());
        return {data, data + facts_bytes.size()};
    }
    case 102:
        if (entry.bundle_bytes.size() > std::numeric_limits<int32_t>::max() - 3)
            throw std::length_error("Haskell withdrawal transport input too large");
        return entry.bundle_bytes;
    case 103: {
        const uint256 digest = Hash(input);
        return {digest.begin(), digest.end()};
    }
    case 105: error.assign(input.begin(), input.end()); return JournalScalar(1);
    default: throw std::logic_error("Invalid Haskell withdrawal journal observation");
    }
}

} // namespace

fs::path WithdrawalJournalPath(const fs::path& data_dir)
{
    return data_dir / JOURNAL_FILENAME;
}

bool WriteWithdrawalJournal(const fs::path& data_dir, const WithdrawalJournalEntry& entry)
{
    const fs::path path = WithdrawalJournalPath(data_dir);
    std::string validation_error;
    fs::path path_tmp;
    uint256 checksum;
    std::optional<AutoFile> fileout;
    bool serialization_scope{false};
    const char* function = __func__;
    try {
        return drivechain::haskell::RunReplayStore(
            drivechain::haskell::ReplayStoreWorkflow::JOURNAL_WRITE,
            [&](uint32_t action, uint64_t index, std::span<const unsigned char> input) {
            if (action == 0 || (action >= 101 && action <= 105))
                return JournalObservation(entry, validation_error, action, index, input);
            if (index || !input.empty()) throw std::logic_error("Invalid Haskell withdrawal journal write request");
            if (action >= 1 && action <= 8 && !fileout)
                throw std::logic_error("Haskell withdrawal journal file is not open");
            switch (action) {
            case 201: {
                uint16_t randv{0};
                GetRandBytes(Span{reinterpret_cast<unsigned char*>(&randv), sizeof(randv)});
                path_tmp = data_dir / fs::PathFromString(strprintf("%s.%04x", JOURNAL_FILENAME, randv));
                break;
            }
            case 202: {
                // Preserve the old catch boundary: validation/randomness and
                // the later directory fsync are outside serialization recovery.
                serialization_scope = true;
                HashWriter hasher;
                hasher << JOURNAL_MAGIC << entry;
                checksum = hasher.GetHash();
                fileout.emplace(fsbridge::fopen(path_tmp, "wb"));
                break;
            }
            case 203: fileout.reset(); serialization_scope = false; break;
            case 204: DirectoryCommit(data_dir); break;
            case 205:
                LogDebug(BCLog::VALIDATION,
                    "drivechain withdrawal journal: recorded m6id=%s state=%d txid=%s\n",
                    entry.m6id.GetHex(), int{entry.state}, entry.sidechain_txid.GetHex());
                break;
            case 209: LogPrintf("%s: refusing invalid journal entry: %s\n", function, validation_error); break;
            case 1: return JournalScalar(!fileout->IsNull());
            case 3: *fileout << JOURNAL_MAGIC << entry << checksum; break;
            case 4: return JournalScalar(fileout->Commit());
            case 6: fileout->fclose(); break;
            case 7: return JournalScalar(RenameOver(path_tmp, path));
            case 2:
            case 5:
            case 8:
                if (action != 8) fileout->fclose();
                fs::remove(path_tmp);
                LogPrintf("%s: %s %s\n", function,
                    action == 2 ? "failed to open" : action == 5 ? "failed to flush" : "rename into place failed for",
                    fs::PathToString(action == 8 ? path : path_tmp));
                break;
            default: throw std::logic_error("Invalid Haskell withdrawal journal write action");
            }
            return JournalScalar(1);
        }) == 1;
    } catch (const std::exception& e) {
        fileout.reset();
        if (!serialization_scope) throw;
        fs::remove(path_tmp);
        LogPrintf("%s: serialization error: %s\n", __func__, e.what());
        return false;
    }

}

WithdrawalJournalReadResult ReadWithdrawalJournal(
    const fs::path& data_dir,
    WithdrawalJournalEntry& entry,
    std::string* error)
{
    if (error) error->clear();
    const fs::path path = WithdrawalJournalPath(data_dir);
    if (!fs::exists(path)) return WithdrawalJournalReadResult::MISSING;

    try {
        FILE* file = fsbridge::fopen(path, "rb");
        AutoFile filein{file};
        std::string magic;
        WithdrawalJournalEntry parsed;
        uint256 checksum;
        std::string validation_error;
        const char* function = __func__;
        const auto accepted = drivechain::haskell::RunReplayStore(
            drivechain::haskell::ReplayStoreWorkflow::JOURNAL_READ,
            [&](uint32_t action, uint64_t index, std::span<const unsigned char> input) {
            if (action == 0 || action >= 101)
                return JournalObservation(parsed, validation_error, action, index, input);
            if (index || !input.empty()) throw std::logic_error("Invalid Haskell withdrawal journal read request");
            switch (action) {
            case 1: return JournalScalar(!filein.IsNull());
            case 3: filein >> magic >> parsed >> checksum; break;
            case 4: return JournalScalar(magic == JOURNAL_MAGIC);
            case 6: {
                HashWriter hasher;
                hasher << JOURNAL_MAGIC << parsed;
                return JournalScalar(hasher.GetHash() == checksum);
            }
            case 10: entry = std::move(parsed); break;
            case 2:
            case 5:
            case 7:
            case 9: {
                const auto message = action == 2 ? strprintf("failed to open %s", fs::PathToString(path)) :
                    action == 5 ? strprintf("%s is not a withdrawal journal", fs::PathToString(path)) :
                    action == 7 ? strprintf("checksum mismatch in %s", fs::PathToString(path)) : validation_error;
                if (error) *error = message;
                if (action == 9) LogPrintf("%s: invalid journal %s: %s\n", function, fs::PathToString(path), message);
                else LogPrintf("%s: %s%s\n", function, message, action == 7 ? "; refusing to act on it" : "");
                break;
            }
            default: throw std::logic_error("Invalid Haskell withdrawal journal read action");
            }
            return JournalScalar(1);
        });
        return accepted ? WithdrawalJournalReadResult::OK : WithdrawalJournalReadResult::CORRUPT;
    } catch (const std::exception& e) {
        const std::string message = strprintf("failed to read %s: %s", fs::PathToString(path), e.what());
        if (error) *error = message;
        LogPrintf("%s: %s\n", __func__, message);
        return WithdrawalJournalReadResult::CORRUPT;
    }
}

bool ClearWithdrawalJournal(const fs::path& data_dir)
{
    const fs::path path = WithdrawalJournalPath(data_dir);
    std::error_code ec;
    const char* function = __func__;
    return drivechain::haskell::RunReplayStore(
        drivechain::haskell::ReplayStoreWorkflow::JOURNAL_CLEAR,
        [&](uint32_t action, uint64_t index, std::span<const unsigned char> input) {
        if (index || (!input.empty() && action != 0)) throw std::logic_error("Invalid Haskell withdrawal journal clear request");
        if (action == 0) throw std::runtime_error(std::string(input.begin(), input.end()));
        switch (action) {
        case 1: return JournalScalar(fs::exists(path));
        case 2: fs::remove(path, ec); return JournalScalar(!ec);
        case 3: LogPrintf("%s: failed to remove %s: %s\n", function, fs::PathToString(path), ec.message()); break;
        case 4: DirectoryCommit(data_dir); break;
        default: throw std::logic_error("Invalid Haskell withdrawal journal clear action");
        }
        return JournalScalar(1);
    }) == 1;
}

} // namespace node
