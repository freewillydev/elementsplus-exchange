// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstate.h>

#include <arith_uint256.h>
#include <chain.h>
#include <coins.h>
#include <consensus/params.h>
#include <kernel/caches.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/ecx_deployment_identity.h>
#include <sync.h>
#include <threadsafety.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/signalinterrupt.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>

#include <algorithm>
#include <cassert>
#include <vector>

using kernel::CacheSizes;

namespace node {
// Complete initialization of chainstates after the initial call has been made
// to ChainstateManager::InitializeChainstate().
static ChainstateLoadResult CompleteChainstateInitialization(
    ChainstateManager& chainman,
    const ChainstateLoadOptions& options) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    if (chainman.m_interrupt) return {ChainstateLoadStatus::INTERRUPTED, {}};

    // LoadBlockIndex will load m_have_pruned if we've ever removed a
    // block file from disk.
    // Note that it also sets m_blockfiles_indexed based on the disk flag!
    if (!chainman.LoadBlockIndex()) {
        if (chainman.m_interrupt) return {ChainstateLoadStatus::INTERRUPTED, {}};
        return {ChainstateLoadStatus::FAILURE, _("Error loading block database")};
    }

    if (!chainman.BlockIndex().empty() &&
            !chainman.m_blockman.LookupBlockIndex(chainman.GetConsensus().hashGenesisBlock)) {
        // If the loaded chain has a wrong genesis, bail out immediately
        // (we're likely using a testnet datadir, or the other way around).
        return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Incorrect or no genesis block found. Wrong datadir for network?")};
    }

    // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
    // in the past, but is now trying to run unpruned.
    if (chainman.m_blockman.m_have_pruned && !options.prune) {
        return {ChainstateLoadStatus::FAILURE, _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain")};
    }

    // At this point blocktree args are consistent with what's on disk.
    // If we're not mid-reindex (based on disk + args), add a genesis block on disk
    // (otherwise we use the one already on disk).
    // This is called again in ImportBlocks after the reindex completes.
    if (chainman.m_blockman.m_blockfiles_indexed && !chainman.ActiveChainstate().LoadGenesisBlock()) {
        return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
    }

    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.wipe_chainstate_db || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    assert(chainman.m_total_coinstip_cache > 0);
    assert(chainman.m_total_coinsdb_cache > 0);

    // If running with multiple chainstates, limit the cache sizes with a
    // discount factor. If discounted the actual cache size will be
    // recalculated by `chainman.MaybeRebalanceCaches()`. The discount factor
    // is conservatively chosen such that the sum of the caches does not exceed
    // the allowable amount during this temporary initialization state.
    double init_cache_fraction = chainman.GetAll().size() > 1 ? 0.2 : 1.0;

    // At this point we're either in reindex or we've loaded a useful
    // block tree into BlockIndex()!

    for (Chainstate* chainstate : chainman.GetAll()) {
        LogPrintf("Initializing chainstate %s\n", chainstate->ToString());

        try {
            chainstate->InitCoinsDB(
                /*cache_size_bytes=*/chainman.m_total_coinsdb_cache * init_cache_fraction,
                /*in_memory=*/options.coins_db_in_memory,
                /*should_wipe=*/options.wipe_chainstate_db);
        } catch (dbwrapper_error& err) {
            LogError("%s\n", err.what());
            return {ChainstateLoadStatus::FAILURE, _("Error opening coins database")};
        }

        if (options.coins_error_cb) {
            chainstate->CoinsErrorCatcher().AddReadErrCallback(options.coins_error_cb);
        }

        // Refuse to load unsupported database format.
        // This is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (chainstate->CoinsDB().NeedsUpgrade()) {
            return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Unsupported chainstate database format found. "
                                                                     "Please restart with -reindex-chainstate. This will "
                                                                     "rebuild the chainstate database.")};
        }
    }

    // Bind runtime consensus configuration before crash-recovery replay can
    // mutate a coins database under different ECX/private-BMM rules.
    std::string ecx_identity_error;
    if (!BindEcxDeploymentIdentityIfNeeded(
            chainman,
            chainman.m_blockman.IsBlockTreeDBInMemory() && options.coins_db_in_memory,
            ecx_identity_error)) {
        LogPrintf("ECX consensus identity: %s\n", ecx_identity_error);
        return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("ECX consensus identity: " + ecx_identity_error)};
    }

    for (Chainstate* chainstate : chainman.GetAll()) {
        // ReplayBlocks is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (!chainstate->ReplayBlocks()) {
            return {ChainstateLoadStatus::FAILURE, _("Unable to replay blocks. You will need to rebuild the database using -reindex-chainstate.")};
        }

        // The on-disk coinsdb is now in a good state, create the cache
        chainstate->InitCoinsCache(chainman.m_total_coinstip_cache * init_cache_fraction);
        assert(chainstate->CanFlushToDisk());

        if (!is_coinsview_empty(chainstate)) {
            // LoadChainTip initializes the chain based on CoinsTip()'s best block
            if (!chainstate->LoadChainTip()) {
                return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
            }
            assert(chainstate->m_chain.Tip() != nullptr);
        }
    }

    auto chainstates{chainman.GetAll()};
    if (std::any_of(chainstates.begin(), chainstates.end(),
                    [](const Chainstate* cs) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return cs->NeedsRedownload(); })) {
        return {ChainstateLoadStatus::FAILURE, strprintf(_("Witness data for blocks after height %d requires validation. Please restart with -reindex."),
                                                         chainman.GetConsensus().SegwitHeight)};
    };

    // Now that chainstates are loaded and we're able to flush to
    // disk, rebalance the coins caches to desired levels based
    // on the condition of each chainstate.
    chainman.MaybeRebalanceCaches();

    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult LoadChainstate(ChainstateManager& chainman, const CacheSizes& cache_sizes,
                                    const ChainstateLoadOptions& options)
{
    if (!chainman.AssumedValidBlock().IsNull()) {
        LogPrintf("Assuming ancestors of block %s have valid signatures.\n", chainman.AssumedValidBlock().GetHex());
    } else {
        LogPrintf("Validating signatures for all blocks.\n");
    }
    LogPrintf("Setting nMinimumChainWork=%s\n", chainman.MinimumChainWork().GetHex());
    if (chainman.MinimumChainWork() < UintToArith256(chainman.GetConsensus().nMinimumChainWork)) {
        LogPrintf("Warning: nMinimumChainWork set below default value of %s\n", chainman.GetConsensus().nMinimumChainWork.GetHex());
    }
    if (chainman.m_blockman.GetPruneTarget() == BlockManager::PRUNE_TARGET_MANUAL) {
        LogPrintf("Block pruning enabled.  Use RPC call pruneblockchain(height) to manually prune block and undo files.\n");
    } else if (chainman.m_blockman.GetPruneTarget()) {
        LogPrintf("Prune configured to target %u MiB on disk for block and undo files.\n", chainman.m_blockman.GetPruneTarget() / 1024 / 1024);
    }

    LOCK(cs_main);

    std::string reset_error;
    if (!CheckEcxDeploymentResetAllowed(
            options.wipe_chainstate_db,
            chainman.m_blockman.IsBlockTreeDBInMemory() && options.coins_db_in_memory,
            reset_error)) {
        return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("ECX consensus identity: " + reset_error)};
    }

    chainman.m_total_coinstip_cache = cache_sizes.coins;
    chainman.m_total_coinsdb_cache = cache_sizes.coins_db;

    // Load the fully validated chainstate.
    chainman.InitializeChainstate(options.mempool);

    // Load a chain created from a UTXO snapshot, if any exist.
    bool has_snapshot = chainman.DetectSnapshotChainstate();

    if (has_snapshot && options.wipe_chainstate_db) {
        LogPrintf("[snapshot] deleting snapshot chainstate due to reindexing\n");
        if (!chainman.DeleteSnapshotChainstate()) {
            return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("Couldn't remove snapshot chainstate.")};
        }
    }

    auto [init_status, init_error] = CompleteChainstateInitialization(chainman, options);
    if (init_status != ChainstateLoadStatus::SUCCESS) {
        return {init_status, init_error};
    }

    // If a snapshot chainstate was fully validated by a background chainstate during
    // the last run, detect it here and clean up the now-unneeded background
    // chainstate.
    //
    // Why is this cleanup done here (on subsequent restart) and not just when the
    // snapshot is actually validated? Because this entails unusual
    // filesystem operations to move leveldb data directories around, and that seems
    // too risky to do in the middle of normal runtime.
    auto snapshot_completion = chainman.MaybeCompleteSnapshotValidation();

    if (snapshot_completion == SnapshotCompletionResult::SKIPPED) {
        // do nothing; expected case
    } else if (snapshot_completion == SnapshotCompletionResult::SUCCESS) {
        LogPrintf("[snapshot] cleaning up unneeded background chainstate, then reinitializing\n");
        if (!chainman.ValidatedSnapshotCleanup()) {
            return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("Background chainstate cleanup failed unexpectedly.")};
        }

        // Because ValidatedSnapshotCleanup() has torn down chainstates with
        // ChainstateManager::ResetChainstates(), reinitialize them here without
        // duplicating the blockindex work above.
        assert(chainman.GetAll().empty());
        assert(!chainman.IsSnapshotActive());
        assert(!chainman.IsSnapshotValidated());

        chainman.InitializeChainstate(options.mempool);

        // A reload of the block index is required to recompute setBlockIndexCandidates
        // for the fully validated chainstate.
        chainman.ActiveChainstate().ClearBlockIndexCandidates();

        auto [init_status, init_error] = CompleteChainstateInitialization(chainman, options);
        if (init_status != ChainstateLoadStatus::SUCCESS) {
            return {init_status, init_error};
        }
    } else {
        return {ChainstateLoadStatus::FAILURE_FATAL, _(
           "UTXO snapshot failed to validate. "
           "Restart to resume normal initial block download, or try loading a different snapshot.")};
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult VerifyLoadedChainstate(ChainstateManager& chainman, const ChainstateLoadOptions& options)
{
    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.wipe_chainstate_db || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    LOCK(cs_main);

    for (Chainstate* chainstate : chainman.GetAll()) {
        if (!is_coinsview_empty(chainstate)) {
            const CBlockIndex* tip = chainstate->m_chain.Tip();
            if (tip && tip->nTime > GetTime() + MAX_FUTURE_BLOCK_TIME) {
                return {ChainstateLoadStatus::FAILURE, _("The block database contains a block which appears to be from the future. "
                                                         "This may be due to your computer's date and time being set incorrectly. "
                                                         "Only rebuild the block database if you are sure that your computer's date and time are correct")};
            }

            VerifyDBResult result = CVerifyDB(chainman.GetNotifications()).VerifyDB(
                *chainstate, chainman.GetConsensus(), chainstate->CoinsDB(),
                options.check_level,
                options.check_blocks);
            switch (result) {
            case VerifyDBResult::SUCCESS:
            case VerifyDBResult::SKIPPED_MISSING_BLOCKS:
                break;
            case VerifyDBResult::INTERRUPTED:
                return {ChainstateLoadStatus::INTERRUPTED, _("Block verification was interrupted")};
            case VerifyDBResult::CORRUPTED_BLOCK_DB:
                return {ChainstateLoadStatus::FAILURE, _("Corrupted block database detected")};
            case VerifyDBResult::SKIPPED_L3_CHECKS:
                if (options.require_full_verification) {
                    return {ChainstateLoadStatus::FAILURE_INSUFFICIENT_DBCACHE, _("Insufficient dbcache for block verification")};
                }
                break;
            } // no default case, so the compiler can warn about missing cases
        }
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}
} // namespace node

// Fork-specific node/ecx_deployment_identity adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#include <node/ecx_deployment_identity.h>

#include <chain.h>
#include <chainparams.h>
#include <drivechain_bmm.h>
#include <ecx_exchange_state.h>
#include <hash.h>
#include <haskell/bridge.h>
#include <logging.h>
#include <tinyformat.h>
#include <txdb.h>
#include <util/readwritefile.h>
#include <common/args.h>
#include <util/fs_helpers.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace node {
namespace {

constexpr const char* ECX_DEPLOYMENT_IDENTITY_FILENAME{
    "ecx_consensus.dat"};

struct ExpectedIdentity
{
    fs::path path;
    std::string record;
    uint256 fingerprint;
    bool consensus_enabled{false};
    bool runtime_configured{false};
    int first_activation_height{std::numeric_limits<int>::max()};
};

bool BuildExpectedIdentity(ExpectedIdentity& identity, std::string& error)
{
    identity = {};
    if (!ecx::GetRuntimeConsensusFingerprint(
            identity.fingerprint,
            identity.runtime_configured,
            identity.first_activation_height,
            error)) {
        return false;
    }
    identity.consensus_enabled = Params().GetConsensus().elements_mode;
    identity.path = gArgs.GetDataDirNet() / ECX_DEPLOYMENT_IDENTITY_FILENAME;
    std::array<unsigned char,64> hashes;
    std::copy_n(Params().GetConsensus().hashGenesisBlock.begin(),32,hashes.begin());
    std::copy_n(identity.fingerprint.begin(),32,hashes.begin()+32);
    identity.record = drivechain::haskell::ConfigurationIdentity(Params().NetworkIDString(),hashes,
        [](uint32_t, std::span<const unsigned char> bytes) {
            const auto digest=Hash(bytes);
            std::array<unsigned char,32> output;
            std::copy_n(digest.begin(),32,output.begin());
            return output;
        });
    return true;
}

bool HasDirectoryEntry(const fs::path& directory)
{
    if (!fs::exists(directory) || !fs::is_directory(directory)) return false;
    return fs::directory_iterator(directory) != fs::directory_iterator();
}

bool ScanMaterialDirectory(const fs::path& directory, bool chainstates)
{
    fs::directory_iterator entry;
    using Flow = drivechain::haskell::ReplayStoreFlow;
    return drivechain::haskell::ParentReplayStore(Flow::MATERIAL_SCAN, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return fs::exists(directory);
        case 2: entry=fs::directory_iterator(directory); break;
        case 3: return entry!=fs::directory_iterator();
        case 4: return chainstates ? fs::is_directory(entry->path()) : fs::is_regular_file(entry->path());
        case 5: return drivechain::haskell::MaterialName(chainstates,fs::PathToString(entry->path().filename()));
        case 6: return !chainstates || HasDirectoryEntry(entry->path());
        case 7: ++entry; break;
        default: throw std::logic_error("Invalid Haskell material scan action");
        }
        return 1;
    });
}

bool HasMaterialChainData()
{
    const fs::path datadir{gArgs.GetDataDirNet()};
    // CBlockTreeDB remains under the network datadir, while -blocksdir moves
    // flat block/undo files. Check both locations so neither can be silently
    // treated as a fresh deployment. A damaged/interrupted LevelDB missing
    // CURRENT is still material: any entry in its index directory preserves
    // evidence that must not be rebound or wiped under new consensus rules.
    using Flow = drivechain::haskell::ReplayStoreFlow;
    return drivechain::haskell::ParentReplayStore(Flow::MATERIAL_LOCATIONS, [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return HasDirectoryEntry(datadir / "blocks" / "index");
        case 2: return HasDirectoryEntry(gArgs.GetBlocksDirPath() / "index");
        case 3: return ScanMaterialDirectory(datadir / "blocks",false);
        case 4: return ScanMaterialDirectory(gArgs.GetBlocksDirPath(),false);
        case 5: return ScanMaterialDirectory(datadir,true);
        default: throw std::logic_error("Invalid Haskell material location action");
        }
    });
}

bool WriteIdentityAtomically(
    const ExpectedIdentity& identity,
    std::string& error)
{
    fs::path temporary{identity.path};
    temporary += ".new";
    std::unique_ptr<FILE,decltype(&std::fclose)> file{nullptr,&std::fclose};
    return drivechain::haskell::IdentityWrite([&](uint32_t action) {
        switch (action) {
        case 1:
            fs::remove(temporary);
            file.reset(fsbridge::fopen(temporary,"wb"));
            return bool(file);
        case 2:
            error = strprintf("cannot create temporary ECX consensus identity %s",fs::PathToString(temporary));
            break;
        case 3: return std::fwrite(identity.record.data(),1,identity.record.size(),file.get())==identity.record.size();
        case 4: return FileCommit(file.get());
        case 5: std::fclose(file.release()); break;
        case 7: return std::fclose(file.release())==0;
        case 9: return RenameOver(temporary,identity.path);
        case 6:
        case 8:
        case 10:
            fs::remove(temporary);
            error = action==6 ? "cannot durably write the ECX consensus identity" :
                action==8 ? "cannot close the ECX consensus identity" : "cannot atomically install the ECX consensus identity";
            break;
        case 11: DirectoryCommit(identity.path.parent_path()); break;
        case 12:
            LogPrintf("Bound runtime ECX consensus configuration %s at %s\n",
                identity.fingerprint.GetHex(),fs::PathToString(identity.path));
            break;
        default: throw std::logic_error("Invalid Haskell identity write action");
        }
        return true;
    });
}

bool CheckLegacyHistory(
    ChainstateManager& chainman,
    const std::optional<uint256>& hash,
    const int first_activation_height,
    const std::string& label,
    std::string& error) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const auto& headers = chainman.BlockIndex();
    auto entry = headers.begin();
    const CBlockIndex* tip{nullptr};
    const CBlockIndex* cursor{nullptr};
    constexpr uint32_t ecx_bmm_mask{
        CBlockHeader::BMM_PROOF_HF_MASK |
        CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK};
    using Flow = drivechain::haskell::ReplayStoreFlow;
    return drivechain::haskell::ParentReplayStore(hash ? Flow::IDENTITY_ANCESTRY : Flow::IDENTITY_TREE,
        [&](uint32_t action) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
        switch (action) {
        case 1: return hash->IsNull();
        case 2:
            tip = cursor = chainman.m_blockman.LookupBlockIndex(*hash);
            return tip != nullptr;
        case 3:
            if (!hash) cursor = entry == headers.end() ? nullptr : &entry->second;
            return cursor != nullptr;
        case 4: return (static_cast<uint32_t>(cursor->nVersion) & ecx_bmm_mask) != 0;
        case 5: return cursor->GetBlockHash() == drivechain::LayerTwoLabsPublicSidechainBlock2();
        case 7:
            if (hash) cursor = cursor->pprev;
            else ++entry;
            break;
        case 8: return (hash ? tip : cursor)->nHeight >= first_activation_height;
        case 10:
            error = strprintf("cannot first-bind ECX consensus: %s block %s is absent from the block index",
                label, hash->GetHex());
            break;
        case 11:
            error = hash ? strprintf(
                "cannot first-bind ECX consensus: %s ancestry already contains "
                "an ECX/BMM header at height %d; recover the original frozen configuration",
                label, cursor->nHeight) : strprintf(
                "cannot first-bind ECX consensus: block-index branch already contains "
                "an ECX/BMM header %s at height %d; recover the original frozen configuration",
                cursor->GetBlockHash().GetHex(), cursor->nHeight);
            break;
        case 12:
            error = hash ? strprintf(
                "cannot first-bind ECX consensus at activation height %d: %s is already at height %d; "
                "restart under the original configuration, roll every chainstate back below activation, then retry",
                first_activation_height, label, tip->nHeight) : strprintf(
                "cannot first-bind ECX consensus at activation height %d: block-index "
                "branch already reaches header %s at height %d; recover the original "
                "configuration and roll every branch below activation",
                first_activation_height, cursor->GetBlockHash().GetHex(), cursor->nHeight);
            break;
        default: throw std::logic_error("Invalid Haskell legacy history action");
        }
        return 1;
    });
}

bool CheckCoinsHistory(ChainstateManager& chainman, int activation, std::string& error) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const auto states = chainman.GetAll();
    size_t state{0}, head{0};
    const CCoinsViewDB* coins{nullptr};
    std::vector<uint256> heads;
    using Flow = drivechain::haskell::ReplayStoreFlow;
    return drivechain::haskell::ParentReplayStore(Flow::IDENTITY_COINS, [&](uint32_t action) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
        switch (action) {
        case 1: return state < states.size();
        case 2:
            coins = &states[state]->CoinsDB();
            return ecx::HasPersistedExchangeConsensusState(*coins);
        case 3: return drivechain::HasPersistedBmmConsensusState(*coins);
        case 4:
            error = "cannot first-bind ECX consensus: chainstate already contains "
                "ECX/BMM tracker state; recover the original frozen configuration";
            break;
        case 5: return CheckLegacyHistory(chainman, coins->GetBestBlock(), activation, "coins best block", error);
        case 6:
            heads = coins->GetHeadBlocks();
            head = 0;
            break;
        case 7: return head < heads.size();
        case 8: return CheckLegacyHistory(chainman, heads[head], activation,
            strprintf("coins crash-recovery head %u", static_cast<unsigned int>(head)), error);
        case 9: ++head; break;
        case 10: ++state; break;
        default: throw std::logic_error("Invalid Haskell coins history action");
        }
        return 1;
    });
}

bool AuditPersistedConsensusHeaders(
    ChainstateManager& chainman,
    std::string& error) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    size_t audited{0};
    const auto& headers = chainman.BlockIndex();
    auto cursor = headers.begin();
    const CBlockIndex* index{nullptr};
    std::string header_error;
    using Flow = drivechain::haskell::ReplayStoreFlow;
    return drivechain::haskell::ParentReplayStore(Flow::IDENTITY_AUDIT, [&](uint32_t action) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
        switch (action) {
        case 1: return cursor != headers.end();
        case 2:
            index = &cursor->second;
            header_error.clear();
            return index->pprev != nullptr;
        case 3: return drivechain::CheckBmmIndexHeader(*index, header_error);
        case 5: return ecx::CheckExchangeStateIndexHeader(*index, header_error, ecx::LayerTwoLabsExchangeConsensus());
        case 4:
        case 6:
            error = strprintf(
                "persisted block-index header %s at height %d violates %s rules: %s; "
                "restart with -reindex to rebuild the header index under the current rules",
                index->GetBlockHash().GetHex(), index->nHeight, action == 4 ? "BMM" : "ECX", header_error);
            break;
        case 7: ++audited; break;
        case 8: ++cursor; break;
        case 9:
            LogPrintf("Audited %u persisted ECX/BMM block-index headers\n", static_cast<unsigned int>(audited));
            break;
        default: throw std::logic_error("Invalid Haskell identity audit action");
        }
        return 1;
    });
}

} // namespace

static bool CheckIdentityFile(bool reset, bool requested, bool in_memory, std::string& error)
{
    error.clear();
    try {
        ExpectedIdentity identity;
        std::string persisted;
        using Flow = drivechain::haskell::ReplayStoreFlow;
        // Actions run after each Haskell transition returns, including the
        // existing-identity check, which may itself enter Haskell.
        return drivechain::haskell::ParentReplayStore(reset ? Flow::IDENTITY_FILE_RESET : Flow::IDENTITY_FILE_CHECK,
            [&](uint32_t action) -> uint32_t {
            switch (action) {
            case 1: return requested;
            case 2: return in_memory;
            case 3: return BuildExpectedIdentity(identity,error);
            case 4: return identity.consensus_enabled;
            case 5: return fs::exists(identity.path);
            case 6: return HasMaterialChainData();
            case 7: return gArgs.GetBoolArg("-reindex",false) || gArgs.GetBoolArg("-reindex-chainstate",false);
            case 8: return WriteIdentityAtomically(identity,error);
            case 9: {
                auto result=ReadBinaryFile(identity.path,drivechain::MAX_ECX_DEPLOYMENT_IDENTITY_BYTES);
                persisted=std::move(result.second);
                return result.first;
            }
            case 10:
                error=strprintf("cannot read ECX consensus identity %s",fs::PathToString(identity.path)); break;
            case 11: return persisted==identity.record;
            case 12:
                error=strprintf("ECX consensus configuration does not match this data directory "
                    "(expected fingerprint %s); use the original frozen parameters",identity.fingerprint.GetHex()); break;
            case 13:
                error="cannot first-bind an ECX consensus identity while reindexing existing data; "
                    "start once without reindex so the existing chainstate/history can be checked"; break;
            case 14: return CheckEcxDeploymentIdentity(error);
            case 15:
                error="cannot reset or reindex existing chain data before ECX consensus identity first-binding; "
                    "start once without reindex so the existing chainstate/history can be checked";
                break;
            default: throw std::logic_error("Invalid Haskell deployment identity action");
            }
            return 1;
        });
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool CheckEcxDeploymentIdentity(std::string& error)
{
    return CheckIdentityFile(false,false,false,error);
}

bool CheckEcxDeploymentResetAllowed(
    const bool reset_requested,
    const bool databases_in_memory,
    std::string& error)
{
    return CheckIdentityFile(true,reset_requested,databases_in_memory,error);
}

bool BindEcxDeploymentIdentityIfNeeded(
    ChainstateManager& chainman,
    const bool databases_in_memory,
    std::string& error)
{
    AssertLockHeld(cs_main);
    error.clear();
    try {
        ExpectedIdentity identity;
        using Flow = drivechain::haskell::ReplayStoreFlow;
        return drivechain::haskell::ParentReplayStore(Flow::IDENTITY_BINDING, [&](uint32_t action) EXCLUSIVE_LOCKS_REQUIRED(cs_main) -> uint32_t {
        switch (action) {
        case 1: return BuildExpectedIdentity(identity, error);
        case 2: return identity.consensus_enabled;
        case 3: return databases_in_memory;
        case 4: return fs::exists(identity.path);
        case 5: return CheckEcxDeploymentIdentity(error);
        case 6:
        case 13: return AuditPersistedConsensusHeaders(chainman, error);
        case 7: return chainman.m_blockman.m_blockfiles_indexed;
        case 8: return HasMaterialChainData();
        case 9:
            error =
                "cannot first-bind an ECX consensus identity while a block-index reindex is in progress; "
                "restore the pre-reindex database and start once without reindex";
            return 1;
        // Check every branch, not only the coins-view ancestry, before binding.
        case 10: return CheckLegacyHistory(chainman, std::nullopt, identity.first_activation_height, "", error);
        case 11: return CheckCoinsHistory(chainman, identity.first_activation_height, error);
        case 12: return WriteIdentityAtomically(identity, error);
        default: throw std::logic_error("Invalid Haskell identity binding action");
        }
        });
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

} // namespace node
