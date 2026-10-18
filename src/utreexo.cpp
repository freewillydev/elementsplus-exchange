// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <utreexo.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <hash.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <exception>
#include <map>
#include <set>
#include <stdexcept>

extern "C" {
void elements_hs_runtime_init();
using UtreexoEmit = uint32_t (*)(void*, const unsigned char*, size_t, const unsigned char*, size_t, uint64_t);
using UtreexoEngine = uint32_t (*)(const unsigned char*, size_t, const unsigned char*, size_t,
                                  const unsigned char*, size_t, UtreexoEmit, void*);
uint32_t elements_utreexo_v1(const unsigned char*, size_t, const unsigned char*, size_t,
                            const unsigned char*, size_t, UtreexoEmit, void*);
uint32_t elements_hs_utreexo_v1(UtreexoEngine, const unsigned char*, size_t, const unsigned char*, size_t,
                               const unsigned char*, size_t, UtreexoEmit, void*);
}

namespace utreexo {
static constexpr uint8_t DB_ACCUMULATOR{'A'};
uint256 Leaf(const uint256& genesis, const COutPoint& outpoint, const Coin& coin)
{
    // Reuse the durable Coin encoding, not the transient CTxOut (whose nonce
    // is discarded by the upstream coins database). The txid binds the nonce.
    return (HashWriter{} << std::string{"Elements/Utreexo/Coin/v1"} << genesis << outpoint
            << coin).GetHash();
}

Result Transition(const std::vector<unsigned char>& previous, const std::vector<uint256>& adds,
                  const std::vector<uint256>& dels)
{
    struct Context { Result result; std::exception_ptr error; bool emitted{false}; } context;
    const auto emit = +[](void* ptr, const unsigned char* forest, size_t size,
                          const unsigned char* roots, size_t count, uint64_t leaves) -> uint32_t {
        auto& ctx = *static_cast<Context*>(ptr);
        try {
            if (ctx.emitted || count > 63 || count != size_t(std::popcount(leaves))) return 1;
            ctx.result.forest.assign(forest, forest + size);
            ctx.result.commitment.leaves = leaves;
            ctx.result.commitment.roots.resize(count);
            for (size_t i = 0; i < count; ++i)
                std::copy_n(roots + i * 32, 32, ctx.result.commitment.roots[i].begin());
            ctx.emitted = true;
            return 0;
        } catch (...) { ctx.error = std::current_exception(); return 1; }
    };
    static_assert(sizeof(uint256) == 32);
    elements_hs_runtime_init();
    const auto status = elements_hs_utreexo_v1(elements_utreexo_v1, previous.data(), previous.size(),
        reinterpret_cast<const unsigned char*>(adds.data()), adds.size(),
        reinterpret_cast<const unsigned char*>(dels.data()), dels.size(), emit, &context);
    if (context.error) std::rethrow_exception(context.error);
    if (status != 0 || !context.emitted || !context.result.commitment.IsCanonical())
        throw std::runtime_error("Utreexo transition failed closed");
    return std::move(context.result);
}

bool CheckHeader(const CBlockHeader& block, const Consensus::Params& consensus, int height)
{
    const bool expected = consensus.utreexo && height > 0;
    return block.HasUtreexo() == expected &&
        (expected ? block.utreexo.IsCanonical() : block.utreexo == UtreexoCommitment{});
}

static Result Genesis(const CChainParams& params)
{
    std::vector<uint256> leaves;
    if (params.GetConsensus().connect_genesis_outputs) {
        for (const auto& tx : params.GenesisBlock().vtx) {
            for (uint32_t i = 0; i < tx->vout.size(); ++i) {
                if (!tx->vout[i].scriptPubKey.IsUnspendable())
                    leaves.push_back(Leaf(params.GetConsensus().hashGenesisBlock,
                        COutPoint(tx->GetHash(), i), Coin(tx->vout[i], 0, tx->IsCoinBase())));
            }
        }
    }
    return Transition({}, leaves, {});
}

struct Snapshot {
    uint256 checksum;
    std::vector<unsigned char> forest;
    SERIALIZE_METHODS(Snapshot, obj) { READWRITE(obj.checksum, obj.forest); }
};

static Result Load(kernel::BlockTreeDB& db, const CBlockIndex& previous, const CChainParams& params)
{
    if (previous.nHeight == 0) return Genesis(params);
    Snapshot record;
    if (!db.Read(std::make_pair(DB_ACCUMULATOR, previous.GetBlockHash()), record) ||
        record.checksum != (HashWriter{} << record.forest).GetHash())
        throw std::runtime_error("Missing/corrupt Utreexo snapshot; reindex required");
    auto result = Transition(record.forest, {}, {});
    if (result.commitment != previous.utreexo)
        throw std::runtime_error("Utreexo snapshot does not match authenticated predecessor header");
    return result;
}

Result Compute(const CBlock& block, const CBlockIndex* previous, const CCoinsViewCache& coins,
               const CChainParams& params, kernel::BlockTreeDB& db)
{
    if (!previous || coins.GetBestBlock() != previous->GetBlockHash())
        throw std::runtime_error("Utreexo coin view does not match predecessor");
    const auto initial = Load(db, *previous, params);
    const auto& genesis = params.GetConsensus().hashGenesisBlock;
    std::vector<uint256> adds, dels;
    std::vector<bool> retained;
    std::map<COutPoint, size_t> created;
    std::set<COutPoint> spent;
    for (const auto& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const auto& in : tx->vin) {
                if (in.m_is_pegin) continue; // Parent replay, not a child UTXO.
                if (!spent.insert(in.prevout).second) throw std::runtime_error("duplicate Utreexo input");
                const auto it = created.find(in.prevout);
                if (it != created.end()) {
                    retained[it->second] = false;
                    created.erase(it);
                } else {
                    const auto& coin = coins.AccessCoin(in.prevout);
                    if (coin.IsSpent()) throw std::runtime_error("missing Utreexo input");
                    dels.push_back(Leaf(genesis, in.prevout, coin));
                }
            }
        }
        for (uint32_t i = 0; i < tx->vout.size(); ++i) {
            if (tx->vout[i].scriptPubKey.IsUnspendable()) continue;
            const COutPoint outpoint(tx->GetHash(), i);
            if (coins.HaveCoin(outpoint) || !created.emplace(outpoint, adds.size()).second)
                throw std::runtime_error("overwritten Utreexo output");
            adds.push_back(Leaf(genesis, outpoint, Coin(tx->vout[i], previous->nHeight + 1, tx->IsCoinBase())));
            retained.push_back(true);
        }
    }
    std::vector<uint256> surviving;
    for (size_t i = 0; i < adds.size(); ++i) if (retained[i]) surviving.push_back(adds[i]);
    return Transition(initial.forest, surviving, dels);
}

bool Store(kernel::BlockTreeDB& db, const uint256& block, const Result& result)
{
    // Durable before BLOCK_VALID_SCRIPTS. A crash can leave an unused immutable
    // snapshot, never a validated tip whose snapshot was not written.
    return db.Write(std::make_pair(DB_ACCUMULATOR, block), Snapshot{
        (HashWriter{} << result.forest).GetHash(), result.forest}, true);
}

void Prepare(CBlock& block, const CBlockIndex* previous, const CCoinsViewCache& coins,
             const CChainParams& params, kernel::BlockTreeDB& db)
{
    if (!params.GetConsensus().utreexo) return;
    block.nVersion |= HEADER_BIT;
    block.utreexo = Compute(block, previous, coins, params, db).commitment;
}
}
