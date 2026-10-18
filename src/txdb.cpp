// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <coins.h>
#include <dbwrapper.h>
#include <haskell/bridge.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <uint256.h>
#include <util/vector.h>

#include <cassert>
#include <cstdlib>
#include <iterator>
#include <utility>

// ELEMENTS
#include <block_proof.h> // CheckProof
#include <chainparams.h> // Params()

static constexpr uint8_t DB_COIN{'C'};
static constexpr uint8_t DB_BEST_BLOCK{'B'};
static constexpr uint8_t DB_HEAD_BLOCKS{'H'};
// Keys used in previous version that might still be found in the DB:
static constexpr uint8_t DB_COINS{'c'};
// ELEMENTS
static constexpr uint8_t DB_PEGIN_FLAG{'w'};

bool CCoinsViewDB::NeedsUpgrade()
{
    std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
    // DB_COINS was deprecated in v0.15.0, commit
    // 1088b02f0ccd7358d2b7076bb9e122d59d502d02
    cursor->Seek(std::make_pair(DB_COINS, uint256{}));
    std::pair<unsigned char, uint256> key;
    return cursor->Valid() && cursor->GetKey(key) && key.first == DB_COINS;
}

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    uint8_t key;
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

    SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }
};

} // namespace

CCoinsViewDB::CCoinsViewDB(DBParams db_params, CoinsViewOptions options) :
    m_db_params{std::move(db_params)},
    m_options{std::move(options)},
    m_db{std::make_unique<CDBWrapper>(m_db_params)} { }

void CCoinsViewDB::ResizeCache(size_t new_cache_size)
{
    // We can't do this operation with an in-memory DB since we'll lose all the coins upon
    // reset.
    if (!m_db_params.memory_only) {
        // Have to do a reset first to get the original `m_db` state to release its
        // filesystem lock.
        m_db.reset();
        m_db_params.cache_bytes = new_cache_size;
        m_db_params.wipe_data = false;
        m_db = std::make_unique<CDBWrapper>(m_db_params);
    }
}

std::optional<Coin> CCoinsViewDB::GetCoin(const COutPoint& outpoint) const
{
    if (Coin coin; m_db->Read(CoinEntry(&outpoint), coin)) return coin;
    return std::nullopt;
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return m_db->Exists(CoinEntry(&outpoint));
}

// ELEMENTS:
bool CCoinsViewDB::IsPeginSpent(const std::pair<uint256, COutPoint> &outpoint) const {
    return m_db->Exists(std::make_pair(DB_PEGIN_FLAG, outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!m_db->Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!m_db->Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) {
    CDBBatch batch(*m_db);
    size_t count = 0;
    size_t changed = 0;
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            if (old_heads[0] != hashBlock) {
                LogPrintLevel(BCLog::COINDB, BCLog::Level::Error, "The coins database detected an inconsistent state, likely due to a previous crash or shutdown. You will need to restart bitcoind with the -reindex-chainstate or -reindex configuration option.\n");
            }
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));

    for (auto it{cursor.Begin()}; it != cursor.End();) {
        if (it->second.IsDirty()) {
            // ELEMENTS:
            if (it->second.IsPegin()) {
                if (!it->second.peginSpent) {
                    batch.Erase(std::make_pair(DB_PEGIN_FLAG, it->first));
                } else {
                    // Once spent, we don't care about the entry data, so we store
                    // a static byte to indicate spentness.
                    batch.Write(std::make_pair(DB_PEGIN_FLAG, it->first), 1);
                }
            } else {
                // Non-pegin entries are stored the same way as in Core.
                CoinEntry entry(&it->first.second);
                if (it->second.coin.IsSpent()) {
                    batch.Erase(entry);
                } else {
                    batch.Write(entry, it->second.coin);
                }
            }
            changed++;
        }
        count++;
        it = cursor.NextAndMaybeErase(*it);
        if (batch.SizeEstimate() > m_options.batch_write_bytes) {
            LogDebug(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
            m_db->WriteBatch(batch);
            batch.Clear();
            if (m_options.simulate_crash_ratio) {
                static FastRandomContext rng;
                if (rng.randrange(m_options.simulate_crash_ratio) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    LogDebug(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
    bool ret = m_db->WriteBatch(batch);
    LogDebug(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return m_db->EstimateSize(DB_COIN, uint8_t(DB_COIN + 1));
}

namespace {
// The generic DB decoder allows trailing data; checkpoint records must not.
template <typename T> struct ExactDBRecord {
    T value{};
    template <typename Stream> void Unserialize(Stream& stream)
    {
        stream >> value;
        if (!stream.empty()) throw std::ios_base::failure("Trailing checkpoint DB bytes");
    }
};
struct ExactCoinKey {
    COutPoint outpoint;
    template <typename Stream> void Unserialize(Stream& stream)
    {
        CoinEntry entry{&outpoint};
        stream >> entry;
        if (entry.key != DB_COIN || !stream.empty())
            throw std::ios_base::failure("Malformed checkpoint coin key");
    }
};

bool ReadCheckpointKey(CDBIterator& cursor, uint8_t expected,
    drivechain::haskell::ReplayStoreFlow flow, const std::function<bool(uint32_t)>& decode,
    const char* prefix_error, const char* record_error)
{
    cursor.CheckStatus();
    uint8_t prefix{};
    const auto result = drivechain::haskell::ParentReplayStore(flow, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return cursor.Valid();
        case 2: return cursor.GetKey(prefix);
        case 3: return prefix == expected;
        default: return decode(step);
        }
    });
    if (result == 2) throw dbwrapper_error(prefix_error);
    if (result == 3) throw dbwrapper_error(record_error);
    return result == 1;
}
}

CSpentPeginCursor::CSpentPeginCursor(std::unique_ptr<CDBIterator> cursor)
    : m_cursor(std::move(cursor))
{
    // Read metadata using the same LevelDB iterator snapshot as the claims.
    uint8_t prefix{};
    ExactDBRecord<uint8_t> key;
    ExactDBRecord<uint256> value;
    const auto admission = drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::CHECKPOINT_METADATA, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: case 4:
                m_cursor->Seek(step == 1 ? DB_HEAD_BLOCKS : DB_BEST_BLOCK);
                m_cursor->CheckStatus();
                return m_cursor->Valid();
            case 2: return m_cursor->GetKey(prefix);
            case 3: return prefix != DB_HEAD_BLOCKS;
            case 5: return m_cursor->GetKey(key);
            case 6: return key.value == DB_BEST_BLOCK;
            case 7: return m_cursor->GetValue(value);
            case 8: return !value.value.IsNull();
            default: throw std::logic_error("Invalid checkpoint metadata step");
            }
        });
    if (admission == 1)
        throw dbwrapper_error("Cannot snapshot an incomplete chainstate transition");
    if (admission != 0)
        throw dbwrapper_error("Missing or malformed checkpoint best block");
    m_best_block = value.value;
    m_cursor->Seek(DB_PEGIN_FLAG);
    ReadKey();
}

void CSpentPeginCursor::ReadKey()
{
    m_key.reset();
    ExactDBRecord<std::pair<uint8_t, std::pair<uint256, COutPoint>>> key;
    ExactDBRecord<int> value;
    if (ReadCheckpointKey(*m_cursor, DB_PEGIN_FLAG, drivechain::haskell::ReplayStoreFlow::CHECKPOINT_CLAIM,
        [&](uint32_t step) {
            switch (step) {
            case 4: return m_cursor->GetKey(key);
            case 5: return m_cursor->GetValue(value);
            case 6: return value.value == 1;
            default: throw std::logic_error("Invalid checkpoint claim step");
            }
        }, "Malformed spent-claim prefix", "Malformed spent-claim record")) m_key = key.value.second;
}

void CSpentPeginCursor::Next()
{
    if (!Valid()) return;
    m_cursor->Next();
    ReadKey();
}

std::unique_ptr<CSpentPeginCursor> CCoinsViewDB::SpentPeginCursor() const
{
    return std::make_unique<CSpentPeginCursor>(std::unique_ptr<CDBIterator>{m_db->NewIterator()});
}

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    // Prefer using CCoinsViewDB::Cursor() since we want to perform some
    // cache warmup on instantiation.
    CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256&hashBlockIn, bool strict = false):
        CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn), m_strict(strict) {}
    ~CCoinsViewDBCursor() = default;

    bool GetKey(COutPoint &key) const override;
    bool GetValue(Coin &coin) const override;

    bool Valid() const override;
    void Next() override;

private:
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;
    bool m_strict;
    void ReadStrictKey();

    friend class CCoinsViewDB;
};

void CCoinsViewDBCursor::ReadStrictKey()
{
    keyTmp.first = 0;
    ExactCoinKey key;
    if (ReadCheckpointKey(*pcursor, DB_COIN, drivechain::haskell::ReplayStoreFlow::CHECKPOINT_COIN_KEY,
        [&](uint32_t step) {
            if (step != 4) throw std::logic_error("Invalid checkpoint coin key step");
            return pcursor->GetKey(key);
        }, "Malformed checkpoint coin prefix", "Malformed checkpoint coin key")) keyTmp = {DB_COIN, key.outpoint};
}

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::CheckpointCoinCursor() const
{
    auto cursor = std::make_unique<CCoinsViewDBCursor>(m_db->NewIterator(), GetBestBlock(), true);
    cursor->pcursor->Seek(DB_COIN);
    cursor->ReadStrictKey();
    return cursor;
}

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::Cursor() const
{
    auto i = std::make_unique<CCoinsViewDBCursor>(
        const_cast<CDBWrapper&>(*m_db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    if (m_strict) {
        ExactDBRecord<Coin> record;
        const auto result = drivechain::haskell::ParentReplayStore(
            drivechain::haskell::ReplayStoreFlow::CHECKPOINT_COIN_VALUE, [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return Valid();
                case 2: pcursor->CheckStatus(); return 1;
                case 3: return pcursor->GetValue(record);
                case 4: return !record.value.IsSpent();
                default: throw std::logic_error("Invalid checkpoint coin value step");
                }
            });
        if (result == 0) return false;
        if (result != 1) throw dbwrapper_error("Malformed checkpoint coin value");
        coin = std::move(record.value);
        return true;
    }
    return pcursor->GetValue(coin);
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    if (m_strict) {
        if (!Valid()) return;
        pcursor->Next();
        ReadStrictKey();
        return;
    }
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}
