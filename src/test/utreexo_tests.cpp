// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <utreexo.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/params.h>
#include <hash.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

struct UtreexoTestingSetup : BasicTestingSetup {
    UtreexoTestingSetup() : BasicTestingSetup(ChainTypeMetaFrom("elementsutreexo")) {}
};

BOOST_FIXTURE_TEST_SUITE(utreexo_tests, UtreexoTestingSetup)

BOOST_AUTO_TEST_CASE(ffi_transition_and_forks)
{
    const auto a = uint256::ONE, b = uint256S("02"), c = uint256S("03");
    const auto initial = utreexo::Transition({}, {a, b}, {});
    BOOST_CHECK_EQUAL(initial.commitment.leaves, 2);
    const auto right = utreexo::Transition(initial.forest, {c}, {a});
    const auto left = utreexo::Transition(initial.forest, {c}, {b});
    BOOST_CHECK(right.commitment != left.commitment);
    BOOST_CHECK(utreexo::Transition(right.forest, {}, {}).commitment == right.commitment);
    BOOST_CHECK(utreexo::Transition(initial.forest, {}, {}).commitment == initial.commitment);
    BOOST_CHECK_THROW(utreexo::Transition(initial.forest, {a}, {}), std::runtime_error);
    BOOST_CHECK_THROW(utreexo::Transition(initial.forest, {}, {c}), std::runtime_error);
    BOOST_CHECK_THROW(utreexo::Transition(initial.forest, {}, {a,a}), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(confidential_coin_binding)
{
    CTxOut out;
    out.nAsset.vchCommitment = std::vector<unsigned char>(33, 7);
    out.nAsset.vchCommitment[0] = 0x0a;
    out.nValue.vchCommitment = std::vector<unsigned char>(33, 9);
    out.nValue.vchCommitment[0] = 0x08;
    out.nNonce.vchCommitment = std::vector<unsigned char>(33, 3);
    out.nNonce.vchCommitment[0] = 0x02;
    out.scriptPubKey = CScript() << OP_TRUE;
    const Coin coin(out, 7, false);
    const COutPoint point(Txid::FromUint256(uint256::ONE), 2);
    const auto genesis = uint256S("1234");
    const auto expected = utreexo::Leaf(genesis, point, coin);
    for (int field = 0; field < 5; ++field) {
        auto changed = coin;
        if (field == 0) changed.out.nAsset.vchCommitment[1] ^= 1;
        if (field == 1) changed.out.nValue.vchCommitment[1] ^= 1;
        if (field == 2) changed.out.scriptPubKey << OP_DROP;
        if (field == 3) changed.nHeight++;
        if (field == 4) changed.fCoinBase = true;
        BOOST_CHECK(utreexo::Leaf(genesis, point, changed) != expected);
    }
    BOOST_CHECK(utreexo::Leaf(uint256::ONE, point, coin) != expected);
    BOOST_CHECK(utreexo::Leaf(genesis, COutPoint(point.hash, 3), coin) != expected);
    DataStream disk;
    disk << coin;
    Coin restored;
    disk >> restored;
    BOOST_CHECK(restored.out.nNonce.IsNull());
    BOOST_CHECK(utreexo::Leaf(genesis, point, restored) == expected);
}

BOOST_AUTO_TEST_CASE(header_identity_and_disk)
{
    CBlock block;
    block.nVersion = 4 | utreexo::HEADER_BIT;
    block.nBits = 0x207fffff;
    block.block_height = 1;
    block.utreexo = utreexo::Transition({}, {uint256::ONE}, {}).commitment;
    const auto hash = block.GetHash(), critical = block.GetBmmCriticalHash();
    DataStream encoded;
    encoded << block.GetBlockHeader();
    CBlockHeader decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded.utreexo == block.utreexo);
    BOOST_CHECK(decoded.GetHash() == hash);
    CBlockIndex index(block);
    index.nHeight = 1;
    CDiskBlockIndex disk(&index), read;
    DataStream index_bytes;
    index_bytes << disk;
    index_bytes >> read;
    BOOST_CHECK(read.utreexo == block.utreexo);
    BOOST_CHECK(read.ConstructBlockHash() == hash);
    BOOST_CHECK(index.GetBlockHeader().utreexo == block.utreexo);
    block.utreexo.roots[0] = uint256S("4321");
    BOOST_CHECK(block.GetHash() != hash);
    BOOST_CHECK(block.GetBmmCriticalHash() != critical);
    Consensus::Params params;
    BOOST_CHECK(!utreexo::CheckHeader(block, params, 1));
    params.utreexo = true;
    BOOST_CHECK(utreexo::CheckHeader(block, params, 1));
    block.nVersion &= ~utreexo::HEADER_BIT;
    BOOST_CHECK(!utreexo::CheckHeader(block, params, 1));
}

BOOST_AUTO_TEST_CASE(bounded_header_shape)
{
    DataStream malformed;
    malformed << uint64_t{1};
    WriteCompactSize(malformed, 64);
    UtreexoCommitment state;
    BOOST_CHECK_THROW(malformed >> state, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(existing_network_serialization)
{
    const auto ordinary = CreateChainParams(ArgsManager{}, "elementsregtest");
    BOOST_CHECK(!ordinary->GetConsensus().utreexo);
    CBlock block;
    block.nVersion = 4 | utreexo::HEADER_BIT;
    BOOST_CHECK(!block.HasUtreexo());
    BOOST_CHECK(utreexo::CheckHeader(block, ordinary->GetConsensus(), 1));
    const auto hash = block.GetHash();
    DataStream before;
    before << block.GetBlockHeader();
    block.utreexo = utreexo::Transition({}, {uint256::ONE}, {}).commitment;
    DataStream after;
    after << block.GetBlockHeader();
    BOOST_CHECK(before.size() == after.size());
    BOOST_CHECK(block.GetHash() == hash);
}

BOOST_AUTO_TEST_CASE(snapshot_authentication)
{
    kernel::BlockTreeDB db(DBParams{.path = m_path_root / "utreexo", .cache_bytes = 0, .memory_only = true});
    CCoinsView base;
    CCoinsViewCache coins(&base);
    const auto hash = uint256S("1234");
    CBlockIndex previous;
    previous.nHeight = 1;
    previous.phashBlock = &hash;
    coins.SetBestBlock(hash);
    CBlock block;
    const auto state = utreexo::Transition({}, {uint256::ONE}, {});
    previous.utreexo = state.commitment;
    const auto withdrawal_key = std::make_pair(uint8_t{'U'}, hash);
    BOOST_REQUIRE(db.Write(withdrawal_key, uint64_t{123}));
    BOOST_CHECK_THROW(utreexo::Compute(block, &previous, coins, Params(), db), std::runtime_error);
    BOOST_REQUIRE(utreexo::Store(db, hash, state));
    uint64_t withdrawal{0};
    BOOST_REQUIRE(db.Read(withdrawal_key, withdrawal));
    BOOST_CHECK_EQUAL(withdrawal, 123);
    BOOST_CHECK(utreexo::Compute(block, &previous, coins, Params(), db).commitment == state.commitment);
    const auto key = std::make_pair(uint8_t{'A'}, hash);
    BOOST_REQUIRE(db.Write(key, std::make_pair(uint256::ZERO, state.forest)));
    BOOST_CHECK_THROW(utreexo::Compute(block, &previous, coins, Params(), db), std::runtime_error);
    const auto other = utreexo::Transition({}, {uint256S("05")}, {});
    BOOST_REQUIRE(db.Write(key, std::make_pair((HashWriter{} << other.forest).GetHash(), other.forest)));
    BOOST_CHECK_THROW(utreexo::Compute(block, &previous, coins, Params(), db), std::runtime_error);
}
BOOST_AUTO_TEST_SUITE_END()
