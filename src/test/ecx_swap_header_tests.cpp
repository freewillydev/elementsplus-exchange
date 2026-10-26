// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <chain.h>
#include <chainparams.h>
#include <haskell/bridge.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {
struct SwapHeaderSetup : BasicTestingSetup {
    SwapHeaderSetup() : BasicTestingSetup(ChainTypeMetaFrom("elementsregtest")) {}
};

struct SwapWireMode {
    const bool previous{g_con_ecx_swap_v3};
    explicit SwapWireMode(bool enabled) { g_con_ecx_swap_v3 = enabled; }
    ~SwapWireMode() { g_con_ecx_swap_v3 = previous; }
};

CBlockHeader Header()
{
    CBlockHeader header;
    header.nVersion = 4 | CBlockHeader::EXCHANGE_STATE_HF_MASK |
        CBlockHeader::FORCED_INBOX_HF_MASK | CBlockHeader::DEPOSIT_INBOX_HF_MASK |
        CBlockHeader::INBOX_CURSOR_HF_MASK | CBlockHeader::SWAP_FORCED_STATE_HF_MASK;
    header.block_height = 42;
    header.nTime = 1234;
    header.swapForcedState.fill(0xa5);
    // Wire tests deliberately include high count/cursor bytes. Semantic state
    // validation and source/proof binding belong to the fresh admission lane.
    header.swapForcedState[0] = 3;
    return header;
}

template <typename T>
std::vector<unsigned char> Bytes(const T& value)
{
    DataStream stream;
    stream << value;
    return {UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(ecx_swap_header_tests, SwapHeaderSetup)

BOOST_AUTO_TEST_CASE(header_layout_bridge_preserves_explicit_mode_boundary)
{
    constexpr uint32_t marker{CBlockHeader::SWAP_FORCED_STATE_HF_MASK};
    for (uint32_t flags : {1U, 3U, 16U, 33U, 35U}) {
        const auto legacy = drivechain::haskell::BmmHeaderLayout(marker, flags);
        const auto fresh = drivechain::haskell::BmmHeaderLayout(marker, flags | 64U);
        BOOST_CHECK_EQUAL(legacy[1] & 512U, 0U);
        BOOST_CHECK_EQUAL(fresh[0], legacy[0]);
        BOOST_CHECK_EQUAL(fresh[1], legacy[1] | 512U);
        BOOST_CHECK_EQUAL(drivechain::haskell::BmmHeaderLayout(0, flags | 64U)[1], legacy[1]);
    }
    for (uint32_t flags : {48U, 63U, 112U, 127U, 128U, UINT32_MAX}) {
        BOOST_CHECK_THROW(drivechain::haskell::BmmHeaderLayout(marker, flags), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(legacy_mode_preserves_arbitrary_bit14)
{
    SwapWireMode mode{false};
    auto header = Header();
    const auto original = Bytes(header);
    const auto original_hash = header.GetHash();
    header.swapForcedState.fill(0);
    BOOST_CHECK(Bytes(header) == original);
    BOOST_CHECK(header.GetHash() == original_hash);
    BOOST_CHECK(!header.HasSwapForcedState());
    DataStream input{original};
    CBlockHeader restored;
    restored.swapForcedState.fill(0xff);
    input >> restored;
    BOOST_CHECK(input.empty());
    BOOST_CHECK(restored.swapForcedState == header.swapForcedState);
    BOOST_CHECK(Bytes(restored) == original);

    // Both the old raw query and old serialization flags preserve their exact
    // behavior. Merely setting the version bit cannot select the fresh codec.
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmHeaderLayout(header.nVersion, 16)[1] & 512, 0);
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmHeaderLayout(header.nVersion, 1)[1] & 512, 0);
}

BOOST_AUTO_TEST_CASE(fresh_header_hash_and_disk_index_preserve_every_state_byte)
{
    const auto header = Header();
    std::vector<unsigned char> legacy;
    { SwapWireMode disabled{false}; legacy = Bytes(header); }
    SwapWireMode enabled{true};
    BOOST_CHECK(header.HasSwapForcedState());
    const auto encoded = Bytes(header);
    BOOST_CHECK_EQUAL(encoded.size(), legacy.size() + CBlockHeader::SWAP_FORCED_STATE_SIZE);
    DataStream input{encoded};
    CBlockHeader restored;
    input >> restored;
    BOOST_CHECK(input.empty());
    BOOST_CHECK(restored.swapForcedState == header.swapForcedState);
    BOOST_CHECK(Bytes(restored) == encoded);
    BOOST_CHECK(restored.GetHash() == header.GetHash());
    for (size_t i = 0; i < header.swapForcedState.size(); ++i) {
        auto changed = header;
        changed.swapForcedState[i] ^= 1;
        BOOST_CHECK(changed.GetHash() != header.GetHash());
        BOOST_CHECK(changed.GetBmmCriticalHash() != header.GetBmmCriticalHash());
    }

    CBlockIndex index{header};
    index.nHeight = header.block_height;
    BOOST_CHECK(index.GetBlockHeader().swapForcedState == header.swapForcedState);
    CDiskBlockIndex disk{&index};
    DataStream disk_bytes;
    disk_bytes << disk;
    CDiskBlockIndex loaded;
    disk_bytes >> loaded;
    BOOST_CHECK(disk_bytes.empty());
    BOOST_CHECK(loaded.swapForcedState == header.swapForcedState);
    BOOST_CHECK(loaded.ConstructBlockHash() == header.GetHash());

    CBlock block;
    static_cast<CBlockHeader&>(block) = header;
    BOOST_CHECK(block.GetBlockHeader().swapForcedState == header.swapForcedState);
    block.SetNull();
    BOOST_CHECK(block.swapForcedState == CBlockHeader{}.swapForcedState);
}

BOOST_AUTO_TEST_CASE(fresh_mode_requires_marker_and_rejects_truncated_state)
{
    SwapWireMode mode{true};
    const auto header = Header();
    const auto encoded = Bytes(header);
    for (size_t length = encoded.size() - CBlockHeader::SWAP_FORCED_STATE_SIZE;
         length < encoded.size(); ++length) {
        DataStream input{std::vector<unsigned char>(encoded.begin(), encoded.begin() + length)};
        CBlockHeader restored;
        BOOST_CHECK_THROW(input >> restored, std::ios_base::failure);
    }
    auto unmarked = header;
    unmarked.nVersion &= ~CBlockHeader::SWAP_FORCED_STATE_HF_MASK;
    BOOST_CHECK(!unmarked.HasSwapForcedState());
    const auto unmarked_bytes = Bytes(unmarked);
    unmarked.swapForcedState.fill(0);
    BOOST_CHECK(Bytes(unmarked) == unmarked_bytes);
}

BOOST_AUTO_TEST_SUITE_END()
