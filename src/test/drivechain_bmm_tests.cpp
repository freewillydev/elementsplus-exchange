// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_bmm.h>
#include <script/interpreter.h>
#include <haskell/bridge.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <vector>
#include <tuple>
#include <type_traits>

namespace {

struct ElementsTestingSetup : BasicTestingSetup {
    ElementsTestingSetup()
        : BasicTestingSetup(ChainTypeMetaFrom("elementsregtest"))
    {
    }
};

template <typename T>
std::vector<unsigned char> SerializeValue(const T& value)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(value);
    return {
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()};
}

drivechain::BmmL1State AuthenticState6399()
{
    return {
        uint256S("000001d9988239435d51e763fd4231893dad22d7d03048266a5e21361e2db065"),
        6399,
        1784825405,
        0x1e0376cc,
        6048,
        1784614805,
        {
            1784819405,
            1784820005,
            1784820605,
            1784821205,
            1784821805,
            1784822405,
            1784823005,
            1784823605,
            1784824205,
            1784824805,
            1784825405,
        }};
}

drivechain::BmmProof AuthenticProof6400()
{
    const std::string coinbase_hex{
        "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03020019ffffffff0b0000000000000000276a25d16173680455ac64b9a5f6a28521c319379ecedfd436b5734fb6ec85aab4168738fd4685ba0000000000000000276a25d1617368094ed23c4ff5c783923cf1ae96b4eff6c85d466c3129fa9996cf8f149710c642400000000000000000276a25d161736862741449c742d45808126397a716bcc81bf9add9f8bb94b6b5e62b585469b67d590000000000000000276a25d161736863c4381671acc63c1281879c7b3f5dfad439a3f2b8933e93f11e11d5568a86651a0000000000000000276a25d1617368020c8c11ed67c0a0f06f078377c51127aaa5592f60b65a414be4e5f9f90efd98bf0000000000000000276a25d1617368ff7dbb40767d35826afdd53ec64334edfde50c00d688f84c1d69e32c1bafe148bc0000000000000000276a25d16173680d8c5c5ce2ad2dea77630824786c1b1c38e45940bc2dbe18715ebb81e1e90b355d00000000000000000f6a0dd77d177601ffffffffffffffff0000000000000000276a25d161736818ce77dfe3b037f2e62624da0ee5e33ae3c23b8b18ddf3b87a687bb372a8406998bdf2052a01000000160014fae83223f01759582ffe70f5f770eb8462f04da20000000000000000986a24aa21a9edfa53326790c56b7b9ccb48914d00fe7edac8cc01712824b2e008620eed22dcb54c70ecc7daa2000247304402204c28ded7cc42bee894128afca0e87aa16bbd361f76a22e792e20b61cac065edf0220407dec66676adeeebe06b567f763e0f44818ed266f1e2edc8f66f88b4ad6fef4012103675b73e701c9dab7de809bb0000b4c1205f9a834d669a7f47c107a7d2c199f560120000000000000000000000000000000000000000000000000000000000000000000000000"};
    const std::string proof_hex{
        "0000002065b02d1e36215e6a264830d0d722ad3d893142fd63e7515d43398298d901000037476252e051ca3d0e1f1757e3e2a4f2e91f19c091430dedec09b5279e96e6b09548626acc76031e5e7525000200000002ec6c869bd1b88b9c3f038d949183429c5d0ec7cc352252bf62e0457606480198528a562cb457d9d04371d471d0504d84b7431e890d289e2974dcbcb0aa27f6350103"};
    drivechain::BmmProof proof;
    proof.previous_state = AuthenticState6399();
    proof.entries.push_back({ParseHex(coinbase_hex), ParseHex(proof_hex)});
    return proof;
}

drivechain::BmmConsensus EasyConsensus()
{
    return {
        uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        14 * 24 * 60 * 60,
        10 * 60,
        CScript() << OP_TRUE,
        drivechain::BMM_SIDECHAIN_SLOT,
        8,
        100'000,
        true};
}

drivechain::BmmL1State EasyState()
{
    return {
        uint256S("01"),
        100,
        100'000,
        UintToArith256(EasyConsensus().pow_limit).GetCompact(),
        0,
        40'000,
        {
            94'000,
            94'600,
            95'200,
            95'800,
            96'400,
            97'000,
            97'600,
            98'200,
            98'800,
            99'400,
            100'000,
        }};
}

CBlock SidechainCandidate(const uint256& parent_hash)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(
        Params().GetConsensus().pegged_asset,
        0,
        CScript() << OP_TRUE);
    coinbase.vout.emplace_back(
        Params().GetConsensus().pegged_asset,
        0,
        CScript() << OP_RETURN <<
            std::vector<unsigned char>(parent_hash.begin(), parent_hash.end()));

    CBlock block;
    block.nVersion = 0x20000000 | CBlockHeader::BMM_PROOF_HF_MASK;
    block.hashPrevBlock = uint256S("02");
    block.nTime = 101'000;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

drivechain::BmmProof EasyProof(
    const drivechain::BmmL1State& previous,
    const uint256& critical_hash,
    const std::vector<CScript>* replacements = nullptr,
    bool include_witness = true)
{
    Sidechain::Bitcoin::CMutableTransaction coinbase;
    coinbase.version = 2;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 101;

    std::vector<unsigned char> witness_commitment{
        0xaa, 0x21, 0xa9, 0xed};
    witness_commitment.resize(36, 0);
    if (include_witness) coinbase.vout.emplace_back(0, CScript() << OP_RETURN << witness_commitment);

    std::vector<unsigned char> m8{
        0xd1, 0x61, 0x73, 0x68,
        static_cast<unsigned char>(drivechain::BMM_SIDECHAIN_SLOT)};
    const std::vector<unsigned char> critical_bytes{
        ParseHex(critical_hash.GetHex())};
    m8.insert(m8.end(), critical_bytes.begin(), critical_bytes.end());
    if (replacements) {
        for (const auto& script : *replacements) coinbase.vout.emplace_back(0, script);
    } else {
        coinbase.vout.emplace_back(0, CScript() << OP_RETURN << m8);
    }

    Sidechain::Bitcoin::CBlockHeader header;
    header.nVersion = 0x20000000;
    header.hashPrevBlock = previous.block_hash;
    header.hashMerkleRoot = coinbase.GetHash();
    header.nTime = previous.block_time + 600;
    header.nBits = previous.n_bits;
    while (UintToArith256(header.GetHash()) >
           UintToArith256(EasyConsensus().pow_limit)) {
        ++header.nNonce;
    }

    Sidechain::Bitcoin::CMerkleBlock merkle;
    merkle.header = header;
    merkle.txn = Sidechain::Bitcoin::CPartialMerkleTree(
        {coinbase.GetHash()},
        {true});

    drivechain::BmmProof proof;
    proof.previous_state = previous;
    proof.entries.push_back({
        SerializeValue(coinbase),
        SerializeValue(merkle)});
    return proof;
}

Sidechain::Bitcoin::CMerkleBlock DecodeMerkleProof(
    const drivechain::BmmProofEntry& entry)
{
    Sidechain::Bitcoin::CMerkleBlock merkle;
    DataStream stream(
        entry.coinbase_proof);
    stream >> merkle;
    BOOST_REQUIRE(stream.empty());
    return merkle;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(drivechain_bmm_tests, ElementsTestingSetup)

BOOST_AUTO_TEST_CASE(haskell_production_preparation_preserves_short_circuiting)
{
    // Facts: Elements mode, parent chain, chainman, mempool, signed blocks,
    // nonce search success, witness construction success, null dynafed params.
    for (unsigned mask = 0; mask < 256; ++mask) {
        for (int fault = -1; fault < 8; ++fault) {
            std::vector<int> expected, actual;
            const auto run = [&](bool haskell, std::vector<int>& trace) {
                const auto fact = [&](int index) {
                    trace.push_back(index);
                    if (index == fault) throw std::runtime_error("production fact fault");
                    return bool(mask & (1U << index));
                };
                if (!haskell) {
                    if (!fact(0) || !fact(1)) return false;
                    if (!fact(2) || !fact(3)) return false;
                    if (!fact(4) && !fact(5)) return false;
                    if (!fact(6) && !fact(7)) return false;
                } else {
                    using drivechain::haskell::ParentReplayAll;
                    if (!ParentReplayAll<2>({[&] { return fact(0); }, [&] { return fact(1); }})) return false;
                    if (!ParentReplayAll<2>({[&] { return fact(2); }, [&] { return fact(3); }})) return false;
                    if (ParentReplayAll<2>({[&] { return !fact(4); }, [&] { return !fact(5); }})) return false;
                    if (ParentReplayAll<2>({[&] { return !fact(6); }, [&] { return !fact(7); }})) return false;
                }
                return true;
            };
            const auto outcome = [&](bool haskell, std::vector<int>& trace) {
                try { return int(run(haskell, trace)); }
                catch (const std::runtime_error& e) {
                    BOOST_CHECK_EQUAL(e.what(), "production fact fault");
                    return -1;
                }
            };
            const int expected_result = outcome(false, expected);
            BOOST_CHECK_EQUAL(outcome(true, actual), expected_result);
            BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
        }
    }
}

BOOST_AUTO_TEST_CASE(haskell_parent_state_preserves_bounds_and_header_phases)
{
    namespace hs = drivechain::haskell;
    for (const auto interval : std::array<int64_t, 7>{-1, 0, 1, 2016, 4294967296LL, 4294967297LL, INT64_MAX}) {
        std::string error = "untouched";
        const bool valid = interval > 0 && static_cast<uint32_t>(interval) != 0;
        BOOST_CHECK_EQUAL(hs::BmmState(true, interval, 1, 1, 1, 0, 1, 11, 1, error),
            valid && 1 < static_cast<uint32_t>(interval));
        if (valid && 1 < static_cast<uint32_t>(interval)) BOOST_CHECK_EQUAL(error, "untouched");
        else BOOST_CHECK_EQUAL(error, "BMM parent-chain state is malformed");
    }
    for (uint32_t proof = 0; proof < 4; ++proof) {
        std::string error;
        BOOST_CHECK_EQUAL(hs::BmmHeader(1 | (proof << 4), error), proof ? 1 : 0);
        BOOST_CHECK_EQUAL(hs::BmmHeader(proof << 4, error), 0);
    }
    std::string error;
    BOOST_CHECK_EQUAL(hs::BmmHeader(2 | 4, error), 2);
    BOOST_CHECK_EQUAL(hs::BmmHeader(2 | 4 | 8, error), 6);
    BOOST_CHECK_EQUAL(hs::BmmHeader(256 | 64, error), 3);
    BOOST_CHECK_EQUAL(hs::BmmHeader(256 | 64 | 16, error), 4);
    BOOST_CHECK_EQUAL(hs::BmmHeader(256 | 64 | 16 | 128, error), 0);
    BOOST_CHECK_EQUAL(hs::BmmHeader(256 | 16, error), 5);
    BOOST_CHECK_THROW(hs::BmmHeader(UINT32_MAX, error), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(haskell_retarget_and_median_preserve_time_rules)
{
    namespace hs = drivechain::haskell;
    BOOST_CHECK_EQUAL(hs::BmmRetarget(2014, 2016, 1209600, 0, UINT32_MAX), -1);
    BOOST_CHECK_EQUAL(hs::BmmRetarget(2015, 2016, 1209600, 0, UINT32_MAX), 302400);
    BOOST_CHECK_EQUAL(hs::BmmRetarget(2015, 2016, 1209600, UINT32_MAX, 0), 4838400);
    BOOST_CHECK_EQUAL(hs::BmmRetarget(2015, 2016, 1209600, 1209610, 10), 1209600);
    BOOST_CHECK_EQUAL(hs::BmmRetarget(UINT32_MAX, 4294967296LL, 3, 0, 1), 0);
    BOOST_CHECK_EQUAL(hs::BmmRetarget(0, 2016, 0, 0, 0), -1); // No clamp is evaluated off boundary.
    BOOST_CHECK_THROW(hs::BmmRetarget(0, 0, 1209600, 0, 0), std::runtime_error);
    BOOST_CHECK_THROW(hs::BmmRetarget(0, 1, INT64_MAX, 0, 0), std::runtime_error);
    BOOST_CHECK_THROW(hs::BmmMedian({}), std::runtime_error);
    for (const auto& times : std::vector<std::vector<uint32_t>>{{0}, {UINT32_MAX}, {1,0},
            {UINT32_MAX,0,1}, {5,4,3,2,1,0,10,9,8,7,6}, {1,1,0,0}}) {
        auto sorted = times;
        std::sort(sorted.begin(), sorted.end());
        BOOST_CHECK_EQUAL(hs::BmmMedian(times), sorted[sorted.size() / 2]);
    }
}

BOOST_AUTO_TEST_CASE(target_scaling_preserves_native_uint256_arithmetic)
{
    namespace hs = drivechain::haskell;
    const int64_t factors[]{0, 1, 1209600, 4838400, 0xffffffffLL, 0x100000000LL, 0x100000001LL, INT64_MAX};
    const int64_t divisors[]{1, 2, 1209600, 0x100000000LL, INT64_MAX};
    for (uint64_t i = 0; i < 2048; ++i) {
        uint256 target = (HashWriter{} << i).GetHash();
        const uint256 limit = (HashWriter{} << i << uint8_t{1}).GetHash();
        const auto factor = factors[i % std::size(factors)];
        const auto divisor = divisors[i % std::size(divisors)];
        arith_uint256 expected = UintToArith256(target);
        expected *= factor;
        expected /= divisor;
        if (expected > UintToArith256(limit)) expected = UintToArith256(limit);
        hs::BmmScaleTarget(factor, divisor, std::span<unsigned char, 32>{target.begin(), 32},
            std::span<const unsigned char, 32>{limit.begin(), 32});
        BOOST_CHECK_EQUAL(target, ArithToUint256(expected));
    }
    uint256 target = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const auto original = target;
    const auto bytes = std::span<unsigned char, 32>{target.begin(), 32};
    BOOST_CHECK_THROW(hs::BmmScaleTarget(1, 0, bytes, bytes), std::runtime_error);
    BOOST_CHECK_EQUAL(target, original);
    hs::BmmScaleTarget(0x100000001ULL, 1, bytes, bytes);
    BOOST_CHECK_EQUAL(target, original);
    hs::BmmScaleTarget(0x100000000ULL, 1, bytes, bytes);
    BOOST_CHECK(target.IsNull());
}

BOOST_AUTO_TEST_CASE(retarget_boundary_proofs_use_clamped_target)
{
    const auto consensus = EasyConsensus();
    for (const uint32_t timestamp : {50'000U, 1'249'600U, 5'000'000U}) {
        auto previous = EasyState();
        previous.height = 2015;
        previous.block_time = timestamp;
        for (size_t i = 0; i < previous.recent_times.size(); ++i) {
            previous.recent_times[i] = timestamp - (10 - i) * 600;
        }
        const auto critical = uint256S("987654321");
        auto proof = EasyProof(previous, critical);
        auto merkle = DecodeMerkleProof(proof.entries[0]);
        // Frozen native retarget calculation, independent of the Haskell plan.
        int64_t span = int64_t(timestamp) - previous.period_start_time;
        span = std::max(consensus.target_timespan / 4, span);
        span = std::min(consensus.target_timespan * 4, span);
        arith_uint256 target;
        target.SetCompact(previous.n_bits);
        target *= span;
        target /= consensus.target_timespan;
        const auto limit = UintToArith256(consensus.pow_limit);
        if (target > limit) target = limit;
        merkle.header.nBits = target.GetCompact();
        target.SetCompact(merkle.header.nBits);
        merkle.header.nNonce = 0;
        while (UintToArith256(merkle.header.GetHash()) > target) ++merkle.header.nNonce;
        proof.entries[0].coinbase_proof = SerializeValue(merkle);
        drivechain::BmmL1State next;
        std::string error;
        BOOST_REQUIRE_MESSAGE(drivechain::VerifyBmmProofEntries(proof, critical,
            previous.block_hash, next, error, consensus), error);
        BOOST_CHECK_EQUAL(next.n_bits, merkle.header.nBits);
        BOOST_CHECK_EQUAL(next.period_start_height, 2016U);
        BOOST_CHECK_EQUAL(next.period_start_time, merkle.header.nTime);
    }
}

BOOST_AUTO_TEST_CASE(activation_rules_preserve_bounds_and_early_exits)
{
    namespace hs = drivechain::haskell;
    for (uint32_t facts = 0; facts < 4; ++facts) {
        BOOST_CHECK_EQUAL(hs::BmmActivation(0, facts), facts == 2 ? 2 : 0);
        BOOST_CHECK_EQUAL(hs::BmmActivation(2, facts), facts ? 1 : 0);
    }
    BOOST_CHECK_EXCEPTION(hs::BmmActivation(1, 0), std::runtime_error, [](const auto& e) {
        return std::string(e.what()) == "-ecxprivatebmmcheckpoint requires an explicit -ecxprivatebmmactivationheight";
    });
    for (const int64_t activation : {-1LL, 0LL, 2147483647LL}) {
        BOOST_CHECK_EXCEPTION(hs::BmmActivation(1, 1, 0, activation), std::runtime_error, [](const auto& e) {
            return std::string(e.what()) == "invalid -ecxprivatebmmactivationheight";
        });
    }
    BOOST_CHECK_EQUAL(hs::BmmActivation(1, 1, 98, 100), 0);
    BOOST_CHECK_EQUAL(hs::BmmActivation(1, 1, 99, 100), 1);
    BOOST_CHECK_EQUAL(hs::BmmActivation(1, 1, 100, 100), 1);
    for (const int height : {std::numeric_limits<int>::min(), -1, 0, 1, 99, 100,
             std::numeric_limits<int>::max() - 1, std::numeric_limits<int>::max()}) {
        for (const int activation : {std::numeric_limits<int>::min(), -1, 0, 1, 100,
                 std::numeric_limits<int>::max() - 1, std::numeric_limits<int>::max()}) {
            BOOST_CHECK_EQUAL(hs::BmmActivation(3, 0, height, activation),
                activation != std::numeric_limits<int>::max() && height >= activation);
            for (uint32_t next : {0U, 1U}) {
                BOOST_CHECK_EQUAL(hs::BmmActivation(4, next, height, activation),
                    int64_t{height} + next >= activation);
            }
        }
    }
    BOOST_CHECK_THROW(hs::BmmActivation(3, 1), std::runtime_error);
    BOOST_CHECK_THROW(hs::BmmActivation(4, 2), std::runtime_error);
    BOOST_CHECK_THROW(hs::BmmActivation(5, 0), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(pow_target_failures_keep_error_and_state)
{
    for (const uint32_t bits : {0x01800000U, 0x20800001U, 0x23000001U, 0x2100ffffU, 0x207fffffU}) {
        auto previous = EasyState();
        previous.n_bits = bits;
        const auto critical = uint256S("789");
        auto proof = EasyProof(previous, critical);
        if (bits == 0x207fffff) {
            auto merkle = DecodeMerkleProof(proof.entries[0]);
            while (UintToArith256(merkle.header.GetHash()) <= UintToArith256(EasyConsensus().pow_limit)) ++merkle.header.nNonce;
            proof.entries[0].coinbase_proof = SerializeValue(merkle);
        }
        auto next = previous;
        std::string error;
        BOOST_CHECK(!drivechain::VerifyBmmProofEntries(proof, critical, previous.block_hash, next, error, EasyConsensus()));
        BOOST_CHECK_EQUAL(error, "BMM proof contains an invalid parent-chain proof-of-work header");
        BOOST_CHECK(next.block_hash == previous.block_hash);
        BOOST_CHECK_EQUAL(next.height, previous.height);
    }
}

BOOST_AUTO_TEST_CASE(signet_validation_steps_preserve_errors_and_terminals)
{
    using Step = drivechain::haskell::SignetStep;
    std::string error{"unchanged"};
    for (const bool has_solution : {false, true}) {
        const std::vector<Step> actions = has_solution ?
            std::vector<Step>{Step::WITNESS, Step::EXTRACT, Step::BUILD, Step::DECODE, Step::MERKLE, Step::COINBASE, Step::VERIFY} :
            std::vector<Step>{Step::WITNESS, Step::EXTRACT, Step::BUILD, Step::MERKLE, Step::COINBASE, Step::VERIFY};
        auto next = drivechain::haskell::SignetValidation(Step::START, 0, 0, 0, 0, error);
        for (const auto action : actions) {
            BOOST_REQUIRE_EQUAL(next, static_cast<int32_t>(action));
            const uint64_t a = action == Step::BUILD ? has_solution : action != Step::DECODE;
            next = drivechain::haskell::SignetValidation(action, a, 1, 1, 0, error);
        }
        BOOST_CHECK_EQUAL(next, 0);
        BOOST_CHECK_EQUAL(error, "unchanged");
    }
    const std::vector<std::tuple<Step, uint64_t, int32_t, std::string>> failures{
        {Step::WITNESS, 0, -1, "BMM parent block has no Bitcoin witness commitment"},
        {Step::EXTRACT, 0, -2, "BMM parent block has a malformed signet commitment script"},
        {Step::DECODE, 1, -3, "BMM parent block signet solution contains trailing data"},
        {Step::DECODE, 2, -4, "BMM parent block signet solution cannot be decoded"},
        {Step::MERKLE, 0, -5, "BMM signet proof does not authenticate exactly the coinbase"},
        {Step::COINBASE, 0, -5, "BMM signet proof does not authenticate exactly the coinbase"},
        {Step::VERIFY, 0, -6, "BMM parent block signet solution is invalid"}};
    for (const auto& [action, a, result, message] : failures) {
        BOOST_CHECK_EQUAL(drivechain::haskell::SignetValidation(action, a, 1, 1, 0, error), result);
        BOOST_CHECK_EQUAL(error, message);
    }
    BOOST_CHECK_THROW(drivechain::haskell::SignetValidation(Step::DECODE, 3, 0, 0, 0, error), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::SignetValidation(static_cast<Step>(8), 0, 0, 0, 0, error), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(parent_cache_expiry_boundaries)
{
    namespace hs = drivechain::haskell;
    static_assert(drivechain::BMM_EDGE_CACHE_MAX == 8);
    static_assert(drivechain::BMM_NEGATIVE_PARENT_CACHE_MAX == 64);
    static_assert(drivechain::BMM_NEGATIVE_PARENT_CACHE_SECONDS == 5);
    for (const auto limit : {drivechain::BMM_EDGE_CACHE_MAX,drivechain::BMM_NEGATIVE_PARENT_CACHE_MAX})
    for (const auto count : {size_t{0},limit-1,limit,limit+1,std::numeric_limits<size_t>::max()}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::LESS,0,0,limit,count),count>limit);
    }
    for (const uint64_t stored : {uint64_t{0},uint64_t{1},uint64_t{UINT32_MAX},UINT64_MAX})
    for (const uint64_t current : {uint64_t{0},uint64_t{1},uint64_t{UINT32_MAX},UINT64_MAX})
    for (bool expired : {false,true}) {
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::CACHE_EXPIRED,expired,0,stored,current),
            stored!=current || expired);
        BOOST_CHECK_EQUAL(hs::ParentReplayRecord(hs::ReplayRecordKind::CACHE_EXPIRED,0,0,stored,current),
            hs::ParentReplayRecord(hs::ReplayRecordKind::EPOCH_CHANGED,0,0,stored,current));
    }
}

BOOST_AUTO_TEST_CASE(signet_sighash_plan_preserves_all_modes)
{
    namespace hs = drivechain::haskell;
    for (int type = 0; type < 256; ++type) {
        for (const uint64_t outputs : {0ULL, 1ULL, 4294967296ULL}) {
            for (const uint32_t index : {0U, 1U, UINT32_MAX}) {
                const int base = type & 0x1f;
                uint32_t expected{0};
                if (!(type & SIGHASH_ANYONECANPAY)) expected |= 1;
                if (!(type & SIGHASH_ANYONECANPAY) && base != SIGHASH_SINGLE && base != SIGHASH_NONE) expected |= 2;
                if (base != SIGHASH_SINGLE && base != SIGHASH_NONE) expected |= 4;
                else if (base == SIGHASH_SINGLE && index < outputs) expected |= 8;
                BOOST_CHECK_EQUAL(hs::BmmSigHashPlan(type, index, outputs), expected);
                BOOST_CHECK_EQUAL(hs::BmmSignatureGate(true, 1, index, outputs), index < outputs);
            }
        }
    }
    BOOST_CHECK(!hs::BmmSignatureGate(false, 72, 0, 1));
    BOOST_CHECK(!hs::BmmSignatureGate(true, 0, 0, 1));
    BOOST_CHECK(!hs::BmmSignatureGate(true, 72, 1, 1));
}

BOOST_AUTO_TEST_CASE(signet_signature_hash_serialization_parity)
{
    Sidechain::Bitcoin::CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 123456;
    tx.vin.resize(3);
    for (size_t i=0; i<tx.vin.size(); ++i) {
        tx.vin[i].prevout.hash = uint256S(std::to_string(i+123));
        tx.vin[i].prevout.n = i+7;
        tx.vin[i].nSequence = 0xffffff00+i;
    }
    const CScript script = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20,0x37) << OP_EQUALVERIFY << OP_CHECKSIG;
    for (unsigned outputs=0; outputs<4; ++outputs) {
        if (outputs) tx.vout.emplace_back(outputs*17001, CScript() << outputs << OP_DROP << OP_TRUE);
        const Sidechain::Bitcoin::CTransaction transaction(tx);
        for (int type=0; type<256; ++type) for (unsigned index=0; index<tx.vin.size(); ++index) {
            // Independent original serialization, with no Haskell plan or shared helper.
            uint256 prevouts, sequences, output_hash;
            const int base = type & 0x1f;
            if (!(type & SIGHASH_ANYONECANPAY)) {
                HashWriter hash;
                for (const auto& input : tx.vin) hash << input.prevout;
                prevouts = hash.GetHash();
            }
            if (!(type & SIGHASH_ANYONECANPAY) && base!=SIGHASH_SINGLE && base!=SIGHASH_NONE) {
                HashWriter hash;
                for (const auto& input : tx.vin) hash << input.nSequence;
                sequences = hash.GetHash();
            }
            if (base!=SIGHASH_SINGLE && base!=SIGHASH_NONE) {
                HashWriter hash;
                for (const auto& output : tx.vout) hash << output;
                output_hash = hash.GetHash();
            } else if (base==SIGHASH_SINGLE && index<tx.vout.size()) {
                output_hash = (HashWriter{} << tx.vout[index]).GetHash();
            }
            const auto expected = (HashWriter{} << tx.version << prevouts << sequences
                << tx.vin[index].prevout << script << int64_t{0} << tx.vin[index].nSequence
                << output_hash << tx.nLockTime << type).GetHash();
            BOOST_CHECK(drivechain::BitcoinWitnessV0SignatureHash(script,transaction,index,type)==expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(header_wire_and_hash_compatibility)
{
    // Generated with the pre-CMake e90b9afee3 build, not this serializer.
    // Each digest commits to 128 (block hash, critical hash, wire bytes) tuples.
    constexpr const char* expected[] = {
        "449d03ee9b142f6200ff32dde7f829d4e9600e8f3f9acff60113e32852c4035a",
        "98245a37992e04f34f719f27b4bc7604b4931bdcd79a3794f644b7bac66634b4",
        "c175b966e32d866a1d478a2525dd21015e6e687d51f15ff4a14d3ab42da113dc",
        "32d44945248839b16a9b98a1d79478a72ce05a3e343681bf7183f3c9bf770831",
        "ecb912ee618ab49ff4ecd75496ebda052faf5e77185ff516dd34112a9879da55",
        "6e7cd222f4ebdafad2a6ea4820508209458759bd38a3aa2928d3b3235d02b87b",
        "6062e4ccbf91b134efd1b8699e2fe3c723fa1e75362011b210186a9d84ca4026",
        "3375f70f47e62eb45d43d726b42fc1be1d10801d7c1ddff2fdbabd4562acdf17",
    };
    constexpr uint32_t masks[] = {
        CBlockHeader::BMM_PROOF_HF_MASK,
        CBlockHeader::EXCHANGE_STATE_HF_MASK,
        CBlockHeader::FORCED_INBOX_HF_MASK,
        CBlockHeader::DEPOSIT_INBOX_HF_MASK,
        CBlockHeader::INBOX_CURSOR_HF_MASK,
    };
    // Captured from the native disk layout before sharing the Haskell layout rule.
    constexpr const char* disk_expected[] = {
        "296d26242e7c25634e95b7db7e33fe799b0cdd807923e4340f1a80886ac6c18a",
        "695c962e10480843995fed144689ce055bba4f04e2cf7410b523539921b1351a",
        "296d26242e7c25634e95b7db7e33fe799b0cdd807923e4340f1a80886ac6c18a",
        "695c962e10480843995fed144689ce055bba4f04e2cf7410b523539921b1351a",
        "83097d7e493f4dbcf9015ebe63ee5e14a4faf3994fe8d6eb21f5581c3b7ec963",
        "1bc55db927b9d05c436237ec1d5fdbe401eb01c41b8c452466ecaaadc148536e",
        "83097d7e493f4dbcf9015ebe63ee5e14a4faf3994fe8d6eb21f5581c3b7ec963",
        "1bc55db927b9d05c436237ec1d5fdbe401eb01c41b8c452466ecaaadc148536e",
    };
    for (unsigned mode = 0; mode < 8; ++mode) {
        g_con_elementsmode = mode & 1;
        g_con_blockheightinheader = mode & 2;
        g_signed_blocks = mode & 4;
        HashWriter aggregate, disk_aggregate;
        for (unsigned variant = 0; variant < 128; ++variant) {
            CBlockHeader header;
            header.nVersion = 0x20000000 | CBlockHeader::DYNAFED_HF_MASK |
                CBlockHeader::WITHDRAWAL_BUNDLE_HF_MASK;
            for (unsigned bit = 0; bit < 5; ++bit) {
                if (variant & (1U << bit)) header.nVersion |= masks[bit];
            }
            BOOST_CHECK_EQUAL(header.HasBmmProof(),bool(variant & 1));
            BOOST_CHECK_EQUAL(header.HasExchangeState(),bool(variant & 2));
            BOOST_CHECK_EQUAL(header.HasForcedInbox(),bool(variant & 4));
            BOOST_CHECK_EQUAL(header.HasDepositInbox(),bool(variant & 8));
            BOOST_CHECK_EQUAL(CBlockHeader::GetLayout(header.nVersion,false,false).bmm,
                bool((mode & 1) && (variant & 1)));
            BOOST_CHECK(!CBlockHeader::GetLayout(header.nVersion,false,false).zero_bmm);
            BOOST_CHECK_EQUAL(CBlockHeader::GetLayout(header.nVersion,false,false,false,true).zero_bmm,
                bool(mode & 1));
            header.hashPrevBlock = uint256S("01");
            header.hashMerkleRoot = uint256S("02");
            if (variant & 32) header.hashWithdrawalBundle = uint256S("03");
            header.hashBmmProof = uint256S("04");
            header.hashExchangeStateRoot = uint256S("05");
            header.hashForcedInboxRoot = uint256S("06");
            header.hashDepositInboxRoot = uint256S("07");
            header.nTime = 1784825405;
            header.nBits = 0x1e0376cc;
            header.nNonce = 0x12345678;
            header.block_height = 6400;
            header.ecxParentHeight = 995347;
            header.forcedProcessedCursor = 0x0102030405060708ULL;
            header.depositProcessedCursor = 0x1112131415161718ULL;
            header.sourceBacklogOldestParentHeight = 0x2122232425262728ULL;
            header.proof.challenge = CScript() << OP_TRUE;
            header.proof.solution = CScript() << OP_2;
            if (variant & 64) {
                header.m_dynafed_params.m_current = DynaFedParamEntry(
                    CScript() << OP_TRUE, 1000, uint256S("08"));
            }
            DataStream wire;
            wire << header;
            aggregate << header.GetHash() << header.GetBmmCriticalHash()
                      << std::vector<unsigned char>(
                          UCharCast(wire.data()), UCharCast(wire.data()) + wire.size());
            const std::vector<unsigned char> original(UCharCast(wire.data()), UCharCast(wire.data()) + wire.size());
            CBlockHeader decoded;
            decoded.hashWithdrawalBundle = decoded.hashBmmProof = decoded.hashExchangeStateRoot =
                decoded.hashForcedInboxRoot = decoded.hashDepositInboxRoot = uint256S("ff");
            decoded.ecxParentHeight = UINT32_MAX;
            decoded.forcedProcessedCursor = decoded.depositProcessedCursor = decoded.sourceBacklogOldestParentHeight = UINT64_MAX;
            wire >> decoded;
            BOOST_CHECK(wire.empty());
            BOOST_CHECK(decoded.GetHash() == header.GetHash());
            const auto expected_hash = [&](unsigned bit, const uint256& value) {
                return g_con_elementsmode && (variant & bit) ? value : uint256::ZERO;
            };
            BOOST_CHECK(decoded.hashWithdrawalBundle == expected_hash(32,header.hashWithdrawalBundle));
            BOOST_CHECK(decoded.hashBmmProof == expected_hash(1,header.hashBmmProof));
            BOOST_CHECK(decoded.hashExchangeStateRoot == expected_hash(2,header.hashExchangeStateRoot));
            BOOST_CHECK(decoded.hashForcedInboxRoot == expected_hash(4,header.hashForcedInboxRoot));
            BOOST_CHECK(decoded.hashDepositInboxRoot == expected_hash(8,header.hashDepositInboxRoot));
            BOOST_CHECK_EQUAL(decoded.ecxParentHeight,g_con_elementsmode && (variant&12)==12 ? header.ecxParentHeight : 0);
            BOOST_CHECK_EQUAL(decoded.forcedProcessedCursor,g_con_elementsmode && (variant&16) ? header.forcedProcessedCursor : 0);
            BOOST_CHECK_EQUAL(decoded.depositProcessedCursor,g_con_elementsmode && (variant&16) ? header.depositProcessedCursor : 0);
            BOOST_CHECK_EQUAL(decoded.sourceBacklogOldestParentHeight,g_con_elementsmode && (variant&16) ? header.sourceBacklogOldestParentHeight : 0);
            DataStream roundtrip;
            roundtrip << decoded;
            const std::vector<unsigned char> restored(UCharCast(roundtrip.data()), UCharCast(roundtrip.data()) + roundtrip.size());
            BOOST_CHECK(restored == original);
            CBlockIndex memory_index{header};
            memory_index.nHeight = header.block_height;
            CDiskBlockIndex disk_index{&memory_index};
            disk_index.hashPrev = header.hashPrevBlock;
            DataStream disk_bytes;
            disk_bytes << disk_index;
            const std::vector<unsigned char> original_disk(UCharCast(disk_bytes.data()),UCharCast(disk_bytes.data())+disk_bytes.size());
            disk_aggregate << original_disk;
            CDiskBlockIndex decoded_index;
            decoded_index.hashWithdrawalBundle = decoded_index.hashBmmProof = decoded_index.hashExchangeStateRoot =
                decoded_index.hashForcedInboxRoot = decoded_index.hashDepositInboxRoot = uint256S("ff");
            decoded_index.ecxParentHeight = UINT32_MAX;
            decoded_index.forcedProcessedCursor = decoded_index.depositProcessedCursor = decoded_index.sourceBacklogOldestParentHeight = UINT64_MAX;
            disk_bytes >> decoded_index;
            BOOST_CHECK(disk_bytes.empty());
            BOOST_CHECK(decoded_index.hashWithdrawalBundle==decoded.hashWithdrawalBundle);
            BOOST_CHECK(decoded_index.hashBmmProof==decoded.hashBmmProof);
            BOOST_CHECK(decoded_index.hashExchangeStateRoot==decoded.hashExchangeStateRoot);
            BOOST_CHECK(decoded_index.hashForcedInboxRoot==decoded.hashForcedInboxRoot);
            BOOST_CHECK(decoded_index.hashDepositInboxRoot==decoded.hashDepositInboxRoot);
            BOOST_CHECK_EQUAL(decoded_index.ecxParentHeight,decoded.ecxParentHeight);
            BOOST_CHECK_EQUAL(decoded_index.forcedProcessedCursor,decoded.forcedProcessedCursor);
            BOOST_CHECK_EQUAL(decoded_index.depositProcessedCursor,decoded.depositProcessedCursor);
            BOOST_CHECK_EQUAL(decoded_index.sourceBacklogOldestParentHeight,decoded.sourceBacklogOldestParentHeight);
            // The legacy disk format only stores dynafed parameters for signed blocks.
            if (!(g_con_elementsmode && (variant&64) && !g_signed_blocks)) {
                DataStream disk_roundtrip;
                disk_roundtrip << decoded_index;
                BOOST_CHECK(std::vector<unsigned char>(UCharCast(disk_roundtrip.data()),
                    UCharCast(disk_roundtrip.data())+disk_roundtrip.size())==original_disk);
            }
            header.m_signblock_witness.stack = {{0x12,0x34},{},{0x56}};
            DataStream full, stripped, witness;
            header.Serialize(full,TX_WITH_WITNESS);
            header.Serialize(stripped,TX_NO_WITNESS);
            std::vector<unsigned char> expected_wire(UCharCast(stripped.data()),UCharCast(stripped.data())+stripped.size());
            if (g_con_elementsmode && (variant&64)) {
                witness << header.m_signblock_witness.stack;
                expected_wire.insert(expected_wire.end(),UCharCast(witness.data()),UCharCast(witness.data())+witness.size());
            }
            BOOST_CHECK(std::vector<unsigned char>(UCharCast(full.data()),UCharCast(full.data())+full.size())==expected_wire);
            CBlockHeader full_decoded, stripped_decoded;
            full_decoded.Unserialize(full,TX_WITH_WITNESS);
            stripped_decoded.m_signblock_witness.stack = {{0x99}};
            stripped_decoded.Unserialize(stripped,TX_NO_WITNESS);
            BOOST_CHECK(full.empty() && stripped.empty());
            BOOST_CHECK(full_decoded.GetHash()==header.GetHash());
            BOOST_CHECK(stripped_decoded.GetHash()==header.GetHash());
            BOOST_CHECK(stripped_decoded.m_signblock_witness.stack==std::vector<std::vector<unsigned char>>{{0x99}});
            if (g_con_elementsmode && (variant&64))
                BOOST_CHECK(full_decoded.m_signblock_witness.stack==header.m_signblock_witness.stack);
        }
        BOOST_TEST_CONTEXT("serialization mode " << mode) {
            BOOST_CHECK_EQUAL(aggregate.GetHash().GetHex(), expected[mode]);
            BOOST_CHECK_EQUAL(disk_aggregate.GetHash().GetHex(),disk_expected[mode]);
        }
    }
}

BOOST_AUTO_TEST_CASE(verifies_authentic_layer_two_labs_successor)
{
    BOOST_CHECK(drivechain::LayerTwoLabsBmmConsensus().require_signet_solution);
    const drivechain::BmmProof proof{AuthenticProof6400()};
    drivechain::BmmL1State next;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProofEntries(
            proof,
            drivechain::LayerTwoLabsPublicSidechainBlock2(),
            proof.previous_state.block_hash,
            next,
            error,
            drivechain::LayerTwoLabsBmmConsensus()),
        error);
    BOOST_CHECK(next == drivechain::LayerTwoLabsInitialBmmState());
}

BOOST_AUTO_TEST_CASE(commits_and_roundtrips_synthetic_proof)
{
    const drivechain::BmmL1State previous{EasyState()};
    CBlock block{SidechainCandidate(previous.block_hash)};
    const uint256 critical_hash{block.GetBmmCriticalHash()};
    drivechain::BmmProof proof{EasyProof(previous, critical_hash)};
    std::string error;
    BOOST_REQUIRE_MESSAGE(drivechain::AttachBmmProof(block, proof, error), error);

    BOOST_CHECK_EQUAL(block.GetBmmCriticalHash(), critical_hash);
    BOOST_CHECK_NE(block.GetHash(), critical_hash);
    BOOST_CHECK_EQUAL(
        block.hashBmmProof,
        drivechain::BmmProofCommitment(block.m_bmm_proof));

    drivechain::BmmL1State next;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProof(
            block,
            previous,
            next,
            error,
            EasyConsensus()),
        error);
    BOOST_CHECK_EQUAL(next.height, previous.height + 1);
    BOOST_CHECK_EQUAL(next.block_hash, proof.entries.empty()
        ? uint256()
        : [&] {
            Sidechain::Bitcoin::CMerkleBlock merkle;
            DataStream stream(
                proof.entries[0].coinbase_proof);
            stream >> merkle;
            return merkle.header.GetHash();
        }());
    drivechain::BmmParentContext previous_context;
    BOOST_REQUIRE_MESSAGE(
        drivechain::GetBmmParentContext(previous, previous_context, error),
        error);
    BOOST_CHECK_EQUAL(previous_context.height, 100U);
    BOOST_CHECK_EQUAL(previous_context.median_time_past, 97'000U);
    BOOST_CHECK_EQUAL(previous_context.block_hash, previous.block_hash);
    drivechain::BmmParentContext next_context;
    BOOST_REQUIRE_MESSAGE(
        drivechain::GetBmmParentContext(next, next_context, error),
        error);
    BOOST_CHECK_EQUAL(next_context.height, 101U);
    BOOST_CHECK_EQUAL(next_context.median_time_past, 97'600U);
    BOOST_CHECK_EQUAL(next_context.block_hash, next.block_hash);

    DataStream encoded;
    encoded << TX_WITH_WITNESS(block);
    CBlock decoded;
    encoded >> TX_WITH_WITNESS(decoded);
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK_EQUAL(decoded.GetHash(), block.GetHash());
    BOOST_CHECK_EQUAL(decoded.GetBmmCriticalHash(), critical_hash);
    BOOST_CHECK(decoded.m_bmm_proof == block.m_bmm_proof);
}

BOOST_AUTO_TEST_CASE(advancement_preserves_wrapping_retarget_and_history)
{
    for (const uint32_t height : {0U, 2014U, 2015U, UINT32_MAX}) {
        for (const int64_t interval : {int64_t{1}, int64_t{2016}, int64_t{4294967296}, INT64_MAX}) {
            std::array<uint32_t, 16> fields{height, 100, 7, 0, 50};
            for (unsigned i = 5; i < fields.size(); ++i) fields[i] = i;
            drivechain::haskell::BmmAdvance(interval, 200, 8, fields);
            const uint32_t next = height + 1;
            const bool boundary = next % interval == 0;
            BOOST_CHECK_EQUAL(fields[0], next);
            BOOST_CHECK_EQUAL(fields[1], 200U);
            BOOST_CHECK_EQUAL(fields[2], 8U);
            BOOST_CHECK_EQUAL(fields[3], boundary ? next : 0U);
            BOOST_CHECK_EQUAL(fields[4], boundary ? 200U : 50U);
            for (unsigned i = 5; i < 15; ++i) BOOST_CHECK_EQUAL(fields[i], i + 1);
            BOOST_CHECK_EQUAL(fields[15], 200U);
            const auto saved = fields;
            BOOST_CHECK_THROW(drivechain::haskell::BmmAdvance(0, 300, 9, fields), std::runtime_error);
            BOOST_CHECK(fields == saved);
        }
    }
}

BOOST_AUTO_TEST_CASE(traversal_gates_entry_mutations_and_publication)
{
    namespace hs = drivechain::haskell;
    using Step = hs::BmmTraversalStep;
    const std::vector<Step> expected{Step::PREFLIGHT, Step::INITIALIZE_ENTRIES, Step::ENTRY_BOUNDS,
        Step::PREPARE_ENTRY, Step::MERKLE, Step::COINBASE, Step::EXTENSION, Step::ADVANCE,
        Step::PARENT, Step::COMMITMENT, Step::CRITICAL, Step::PUBLISH_ENTRIES};
    for (size_t fault = 0; fault <= expected.size(); ++fault) {
        std::vector<Step> observed;
        bool copied{false}, prepared{false}, published{false}, threw{false};
        std::string error;
        try {
            auto phase = hs::BmmTraversal(Step::START, 0, 0, error);
            while (phase > 0) {
                const auto action = static_cast<Step>(phase);
                BOOST_REQUIRE_LT(observed.size(), expected.size());
                BOOST_CHECK(action == expected[observed.size()]);
                observed.push_back(action);
                if (observed.size() == fault + 1) throw std::logic_error("entry action fault");
                if (action == Step::INITIALIZE_ENTRIES) copied = true;
                if (action == Step::PREPARE_ENTRY) prepared = true;
                if (action == Step::PUBLISH_ENTRIES) {
                    published = true;
                    phase = 0;
                    break;
                }
                BOOST_CHECK_EQUAL(hs::BmmSignetTemplate()[0], 0);
                phase = hs::BmmTraversal(action, action == Step::ADVANCE ? 0 : 1,
                    action == Step::ADVANCE ? 1 : 0, error);
            }
            BOOST_CHECK_EQUAL(phase, 0);
        } catch (const std::logic_error&) { threw = true; }
        BOOST_CHECK_EQUAL(threw, fault < expected.size());
        BOOST_CHECK_EQUAL(copied, fault > 1);
        BOOST_CHECK_EQUAL(prepared, fault > 3);
        BOOST_CHECK_EQUAL(published, fault == expected.size());
        BOOST_CHECK(observed == std::vector<Step>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
    }
}

BOOST_AUTO_TEST_CASE(traversal_preserves_multi_entry_state_and_failure_atomicity)
{
    const auto critical = uint256S("abc");
    for (unsigned count = 1; count <= 4; ++count) {
        drivechain::BmmProof proof;
        proof.previous_state = EasyState();
        auto expected = proof.previous_state;
        uint256 parent;
        for (unsigned i = 0; i < count; ++i) {
            parent = expected.block_hash;
            const auto part = EasyProof(expected, i + 1 == count ? critical : uint256S("def"));
            proof.entries.push_back(part.entries.front());
            const auto header = DecodeMerkleProof(part.entries.front()).header;
            ++expected.height;
            expected.block_hash = header.GetHash();
            expected.block_time = header.nTime;
            expected.n_bits = header.nBits;
            expected.recent_times.erase(expected.recent_times.begin());
            expected.recent_times.push_back(header.nTime);
        }
        for (const bool signet : {false, true}) {
            auto consensus = EasyConsensus();
            consensus.require_signet_solution = signet;
            auto next = EasyState();
            std::string error;
            BOOST_REQUIRE_MESSAGE(drivechain::VerifyBmmProofEntries(proof, critical, parent, next, error, consensus), error);
            BOOST_CHECK(next == expected);
            for (unsigned i = 0; i < count; ++i) {
                auto bad = proof;
                bad.entries[i].coinbase_tx.clear();
                next = EasyState();
                BOOST_CHECK(!drivechain::VerifyBmmProofEntries(bad, critical, parent, next, error, consensus));
                BOOST_CHECK_EQUAL(error, "BMM proof entry exceeds its transaction or Merkle proof bound");
                BOOST_CHECK(next == EasyState());
            }
            next = EasyState();
            BOOST_CHECK(!drivechain::VerifyBmmProofEntries(proof, uint256S("bad"), parent, next, error, consensus));
            BOOST_CHECK_EQUAL(error, "BMM successor commitment does not match the sidechain critical hash");
            BOOST_CHECK(next == EasyState());
        }
    }
    using Step = drivechain::haskell::BmmTraversalStep;
    std::string error;
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmTraversal(Step::SIGNET, 0, 0, error), -2);
    BOOST_CHECK_EQUAL(error, "BMM parent header does not extend the authenticated state");
    error = "specific error";
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmTraversal(Step::EXTENSION, 0, 0, error), -2);
    BOOST_CHECK_EQUAL(error, "specific error");
    BOOST_CHECK_THROW(drivechain::haskell::BmmTraversal(Step::ADVANCE, 0, 0, error), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(proof_codec_bounds_and_partial_outputs)
{
    auto proof = EasyProof(EasyState(), uint256S("abc"));
    std::string error{"old error"};
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(drivechain::SerializeBmmProof(proof, bytes, error));
    BOOST_CHECK(error.empty());
    drivechain::BmmProof decoded;
    BOOST_REQUIRE(drivechain::DeserializeBmmProof(bytes, decoded, error));
    BOOST_CHECK_EQUAL(decoded.version, proof.version);
    BOOST_CHECK(decoded.previous_state == proof.previous_state);
    for (size_t size = 0; size <= bytes.size(); ++size) {
        const std::vector<unsigned char> truncated(bytes.begin(), bytes.begin() + size);
        auto expected = proof;
        if (size != 0) {
            try {
                DataStream stream{truncated};
                stream >> TX_WITH_WITNESS(expected);
            } catch (...) {}
        }
        auto actual = proof;
        BOOST_CHECK_EQUAL(drivechain::DeserializeBmmProof(truncated, actual, error), size == bytes.size());
        BOOST_CHECK(SerializeValue(actual) == SerializeValue(expected));
        BOOST_CHECK_EQUAL(error, size == bytes.size() ? "" : size == 0 ?
            "BMM proof is empty or exceeds its consensus size bound" : "BMM proof is malformed or non-canonical");
    }
    for (const auto size : {size_t{0}, drivechain::MAX_BMM_PROOF_BYTES + 1}) {
        BOOST_CHECK(!drivechain::DeserializeBmmProof(std::vector<unsigned char>(size), decoded, error));
        BOOST_CHECK_EQUAL(error, "BMM proof is empty or exceeds its consensus size bound");
        BOOST_CHECK(decoded.previous_state == proof.previous_state);
    }
    for (unsigned mutation = 0; mutation < 4; ++mutation) {
        auto invalid = proof;
        if (mutation == 0) ++invalid.version;
        if (mutation == 1) invalid.entries.clear();
        if (mutation == 2) invalid.entries.resize(drivechain::MAX_BMM_PROOF_ENTRIES + 1);
        auto encoded = SerializeValue(invalid);
        if (mutation == 3) encoded.push_back(0);
        BOOST_CHECK(!drivechain::DeserializeBmmProof(encoded, decoded, error));
        BOOST_CHECK_EQUAL(error, "BMM proof is malformed or non-canonical");
        BOOST_CHECK_EQUAL(decoded.version, invalid.version);
    }
    proof.entries[0].coinbase_tx.resize(drivechain::MAX_BMM_PROOF_BYTES);
    BOOST_CHECK(!drivechain::SerializeBmmProof(proof, bytes, error));
    BOOST_CHECK_EQUAL(error, "serialized BMM proof exceeds its consensus size bound");
    BOOST_CHECK(bytes.size() > drivechain::MAX_BMM_PROOF_BYTES);
    CBlock block;
    block.nVersion = 0;
    block.m_bmm_proof = {1,2,3};
    block.hashBmmProof = uint256S("123");
    BOOST_CHECK(!drivechain::AttachBmmProof(block, proof, error));
    BOOST_CHECK_EQUAL(error, "cannot attach BMM proof without the header version bit");
    BOOST_CHECK(block.m_bmm_proof == std::vector<unsigned char>({1,2,3}));
    BOOST_CHECK(block.hashBmmProof == uint256S("123"));
    block.nVersion = SidechainCandidate(EasyState().block_hash).nVersion;
    BOOST_CHECK(!drivechain::AttachBmmProof(block, proof, error));
    BOOST_CHECK_EQUAL(error, "serialized BMM proof exceeds its consensus size bound");
    BOOST_CHECK(block.m_bmm_proof == bytes);
    BOOST_CHECK(block.hashBmmProof == uint256S("123"));
}

BOOST_AUTO_TEST_CASE(coin_preflight_stops_before_guarded_access)
{
    using Step = drivechain::haskell::BmmStateStep;
    for (uint32_t facts = 0; facts < 32; ++facts) {
        std::vector<uint32_t> expected;
        for (uint32_t field = 0; field < 5; ++field) {
            expected.push_back(field);
            if (!(facts & (1U << field))) break;
        }
        std::vector<uint32_t> observed;
        const bool accepted = drivechain::haskell::RunBmmStateFlow(Step::COIN_START, [&](Step step) {
            const auto field = static_cast<uint32_t>(step) - static_cast<uint32_t>(Step::COIN_UNSPENT);
            BOOST_REQUIRE_LT(field, 5U);
            observed.push_back(field);
            return (facts >> field) & 1U;
        });
        BOOST_CHECK_EQUAL(accepted, facts == 31);
        BOOST_CHECK(observed == expected);
        std::string error;
        BOOST_CHECK_EQUAL(drivechain::haskell::BmmCodec(drivechain::haskell::BmmCodecPhase::STATE_ASSET,
            accepted ? 31 : 0, 0, 0, error), accepted);
        BOOST_CHECK_EQUAL(error, accepted ? "" : "persisted BMM state has invalid asset or value encoding");
    }
}

BOOST_AUTO_TEST_CASE(persisted_state_codec_retains_wire_and_rejection_behavior)
{
    const COutPoint outpoint{Txid::FromUint256(uint256S("f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9")), 0};
    BOOST_REQUIRE(drivechain::IsBmmStateInternalOutpoint(outpoint));
    const auto original = drivechain::LayerTwoLabsInitialBmmState();
    {
        CCoinsView base;
        CCoinsViewCache view(&base);
        auto unchanged = original;
        std::string error{"caller sentinel"};
        BOOST_CHECK(!drivechain::GetBmmState(view, unchanged, &error));
        BOOST_CHECK(unchanged == original);
        BOOST_CHECK_EQUAL(error, "caller sentinel");
        BOOST_CHECK(!drivechain::GetBmmState(view, unchanged, nullptr));
        BOOST_CHECK(!drivechain::HasPersistedBmmConsensusState(view));
    }
    const std::vector<unsigned char> marker{'d','r','i','v','e','c','h','a','i','n','-','b','m','m','-','v','1'};
    DataStream full_payload;
    full_payload << marker << original;
    for (size_t size = 0; size <= full_payload.size(); ++size) {
        const std::vector<unsigned char> bytes(UCharCast(full_payload.data()), UCharCast(full_payload.data()) + size);
        auto expected_state = EasyState();
        bool expected_ok{true};
        try {
            DataStream reference{bytes};
            std::vector<unsigned char> decoded_marker;
            reference >> decoded_marker >> expected_state;
        } catch (...) { expected_ok = false; }
        CCoinsView base;
        CCoinsViewCache view(&base);
        view.AddCoin(outpoint, Coin(CTxOut(Params().GetConsensus().pegged_asset, 0,
            CScript() << bytes << OP_DROP << OP_FALSE), 2, false), false);
        auto actual_state = EasyState();
        std::string error{"sentinel"};
        BOOST_CHECK_EQUAL(drivechain::GetBmmState(view, actual_state, &error), expected_ok);
        BOOST_CHECK(actual_state == expected_state);
        BOOST_CHECK_EQUAL(error, expected_ok ? "sentinel" : "persisted BMM state payload cannot be decoded");
    }
    for (unsigned mutation = 0; mutation < 16; ++mutation) {
        BOOST_TEST_CONTEXT("persisted state mutation " << mutation) {
            auto state = original;
            auto prefix = marker;
            if (mutation == 9) prefix[0] ^= 1;
            if (mutation == 11) state.block_hash.SetNull();
            DataStream payload;
            payload << prefix << state;
            std::vector<unsigned char> data{UCharCast(payload.data()), UCharCast(payload.data()) + payload.size()};
            if (mutation == 8) data.resize(1);
            if (mutation == 10) data.push_back(0);
            CScript script;
            if (mutation == 1) {
                script << OP_PUSHDATA2;
                script.push_back(data.size() & 0xff);
                script.push_back((data.size() >> 8) & 0xff);
                script.insert(script.end(), data.begin(), data.end());
            } else {
                script << data;
            }
            script << OP_DROP << OP_FALSE;
            if (mutation == 2) script = CScript() << OP_TRUE;
            if (mutation == 3) script = CScript() << data << OP_DUP << OP_FALSE;
            if (mutation == 4) script = CScript() << data << OP_DROP << OP_TRUE;
            if (mutation == 5) script << OP_FALSE;
            if (mutation == 6) script = CScript() << OP_PUSHDATA1;
            if (mutation == 7) script = CScript() << data << OP_DROP;
            CTxOut output(Params().GetConsensus().pegged_asset, 0, script);
            if (mutation == 12) output.nValue.SetToAmount(1);
            if (mutation == 13) output.nAsset = CConfidentialAsset(CAsset(uint256S("123")));
            if (mutation == 14) {
                output.nValue.vchCommitment.assign(33, 0);
                output.nValue.vchCommitment[0] = 8;
            }
            if (mutation == 15) {
                output.nAsset.vchCommitment.assign(33, 0);
                output.nAsset.vchCommitment[0] = 10;
            }
            CCoinsView base;
            CCoinsViewCache view(&base);
            view.AddCoin(outpoint, Coin(std::move(output), 2, false), false);
            auto decoded = EasyState();
            std::string error{"caller sentinel"};
            BOOST_CHECK_EQUAL(drivechain::GetBmmState(view, decoded, &error), mutation <= 1);
            const std::string expected = mutation <= 1 ? "caller sentinel" : mutation <= 7 ? "persisted BMM state script is malformed" :
                mutation == 8 ? "persisted BMM state payload cannot be decoded" : mutation <= 10 ? "persisted BMM state payload is invalid" :
                mutation == 11 ? "BMM parent-chain state is malformed" : "persisted BMM state has invalid asset or value encoding";
            BOOST_CHECK_EQUAL(error, expected);
            if (mutation <= 1 || (mutation >= 9 && mutation <= 11)) BOOST_CHECK(decoded == state);
            if ((mutation >= 2 && mutation <= 7) || mutation >= 12) BOOST_CHECK(decoded == EasyState());
            BOOST_CHECK(drivechain::HasPersistedBmmConsensusState(view));
            BOOST_CHECK_EQUAL(drivechain::GetBmmState(view, decoded, nullptr), mutation <= 1);
        }
    }
    std::string preserved{"prior diagnostic"};
    BOOST_CHECK(!drivechain::haskell::BmmCodec(drivechain::haskell::BmmCodecPhase::STATE_PAYLOAD, 0, 0, 0, preserved));
    BOOST_CHECK_EQUAL(preserved, "prior diagnostic");
    BOOST_CHECK_THROW(drivechain::haskell::BmmCodec(static_cast<drivechain::haskell::BmmCodecPhase>(11), 0, 0, 0, preserved), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(persisted_state_runner_preserves_exception_boundary)
{
    namespace hs = drivechain::haskell;
    using Step = hs::BmmStateStep;
    for (auto fault = Step::READ_PUSH; fault <= Step::READ_VALID;
         fault = static_cast<Step>(static_cast<uint32_t>(fault) + 1)) {
        for (unsigned mode = 0; mode < 6; ++mode) {
            const auto run = [&](bool reference) {
                std::vector<Step> trace;
                unsigned writes{0};
                std::string error{"prior diagnostic"}, escaped;
                bool accepted{false};
                const auto action = [&](Step step) {
                    trace.push_back(step);
                    if (step == fault && mode == 2) throw std::logic_error("before write");
                    if (step == fault && mode == 3) throw 17;
                    ++writes;
                    if (step == fault && mode == 4) throw std::logic_error("after write");
                    if (step == fault && mode == 5) throw 19;
                    return step != fault || mode != 1;
                };
                const auto recover = [&](Step step) {
                    if (step < Step::READ_MARKER) throw;
                    return hs::BmmCodec(hs::BmmCodecPhase::STATE_EXCEPTION, 0, 0, 0, error);
                };
                try {
                    if (reference) {
                        auto phase = static_cast<int32_t>(Step::READ_PUSH);
                        while (phase > 0) {
                            try {
                                const auto step = static_cast<Step>(phase);
                                phase = !action(step) ? -1 : step == Step::READ_VALID ? 0 : phase + 1;
                            } catch (...) {
                                accepted = recover(static_cast<Step>(phase));
                                break;
                            }
                        }
                        accepted = phase == 0;
                    } else {
                        Step current{Step::READ_START};
                        try {
                            accepted = hs::RunBmmStateFlow(Step::READ_START, [&](Step step) {
                                current = step;
                                return action(step);
                            });
                        } catch (...) { accepted = recover(current); }
                    }
                } catch (const std::logic_error& e) { escaped = e.what(); }
                catch (int value) { escaped = std::to_string(value); }
                return std::tuple{accepted, trace, writes, error, escaped};
            };
            BOOST_CHECK(run(false) == run(true));
        }
    }
}

BOOST_AUTO_TEST_CASE(accepts_non_monotonic_parent_timestamps_above_median)
{
    drivechain::BmmL1State previous{EasyState()};
    previous.recent_times = {
        94'000,
        97'000,
        95'200,
        98'800,
        96'400,
        99'400,
        97'600,
        95'800,
        98'200,
        94'600,
        100'000,
    };
    CBlock block{SidechainCandidate(previous.block_hash)};
    const uint256 critical_hash{block.GetBmmCriticalHash()};
    const drivechain::BmmProof proof{EasyProof(previous, critical_hash)};

    drivechain::BmmL1State next;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProofEntries(
            proof,
            critical_hash,
            previous.block_hash,
            next,
            error,
            EasyConsensus()),
        error);
    BOOST_CHECK_EQUAL(next.height, previous.height + 1);
}

BOOST_AUTO_TEST_CASE(block_wrapper_error_order_and_state_atomicity)
{
    const auto previous = EasyState();
    auto original = SidechainCandidate(previous.block_hash);
    const auto proof = EasyProof(previous, original.GetBmmCriticalHash());
    std::string error;
    BOOST_REQUIRE(drivechain::AttachBmmProof(original, proof, error));
    const std::array<const char*, 7> expected{
        "sidechain block does not commit its exact BMM proof bytes",
        "sidechain block does not commit its exact BMM proof bytes",
        "BMM proof is malformed or non-canonical",
        "BMM proof does not extend the locally authenticated parent-chain state",
        "sidechain block has no L1 parent commitment",
        "BMM successor commitment does not match the sidechain critical hash",
        "sidechain block has no coinbase transaction"};
    for (unsigned i = 0; i < expected.size(); ++i) {
        auto block = original;
        auto prior = previous;
        if (i <= 2) block.m_bmm_proof = {0};
        if (i == 0) block.nVersion = 0;
        if (i == 2) block.hashBmmProof = drivechain::BmmProofCommitment(block.m_bmm_proof);
        if (i == 3) ++prior.height;
        if (i == 4) {
            CMutableTransaction coinbase(*block.vtx.front());
            coinbase.vout.clear();
            block.vtx.front() = MakeTransactionRef(coinbase);
        }
        if (i == 5) ++block.nTime;
        if (i == 6) block.vtx.clear();
        auto next = EasyState();
        error = "old error";
        BOOST_CHECK(!drivechain::VerifyBmmProof(block, prior, next, error, EasyConsensus()));
        BOOST_CHECK_EQUAL(error, expected[i]);
        BOOST_CHECK(next == EasyState());
    }
}

BOOST_AUTO_TEST_CASE(state_replacement_preserves_order_and_exceptions)
{
    for (const auto [height, restore] : {std::pair{INT32_MIN, false}, {INT32_MIN, true},
            {-1, false}, {-1, true}, {0, false}, {0, true}, {1, false}, {1, true},
            {INT32_MAX, false}, {INT32_MAX, true}}) {
        for (const int failure : {-1, 0, 1, 2}) {
            std::vector<uint32_t> actions;
            uint32_t stored_height{0};
            bool spent{false}, published{false}, threw{false};
            try {
                drivechain::haskell::BmmStoreState(height, [&](uint32_t action, uint32_t normalized) {
                    actions.push_back(action);
                    // Exercise a Haskell-backed preparation after the planner returns.
                    if (action == 1) {
                        BOOST_CHECK_EQUAL(normalized, 0U);
                        BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateFlow(
                            drivechain::haskell::BmmStateStep::CONNECT_START, 0), 1);
                    }
                    if (static_cast<int>(action) == failure) throw std::logic_error("storage failure");
                    if (action == 0) spent = true;
                    if (action == 2) { published = true; stored_height = normalized; }
                }, restore);
            } catch (const std::logic_error& error) {
                threw = true;
                BOOST_CHECK_EQUAL(error.what(), "storage failure");
            }
            const std::vector<uint32_t> expected = failure == 0 ? std::vector<uint32_t>{0} :
                failure == 1 ? std::vector<uint32_t>{0,1} : std::vector<uint32_t>{0,1,2};
            BOOST_CHECK(actions == expected);
            BOOST_CHECK_EQUAL(threw, failure >= 0);
            BOOST_CHECK_EQUAL(spent, failure != 0);
            BOOST_CHECK_EQUAL(published, failure < 0);
            if (published) BOOST_CHECK_EQUAL(stored_height, static_cast<uint32_t>(std::max<int64_t>(int64_t{height} - restore, 0)));
        }
    }
}

BOOST_AUTO_TEST_CASE(state_encoding_preserves_order_and_exceptions)
{
    const std::vector<std::pair<uint32_t, uint32_t>> expected{
        {0, 0}, {1, 0}, {2, 0}, {3, OP_DROP}, {3, OP_FALSE}};
    for (size_t failure = 0; failure <= expected.size(); ++failure) {
        std::vector<std::pair<uint32_t, uint32_t>> observed;
        bool threw{false};
        try {
            drivechain::haskell::BmmEncodeState([&](uint32_t action, uint32_t argument) {
                observed.emplace_back(action, argument);
                if (observed.size() == failure + 1) throw std::logic_error("encoding failure");
            });
        } catch (const std::logic_error& error) {
            threw = true;
            BOOST_CHECK_EQUAL(error.what(), "encoding failure");
        }
        BOOST_CHECK_EQUAL(threw, failure < expected.size());
        BOOST_CHECK(observed == decltype(observed)(expected.begin(), expected.begin() +
            std::min(failure + 1, expected.size())));
    }
}

BOOST_AUTO_TEST_CASE(private_construction_flow_retries_and_short_circuits)
{
    using Step = drivechain::haskell::BmmStateStep;
    const auto advance = [](Step step, int reply) { return drivechain::haskell::BmmStateFlow(step, reply); };
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_START, 0), static_cast<int>(Step::PRIVATE_ENABLED));
    for (const auto step : {Step::PRIVATE_ENABLED, Step::PRIVATE_VALID, Step::PRIVATE_VERIFY}) {
        BOOST_CHECK_EQUAL(advance(step, 0), -1);
        BOOST_CHECK_THROW(advance(step, 2), std::runtime_error);
    }
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_ENABLED, 1), static_cast<int>(Step::PRIVATE_VALID));
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_VALID, 1), static_cast<int>(Step::PRIVATE_COINBASE));
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_COINBASE, 1), static_cast<int>(Step::PRIVATE_HEADER));
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_HEADER, 1), static_cast<int>(Step::PRIVATE_POW));
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_POW, 0), static_cast<int>(Step::PRIVATE_NONCE));
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_NONCE, 1), static_cast<int>(Step::PRIVATE_POW));
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_POW, 1), static_cast<int>(Step::PRIVATE_ASSEMBLE));
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_ASSEMBLE, 1), static_cast<int>(Step::PRIVATE_VERIFY));
    BOOST_CHECK_EQUAL(advance(Step::PRIVATE_VERIFY, 1), 0);
    BOOST_CHECK_THROW(advance(Step::PRIVATE_POW, -1), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(private_template_preserves_native_byte_and_integer_semantics)
{
    const auto critical = uint256S("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021");
    for (const uint32_t time : {0U, 1U, UINT32_MAX}) {
        for (const uint32_t median : {0U, 1U, UINT32_MAX}) {
            std::array<uint32_t, 4> fields{};
            std::array<unsigned char, 37> commitment{};
            drivechain::haskell::BmmPrivateTemplate(UINT32_MAX, time, median, 280,
                std::span<const unsigned char, 32>{critical.begin(), 32}, fields, commitment);
            BOOST_CHECK(fields == (std::array<uint32_t, 4>{2, 0, 0x20000000, std::max(time + 1, median + 1)}));
            std::vector<unsigned char> expected{0xd1,0x61,0x73,0x68,24};
            const auto bytes = ParseHex(critical.GetHex());
            expected.insert(expected.end(), bytes.begin(), bytes.end());
            BOOST_CHECK_EQUAL_COLLECTIONS(commitment.begin(), commitment.end(), expected.begin(), expected.end());
        }
    }
}

BOOST_AUTO_TEST_CASE(preimage_order_preserves_writer_failure_boundaries)
{
    for (uint32_t kind = 0; kind < 4; ++kind) {
        const uint32_t count = std::array<uint32_t, 4>{10,4,6,2}[kind];
        for (uint32_t failure = 0; failure <= count; ++failure) {
            uint32_t next{0};
            bool threw{false};
            try {
                const auto action = [&](uint32_t field) {
                    BOOST_CHECK_EQUAL(field, next++);
                    if (field == failure) throw std::logic_error("preimage writer failure");
                };
                if (kind < 2) drivechain::haskell::BmmPreimage(kind, action);
                else drivechain::haskell::BmmSignetActions(kind == 3, action);
            } catch (const std::logic_error& error) {
                threw = true;
                BOOST_CHECK_EQUAL(error.what(), "preimage writer failure");
            }
            BOOST_CHECK_EQUAL(threw, failure < count);
            BOOST_CHECK_EQUAL(next, std::min(failure + 1, count));
        }
    }
    bool called{false};
    BOOST_CHECK_THROW(drivechain::haskell::BmmPreimage(2, [&](uint32_t) { called = true; }), std::runtime_error);
    BOOST_CHECK(!called);
}

BOOST_AUTO_TEST_CASE(signature_hash_actions_keep_original_priority)
{
    for (uint32_t plan = 0; plan < 16; ++plan) {
        std::vector<uint32_t> expected;
        if (plan & 1) expected.push_back(0);
        if (plan & 2) expected.push_back(1);
        if (plan & 4) expected.push_back(2);
        else if (plan & 8) expected.push_back(3);
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<uint32_t> observed;
            bool threw{false};
            try {
                drivechain::haskell::BmmSignatureActions(plan, [&](uint32_t action) {
                    observed.push_back(action);
                    BOOST_CHECK_EQUAL(drivechain::haskell::BmmSignetTemplate()[0], 0);
                    if (observed.size() == fault + 1) throw std::logic_error("hash writer fault");
                });
            } catch (const std::logic_error&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK(observed == std::vector<uint32_t>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
        }
    }
    bool called{false};
    BOOST_CHECK_THROW(drivechain::haskell::BmmSignatureActions(16, [&](uint32_t) { called = true; }), std::runtime_error);
    BOOST_CHECK(!called);
}

BOOST_AUTO_TEST_CASE(signature_split_preserves_prefix_and_all_hash_types)
{
    std::vector<unsigned char> payload(37);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = i;
    auto extracted = drivechain::haskell::BmmCommitmentBytes(0, payload);
    BOOST_CHECK(uint256(extracted.data(), extracted.size()) == uint256S(HexStr(Span<const unsigned char>{payload}.subspan(5))));
    payload.resize(32);
    extracted = drivechain::haskell::BmmCommitmentBytes(1, payload);
    BOOST_CHECK(uint256(extracted.data(), extracted.size()) == uint256{payload});
    BOOST_CHECK_THROW(drivechain::haskell::BmmCommitmentBytes(0, payload), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::BmmCommitmentBytes(2, payload), std::runtime_error);
    BOOST_CHECK(drivechain::haskell::BmmSignetTemplate() ==
        (std::array<uint32_t, 6>{0,0,0,0,OP_0,OP_RETURN}));
    for (unsigned hash_type = 0; hash_type < 256; ++hash_type) {
        for (const size_t size : {size_t{0}, size_t{72}}) {
            const std::vector<unsigned char> prefix(size, 0x42);
            auto signature = prefix;
            signature.push_back(hash_type);
            BOOST_CHECK_EQUAL(drivechain::haskell::BmmSplitSignature(signature), hash_type);
            BOOST_CHECK(signature == prefix);
        }
    }
    std::vector<unsigned char> empty;
    BOOST_CHECK_THROW(drivechain::haskell::BmmSplitSignature(empty), std::runtime_error);
    BOOST_CHECK(empty.empty());
}

BOOST_AUTO_TEST_CASE(script_inspection_order_and_failure_short_circuit)
{
    struct Trace { uint32_t kind; int64_t first; int fault; std::vector<uint32_t> actions; };
    const auto read = +[](void* opaque, uint32_t index, uint32_t action, int64_t* fields) -> int32_t {
        auto& trace = *static_cast<Trace*>(opaque);
        BOOST_CHECK_EQUAL(index, 0U);
        trace.actions.push_back(action);
        if (int(action) == trace.fault) return 0;
        std::fill_n(fields, 4, 0);
        switch (action) {
        case 0: fields[0] = 38; fields[1] = 0xeda921aa246aLL; break;
        case 1: fields[0] = trace.first; break;
        case 2: fields[0] = trace.kind == 0 ? 37 : 32; break;
        case 3:
            fields[0] = 1; fields[1] = trace.kind == 0 ? 37 : 32;
            fields[2] = 0x687361d1; fields[3] = 24; break;
        default: return 0;
        }
        return 1;
    };
    for (uint32_t kind = 0; kind < 3; ++kind) {
        for (int64_t first : {-1, 0, 106, 512}) {
            for (int fault : {-1, 0, 1, 2, 3}) {
                Trace trace{kind, first, fault, {}};
                std::vector<uint32_t> expected = kind == 2 ? std::vector<uint32_t>{0} :
                    first == 106 ? std::vector<uint32_t>{1, 2, 3} : std::vector<uint32_t>{1, 3};
                const auto failed = std::find(expected.begin(), expected.end(), uint32_t(fault));
                const bool fails = failed != expected.end();
                if (fails) expected.erase(failed + 1, expected.end());
                std::string error;
                if (fails || (kind != 2 && (first < 0 || first > 511))) BOOST_CHECK_THROW(drivechain::haskell::BmmCommitment(kind, 24, 1, read, &trace, error), std::runtime_error);
                else BOOST_CHECK_EQUAL(drivechain::haskell::BmmCommitment(kind, 24, 1, read, &trace, error), kind == 2 || first == 106 ? 0 : -1);
                BOOST_CHECK(trace.actions == expected);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(work_flow_short_circuits_and_propagates_exceptions)
{
    namespace hs = drivechain::haskell;
    using Step = hs::BmmStateStep;
    for (bool first : {false, true}) {
        for (bool second : {false, true}) {
            std::vector<Step> visited;
            const bool valid = hs::RunBmmStateFlow(Step::POW_START, [&](Step step) {
                visited.push_back(step);
                BOOST_CHECK_EQUAL(hs::BmmSignetTemplate()[5], 106U);
                return step == Step::POW_TARGET ? first : second;
            });
            BOOST_CHECK_EQUAL(valid, first && second);
            const std::vector<Step> expected = first ? std::vector{Step::POW_TARGET, Step::POW_HASH} : std::vector{Step::POW_TARGET};
            BOOST_CHECK(visited == expected);
        }
        std::vector<Step> visited;
        BOOST_CHECK(hs::RunBmmStateFlow(Step::RETARGET_START, [&](Step step) {
            visited.push_back(step);
            return step == Step::RETARGET_SPAN ? first : true;
        }));
        const std::vector<Step> expected = first ? std::vector{Step::RETARGET_SPAN, Step::RETARGET_SCALE} : std::vector{Step::RETARGET_SPAN};
        BOOST_CHECK(visited == expected);
    }
    BOOST_CHECK_THROW(hs::RunBmmStateFlow(Step::POW_START, [](Step) -> int32_t {
        throw std::runtime_error("native target failure");
    }), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(generated_defaults_preserve_aggregate_contract)
{
    static_assert(std::is_aggregate_v<drivechain::BmmConsensus>);
    static_assert(drivechain::BMM_PROOF_SCHEMA_VERSION == 1);
    static_assert(DrivechainAnchor::CURRENT_VERSION == 1);
    BOOST_CHECK_EQUAL(DrivechainAnchor{}.version, 1);
    static_assert(drivechain::BMM_SIDECHAIN_SLOT == 24);
    static_assert(drivechain::MAX_BMM_PROOF_ENTRIES == 128);
    static_assert(drivechain::MAX_BMM_PROOF_BYTES == 1000000);
    static_assert(drivechain::BMM_TARGET_TIMESPAN == 1209600);
    static_assert(drivechain::BMM_TARGET_SPACING == 600);
    static_assert(drivechain::BMM_REQUIRE_SIGNET_SOLUTION);
    BOOST_CHECK_EQUAL(drivechain::BMM_FINGERPRINT_TAG, "ECX/BMM-runtime-consensus/v4");
    const drivechain::BmmConsensus defaults{};
    BOOST_CHECK(defaults.pow_limit.IsNull());
    BOOST_CHECK(defaults.signet_challenge.empty());
    BOOST_CHECK_EQUAL(defaults.target_timespan, 1209600);
    BOOST_CHECK_EQUAL(defaults.target_spacing, 600);
    BOOST_CHECK_EQUAL(defaults.sidechain_slot, 24);
    BOOST_CHECK_EQUAL(defaults.max_entries, 128);
    BOOST_CHECK_EQUAL(defaults.max_proof_bytes, 1000000);
    BOOST_CHECK(defaults.require_signet_solution);
    const drivechain::BmmConsensus legacy{uint256{}, 8, 2, CScript{}, 7, 3, 9};
    BOOST_CHECK_EQUAL(legacy.target_timespan, 8);
    BOOST_CHECK_EQUAL(legacy.target_spacing, 2);
    BOOST_CHECK_EQUAL(legacy.sidechain_slot, 7);
    BOOST_CHECK_EQUAL(legacy.max_entries, 3);
    BOOST_CHECK_EQUAL(legacy.max_proof_bytes, 9);
    BOOST_CHECK(legacy.require_signet_solution);
    BOOST_CHECK_EQUAL(drivechain::BmmProof{}.version, 1);
}

BOOST_AUTO_TEST_CASE(runtime_fingerprint_preserves_v4_wire_identity)
{
    const auto* selected = &drivechain::LayerTwoLabsBmmConsensus();
    BOOST_CHECK(selected == &drivechain::LayerTwoLabsBmmConsensus());
    BOOST_CHECK_EQUAL(selected->DifficultyAdjustmentInterval(), 2016);
    const auto* checkpoint = &drivechain::LayerTwoLabsInitialBmmState();
    BOOST_CHECK(checkpoint == &drivechain::LayerTwoLabsInitialBmmState());
    BOOST_CHECK_EQUAL(checkpoint->height, 6400);
    BOOST_CHECK(&drivechain::LayerTwoLabsPublicSidechainBlock1() == &drivechain::LayerTwoLabsPublicSidechainBlock1());
    BOOST_CHECK(&drivechain::LayerTwoLabsPublicSidechainBlock2() == &drivechain::LayerTwoLabsPublicSidechainBlock2());
    // Independent SHA256 vectors bind byte order, length prefixes, and the
    // immutable public checkpoint even when private replay is selected.
    const char* expected = "df3f501c76afbe66c20d4edd8c611045c4285db51cc16763c6ba087addc07ff9";
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
    if (gArgs.GetBoolArg("-ecxprivatebmmcheckpoint", false)) {
        expected = "000c09cc8e8d22e73a6c3b19a7e2767b8334ed6c399c9e2e51662d78452c3225";
    }
#endif
    BOOST_CHECK_EQUAL(drivechain::RuntimeBmmConsensusFingerprint().GetHex(), expected);
}

BOOST_AUTO_TEST_CASE(fingerprint_adapter_is_fail_closed)
{
    namespace hs = drivechain::haskell;
    const auto empty = [](uint32_t group, uint32_t index, uint64_t& value, const unsigned char*& bytes) {
        BOOST_CHECK(group < 4);
        BOOST_CHECK(group != 1 || index != 9);
        value = 0;
        bytes = nullptr;
        return true;
    };
    auto expected = std::vector<unsigned char>(99, 0);
    expected[3] = 4;
    BOOST_CHECK(hs::BmmFingerprint(empty) == expected);
    BOOST_CHECK_EXCEPTION(hs::BmmFingerprint([](auto, auto, auto&, auto&) -> bool {
        throw std::logic_error("reader exception");
    }), std::logic_error, [](const auto& error) { return std::string(error.what()) == "reader exception"; });
    BOOST_CHECK_THROW(hs::BmmFingerprint([](auto, auto, auto&, auto&) { return false; }), std::runtime_error);
    BOOST_CHECK_THROW(hs::BmmFingerprint([](uint32_t group, uint32_t, uint64_t& size, const unsigned char*& bytes) {
        size = group == 1 ? 1 : 0;
        bytes = nullptr;
        return true;
    }), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(parent_context_rejects_zero_median_without_publishing)
{
    auto state = EasyState();
    std::fill(state.recent_times.begin(), state.recent_times.end() - 1, 0);
    drivechain::BmmParentContext context;
    context.height = 42;
    context.block_hash = state.block_hash;
    context.median_time_past = 42;
    std::string error = "stale error";
    BOOST_CHECK(!drivechain::GetBmmParentContext(state, context, error));
    BOOST_CHECK_EQUAL(error, "authenticated BMM parent median time past is zero");
    BOOST_CHECK(context.block_hash.IsNull());
    BOOST_CHECK_EQUAL(context.height, 0U);
    BOOST_CHECK_EQUAL(context.median_time_past, 0U);
    state = EasyState();
    BOOST_REQUIRE(drivechain::GetBmmParentContext(state, context, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(context.block_hash, state.block_hash);
    state.block_hash.SetNull();
    std::fill(state.recent_times.begin(), state.recent_times.end(), 0);
    BOOST_CHECK(!drivechain::GetBmmParentContext(state, context, error));
    BOOST_CHECK_EQUAL(error, "BMM parent-chain state is malformed");
    BOOST_CHECK(context.block_hash.IsNull());
    BOOST_CHECK_EQUAL(context.height, 0U);
    BOOST_CHECK_EQUAL(context.median_time_past, 0U);
    BOOST_CHECK_THROW(drivechain::haskell::BmmParentMedian({}, error), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(state_flow_sequences_writes_after_verification)
{
    using Step = drivechain::haskell::BmmStateStep;
    const std::vector<std::vector<std::pair<Step, int32_t>>> paths{
        {{Step::ACTIVATION_START,0},{Step::ACTIVATION_PREFLIGHT,0}},
        {{Step::ACTIVATION_START,0},{Step::ACTIVATION_PREFLIGHT,2},{Step::MODE_SELECT,0},{Step::MODE_PUBLIC,1}},
        {{Step::ACTIVATION_START,0},{Step::ACTIVATION_PREFLIGHT,2},{Step::MODE_SELECT,1},{Step::MODE_PRIVATE,1}},
        {{Step::CONSENSUS_START,0},{Step::MODE_SELECT,0},{Step::MODE_PUBLIC,1}},
        {{Step::CONSENSUS_START,0},{Step::MODE_SELECT,1},{Step::MODE_PRIVATE,1}},
        {{Step::CONNECT_START,0},{Step::CONNECT_KIND,2},{Step::CHECKPOINT,4},{Step::REQUIRED,6},
         {Step::INCOMPLETE,7},{Step::EFFECTIVE,1},{Step::VERIFY,1},{Step::STORE_NEXT,1}},
        {{Step::CONNECT_START,0},{Step::CONNECT_KIND,2},{Step::CHECKPOINT,3},{Step::INITIALIZE,5},{Step::STORE_INITIAL,1}},
        {{Step::DISCONNECT_START,0},{Step::DISCONNECT_KIND,2},{Step::HAS_PROOF,4},{Step::DECODE_PROOF,1},
         {Step::LOAD_CURRENT,5},{Step::EXTRACT_PARENT,1},{Step::VERIFY_ENTRIES,1},{Step::COMPARE_CURRENT,6},{Step::STORE_PRIOR,1}}};
    for (const auto& path : paths) {
        for (size_t i = 0; i < path.size(); ++i) {
            const auto [step, reply] = path[i];
            const auto expected = i + 1 == path.size() ? 0 : static_cast<int32_t>(path[i + 1].first);
            BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateFlow(step, reply), expected);
        }
    }
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateFlow(Step::VERIFY, 0), -1);
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateFlow(Step::EXTRACT_PARENT, 0), static_cast<int32_t>(Step::REJECT_PRIOR));
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateFlow(Step::VERIFY_ENTRIES, 0), static_cast<int32_t>(Step::REJECT_PRIOR));
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateFlow(Step::COMPARE_CURRENT, -7), -1);
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateFlow(Step::REJECT_PRIOR, -7), -1);
    BOOST_CHECK_THROW(drivechain::haskell::BmmStateFlow(Step::CONNECT_KIND, 3), std::runtime_error);
    BOOST_CHECK_THROW(drivechain::haskell::BmmStateFlow(static_cast<Step>(UINT32_MAX), 0), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(parent_signature_flow_preserves_encoding_order_and_faults)
{
    namespace hs = drivechain::haskell;
    using Step = hs::BmmStateStep;
    const std::vector<Step> steps{Step::PARENT_SIGNATURE_GATE, Step::PARENT_SIGNATURE_ENCODING,
        Step::SIGNATURE_KEY, Step::SIGNATURE_SPLIT, Step::SIGNATURE_HASH, Step::SIGNATURE_VERIFY};
    for (size_t fail = 0; fail <= steps.size(); ++fail) {
        const std::vector<Step> expected(steps.begin(), steps.begin() + std::min(fail + 1, steps.size()));
        std::vector<Step> seen;
        BOOST_CHECK_EQUAL(hs::RunBmmStateFlow(Step::PARENT_SIGNATURE_START, [&](Step step) {
            seen.push_back(step);
            return seen.size() == fail + 1 ? 0 : 1;
        }), fail == steps.size());
        BOOST_CHECK(seen == expected);
        for (size_t fault = 0; fault < expected.size(); ++fault) {
            seen.clear();
            BOOST_CHECK_THROW(hs::RunBmmStateFlow(Step::PARENT_SIGNATURE_START, [&](Step step) {
                seen.push_back(step);
                if (seen.size() == fault + 1) throw std::runtime_error("injected signature fault");
                return seen.size() == fail + 1 ? 0 : 1;
            }), std::runtime_error);
            BOOST_CHECK(seen == std::vector<Step>(expected.begin(), expected.begin() + fault + 1));
        }
    }
}

BOOST_AUTO_TEST_CASE(native_lookup_and_incomplete_candidate_preserve_decisions)
{
    namespace hs = drivechain::haskell;
    using Step = hs::BmmStateStep;
    for (bool proof : {false, true}) for (bool stored : {false, true}) {
        const std::vector<Step> expected = proof ? std::vector{Step::NATIVE_CHECK_PROOF, Step::NATIVE_CHECK_RESULT} :
            std::vector{Step::NATIVE_CHECK_PROOF, Step::NATIVE_CHECK_LOOKUP, Step::NATIVE_CHECK_RESULT};
        for (size_t fault = 0; fault <= expected.size(); ++fault) {
            std::vector<Step> observed;
            bool has_state{false}, threw{false};
            std::string error;
            try {
                const bool accepted = hs::RunBmmStateFlow(Step::NATIVE_CHECK_START, [&](Step action) -> int32_t {
                    observed.push_back(action);
                    if (observed.size() == fault + 1) throw std::logic_error("lookup fault");
                    switch (action) {
                    case Step::NATIVE_CHECK_PROOF: has_state = proof; return has_state;
                    case Step::NATIVE_CHECK_LOOKUP: has_state = stored; return has_state;
                    case Step::NATIVE_CHECK_RESULT: return hs::BmmLifecycle(hs::BmmLifecyclePhase::NATIVE_STATE, has_state, {}, error);
                    default: throw std::runtime_error("unexpected lookup action");
                    }
                });
                BOOST_CHECK_EQUAL(accepted, !(proof || stored));
                BOOST_CHECK_EQUAL(error, proof || stored ? "historical signet BMM state is not valid on native Elements" : "");
            } catch (const std::logic_error&) { threw = true; }
            BOOST_CHECK_EQUAL(threw, fault < expected.size());
            BOOST_CHECK(observed == std::vector<Step>(expected.begin(), expected.begin() + std::min(fault + 1, expected.size())));
        }
    }
    for (uint32_t facts = 0; facts < 16; ++facts) {
        const bool allow = facts & 1;
        const bool proof = allow && (facts & 2);
        const bool uncommitted = proof && (facts & 4);
        const bool empty = uncommitted && (facts & 8);
        std::string old_error, new_error;
        BOOST_CHECK_EQUAL(hs::BmmLifecycle(hs::BmmLifecyclePhase::INCOMPLETE, facts, {}, new_error),
            hs::BmmLifecycle(hs::BmmLifecyclePhase::INCOMPLETE, allow | (proof << 1) | (uncommitted << 2) | (empty << 3), {}, old_error));
        BOOST_CHECK_EQUAL(new_error, old_error);
    }
}

BOOST_AUTO_TEST_CASE(lifecycle_noops_and_missing_state_do_not_write)
{
    CCoinsView base;
    CCoinsViewCache view(&base);
    CBlock plain;
    plain.nVersion = 0;
    std::string error{"unchanged"};
    BOOST_CHECK(drivechain::ConnectBmmState(plain, nullptr, view, 0, false, error));
    BOOST_CHECK(drivechain::DisconnectBmmState(plain, nullptr, view, 0, error));
    BOOST_CHECK_EQUAL(error, "unchanged");
    auto candidate = SidechainCandidate(EasyState().block_hash);
    BOOST_CHECK(drivechain::ConnectBmmState(candidate, nullptr, view, 1, true, error));
    BOOST_CHECK(!drivechain::ConnectBmmState(candidate, nullptr, view, 1, false, error));
    BOOST_CHECK_EQUAL(error, "authenticated BMM parent-chain state is missing");
    const auto proof = EasyProof(EasyState(), candidate.GetBmmCriticalHash());
    BOOST_REQUIRE(drivechain::AttachBmmProof(candidate, proof, error));
    BOOST_CHECK(!drivechain::DisconnectBmmState(candidate, nullptr, view, 1, error));
    BOOST_CHECK_EQUAL(error, "cannot disconnect BMM proof without authenticated state");
    candidate.m_bmm_proof = {0};
    BOOST_CHECK(!drivechain::DisconnectBmmState(candidate, nullptr, view, 1, error));
    BOOST_CHECK_EQUAL(error, "BMM proof is malformed or non-canonical");
    BOOST_CHECK(!drivechain::HasPersistedBmmConsensusState(view));
    using Phase = drivechain::haskell::BmmLifecyclePhase;
    error = "specific verification error";
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmLifecycle(Phase::RESTORE, 0, {}, error), -7);
    BOOST_CHECK_EQUAL(error, "specific verification error");
    error.clear();
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmLifecycle(Phase::RESTORE, 0, {}, error), -7);
    BOOST_CHECK_EQUAL(error, "BMM state is inconsistent during disconnect");
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmLifecycle(Phase::REMOVED, 0, {}, error), -5);
    BOOST_CHECK_EQUAL(error, "public BMM checkpoint state could not be removed");
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmLifecycle(Phase::NATIVE_STATE, 1, {}, error), -1);
    BOOST_CHECK_EQUAL(error, "historical signet BMM state is not valid on native Elements");
    BOOST_CHECK_THROW(drivechain::haskell::BmmLifecycle(static_cast<Phase>(12), 0, {}, error), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(effective_state_does_not_hide_corrupt_storage)
{
    BOOST_REQUIRE(!Params().GetConsensus().drivechain_slot);
    CCoinsView base;
    CCoinsViewCache view(&base);
    auto state = EasyState();
    std::string error;
    BOOST_CHECK(!drivechain::GetEffectiveBmmState(view, nullptr, state, error));
    BOOST_CHECK_EQUAL(error, "authenticated BMM parent-chain state is missing");
    const auto checkpoint = uint256S("ce77dfe3b037f2e62624da0ee5e33ae3c23b8b18ddf3b87a687bb372a8406998");
    CBlockIndex previous;
    previous.phashBlock = &checkpoint;
    BOOST_REQUIRE(drivechain::GetEffectiveBmmState(view, &previous, state, error));
    BOOST_CHECK(state == drivechain::LayerTwoLabsInitialBmmState());
    const COutPoint outpoint{Txid::FromUint256(uint256S("f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9")), 0};
    view.AddCoin(outpoint, Coin(CTxOut(Params().GetConsensus().pegged_asset, 0, CScript() << OP_TRUE), 2, false), false);
    state = EasyState();
    BOOST_CHECK(!drivechain::GetEffectiveBmmState(view, &previous, state, error));
    BOOST_CHECK_EQUAL(error, "persisted BMM state script is malformed");
    BOOST_CHECK(state == EasyState());
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateSource(0, 1, {}, error), -1);
    BOOST_CHECK_EQUAL(error, "native Elements requires its authenticated parent replay, not signet BMM state");
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateSource(1, 3, "ignored", error), 0);
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateSource(1, 2, "corrupt state", error), -2);
    BOOST_CHECK_EQUAL(error, "corrupt state");
    BOOST_CHECK_EQUAL(drivechain::haskell::BmmStateSource(3, 1, {}, error), 5);
    BOOST_CHECK_THROW(drivechain::haskell::BmmStateSource(6, 0, {}, error), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(proof_rule_error_priority_and_output_atomicity)
{
    const auto previous = EasyState();
    const auto block = SidechainCandidate(previous.block_hash);
    const auto critical = block.GetBmmCriticalHash();
    const auto original = EasyProof(previous, critical);
    const std::array<const char*, 9> errors{
        "BMM proof envelope is invalid", "BMM parent-chain state is malformed",
        "BMM proof entry exceeds its transaction or Merkle proof bound",
        "BMM proof entry has a malformed or non-canonical coinbase proof",
        "BMM parent header does not extend the authenticated state",
        "BMM successor commitment does not match the sidechain critical hash",
        "BMM proof entry has a malformed or non-canonical coinbase proof",
        "BMM proof entry has a malformed or non-canonical coinbase proof",
        "BMM proof entry has a malformed or non-canonical coinbase proof",
    };
    for (unsigned variant = 0; variant < errors.size(); ++variant) {
        auto proof = original;
        auto expected = critical;
        switch (variant) {
        case 0: proof.version = 0; proof.previous_state.height = 0; break;
        case 1: proof.previous_state.height = 0; proof.entries[0].coinbase_tx.clear(); break;
        case 2: proof.entries[0].coinbase_tx.clear(); proof.entries[0].coinbase_proof = {0}; break;
        case 3: proof.entries[0].coinbase_tx = {0}; break;
        case 4: proof.previous_state.block_hash = uint256S("02"); break;
        case 5: expected = uint256::ONE; break;
        case 6: proof.entries[0].coinbase_proof = {0}; break;
        case 7: proof.entries[0].coinbase_tx.push_back(0); break;
        case 8: proof.entries[0].coinbase_proof.push_back(0); break;
        }
        drivechain::BmmL1State next;
        next.height = 123;
        next.block_hash = uint256::ONE;
        std::string error = "stale";
        BOOST_CHECK(!drivechain::VerifyBmmProofEntries(proof, expected, previous.block_hash, next, error, EasyConsensus()));
        BOOST_CHECK_EQUAL(error, errors[variant]);
        BOOST_CHECK_EQUAL(next.height, 123);
        BOOST_CHECK(next.block_hash == uint256::ONE);
    }
}

BOOST_AUTO_TEST_CASE(difficulty_interval_preserves_signed_division)
{
    auto consensus = EasyConsensus();
    for (int64_t timespan : {INT64_MIN, int64_t{-7}, int64_t{0}, int64_t{7}, INT64_MAX}) {
        for (int64_t spacing : {int64_t{-3}, int64_t{1}, int64_t{3}}) {
            consensus.target_timespan = timespan;
            consensus.target_spacing = spacing;
            BOOST_CHECK_EQUAL(consensus.DifficultyAdjustmentInterval(), timespan / spacing);
        }
    }
    consensus.target_spacing = 0;
    BOOST_CHECK_THROW(consensus.DifficultyAdjustmentInterval(), std::runtime_error);
    consensus.target_timespan = INT64_MIN;
    consensus.target_spacing = -1;
    BOOST_CHECK_THROW(consensus.DifficultyAdjustmentInterval(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(state_action_runner_preserves_native_exception_boundaries)
{
    using Step = drivechain::haskell::BmmStateStep;
    for (const auto [begin, end] : {std::pair{34U,40U}, {42U,45U}, {47U,48U}, {50U,54U}, {56U,58U}, {60U,62U}, {64U,67U}, {88U,91U}, {93U,94U}, {96U,100U}, {102U,106U}}) {
        for (uint32_t failure = begin; failure <= end + 1; ++failure) {
            uint32_t next{begin};
            bool threw{false};
            try {
                BOOST_CHECK(drivechain::haskell::RunBmmStateFlow(static_cast<Step>(begin - 1), [&](Step action) {
                    BOOST_CHECK_EQUAL(static_cast<uint32_t>(action), next++);
                    BOOST_CHECK_EQUAL(drivechain::haskell::BmmSignetTemplate()[0], 0);
                    if (static_cast<uint32_t>(action) == failure) throw std::logic_error("injected action failure");
                    return 1;
                }));
            } catch (const std::logic_error& error) {
                threw = true;
                BOOST_CHECK_EQUAL(error.what(), "injected action failure");
            }
            BOOST_CHECK_EQUAL(threw, failure <= end);
            BOOST_CHECK_EQUAL(next, std::min(failure + 1, end + 1));
        }
    }
}

BOOST_AUTO_TEST_CASE(commitment_selection_preserves_push_encodings_and_duplicates)
{
    const auto previous = EasyState();
    const auto critical = uint256S("1234567890abcdef");
    auto payload = ParseHex("d161736818" + critical.GetHex());
    for (const int width : {0, 1, 2, 4}) {
        CScript script;
        script << OP_RETURN;
        if (width == 0) script << payload;
        else {
            script.push_back(width == 1 ? OP_PUSHDATA1 : width == 2 ? OP_PUSHDATA2 : OP_PUSHDATA4);
            for (int i = 0; i < width; ++i) script.push_back(i == 0 ? payload.size() : 0);
            script.insert(script.end(), payload.begin(), payload.end());
        }
        for (const int mode : {0, 1, 2, 3, 4}) {
            auto altered = script;
            if (mode == 1) altered << OP_TRUE; // Trailing data is not a commitment.
            if (mode == 2) altered.pop_back(); // Truncated push.
            if (mode == 3) altered[altered.size() - 33] = 23; // Another slot.
            std::vector<CScript> scripts{CScript() << OP_TRUE, altered};
            if (mode == 4) scripts.push_back(script);
            const auto proof = EasyProof(previous, critical, &scripts);
            drivechain::BmmL1State next;
            std::string error;
            const bool accepted = drivechain::VerifyBmmProofEntries(proof, critical, previous.block_hash, next, error, EasyConsensus());
            BOOST_CHECK_EQUAL(accepted, mode == 0);
            if (mode != 0) BOOST_CHECK(error.find(mode == 4 ? "multiple M8" : "no M8") != std::string::npos);
        }
    }
    for (const bool duplicate : {false, true}) {
        auto block = SidechainCandidate(previous.block_hash);
        CMutableTransaction coinbase{*block.vtx[0]};
        if (duplicate) coinbase.vout.push_back(coinbase.vout.back());
        else coinbase.vout.back().scriptPubKey << OP_TRUE;
        block.vtx[0] = MakeTransactionRef(std::move(coinbase));
        block.hashMerkleRoot = BlockMerkleRoot(block);
        const auto proof = EasyProof(previous, block.GetBmmCriticalHash());
        std::string error;
        BOOST_REQUIRE(drivechain::AttachBmmProof(block, proof, error));
        drivechain::BmmL1State next;
        BOOST_CHECK(!drivechain::VerifyBmmProof(block, previous, next, error, EasyConsensus()));
        BOOST_CHECK(error.find(duplicate ? "multiple L1 parent" : "no L1 parent") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(signet_selects_last_raw_witness_commitment)
{
    const auto previous = EasyState();
    const auto critical = uint256S("abcdef1234");
    auto witness_bytes = ParseHex("aa21a9ed");
    witness_bytes.resize(36, 0);
    const auto good = CScript() << OP_RETURN << witness_bytes;
    const auto bad = CScript(good) << ParseHex("ecc7daa2ff");
    const auto m8 = CScript() << OP_RETURN << ParseHex("d161736818" + critical.GetHex());
    auto short_script = good;
    short_script.pop_back();
    auto wrong_prefix = good;
    wrong_prefix[2] ^= 1;
    CScript nonminimal;
    nonminimal << OP_RETURN << OP_PUSHDATA1;
    nonminimal.push_back(36);
    nonminimal.insert(nonminimal.end(), witness_bytes.begin(), witness_bytes.end());
    const std::vector<std::pair<std::vector<CScript>, bool>> cases{
        {{bad, good, m8}, true}, {{good, bad, m8}, false},
        {{bad, short_script, m8}, false}, {{bad, wrong_prefix, m8}, false},
        {{bad, nonminimal, m8}, false}, {{bad, CScript(good) << OP_TRUE, m8}, true}};
    for (const auto& [scripts, expected] : cases) {
        const auto proof = EasyProof(previous, critical, &scripts);
        drivechain::BmmL1State next;
        std::string error;
        BOOST_CHECK_EQUAL(drivechain::VerifyBmmProofEntries(proof, critical,
            previous.block_hash, next, error, EasyConsensus()), expected);
        if (!expected) BOOST_CHECK(error.find("signet solution cannot be decoded") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(signet_missing_witness_rejects_without_publishing_state)
{
    const auto previous = EasyState();
    const auto critical = uint256S("fedcba");
    const auto proof = EasyProof(previous, critical, nullptr, false);
    auto next = previous;
    std::string error;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(proof, critical,
        previous.block_hash, next, error, EasyConsensus()));
    BOOST_CHECK_EQUAL(error, "BMM parent block has no Bitcoin witness commitment");
    BOOST_CHECK(next == previous);
}

BOOST_AUTO_TEST_CASE(signet_extracts_first_solution_and_preserves_parse_end_rules)
{
    const auto previous = EasyState();
    const auto critical = uint256S("fedcba");
    auto bytes = ParseHex("aa21a9ed");
    bytes.resize(36, 0);
    const auto base = CScript() << OP_RETURN << bytes;
    const auto valid = ParseHex("ecc7daa20000");
    const auto invalid = ParseHex("ecc7daa2ff");
    const auto m8 = CScript() << OP_RETURN << ParseHex("d161736818" + critical.GetHex());
    auto failed_at_end = CScript(base) << valid;
    failed_at_end.push_back(OP_PUSHDATA1);
    auto failed_before_end = failed_at_end;
    failed_before_end.push_back(3);
    failed_before_end.push_back(1);
    const std::vector<std::pair<CScript, std::string>> cases{
        {CScript(base) << valid << invalid, ""},
        {CScript(base) << invalid << valid, "signet solution cannot be decoded"},
        {CScript(base) << ParseHex("ecc7daa2000000"), "signet solution contains trailing data"},
        {CScript(base) << ParseHex("ecc7daa2") << valid, ""},
        {CScript(base) << OP_0 << OP_TRUE << valid, ""},
        {failed_at_end, ""},
        {failed_before_end, "malformed signet commitment script"}};
    for (const auto& [script, expected] : cases) {
        const std::vector<CScript> scripts{script, m8};
        const auto proof = EasyProof(previous, critical, &scripts);
        drivechain::BmmL1State next;
        std::string error;
        BOOST_CHECK_EQUAL(drivechain::VerifyBmmProofEntries(proof, critical,
            previous.block_hash, next, error, EasyConsensus()), expected.empty());
        if (!expected.empty()) BOOST_CHECK(error.find(expected) != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(rejects_mismatches_replays_and_corruption)
{
    const drivechain::BmmL1State previous{EasyState()};
    CBlock block{SidechainCandidate(previous.block_hash)};
    const uint256 critical_hash{block.GetBmmCriticalHash()};
    drivechain::BmmProof proof{EasyProof(previous, critical_hash)};
    std::string error;
    BOOST_REQUIRE_MESSAGE(drivechain::AttachBmmProof(block, proof, error), error);

    drivechain::BmmL1State next;
    CBlock corrupted{block};
    corrupted.m_bmm_proof.back() ^= 1;
    BOOST_CHECK(!drivechain::VerifyBmmProof(
        corrupted, previous, next, error, EasyConsensus()));
    BOOST_CHECK(error.find("exact BMM proof") != std::string::npos);

    drivechain::BmmL1State stale{previous};
    --stale.height;
    BOOST_CHECK(!drivechain::VerifyBmmProof(
        block, stale, next, error, EasyConsensus()));
    BOOST_CHECK(error.find("locally authenticated") != std::string::npos);

    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        uint256S("03"),
        previous.block_hash,
        next,
        error,
        EasyConsensus()));
    BOOST_CHECK(error.find("critical hash") != std::string::npos);

    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        critical_hash,
        uint256S("04"),
        next,
        error,
        EasyConsensus()));
    BOOST_CHECK(error.find("successor") != std::string::npos);

    BOOST_REQUIRE_MESSAGE(drivechain::VerifyBmmProof(
        block, previous, next, error, EasyConsensus()), error);
    const auto accepted_state = next;
    BOOST_CHECK(!drivechain::VerifyBmmProof(
        block, accepted_state, next, error, EasyConsensus()));
    BOOST_CHECK(next == accepted_state);

    drivechain::BmmProof replay{proof};
    replay.previous_state = next;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        replay,
        critical_hash,
        previous.block_hash,
        next,
        error,
        EasyConsensus()));

    BOOST_CHECK(next == accepted_state);

    drivechain::BmmProof reorged{proof};
    reorged.previous_state.block_hash = uint256S("05");
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        reorged,
        critical_hash,
        previous.block_hash,
        next,
        error,
        EasyConsensus()));
    BOOST_CHECK(error.find("does not extend") != std::string::npos);

    drivechain::BmmProof bad_merkle{proof};
    bad_merkle.entries[0].coinbase_proof.back() ^= 1;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        bad_merkle,
        critical_hash,
        previous.block_hash,
        next,
        error,
        EasyConsensus()));
    BOOST_CHECK(error.find("Merkle proof") != std::string::npos ||
        error.find("malformed") != std::string::npos);

    drivechain::BmmProof old_timestamp{proof};
    Sidechain::Bitcoin::CMerkleBlock merkle{
        DecodeMerkleProof(old_timestamp.entries[0])};
    merkle.header.nTime = 97'000;
    merkle.header.hashMerkleRoot = uint256S("06");
    old_timestamp.entries[0].coinbase_proof = SerializeValue(merkle);
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        old_timestamp,
        critical_hash,
        previous.block_hash,
        next,
        error,
        EasyConsensus()));

    drivechain::BmmConsensus wrong_slot{EasyConsensus()};
    wrong_slot.sidechain_slot = 23;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        critical_hash,
        previous.block_hash,
        next,
        error,
        wrong_slot));
    BOOST_CHECK(error.find("no M8 commitment") != std::string::npos);

    drivechain::BmmConsensus wrong_signet{EasyConsensus()};
    wrong_signet.signet_challenge = CScript() << OP_FALSE;
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        critical_hash,
        previous.block_hash,
        next,
        error,
        wrong_signet));
    BOOST_CHECK(error.find("signet solution is invalid") != std::string::npos);

    drivechain::BmmConsensus explicit_no_signet{wrong_signet};
    explicit_no_signet.require_signet_solution = false;
    drivechain::BmmL1State no_signet_next;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProofEntries(
            proof,
            critical_hash,
            previous.block_hash,
            no_signet_next,
            error,
            explicit_no_signet),
        error);
    BOOST_CHECK_EQUAL(no_signet_next.height, previous.height + 1);

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
    // The verifier result is a property of the explicit consensus object. A
    // process-global private-E2E flag must not weaken a public/signet check.
    gArgs.ForceSetArg("-ecxprivatebmmcheckpoint", "1");
    gArgs.ForceSetArg("-ecxprivatebmmactivationheight", "110");
    BOOST_CHECK(!drivechain::VerifyBmmProofEntries(
        proof,
        critical_hash,
        previous.block_hash,
        next,
        error,
        wrong_signet));
    BOOST_CHECK(error.find("signet solution is invalid") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(two_verifiers_converge_from_serialized_evidence)
{
    const drivechain::BmmL1State previous{EasyState()};
    CBlock block{SidechainCandidate(previous.block_hash)};
    const uint256 critical_hash{block.GetBmmCriticalHash()};
    const drivechain::BmmProof proof{EasyProof(previous, critical_hash)};
    std::string error;
    BOOST_REQUIRE_MESSAGE(drivechain::AttachBmmProof(block, proof, error), error);

    DataStream wire;
    wire << TX_WITH_WITNESS(block);
    CBlock peer_a;
    CBlock peer_b;
    wire >> TX_WITH_WITNESS(peer_a);
    DataStream second_wire;
    second_wire << TX_WITH_WITNESS(peer_a);
    second_wire >> TX_WITH_WITNESS(peer_b);

    drivechain::BmmL1State state_a;
    drivechain::BmmL1State state_b;
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProof(
            peer_a,
            previous,
            state_a,
            error,
            EasyConsensus()),
        error);
    BOOST_REQUIRE_MESSAGE(
        drivechain::VerifyBmmProof(
            peer_b,
            previous,
            state_b,
            error,
            EasyConsensus()),
        error);
    BOOST_CHECK(state_a == state_b);
    BOOST_CHECK_EQUAL(peer_a.GetHash(), peer_b.GetHash());
    BOOST_CHECK_EQUAL(peer_a.GetBmmCriticalHash(), peer_b.GetBmmCriticalHash());
}

BOOST_AUTO_TEST_CASE(enforces_public_checkpoint_activation)
{
    const std::vector<unsigned char> height_two_header_bytes{ParseHex(
        "000000a043e5de39494df3a659e2ffd2610049ef5e4067032af44a0642132489cb312f94343f07c20d76afcd71dfd94dfb09a4afb9df7d197e1227e9e5cc58f2224621f09746626a02000000012200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332604a000000fbee9cea00d8efdc49cfbec328537e0d7032194de6ebf3cf42e5c05bb89a08b100010151")};
    DataStream height_two_stream(
        height_two_header_bytes);
    CBlockHeader height_two;
    height_two_stream >> height_two;
    BOOST_REQUIRE(height_two_stream.empty());
    BOOST_CHECK_EQUAL(
        height_two.GetHash(),
        drivechain::LayerTwoLabsPublicSidechainBlock2());

    CBlockIndex public_height_one;
    const uint256 public_height_one_hash{
        drivechain::LayerTwoLabsPublicSidechainBlock1()};
    public_height_one.phashBlock = &public_height_one_hash;
    std::string error;
    CBlockIndex wrong_previous;
    const uint256 wrong_previous_hash{uint256S("99")};
    wrong_previous.phashBlock = &wrong_previous_hash;
    for (const CBlockIndex* previous : {static_cast<const CBlockIndex*>(nullptr),
            static_cast<const CBlockIndex*>(&wrong_previous)}) {
        CCoinsView base;
        CCoinsViewCache view(&base);
        CBlock checkpoint_block;
        static_cast<CBlockHeader&>(checkpoint_block) = height_two;
        drivechain::ConnectBmmState(checkpoint_block, previous, view, 2, false, error);
        BOOST_CHECK(!drivechain::HasPersistedBmmConsensusState(view));
        drivechain::DisconnectBmmState(checkpoint_block, previous, view, 2, error);
        BOOST_CHECK(!drivechain::HasPersistedBmmConsensusState(view));
    }
    {
        CCoinsView base;
        CCoinsViewCache view(&base);
        CBlock checkpoint_block;
        static_cast<CBlockHeader&>(checkpoint_block) = height_two;
        drivechain::BmmL1State state;
        BOOST_REQUIRE(drivechain::ConnectBmmState(checkpoint_block, &public_height_one, view, 2, false, error));
        const COutPoint state_outpoint{Txid::FromUint256(uint256S(
            "f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9")), 0};
        const Coin& stored = view.AccessCoin(state_outpoint);
        // Independent wire vector: CompactSize marker/history, LE scalars/hash,
        // PUSHDATA1 payload, DROP, FALSE. Do not derive it with the state encoder.
        const auto expected_script = ParseHex(
            "4c73116472697665636861696e2d626d6d2d7631657674190b9bd439b47fff98fb29de90"
            "ee6cabc08cd4ebd14e849eb61b030000001900009548626acc76031ea0170000950f5f6a"
            "0b2531626a7d33626ad535626a2d38626a853a626add3c626a353f626a8d41626ae543626a"
            "3d46626a9548626a7500");
        BOOST_REQUIRE(!stored.IsSpent());
        BOOST_CHECK_EQUAL_COLLECTIONS(stored.out.scriptPubKey.begin(), stored.out.scriptPubKey.end(),
            expected_script.begin(), expected_script.end());
        BOOST_CHECK_EQUAL(stored.nHeight, 2);
        BOOST_CHECK(!stored.fCoinBase);
        BOOST_REQUIRE(drivechain::GetBmmState(view, state, &error));
        BOOST_CHECK(state == drivechain::LayerTwoLabsInitialBmmState());
        BOOST_CHECK(!drivechain::ConnectBmmState(checkpoint_block, &public_height_one, view, 2, false, error));
        BOOST_CHECK_EQUAL(error, "public BMM checkpoint cannot overwrite existing parent-chain state");
        BOOST_REQUIRE(drivechain::DisconnectBmmState(checkpoint_block, &public_height_one, view, 2, error));
        BOOST_CHECK(!drivechain::HasPersistedBmmConsensusState(view));
        BOOST_CHECK(!drivechain::DisconnectBmmState(checkpoint_block, &public_height_one, view, 2, error));
        BOOST_CHECK_EQUAL(error, "public BMM checkpoint state is inconsistent during disconnect");
        const COutPoint point{Txid::FromUint256(uint256S("f0bcf7ca88c8a7c66d74d5540d5458ead1a15df5a8b6b98c08032a1300579ff9")), 0};
        const auto corrupt = CScript() << OP_TRUE;
        view.AddCoin(point, Coin(CTxOut(Params().GetConsensus().pegged_asset, 0, corrupt), 2, false), false);
        BOOST_CHECK(!drivechain::ConnectBmmState(checkpoint_block, &public_height_one, view, 2, false, error));
        BOOST_CHECK_EQUAL(error, "persisted BMM state script is malformed");
        BOOST_CHECK(!drivechain::DisconnectBmmState(checkpoint_block, &public_height_one, view, 2, error));
        BOOST_CHECK_EQUAL(error, "persisted BMM state script is malformed");
        BOOST_CHECK(view.AccessCoin(point).out.scriptPubKey == corrupt);
    }
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmHeader(
            height_two,
            &public_height_one,
            error),
        error);
    CBlockIndex persisted_height_two{height_two};
    persisted_height_two.pprev = &public_height_one;
    persisted_height_two.nHeight = 2;
    const uint256 persisted_height_two_hash{height_two.GetHash()};
    persisted_height_two.phashBlock = &persisted_height_two_hash;
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmIndexHeader(persisted_height_two, error),
        error);

    CBlockHeader alternate_height_two{height_two};
    ++alternate_height_two.nTime;
    BOOST_CHECK(!drivechain::CheckBmmHeader(
        alternate_height_two,
        &public_height_one,
        error));
    BOOST_CHECK(error.find("immutable checkpoint") != std::string::npos);
    CBlockIndex persisted_alternate{alternate_height_two};
    persisted_alternate.pprev = &public_height_one;
    persisted_alternate.nHeight = 2;
    const uint256 persisted_alternate_hash{alternate_height_two.GetHash()};
    persisted_alternate.phashBlock = &persisted_alternate_hash;
    BOOST_CHECK(!drivechain::CheckBmmIndexHeader(persisted_alternate, error));
    BOOST_CHECK(error.find("immutable checkpoint") != std::string::npos);

    CBlockIndex public_tip;
    const uint256 public_tip_hash{
        drivechain::LayerTwoLabsPublicSidechainBlock2()};
    public_tip.phashBlock = &public_tip_hash;

    CBlockHeader child;
    child.nVersion = 0x20000000;
    BOOST_CHECK(!drivechain::CheckBmmHeader(child, &public_tip, error));
    BOOST_CHECK(error.find("does not signal") != std::string::npos);

    child.nVersion |= CBlockHeader::BMM_PROOF_HF_MASK;
    BOOST_CHECK(!drivechain::CheckBmmHeader(child, &public_tip, error));
    BOOST_CHECK(error.find("no proof commitment") != std::string::npos);
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmHeader(child, &public_tip, error, true),
        error);
    CBlockIndex persisted_child{child};
    persisted_child.pprev = &public_tip;
    persisted_child.nHeight = 3;
    const uint256 persisted_child_hash{child.GetHash()};
    persisted_child.phashBlock = &persisted_child_hash;
    BOOST_CHECK(!drivechain::CheckBmmIndexHeader(persisted_child, error));
    BOOST_CHECK(error.find("no proof commitment") != std::string::npos);
    child.hashBmmProof = uint256S("02");
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmHeader(child, &public_tip, error),
        error);

    CBlockIndex unrelated;
    const uint256 unrelated_hash{uint256S("01")};
    unrelated.phashBlock = &unrelated_hash;
    BOOST_CHECK(!drivechain::CheckBmmHeader(child, &unrelated, error));
    BOOST_CHECK(error.find("cannot activate") != std::string::npos);
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
BOOST_AUTO_TEST_CASE(private_builder_constructs_verifiable_proofs)
{
    const auto critical = uint256S("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021");
    auto previous = EasyState();
    drivechain::BmmProof proof;
    proof.version = 99;
    std::string error{"sentinel"};
    gArgs.ForceSetArg("-ecxprivatebmmcheckpoint", "0");
    BOOST_CHECK(!drivechain::BuildPrivateE2eBmmProof(previous, critical, proof, error));
    BOOST_CHECK_EQUAL(error, "private BMM proof construction is disabled");
    BOOST_CHECK_EQUAL(proof.version, 99);
    gArgs.ForceSetArg("-ecxprivatebmmcheckpoint", "1");
    BOOST_CHECK_EQUAL(drivechain::RuntimeBmmConsensusFingerprint().GetHex(),
        "000c09cc8e8d22e73a6c3b19a7e2767b8334ed6c399c9e2e51662d78452c3225");
    auto malformed = previous;
    malformed.block_hash.SetNull();
    BOOST_CHECK(!drivechain::BuildPrivateE2eBmmProof(malformed, critical, proof, error));
    BOOST_CHECK_EQUAL(proof.version, 99);
    for (unsigned block = 0; block < 3; ++block) {
        BOOST_REQUIRE_MESSAGE(drivechain::BuildPrivateE2eBmmProof(previous, critical, proof, error), error);
        BOOST_CHECK(error.empty());
        BOOST_CHECK(proof.previous_state == previous);
        BOOST_REQUIRE_EQUAL(proof.entries.size(), 1);
        drivechain::BmmL1State next;
        BOOST_REQUIRE_MESSAGE(drivechain::VerifyBmmProofEntries(proof, critical, previous.block_hash,
            next, error, drivechain::LayerTwoLabsBmmConsensus()), error);
        BOOST_CHECK_EQUAL(next.height, previous.height + 1);
        BOOST_CHECK_EQUAL(next.block_time, previous.block_time + 1);
        std::vector<unsigned char> encoded;
        BOOST_REQUIRE(drivechain::SerializeBmmProof(proof, encoded, error));
        drivechain::BmmProof decoded;
        BOOST_REQUIRE(drivechain::DeserializeBmmProof(encoded, decoded, error));
        BOOST_REQUIRE(drivechain::VerifyBmmProofEntries(decoded, critical, previous.block_hash,
            next, error, drivechain::LayerTwoLabsBmmConsensus()));
        const auto accepted = next;
        BOOST_CHECK(!drivechain::VerifyBmmProofEntries(decoded, uint256S("02"), previous.block_hash,
            next, error, drivechain::LayerTwoLabsBmmConsensus()));
        BOOST_CHECK(next == accepted);
        previous = accepted;
    }
}

BOOST_AUTO_TEST_CASE(private_activation_height_does_not_invalidate_history)
{
    gArgs.ForceSetArg("-ecxprivatebmmcheckpoint", "1");
    gArgs.ForceSetArg("-ecxprivatebmmactivationheight", "110");
    BOOST_CHECK(!drivechain::LayerTwoLabsBmmConsensus().require_signet_solution);

    CBlockIndex previous;
    const uint256 previous_hash{uint256S("03")};
    previous.phashBlock = &previous_hash;
    previous.nHeight = 108;
    CBlockHeader legacy;
    legacy.nVersion = 0x20000000;
    std::string error;
    BOOST_CHECK_MESSAGE(drivechain::CheckBmmHeader(legacy, &previous, error), error);

    previous.nHeight = 109;
    BOOST_CHECK(!drivechain::CheckBmmHeader(legacy, &previous, error));
    BOOST_CHECK(error.find("does not signal") != std::string::npos);
    legacy.nVersion |= CBlockHeader::BMM_PROOF_HF_MASK;
    BOOST_CHECK_MESSAGE(
        drivechain::CheckBmmHeader(legacy, &previous, error, true),
        error);
    legacy.hashBmmProof = uint256S("04");
    BOOST_CHECK_MESSAGE(drivechain::CheckBmmHeader(legacy, &previous, error), error);

}
#endif

BOOST_AUTO_TEST_SUITE_END()
