// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <drivechain_bid_wallet.h>
#include <core_io.h>
#include <primitives/bitcoin/transaction.h>
#include <rpc/util.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <boost/test/unit_test.hpp>

namespace {
namespace B = Sidechain::Bitcoin;
std::string Encode(const B::CMutableTransaction& tx)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(tx);
    return HexStr(stream);
}
B::CMutableTransaction Decode(const std::string& hex, bool witness = true)
{
    DataStream stream{ParseHex(hex)};
    B::CMutableTransaction tx;
    if (witness) stream >> TX_WITH_WITNESS(tx);
    else stream >> TX_NO_WITNESS(tx);
    BOOST_REQUIRE(stream.empty());
    return tx;
}
struct BidFixture {
    drivechain::LocalBid bid{24, 100, uint256S("112233"), uint256S("aabbcc"), 250, 0};
    CScript change = CScript() << OP_0 << std::vector<unsigned char>(20, 7);
    std::string saved, broadcast;
    std::vector<std::string> calls;
    bool pending{false}, confirmed{true}, signing{true}, accepts{true};
    bool cancelled{false}, save_fails{false}, broadcast_timeout{false};
    int funds{0}, sends{0};
    std::function<void(B::CMutableTransaction&)> alter_funded, alter_signed;
    std::function<void()> after_save, after_sign;

    UniValue Node(const std::string& method, const UniValue& params)
    {
        calls.push_back(method);
        UniValue result{UniValue::VOBJ};
        if (method == "getbestblockhash") return bid.parent.GetHex();
        if (method == "getblockheader") {
            BOOST_CHECK_EQUAL(params[0].get_str(), bid.parent.GetHex());
            result.pushKV("height", bid.height);
        } else if (method == "gettxout") {
            BOOST_CHECK(!params[2].get_bool());
            if (!confirmed) return UniValue();
            result.pushKV("confirmations", 6);
            result.pushKV("value", ValueFromAmount(100000));
        } else if (method == "getmempoolentry") {
            if (!pending) return UniValue();
            UniValue fees{UniValue::VOBJ};
            fees.pushKV("base", ValueFromAmount(100000 - Decode(saved).vout[1].nValue));
            result.pushKV("fees", fees);
            result.pushKV("vsize", 170);
        } else if (method == "getmempoolinfo") {
            result.pushKV("incrementalrelayfee", ValueFromAmount(1000));
        } else if (method == "testmempoolaccept") {
            BOOST_CHECK_EQUAL(params[0].size(), 1U);
            UniValue item{UniValue::VOBJ}, array{UniValue::VARR};
            item.pushKV("allowed", accepts);
            array.push_back(item);
            return array;
        } else if (method == "sendrawtransaction") {
            broadcast = params[0].get_str();
            BOOST_CHECK_EQUAL(saved, broadcast);
            ++sends;
            pending = true;
            if (broadcast_timeout) throw std::runtime_error("Lost response");
            return B::CTransaction(Decode(broadcast)).GetHash().GetHex();
        } else {
            throw std::runtime_error("Unexpected node method: " + method);
        }
        return result;
    }
    UniValue Wallet(const std::string& method, const UniValue& params)
    {
        calls.push_back(method);
        UniValue result{UniValue::VOBJ};
        if (method == "getwalletinfo") {
            result.pushKV("private_keys_enabled", signing);
        } else if (method == "getrawchangeaddress") {
            return "fixture-change";
        } else if (method == "getaddressinfo") {
            result.pushKV("ismine", true);
            result.pushKV("scriptPubKey", HexStr(change));
        } else if (method == "fundrawtransaction") {
            ++funds;
            BOOST_CHECK_EQUAL(params[1]["changeAddress"].get_str(), "fixture-change");
            BOOST_CHECK_EQUAL(params[1]["minconf"].getInt<int>(), 1);
            BOOST_CHECK_EQUAL(params[1]["subtractFeeFromOutputs"][0].getInt<int>(), 1);
            BOOST_CHECK(params[1]["replaceable"].get_bool());
            auto tx = Decode(params[0].get_str(), false);
            BOOST_REQUIRE(tx.vin.empty());
            BOOST_REQUIRE_EQUAL(tx.vout.size(), 2U);
            BOOST_CHECK_EQUAL(tx.vout[1].nValue, bid.fee + 1000);
            tx.vout[1].nValue -= 200;
            tx.vin.emplace_back(B::COutPoint{uint256S("1234"), 0});
            tx.vout.insert(tx.vout.begin() + 1, B::CTxOut{100000 - bid.fee - 1000, change});
            if (alter_funded) alter_funded(tx);
            result.pushKV("hex", Encode(tx));
            result.pushKV("changepos", 1);
        } else if (method == "signrawtransactionwithwallet") {
            auto tx = Decode(params[0].get_str());
            tx.vin[0].scriptWitness.stack = {{1, 2, 3}, {4, 5, 6}};
            if (alter_signed) alter_signed(tx);
            result.pushKV("hex", Encode(tx));
            result.pushKV("complete", true);
            if (after_sign) after_sign();
        } else {
            throw std::runtime_error("Unexpected wallet method: " + method);
        }
        return result;
    }
    uint256 Submit()
    {
        // Copy the request: callbacks may advance the simulated parent tip.
        const auto request = bid;
        return drivechain::SubmitLocalBid(request, {
            [&](const auto& m, const auto& p) { return Node(m, p); },
            [&](const auto& m, const auto& p) { return Wallet(m, p); },
            [&] { return saved; },
            [&](const auto& hex) {
                if (save_fails) throw std::runtime_error("Disk full");
                saved = hex;
                if (after_save) after_save();
            },
            [&] { return cancelled; }});
    }
    void NextParent()
    {
        bid.parent = uint256S("223344");
        bid.critical = uint256S("bbccdd");
        ++bid.height;
    }
};
}

BOOST_FIXTURE_TEST_SUITE(drivechain_bid_wallet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(exact_m8_local_wallet_fee_and_change)
{
    BidFixture f;
    const auto id = f.Submit();
    const auto tx = Decode(f.broadcast);
    BOOST_CHECK(id == B::CTransaction(tx).GetHash());
    BOOST_CHECK_EQUAL(tx.version, 2);
    BOOST_CHECK_EQUAL(tx.nLockTime, 100U);
    BOOST_CHECK_EQUAL(tx.vin[0].nSequence, 0xfffffffdU);
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, 0);
    BOOST_CHECK_EQUAL(tx.vout[1].nValue, 99750);
    BOOST_CHECK(tx.vout[1].scriptPubKey == f.change);
    BOOST_CHECK_EQUAL(HexStr(tx.vout[0].scriptPubKey),
        "6a4400bf0018" + f.bid.critical.GetHex() + HexStr(f.bid.parent));
    BOOST_CHECK_EQUAL(f.funds, 1);
    BOOST_CHECK_EQUAL(f.sends, 1);
}

BOOST_AUTO_TEST_CASE(ambiguous_broadcast_and_restart_do_not_double_pay)
{
    BidFixture f;
    f.broadcast_timeout = true;
    BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
    const auto signed_bid = f.saved;
    f.broadcast_timeout = false;
    BOOST_CHECK(f.Submit() == B::CTransaction(Decode(signed_bid)).GetHash());
    BOOST_CHECK_EQUAL(f.funds, 1);
    BOOST_CHECK_EQUAL(f.sends, 1);
    f.pending = false; // Retry the exact signed transaction if absent.
    f.Submit();
    BOOST_CHECK_EQUAL(f.broadcast, signed_bid);
    BOOST_CHECK_EQUAL(f.funds, 1);
    BOOST_CHECK_EQUAL(f.sends, 2);
}

BOOST_AUTO_TEST_CASE(replacement_reuses_inputs_and_is_bounded)
{
    BidFixture f;
    f.Submit();
    const auto original = Decode(f.saved);
    f.NextParent();
    BOOST_CHECK_THROW(f.Submit(), std::runtime_error); // No fee escalation authorized.
    BOOST_CHECK_EQUAL(f.sends, 1);
    f.bid.replacement_extra = 202;
    f.Submit();
    const auto replacement = Decode(f.saved);
    BOOST_CHECK(replacement.vin[0].prevout == original.vin[0].prevout);
    BOOST_CHECK_EQUAL(replacement.vout[1].nValue, 99548);
    BOOST_CHECK_EQUAL(replacement.nLockTime, 101U);
    BOOST_CHECK_EQUAL(f.funds, 1);
    BOOST_CHECK_EQUAL(f.sends, 2);
}

BOOST_AUTO_TEST_CASE(evicted_or_unbroadcast_bid_reuses_confirmed_coin)
{
    BidFixture f;
    f.Submit();
    f.pending = false;
    f.NextParent();
    f.Submit();
    BOOST_CHECK_EQUAL(f.funds, 1);
    BOOST_CHECK_EQUAL(Decode(f.saved).vout[1].nValue, 99750);
}

BOOST_AUTO_TEST_CASE(reject_conflicting_candidate_and_corrupt_journal)
{
    BidFixture f;
    f.Submit();
    f.bid.critical = uint256S("dead");
    BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
    BOOST_CHECK_EQUAL(f.sends, 1);
    f.saved += "00";
    BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
    f.saved = "not hex";
    BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(fail_closed_before_broadcast)
{
    for (int failure = 0; failure < 8; ++failure) {
        BidFixture f;
        switch (failure) {
        case 0: f.confirmed = false; break;
        case 1: f.signing = false; break;
        case 2: f.cancelled = true; break;
        case 3: f.accepts = false; break;
        case 4: f.save_fails = true; break;
        case 5: f.after_save = [&] { f.cancelled = true; }; break;
        case 6: f.after_save = [&] { f.NextParent(); }; break;
        case 7: f.after_sign = [&] { f.NextParent(); }; break;
        }
        BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
        BOOST_CHECK_EQUAL(f.sends, 0);
    }
}

BOOST_AUTO_TEST_CASE(reject_mutated_wallet_response)
{
    const std::vector<std::function<void(B::CMutableTransaction&)>> mutations{
        [](auto& tx) { tx.vout.emplace_back(1, CScript() << OP_TRUE); },
        [](auto& tx) { tx.vout[0].scriptPubKey = CScript() << OP_RETURN; },
        [](auto& tx) { tx.vout[0].nValue = 1; },
        [](auto& tx) { tx.vout[1].scriptPubKey = CScript() << OP_TRUE; },
        [](auto& tx) { ++tx.nLockTime; },
        [](auto& tx) { tx.version = 1; },
    };
    for (const auto& mutate : mutations) {
        for (bool signing : {false, true}) {
            BidFixture f;
            (signing ? f.alter_signed : f.alter_funded) = mutate;
            BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
            BOOST_CHECK_EQUAL(f.sends, 0);
        }
    }
    BidFixture f;
    f.alter_signed = [](auto& tx) { tx.vin[0].prevout.n++; };
    BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
    f.alter_signed = [](auto& tx) { tx.vin[0].nSequence++; };
    BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
    BOOST_CHECK_EQUAL(f.sends, 0);
}

BOOST_AUTO_TEST_CASE(reject_invalid_budget_slot_and_dust)
{
    for (int failure = 0; failure < 7; ++failure) {
        BidFixture f;
        switch (failure) {
        case 0: f.bid.fee = 0; break;
        case 1: f.bid.fee = 99500; break;
        case 2: f.bid.replacement_extra = -1; break;
        case 3: f.bid.replacement_extra = MAX_MONEY; break;
        case 4: f.bid.slot = 256; break;
        case 5: f.bid.height = 500000000; break;
        case 6: f.bid.parent.SetNull(); break;
        }
        BOOST_CHECK_THROW(f.Submit(), std::runtime_error);
        BOOST_CHECK_EQUAL(f.sends, 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
