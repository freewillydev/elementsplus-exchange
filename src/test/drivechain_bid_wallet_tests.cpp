// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <drivechain_bid_wallet.h>
#include <core_io.h>
#include <common/args.h>
#include <mainchainrpc.h>
#include <primitives/bitcoin/transaction.h>
#include <rpc/util.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <boost/test/unit_test.hpp>
#include <set>
#include <cstdlib>

namespace bid_reference {
using drivechain::LocalBid;
using drivechain::BidWalletIO;
namespace {
namespace B = Sidechain::Bitcoin;
void Require(bool condition, const char* error)
{
    if (!condition) throw std::runtime_error(error);
}
UniValue Args(std::initializer_list<UniValue> values)
{
    UniValue result{UniValue::VARR};
    for (const auto& value : values) result.push_back(value);
    return result;
}
B::CMutableTransaction Decode(const std::string& hex)
{
    Require(hex.size() <= 200000 && IsHex(hex), "Invalid parent bid transaction encoding");
    DataStream stream{ParseHex(hex)};
    B::CMutableTransaction tx;
    stream >> TX_WITH_WITNESS(tx);
    Require(stream.empty(), "Trailing parent bid transaction data");
    return tx;
}
std::string Encode(const B::CMutableTransaction& tx)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(tx);
    return HexStr(stream);
}
CScript RequestScript(const LocalBid& bid)
{
    std::vector<unsigned char> payload{0, 0xbf, 0, static_cast<unsigned char>(bid.slot)};
    // M8 h* is display order; prevMainBlock is Bitcoin's internal byte order.
    const auto critical = ParseHex(bid.critical.GetHex());
    payload.insert(payload.end(), critical.begin(), critical.end());
    payload.insert(payload.end(), bid.parent.begin(), bid.parent.end());
    return CScript() << OP_RETURN << payload;
}
CAmount InputTotal(const B::CMutableTransaction& tx, const BidWalletIO& io)
{
    Require(!tx.vin.empty() && tx.vin.size() <= 100, "Invalid BMM funding input count");
    std::set<B::COutPoint> seen;
    CAmount total{0};
    for (const auto& input : tx.vin) {
        Require(!io.cancelled(), "BMM submission cancelled");
        Require(seen.insert(input.prevout).second, "Duplicate BMM funding input");
        const auto coin = io.node("gettxout", Args({input.prevout.hash.GetHex(), input.prevout.n, false}));
        Require(coin.isObject() && coin["confirmations"].getInt<int>() > 0,
            "BMM funding input is not confirmed and unspent on L1");
        const CAmount value = AmountFromValue(coin["value"]);
        Require(MoneyRange(value) && value <= MAX_MONEY - total, "BMM input amount overflow");
        total += value;
    }
    return total;
}
void Current(const LocalBid& bid, const BidWalletIO& io)
{
    Require(!io.cancelled(), "BMM submission cancelled");
    Require(io.node("getbestblockhash", Args({})).get_str() == bid.parent.GetHex(),
        "BMM parent changed before broadcast");
    const auto header = io.node("getblockheader", Args({bid.parent.GetHex()}));
    Require(header["height"].getInt<int64_t>() == bid.height, "BMM parent height mismatch");
    Require(!io.cancelled(), "BMM submission cancelled");
}
}

uint256 SubmitLocalBid(const LocalBid& bid, const BidWalletIO& io)
{
    Require(bid.slot >= 0 && bid.slot <= 255 && bid.height > 0 && bid.height < 500000000 &&
        !bid.parent.IsNull() && !bid.critical.IsNull() && bid.fee > 0 && MoneyRange(bid.fee) &&
        bid.replacement_extra >= 0 && bid.replacement_extra <= MAX_MONEY - bid.fee, "Invalid local BMM bid");
    Current(bid, io);
    const auto wallet = io.wallet("getwalletinfo", Args({}));
    Require(wallet["private_keys_enabled"].isBool() && wallet["private_keys_enabled"].get_bool(),
        "BMM requires a signing parent wallet");
    const CScript request = RequestScript(bid);
    const std::string saved = io.load();
    B::CMutableTransaction tx;
    bool retry{false}, reuse{false};
    CAmount fee = bid.fee;
    if (!saved.empty()) {
        tx = Decode(saved);
        Require(tx.version == 2 && !tx.vin.empty() && tx.vin.size() <= 100 &&
            tx.vout.size() == 2 && tx.vout[0].nValue == 0 &&
            tx.vout[0].scriptPubKey.size() == 70 && tx.vout[0].scriptPubKey[0] == OP_RETURN &&
            tx.vout[0].scriptPubKey[1] == 68 && tx.vout[0].scriptPubKey[2] == 0 &&
            tx.vout[0].scriptPubKey[3] == 0xbf && tx.vout[0].scriptPubKey[4] == 0 &&
            tx.vout[0].scriptPubKey[5] == bid.slot, "Corrupt saved BMM bid");
        const bool same_parent = std::equal(bid.parent.begin(), bid.parent.end(),
            tx.vout[0].scriptPubKey.end() - 32);
        if (same_parent) {
            Require(tx.nLockTime == bid.height && tx.vout[0].scriptPubKey == request,
                "A different candidate is already recorded for this parent; refusing another bid");
            const auto txid = B::CTransaction(tx).GetHash();
            const auto entry = io.node("getmempoolentry", Args({txid.GetHex()}));
            if (!entry.isNull()) return txid;
            retry = true;
        } else {
            // Reuse a pending bid's inputs rather than silently making an
            // unrelated payment. Unknown RPC failures never imply absence.
            const auto entry = io.node("getmempoolentry", Args({B::CTransaction(tx).GetHash().GetHex()}));
            if (!entry.isNull()) {
                const CAmount old_fee = AmountFromValue(entry["fees"]["base"]);
                const CAmount rate = AmountFromValue(io.node("getmempoolinfo", Args({}))["incrementalrelayfee"]);
                const int64_t size = entry["vsize"].getInt<int64_t>();
                Require(MoneyRange(old_fee) && rate > 0 && rate <= MAX_MONEY / 100032 &&
                    size > 0 && size <= 100000, "Invalid replacement fee data");
                const CAmount increment = (rate * (size + 32) + 999) / 1000;
                Require(old_fee <= MAX_MONEY - increment, "Replacement fee overflow");
                fee = std::max(fee, old_fee + increment);
                Require(fee <= bid.fee + bid.replacement_extra, "BMM replacement exceeds configured fee allowance");
            }
            // An evicted (or never broadcast) journal entry can still hold the
            // wallet's only funding coin. Reuse it when all inputs remain on L1.
            reuse = true;
            for (const auto& input : tx.vin) {
                Require(!io.cancelled(), "BMM submission cancelled");
                if (io.node("gettxout", Args({input.prevout.hash.GetHex(), input.prevout.n, false})).isNull())
                    reuse = false;
            }
            Require(entry.isNull() || reuse, "Pending BMM bid inputs no longer exist");
        }
    }
    if (!retry) {
        if (!reuse) {
            tx = B::CMutableTransaction{};
            tx.version = 2;
            tx.nLockTime = bid.height;
            tx.vout.emplace_back(0, request);
            const auto address = io.wallet("getrawchangeaddress", Args({"bech32"})).get_str();
            const auto info = io.wallet("getaddressinfo", Args({address}));
            Require(info["ismine"].get_bool(), "BMM change address is not wallet-owned");
            const auto change_bytes = ParseHex(info["scriptPubKey"].get_str());
            const CScript change{change_bytes.begin(), change_bytes.end()};
            Require(!change.empty() && fee <= MAX_MONEY - 1000, "Invalid BMM funding target");
            // Reserve the absolute bid plus non-dust change during coin selection.
            // Both wallet-owned outputs are consolidated before signing.
            tx.vout.emplace_back(fee + 1000, change);
            UniValue options{UniValue::VOBJ};
            options.pushKV("changeAddress", address);
            options.pushKV("changePosition", 1);
            options.pushKV("replaceable", true);
            options.pushKV("lockUnspents", false);
            options.pushKV("minconf", 1);
            options.pushKV("fee_rate", 1);
            options.pushKV("subtractFeeFromOutputs", Args({1}));
            const auto funded = io.wallet("fundrawtransaction", Args({Encode(tx), options}));
            tx = Decode(funded["hex"].get_str());
            const int change_pos = funded["changepos"].getInt<int>();
            Require((tx.vout.size() == 2 && change_pos == -1) ||
                (tx.vout.size() == 3 && change_pos == 1),
                "Unexpected BMM funding outputs");
            for (size_t i = 1; i < tx.vout.size(); ++i)
                Require(tx.vout[i].scriptPubKey == change, "Wallet changed BMM change script");
            tx.vout.resize(2);
        }
        Require(tx.version == 2 && tx.vout.size() == 2 && tx.vout[0].nValue == 0,
            "Unexpected BMM funding transaction");
        if (!reuse) Require(tx.vout[0].scriptPubKey == request && tx.nLockTime == bid.height,
            "Wallet changed BMM request");
        tx.nLockTime = bid.height;
        tx.vout[0].scriptPubKey = request;
        const auto total = InputTotal(tx, io);
        Require(total > fee && total - fee >= 1000, "Insufficient BMM funds or dust change");
        tx.vout[1].nValue = total - fee;
        for (auto& input : tx.vin) {
            input.nSequence = 0xfffffffd;
            input.scriptSig.clear();
            input.scriptWitness.SetNull();
        }
        Current(bid, io);
        const auto signed_result = io.wallet("signrawtransactionwithwallet", Args({Encode(tx)}));
        Require(signed_result["complete"].get_bool(), "Incomplete BMM signature");
        const auto signed_tx = Decode(signed_result["hex"].get_str());
        Require(signed_tx.version == tx.version && signed_tx.nLockTime == tx.nLockTime &&
            signed_tx.vout == tx.vout && signed_tx.vin.size() == tx.vin.size(), "Signer changed BMM transaction");
        for (size_t i = 0; i < tx.vin.size(); ++i)
            Require(signed_tx.vin[i].prevout == tx.vin[i].prevout &&
                signed_tx.vin[i].nSequence == tx.vin[i].nSequence, "Signer changed BMM inputs");
        tx = signed_tx;
    }
    const auto total = InputTotal(tx, io);
    Require(MoneyRange(tx.vout[1].nValue) && total > tx.vout[1].nValue &&
        total - tx.vout[1].nValue <= bid.fee + bid.replacement_extra, "Saved BMM fee exceeds current budget");
    const auto hex = Encode(tx);
    Current(bid, io);
    const auto accepted = io.node("testmempoolaccept", Args({Args({hex})}));
    Require(accepted.isArray() && accepted.size() == 1 && accepted[0]["allowed"].isBool(),
        "Malformed parent mempool response");
    if (!accepted[0]["allowed"].get_bool()) {
        const auto& reason = accepted[0]["reject-reason"];
        throw std::runtime_error("Parent mempool rejected BMM bid: " +
            (reason.isStr() ? reason.get_str() : "no reason supplied"));
    }
    io.save(hex); // A timeout or restart after broadcast must reuse this exact bid.
    Current(bid, io);
    const auto expected = B::CTransaction(tx).GetHash();
    Require(io.node("sendrawtransaction", Args({hex})).get_str() == expected.GetHex(),
        "Parent returned a different BMM transaction ID");
    return expected;
}
}


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
    std::function<void(const std::string&, UniValue&)> alter_reply;
    std::vector<std::string> effects;
    int fault{-1};
    bool nonstandard{false};

    void Observe(const std::string& name, const UniValue& params = UniValue())
    {
        effects.push_back(name + ":" + params.write());
        if (int(effects.size())-1 == fault) {
            if (nonstandard) throw 71;
            throw std::runtime_error("injected local bid effect failure");
        }
    }

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
    uint256 Submit(bool reference = false)
    {
        // Copy the request: callbacks may advance the simulated parent tip.
        const auto request = bid;
        return (reference ? bid_reference::SubmitLocalBid : drivechain::SubmitLocalBid)(request, {
            [&](const auto& m, const auto& p) {
                Observe("node:"+m,p); auto reply = Node(m,p);
                if (alter_reply) alter_reply(m,reply);
                return reply;
            },
            [&](const auto& m, const auto& p) {
                Observe("wallet:"+m,p); auto reply = Wallet(m,p);
                if (alter_reply) alter_reply(m,reply);
                return reply;
            },
            [&] { Observe("load"); return saved; },
            [&](const auto& hex) {
                Observe("save",UniValue(hex));
                if (save_fails) throw std::runtime_error("Disk full");
                saved = hex;
                if (after_save) after_save();
            },
            [&] { Observe("cancelled"); return cancelled; }});
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

BOOST_AUTO_TEST_CASE(local_bid_complete_workflow_matches_pre_migration_effects)
{
    struct Outcome {
        std::string result, saved, broadcast;
        std::vector<std::string> effects;
        int funds, sends;
    };
    const auto run = [](bool reference, int scenario, int fault, bool nonstandard) {
        BidFixture f;
        if ((scenario >= 1 && scenario <= 9) || scenario == 38) {
            f.Submit(true);
            if (scenario == 3 || scenario == 4 || scenario == 5 || scenario == 38) f.NextParent();
            if (scenario == 2 || scenario == 5) f.pending = false;
            if (scenario == 4) f.bid.replacement_extra = 202;
            if (scenario == 6) f.bid.critical = uint256S("dead");
            if (scenario == 7) f.saved = "invalid";
            if (scenario == 8) f.saved += "00";
            if (scenario == 9) { auto tx = Decode(f.saved); tx.version = 1; f.saved = Encode(tx); }
        }
        switch (scenario) {
        case 10: f.confirmed = false; break;
        case 11: f.signing = false; break;
        case 12: f.cancelled = true; break;
        case 13: f.accepts = false; break;
        case 14: f.save_fails = true; break;
        case 15: f.broadcast_timeout = true; break;
        case 16: f.after_sign = [&] { f.cancelled = true; }; break;
        case 17: f.after_sign = [&] { f.NextParent(); }; break;
        case 18: f.after_save = [&] { f.cancelled = true; }; break;
        case 19: f.after_save = [&] { f.NextParent(); }; break;
        case 20: f.alter_funded = [](auto& tx) { tx.vin.push_back(tx.vin[0]); }; break;
        case 21: f.alter_funded = [](auto& tx) { tx.vin.clear(); }; break;
        case 22: f.alter_funded = [](auto& tx) { tx.vin.resize(101); }; break;
        case 23: f.alter_funded = [](auto& tx) { tx.vout.clear(); }; break;
        case 24: f.alter_funded = [](auto& tx) { tx.vout[0].nValue = 1; }; break;
        case 25: f.alter_funded = [](auto& tx) { tx.nLockTime++; }; break;
        case 26: f.alter_signed = [](auto& tx) { tx.vin[0].nSequence++; }; break;
        case 27: f.alter_signed = [](auto& tx) { tx.vout.clear(); }; break;
        case 28: f.bid.fee = 0; break;
        case 29: f.bid.fee = 99500; break;
        case 30: f.bid.replacement_extra = -1; break;
        case 31: f.bid.replacement_extra = MAX_MONEY; break;
        case 32: f.bid.slot = -1; break;
        case 33: f.bid.slot = 256; break;
        case 34: f.bid.height = 0; break;
        case 35: f.bid.height = 500000000; break;
        case 36: f.bid.parent.SetNull(); break;
        case 37: f.bid.critical.SetNull(); break;
        case 38: f.confirmed = false; break;
        default: break;
        }
        f.alter_reply = [&](const std::string& method, UniValue& reply) {
            if (scenario == 39 && method == "getwalletinfo") reply = UniValue();
            if (scenario == 40 && method == "gettxout") reply = UniValue("not an object");
            if (scenario == 41 && method == "gettxout") reply.pushKV("confirmations",0);
            if (scenario == 42 && method == "gettxout") reply.pushKV("value",ValueFromAmount(MAX_MONEY));
            if (scenario == 43 && method == "gettxout") reply.pushKV("value","invalid");
            if (scenario == 44 && method == "getaddressinfo") reply.pushKV("ismine",false);
            if (scenario == 45 && method == "getaddressinfo") reply.pushKV("scriptPubKey","");
            if (scenario == 46 && method == "signrawtransactionwithwallet") reply.pushKV("complete",false);
            if (scenario == 47 && method == "testmempoolaccept") reply = UniValue();
            if (scenario == 48 && method == "testmempoolaccept") {
                reply = UniValue(UniValue::VARR); reply.push_back(UniValue());
            }
            if (scenario == 49 && method == "sendrawtransaction") reply = UniValue("wrong txid");
            if (scenario == 50 && method == "getbestblockhash") reply = UniValue("wrong parent");
            if (scenario == 51 && method == "getblockheader") reply.pushKV("height",99);
        };
        f.effects.clear(); f.calls.clear(); f.funds = f.sends = 0;
        f.fault = fault; f.nonstandard = nonstandard;
        std::string result;
        try { result = "ok:"+f.Submit(reference).GetHex(); }
        catch (const std::exception& ex) { result = std::string(typeid(ex).name())+":"+ex.what(); }
        catch (const UniValue& error) { result = "rpc:"+error.write(); }
        catch (int value) { result = "int:"+std::to_string(value); }
        return Outcome{result,f.saved,f.broadcast,f.effects,f.funds,f.sends};
    };
    for (int scenario = 0; scenario < 52; ++scenario) for (int fault = -1; fault < 60; ++fault)
        for (bool nonstandard : {false,true}) {
            BOOST_TEST_CONTEXT("scenario=" << scenario << " fault=" << fault << " nonstandard=" << nonstandard) {
                const auto expected = run(true,scenario,fault,nonstandard);
                const auto actual = run(false,scenario,fault,nonstandard);
                BOOST_CHECK_EQUAL(actual.result,expected.result);
                BOOST_CHECK_EQUAL(actual.saved,expected.saved);
                BOOST_CHECK_EQUAL(actual.broadcast,expected.broadcast);
                BOOST_CHECK(actual.effects == expected.effects);
                BOOST_CHECK_EQUAL(actual.funds,expected.funds);
                BOOST_CHECK_EQUAL(actual.sends,expected.sends);
            }
        }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(bmm_submission_tests)
BOOST_AUTO_TEST_CASE(bmm_submission_native_http)
{
    // Only the isolated HTTP harness enables this test. No real wallet, node
    // or peer is used; the server returns synthetic transactions and signatures.
    const char* port = std::getenv("ELEMENTS_TEST_BID_RPC_PORT");
    if (!port) return;
    const char* mode_value = std::getenv("ELEMENTS_TEST_BID_MODE");
    const char* expected_error = std::getenv("ELEMENTS_TEST_BID_ERROR");
    const char* credential = std::getenv("ELEMENTS_TEST_BID_CREDENTIAL");
    BOOST_REQUIRE(mode_value && expected_error && credential);
    const std::string mode{mode_value};
    BasicTestingSetup setup{ChainTypeMetaFrom("elements")};
    gArgs.ForceSetArg("-mainchainrpchost",mode == "host" ? "localhost" : "127.0.0.1");
    gArgs.ForceSetArg("-mainchainrpcport",port);
    gArgs.ForceSetArg("-mainchainrpccredentialfile",credential);
    gArgs.ForceSetArg("-mainchainrpctimeout","1");
    gArgs.ForceSetArg("-drivechainbmmwallet",mode == "wallet" ? "" : "fixture-bid-wallet");
    gArgs.ForceSetArg("-drivechainbmmreplacementextra","0");
    const uint256 parent = uint256S("112233"), critical = uint256S("aabbcc"), sentinel = uint256S("abcd");
    uint256 txid = sentinel;
    std::string error{"unchanged"};
    const auto submit = [&](const uint256& candidate) {
        return SubmitDrivechainBmmBid(mode == "slot" ? 25 : 24,250,973958,candidate,parent,
            txid,&error,[&] { return mode == "cancel"; });
    };
    const bool expected = std::string{expected_error}.empty();
    BOOST_CHECK_MESSAGE(submit(critical) == expected,error);
    if (!expected) {
        BOOST_CHECK(txid == sentinel);
        BOOST_CHECK_MESSAGE(error.find(expected_error) != std::string::npos,error);
        if (mode != "retry") return;
        BOOST_REQUIRE_MESSAGE(submit(critical),error);
    }
    BOOST_CHECK(txid != sentinel && !txid.IsNull());
    const uint256 first = txid;
    BOOST_REQUIRE_MESSAGE(submit(critical),error);
    BOOST_CHECK(txid == first); // Already-pending journal record must not pay again.
    BOOST_CHECK(!submit(uint256S("aabbcd")));
    BOOST_CHECK(txid == first);
    BOOST_CHECK(error.find("different candidate") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
