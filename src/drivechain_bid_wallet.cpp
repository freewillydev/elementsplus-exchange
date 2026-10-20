// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <drivechain_bid_wallet.h>
#include <primitives/bitcoin/transaction.h>
#include <rpc/util.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>
#include <set>
#include <stdexcept>

namespace drivechain {
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
