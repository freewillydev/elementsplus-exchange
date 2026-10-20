// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef ELEMENTS_DRIVECHAIN_BID_WALLET_H
#define ELEMENTS_DRIVECHAIN_BID_WALLET_H
#include <consensus/amount.h>
#include <uint256.h>
#include <univalue.h>
#include <functional>
#include <string>

namespace drivechain {
struct LocalBid {
    int slot;
    uint32_t height;
    uint256 parent;
    uint256 critical;
    CAmount fee;
    CAmount replacement_extra;
};
// RPC callbacks return results; getmempoolentry returns null only for RPC -5.
// Save must durably persist the signed transaction before returning.
struct BidWalletIO {
    std::function<UniValue(const std::string&, const UniValue&)> node;
    std::function<UniValue(const std::string&, const UniValue&)> wallet;
    std::function<std::string()> load;
    std::function<void(const std::string&)> save;
    std::function<bool()> cancelled;
};
uint256 SubmitLocalBid(const LocalBid& bid, const BidWalletIO& io);
}
#endif
