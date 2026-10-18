// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPC_UTIL_H
#define BITCOIN_WALLET_RPC_UTIL_H

#include <rpc/util.h>
#include <consensus/amount.h>
#include <script/script.h>
#include <wallet/wallet.h>

#include <any>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class JSONRPCRequest;
class UniValue;
struct bilingual_str;

namespace wallet {
class LegacyScriptPubKeyMan;
enum class DatabaseStatus;
struct WalletContext;

struct DepositBroadcastResult { bool already_imported; bool broadcast; };
/** Invoke broadcast at most once, preserving deposit RPC duplicate-error handling. */
DepositBroadcastResult BroadcastDrivechainDeposit(bool known, const std::function<bool(std::string&)>& broadcast);
/** Parse integer satoshis without monetary bounds; use fallback only for null/missing input. */
int64_t ParseDrivechainSatoshis(const UniValue& value, const char* field, std::optional<int64_t> fallback = std::nullopt);
enum class DepositArgument : uint32_t {
    NATIVE_VALUE, NATIVE_FEE, HISTORICAL_VALUE, HISTORICAL_FEE, OUTPUT_INDEX,
    NATIVE_NETWORK, HISTORICAL_NETWORK, TXID, BLOCK_HASH, ADDRESS, FEDERATED_NETWORK
};
void CheckDepositArgument(DepositArgument rule, int64_t amount, int64_t bound = MAX_MONEY);

extern const std::string HELP_REQUIRING_PASSPHRASE;

static const RPCResult RESULT_LAST_PROCESSED_BLOCK { RPCResult::Type::OBJ, "lastprocessedblock", "hash and height of the block this information was generated on",{
    {RPCResult::Type::STR_HEX, "hash", "hash of the block this information was generated on"},
    {RPCResult::Type::NUM, "height", "height of the block this information was generated on"}}
};

/**
 * Figures out what wallet, if any, to use for a JSONRPCRequest.
 *
 * @param[in] request JSONRPCRequest that wishes to access a wallet
 * @return nullptr if no wallet should be used, or a pointer to the CWallet
 */
std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request);
bool GetWalletNameFromJSONRPCRequest(const JSONRPCRequest& request, std::string& wallet_name);

void EnsureWalletIsUnlocked(const CWallet&);
WalletContext& EnsureWalletContext(const std::any& context);
LegacyScriptPubKeyMan& EnsureLegacyScriptPubKeyMan(CWallet& wallet, bool also_create = false);
const LegacyScriptPubKeyMan& EnsureConstLegacyScriptPubKeyMan(const CWallet& wallet);

bool GetAvoidReuseFlag(const CWallet& wallet, const UniValue& param);
bool ParseIncludeWatchonly(const UniValue& include_watchonly, const CWallet& wallet);
std::string LabelFromValue(const UniValue& value);
//! Fetch parent descriptors of this scriptPubKey.
void PushParentDescriptors(const CWallet& wallet, const CScript& script_pubkey, UniValue& entry);

void HandleWalletError(const std::shared_ptr<CWallet> wallet, DatabaseStatus& status, bilingual_str& error);
void AppendLastProcessedBlock(UniValue& entry, const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
} //  namespace wallet

#endif // BITCOIN_WALLET_RPC_UTIL_H
