// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/rpc/util.h>

#include <common/url.h>
#include <haskell/bridge.h>
#include <rpc/util.h>
#include <util/any.h>
#include <util/translation.h>
#include <util/strencodings.h>
#include <wallet/context.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <string_view>
#include <array>
#include <utility>
#include <stdexcept>
#include <univalue.h>

namespace wallet {
void CheckDepositArgument(DepositArgument rule, int64_t amount, int64_t bound)
{
    static constexpr std::array<std::pair<int,const char*>,11> failures{{
        {RPC_INVALID_PARAMETER,"value_sats must be positive and within the money range"},
        {RPC_INVALID_PARAMETER,"fee_sats must be a non-negative monetary amount"},
        {RPC_INVALID_PARAMETER,"value_sats must be greater than zero"},
        {RPC_INVALID_PARAMETER,"fee_sats must be non-negative and less than value_sats"},
        {RPC_INVALID_PARAMETER,"mainchain_vout must be a valid uint32 output index"},
        {RPC_METHOD_NOT_FOUND,"Native BIP300 deposits are not enabled on this network"},
        {RPC_MISC_ERROR,"importdrivechaindeposit is unavailable outside an Elements parent-chain configuration"},
        {RPC_INVALID_PARAMETER,"mainchain_txid must be a 32-byte hex transaction id"},
        {RPC_INVALID_PARAMETER,"mainchain_block_hash must be a 32-byte hex block hash"},
        {RPC_INVALID_ADDRESS_OR_KEY,"Invalid Elements address"},
        {RPC_METHOD_NOT_FOUND,"Legacy federated peg-ins are disabled on a Drivechain network; use importdrivechaindeposit"}}};
    if (static_cast<size_t>(rule) >= failures.size()) throw std::runtime_error("Unknown deposit argument rule");
    if (!drivechain::haskell::DepositPreflight(static_cast<uint32_t>(rule), amount, bound)) {
        const auto [code,message] = failures.at(static_cast<size_t>(rule));
        throw JSONRPCError(code, message);
    }
}

int64_t ParseDrivechainSatoshis(const UniValue& value, const char* field, std::optional<int64_t> fallback)
{
    int64_t amount{fallback.value_or(0)};
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::DEPOSIT_SATOSHIS,
        [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return value.isNum();
        case 2: amount=value.getInt<int64_t>(); return 1;
        case 3: return value.isStr();
        case 4: return ParseInt64(value.get_str(),&amount);
        case 5: throw JSONRPCError(RPC_INVALID_PARAMETER,strprintf("%s must be an integer number of satoshis",field));
        case 6: return fallback.has_value();
        case 7: return value.isNull();
        default: throw std::logic_error("Invalid Haskell deposit satoshi action");
        }
    });
    return amount;
}

DepositBroadcastResult BroadcastDrivechainDeposit(bool known, const std::function<bool(std::string&)>& broadcast)
{
    std::string error;
    const auto result = drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::DEPOSIT_BROADCAST, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return known;
        case 2: return broadcast(error);
        case 3: case 4: return drivechain::haskell::DepositMessageMatches(step-3,error);
        case 5: throw JSONRPCError(RPC_TRANSACTION_REJECTED,error);
        default: throw std::logic_error("Invalid Haskell deposit broadcast action");
        }
    });
    return {result==1,result==2};
}

static const std::string WALLET_ENDPOINT_BASE = "/wallet/";
const std::string HELP_REQUIRING_PASSPHRASE{"\nRequires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.\n"};

bool GetAvoidReuseFlag(const CWallet& wallet, const UniValue& param) {
    bool can_avoid_reuse = wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    bool avoid_reuse = param.isNull() ? can_avoid_reuse : param.get_bool();

    if (avoid_reuse && !can_avoid_reuse) {
        throw JSONRPCError(RPC_WALLET_ERROR, "wallet does not have the \"avoid reuse\" feature enabled");
    }

    return avoid_reuse;
}

/** Used by RPC commands that have an include_watchonly parameter.
 *  We default to true for watchonly wallets if include_watchonly isn't
 *  explicitly set.
 */
bool ParseIncludeWatchonly(const UniValue& include_watchonly, const CWallet& wallet)
{
    if (include_watchonly.isNull()) {
        // if include_watchonly isn't explicitly set, then check if we have a watchonly wallet
        return wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    }

    // otherwise return whatever include_watchonly was set to
    return include_watchonly.get_bool();
}

bool GetWalletNameFromJSONRPCRequest(const JSONRPCRequest& request, std::string& wallet_name)
{
    if (request.URI.starts_with(WALLET_ENDPOINT_BASE)) {
        // wallet endpoint was used
        wallet_name = UrlDecode(std::string_view{request.URI}.substr(WALLET_ENDPOINT_BASE.size()));
        return true;
    }
    return false;
}

static std::shared_ptr<CWallet> LoadOrCreateDefaultWallet(WalletContext& context)
{
    std::shared_ptr<CWallet> wallet;
    DatabaseStatus status;
    bilingual_str error;
    const auto attempt = [&](auto open, bool create) {
        DatabaseOptions options;
        options.require_existing = !create;
        options.require_create = create;
        options.verify = create;
#ifdef USE_SQLITE
        options.create_flags = create ? WALLET_FLAG_DESCRIPTORS : 0;
#endif
        error = {};
        std::vector<bilingual_str> warnings;
        wallet = open(context, "default", /*load_on_start=*/true, options, status, error, warnings);
        return bool(wallet);
    };
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::DEFAULT_WALLET,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return attempt(LoadWallet, false);
        case 2: return status == DatabaseStatus::FAILED_NOT_FOUND;
        case 4: return attempt(CreateWallet, true);
        case 3: case 5: throw JSONRPCError(RPC_WALLET_ERROR, error.original);
        default: throw std::logic_error("invalid default wallet action");
        }
    });
    return wallet;
}

std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    CHECK_NONFATAL(request.mode == JSONRPCRequest::EXECUTE);
    WalletContext& context = EnsureWalletContext(request.context);

    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        std::shared_ptr<CWallet> pwallet = GetWallet(context, wallet_name);
        if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
        return pwallet;
    }

    size_t count{0};
    auto wallet = GetDefaultWallet(context, count);
    if (wallet) return wallet;

    if (count == 0) {
        return LoadOrCreateDefaultWallet(context);
    }
    throw JSONRPCError(RPC_WALLET_NOT_SPECIFIED,
        "Multiple wallets are loaded. Please select which wallet to use by requesting the RPC through the /wallet/<walletname> URI path.");
}

void EnsureWalletIsUnlocked(const CWallet& wallet)
{
    if (wallet.IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

WalletContext& EnsureWalletContext(const std::any& context)
{
    auto wallet_context = util::AnyPtr<WalletContext>(context);
    if (!wallet_context) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet context not found");
    }
    return *wallet_context;
}

// also_create should only be set to true only when the RPC is expected to add things to a blank wallet and make it no longer blank
LegacyScriptPubKeyMan& EnsureLegacyScriptPubKeyMan(CWallet& wallet, bool also_create)
{
    LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
    if (!spk_man && also_create) {
        spk_man = wallet.GetOrCreateLegacyScriptPubKeyMan();
    }
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Only legacy wallets are supported by this command");
    }
    return *spk_man;
}

const LegacyScriptPubKeyMan& EnsureConstLegacyScriptPubKeyMan(const CWallet& wallet)
{
    const LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Only legacy wallets are supported by this command");
    }
    return *spk_man;
}

std::string LabelFromValue(const UniValue& value)
{
    static const std::string empty_string;
    if (value.isNull()) return empty_string;

    const std::string& label{value.get_str()};
    if (label == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, "Invalid label name");
    return label;
}

void PushParentDescriptors(const CWallet& wallet, const CScript& script_pubkey, UniValue& entry)
{
    UniValue parent_descs(UniValue::VARR);
    for (const auto& desc: wallet.GetWalletDescriptors(script_pubkey)) {
        parent_descs.push_back(desc.descriptor->ToString());
    }
    entry.pushKV("parent_descs", std::move(parent_descs));
}

void HandleWalletError(const std::shared_ptr<CWallet> wallet, DatabaseStatus& status, bilingual_str& error)
{
    if (!wallet) {
        // Map bad format to not found, since bad format is returned when the
        // wallet directory exists, but doesn't contain a data file.
        RPCErrorCode code = RPC_WALLET_ERROR;
        switch (status) {
            case DatabaseStatus::FAILED_NOT_FOUND:
            case DatabaseStatus::FAILED_BAD_FORMAT:
                code = RPC_WALLET_NOT_FOUND;
                break;
            case DatabaseStatus::FAILED_ALREADY_LOADED:
                code = RPC_WALLET_ALREADY_LOADED;
                break;
            case DatabaseStatus::FAILED_ALREADY_EXISTS:
                code = RPC_WALLET_ALREADY_EXISTS;
                break;
            case DatabaseStatus::FAILED_INVALID_BACKUP_FILE:
                code = RPC_INVALID_PARAMETER;
                break;
            default: // RPC_WALLET_ERROR is returned for all other cases.
                break;
        }
        throw JSONRPCError(code, error.original);
    }
}

void AppendLastProcessedBlock(UniValue& entry, const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    UniValue lastprocessedblock{UniValue::VOBJ};
    lastprocessedblock.pushKV("hash", wallet.GetLastBlockHash().GetHex());
    lastprocessedblock.pushKV("height", wallet.GetLastBlockHeight());
    entry.pushKV("lastprocessedblock", std::move(lastprocessedblock));
}

} // namespace wallet
