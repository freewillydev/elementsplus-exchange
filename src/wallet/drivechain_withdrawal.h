// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_DRIVECHAIN_WITHDRAWAL_H
#define BITCOIN_WALLET_DRIVECHAIN_WITHDRAWAL_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class UniValue;

namespace wallet {

CAmount LegacyWithdrawalAmount(CAmount payout);
CAmount ValidateNativePayout(const CScript& destination, CAmount payout);
/** Payout must already be admitted. Validate fee/total before constructing the burn. */
CAmount PrepareNativeBurn(const uint256& parent, const CScript& destination,
    CAmount payout, CAmount fee, CScript& burn);
enum class WithdrawalCheck : unsigned char { NETWORK, ACTIVATION, SUBTRACT_FEE, RELAY, LEGACY_NETWORK };
void CheckWithdrawal(WithdrawalCheck check, bool value);

struct DrivechainWithdrawalBundle {
    std::vector<unsigned char> bytes;
    std::vector<unsigned char> no_witness_bytes;
    uint256 m6id;
};

/** Decode a parent-network address or exact hex script and reject unspendable payouts. */
CScript DecodeDrivechainWithdrawalDestination(const std::string& destination);

/** Require exactly one parsed native burn matching all requested amounts. */
uint32_t FindNativeWithdrawalOutput(const CTransaction& tx, const CScript& burn_script,
    const CAsset& asset, const uint256& parent_genesis, CAmount burn, CAmount payout, CAmount fee);

/** Read the first matching legacy enforcer event; this does not authenticate it. */
std::string FindWithdrawalBundleEventStatus(const UniValue& peg_data, const std::string& m6id_hex);

/** Legacy inputless M6 codec; does not authorize a burn or broadcast.
 * Native Betanet withdrawals use drivechain::BuildNativeWithdrawalM6 instead.
 */
DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height);

/** Build the historical slot-24 ECX-bound BIP300 M6 bytes. */
DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount,
    CAmount mainchain_fee,
    const CScript& payout_script,
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height,
    const uint256& child_genesis,
    const uint256& previous_child_hash,
    const uint256& exchange_state_root);

} // namespace wallet

#endif // BITCOIN_WALLET_DRIVECHAIN_WITHDRAWAL_H
