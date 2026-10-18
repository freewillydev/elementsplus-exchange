// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_withdrawal.h>
#include <crypto/common.h>
#include <haskell/bridge.h>
#include <hash.h>
#include <primitives/txwitness.h>
#include <span.h>
#include <streams.h>

#include <algorithm>
#include <exception>
#include <limits>
#include <utility>

namespace drivechain {
namespace {

using Bytes = std::vector<unsigned char>;
using haskell::WithdrawalBytes;
using haskell::WithdrawalOp;

static_assert(NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE == 128);
static_assert(NATIVE_WITHDRAWAL_M6_REFERENCE_SIZE == 74);
static_assert(NATIVE_WITHDRAWAL_MAX_M6_LEGACY_SIZE == 251);
static_assert(Sidechain::Bitcoin::CTransaction::CURRENT_VERSION == 2);

Bytes Context(const uint256& genesis, uint8_t slot, const uint256& txid, uint32_t vout)
{
    Bytes input(69);
    std::copy(genesis.begin(), genesis.end(), input.begin());
    input[32] = slot;
    std::copy(txid.begin(), txid.end(), input.begin() + 33);
    WriteBE32(input.data() + 65, vout);
    return input;
}

void AppendAmount(Bytes& input, CAmount value)
{
    const auto offset = input.size();
    input.resize(offset + 8);
    WriteLE64(input.data() + offset, static_cast<uint64_t>(value));
}

void FillM6(NativeWithdrawalM6& m6, const Sidechain::Bitcoin::CMutableTransaction& tx,
            const NativeWithdrawalCommitment& reference, CAmount fee, CAmount burn, Bytes legacy)
{
    m6.blinded_transaction = tx;
    m6.burn_commitment = reference;
    m6.parent_fee = fee;
    m6.payout_amount = tx.vout[2].nValue;
    m6.burn_amount = burn;
    m6.destination = tx.vout[2].scriptPubKey;
    m6.legacy_serialization = std::move(legacy);
    m6.m6id = Hash(m6.legacy_serialization);
}

} // namespace

bool BuildNativeWithdrawalScript(const uint256& parent_genesis,
                                 const CScript& destination, CAmount parent_fee,
                                 CScript& script, std::string* error)
{
    script.clear();
    Bytes input(parent_genesis.begin(), parent_genesis.end()), result;
    AppendAmount(input, parent_fee);
    input.insert(input.end(), destination.begin(), destination.end());
    if (!WithdrawalBytes(WithdrawalOp::BUILD_SCRIPT, input, result, error)) return false;
    script.assign(result.begin(), result.end());
    return true;
}

bool ParseNativeWithdrawalScript(const CScript& script, const uint256& parent_genesis,
                                 CScript& destination, CAmount& parent_fee, std::string* error)
{
    destination.clear();
    parent_fee = 0;
    Bytes input(parent_genesis.begin(), parent_genesis.end()), result;
    input.insert(input.end(), script.begin(), script.end());
    if (!WithdrawalBytes(WithdrawalOp::PARSE_SCRIPT, input, result, error)) return false;
    parent_fee = static_cast<CAmount>(ReadLE64(result.data()));
    destination.assign(result.begin() + 8, result.end());
    return true;
}

bool BuildNativeWithdrawalOutput(const CAsset& pegged_asset, const uint256& parent_genesis,
                                 const CScript& destination, CAmount burn_amount,
                                 CAmount parent_fee, CTxOut& output, std::string* error)
{
    output.SetNull();
    Bytes input(pegged_asset.begin(), pegged_asset.end()), result;
    input.insert(input.end(), parent_genesis.begin(), parent_genesis.end());
    AppendAmount(input, burn_amount);
    AppendAmount(input, parent_fee);
    input.insert(input.end(), destination.begin(), destination.end());
    if (!WithdrawalBytes(WithdrawalOp::BUILD_OUTPUT, input, result, error)) return false;
    output = CTxOut(pegged_asset, burn_amount, CScript(result.begin(), result.end()));
    return true;
}

bool ParseNativeWithdrawalOutput(const CTxOut& output, const CTxOutWitness* witness,
                                 const CAsset& pegged_asset, const uint256& parent_genesis,
                                 NativeWithdrawal& withdrawal, std::string* error)
{
    withdrawal = {};
    const CAsset asset = output.nAsset.IsExplicit() ? output.nAsset.GetAsset() : CAsset{};
    const CAmount amount = output.nValue.IsExplicit() ? output.nValue.GetAmount() : 0;
    Bytes input(pegged_asset.begin(), pegged_asset.end()), result;
    input.insert(input.end(), asset.begin(), asset.end());
    for (bool flag : {output.nAsset.IsExplicit(), output.nValue.IsExplicit(),
                      output.nNonce.IsNull(), !witness || witness->IsNull()}) input.push_back(flag);
    AppendAmount(input, amount);
    input.insert(input.end(), parent_genesis.begin(), parent_genesis.end());
    input.insert(input.end(), output.scriptPubKey.begin(), output.scriptPubKey.end());
    if (!WithdrawalBytes(WithdrawalOp::PARSE_OUTPUT, input, result, error)) return false;
    withdrawal.parent_genesis = parent_genesis;
    withdrawal.burn_amount = amount;
    withdrawal.parent_fee = static_cast<CAmount>(ReadLE64(result.data()));
    withdrawal.payout_amount = static_cast<CAmount>(ReadLE64(result.data() + 8));
    withdrawal.destination.assign(result.begin() + 16, result.end());
    return true;
}

NativeWithdrawalCommitment ComputeNativeWithdrawalM6Commitment(
    const uint256& genesis, uint8_t slot, const uint256& txid, uint32_t vout)
{
    Bytes result;
    WithdrawalBytes(WithdrawalOp::BUILD_REFERENCE, Context(genesis, slot, txid, vout), result, nullptr);
    NativeWithdrawalCommitment commitment;
    std::copy(result.begin(), result.end(), commitment.begin());
    return commitment;
}

bool ParseNativeWithdrawalM6Commitment(const CScript& script, uint256& genesis,
                                      uint8_t& slot, uint256& txid, uint32_t& vout,
                                      std::string* error)
{
    genesis.SetNull();
    slot = 0;
    txid.SetNull();
    vout = std::numeric_limits<uint32_t>::max();
    Bytes result;
    if (!WithdrawalBytes(WithdrawalOp::PARSE_REFERENCE, script, result, error)) return false;
    std::copy_n(result.begin(), 32, genesis.begin());
    slot = result[32];
    std::copy_n(result.begin() + 33, 32, txid.begin());
    vout = ReadBE32(result.data() + 65);
    return true;
}

Bytes SerializeNativeWithdrawalM6Legacy(const Sidechain::Bitcoin::CMutableTransaction& tx)
{
    DataStream stream;
    stream << TX_NO_WITNESS(tx);
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

bool DeserializeNativeWithdrawalM6Legacy(const Bytes& bytes,
                                         Sidechain::Bitcoin::CMutableTransaction& tx,
                                         std::string* error)
{
    tx = {};
    Bytes result;
    // Reject unbounded counts and lengths before upstream allocation.
    if (!WithdrawalBytes(WithdrawalOp::LEGACY_FRAME, bytes, result, error)) return false;
    try {
        DataStream stream{bytes};
        stream >> TX_NO_WITNESS(tx);
        if (stream.empty()) return true;
        if (error) *error = "blinded M6 legacy serialization has trailing bytes";
    } catch (const std::exception& exception) {
        if (error) *error = std::string{"invalid blinded M6 legacy serialization: "} + exception.what();
    }
    tx = {};
    return false;
}

uint256 ComputeNativeWithdrawalM6Id(const Sidechain::Bitcoin::CMutableTransaction& tx)
{
    return Hash(SerializeNativeWithdrawalM6Legacy(tx));
}

bool BuildNativeWithdrawalM6(const uint256& genesis, uint8_t slot, const uint256& txid,
                             uint32_t vout, const NativeWithdrawal& withdrawal,
                             NativeWithdrawalM6& m6, std::string* error)
{
    m6 = {};
    Bytes input = Context(genesis, slot, txid, vout), result;
    AppendAmount(input, withdrawal.burn_amount);
    AppendAmount(input, withdrawal.parent_fee);
    AppendAmount(input, withdrawal.payout_amount);
    input.insert(input.end(), withdrawal.destination.begin(), withdrawal.destination.end());
    if (!WithdrawalBytes(WithdrawalOp::BUILD_M6, input, result, error)) return false;
    Sidechain::Bitcoin::CMutableTransaction tx;
    if (!DeserializeNativeWithdrawalM6Legacy(result, tx, error)) return false;
    FillM6(m6, tx, ComputeNativeWithdrawalM6Commitment(genesis, slot, txid, vout),
        withdrawal.parent_fee, withdrawal.burn_amount, std::move(result));
    return true;
}

bool ParseNativeWithdrawalM6(const Sidechain::Bitcoin::CMutableTransaction& tx,
                             const uint256& genesis, uint8_t slot, const uint256& txid,
                             uint32_t vout, NativeWithdrawalM6& m6, std::string* error)
{
    m6 = {};
    Bytes input = Context(genesis, slot, txid, vout), result;
    Bytes legacy = SerializeNativeWithdrawalM6Legacy(tx);
    input.insert(input.end(), legacy.begin(), legacy.end());
    if (!WithdrawalBytes(WithdrawalOp::PARSE_M6, input, result, error)) return false;
    FillM6(m6, tx, ComputeNativeWithdrawalM6Commitment(genesis, slot, txid, vout),
           static_cast<CAmount>(ReadLE64(result.data())), static_cast<CAmount>(ReadLE64(result.data()+8)), std::move(legacy));
    return true;
}

} // namespace drivechain
