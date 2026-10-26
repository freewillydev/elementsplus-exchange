// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <haskell/bridge.h>
#include <map>

static bool CheckTransactionImpl(const CTransaction&, TxValidationState&, bool, bool);

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    return CheckTransaction(tx, state, false);
}

bool CheckTransaction(const CTransaction& tx, TxValidationState& state, bool explicit_asset_totals)
{
    return CheckTransactionImpl(tx, state, explicit_asset_totals, false);
}

bool CheckTransactionWithoutAggregateTotals(const CTransaction& tx, TxValidationState& state)
{
    return CheckTransactionImpl(tx, state, false, true);
}

static bool CheckTransactionImpl(const CTransaction& tx, TxValidationState& state, bool explicit_asset_totals, bool defer_totals)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOutExplicit = 0;
    std::map<CAsset, CAmount> asset_totals;
    for (const auto& txout : tx.vout)
    {
        if (!txout.nValue.IsValid())
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-amount-invalid");
        if (!txout.nValue.IsExplicit())
            continue;
        if (txout.nValue.GetAmount() < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue.GetAmount() > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        using TotalMode = drivechain::haskell::OutputTotalMode;
        const auto mode = drivechain::haskell::SelectOutputTotalMode(
            defer_totals, explicit_asset_totals, txout.nAsset.IsExplicit());
        if (mode == TotalMode::DEFERRED) continue;
        // The activated explicit-only rule supplies public asset identities.
        // Never treat an unknown/confidential asset as a distinct public asset.
        if (mode == TotalMode::REJECT)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-asset-not-explicit");
        CAmount& total = mode == TotalMode::PER_ASSET ? asset_totals[txout.nAsset.GetAsset()] : nValueOutExplicit;
        if (!drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::AMOUNT_SUM,
                0, txout.nValue.GetAmount(), total, MAX_MONEY))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
        total += txout.nValue.GetAmount();
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");

        for (unsigned int i = 0; i < tx.vout.size(); i++) {
            if (tx.vout[i].IsFee()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-fee");
            }
        }
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}

// Fork-specific drivechain_withdrawal adapters.
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

// Fork-specific haskell/bridge adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/bridge.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/consensus.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <util/moneystr.h>

#include <haskell/domain_abi.h>

#include <array>
#include <algorithm>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>
#include <exception>

extern "C" void elements_hs_runtime_init(void);

namespace {
bool ParameterGate(uint32_t mode, int64_t first, int64_t second)
{
    elements_hs_runtime_init();
    const int result = elements_hs_parameter_gate_v1(mode, first, second);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell parameter gate failed");
    return result == 1;
}
}

bool Consensus::Params::ExplicitOnlyActive(int height) const
{
    return ParameterGate(0, explicit_only_height, height);
}

bool Consensus::Params::ExplicitOnlyConfigured() const
{
    return ParameterGate(2, explicit_only_height, 0);
}

bool Consensus::Params::DrivechainWithdrawalValidationEnabled() const
{
    return ParameterGate(1, drivechain_slot.has_value(), drivechain_m6_withdrawal_validation);
}

namespace drivechain::haskell {
void ScriptCacheEncode(bool endpoint_only, std::span<const std::byte> input, std::span<unsigned char> output)
{
    elements_hs_runtime_init();
    if (elements_hs_script_cache_encode_v1(endpoint_only,input.size(),
        reinterpret_cast<unsigned char*>(const_cast<std::byte*>(input.data())),output.size(),output.data()) != 0)
        throw std::runtime_error("Haskell script cache encoding failed");
}

namespace {
int CheckedStatus(int code, int maximum, const char* failure)
{
    if (code < 0 || code > maximum) throw std::runtime_error(failure);
    return code;
}
}

bool AdmitStandardness(StandardnessGate kind, uint32_t facts, uint64_t count, uint64_t limit)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_standardness_gate_v1(static_cast<uint32_t>(kind), facts, count, limit);
    return CheckedStatus(result,1,"Haskell standardness gate failed") == 1;
}

int VerifyJournal(RustVerifierVersion version, RustVerifyAnnex verify, std::span<const unsigned char> annex,
    std::span<const unsigned char> program, std::span<const unsigned char> digest)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_verify_journal_v1(reinterpret_cast<HsFunPtr>(version),
        reinterpret_cast<HsFunPtr>(verify), const_cast<unsigned char*>(annex.data()), annex.size(),
        const_cast<unsigned char*>(program.data()), program.size(), const_cast<unsigned char*>(digest.data()),
        digest.size()),2,"Haskell journal verification failed");
}

bool VerifyGroth16(RustGroth16 verify, void* context, const unsigned char* proof, size_t size,
    const uint32_t* program, const unsigned char* digest)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_verify_groth16_v1(reinterpret_cast<HsFunPtr>(verify),
        context, const_cast<unsigned char*>(proof), size, const_cast<uint32_t*>(program),
        const_cast<unsigned char*>(digest)),1,"Haskell Groth16 verification failed") == 1;
}

bool VerifyCustody(RustCustody verify, std::span<const unsigned char> bundle,
    std::span<const unsigned char> registry, std::span<const unsigned char> receipts, size_t count)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_verify_custody_v1(reinterpret_cast<HsFunPtr>(verify),
        const_cast<unsigned char*>(bundle.data()), bundle.size(), const_cast<unsigned char*>(registry.data()),
        registry.size(), const_cast<unsigned char*>(receipts.data()), receipts.size(), count),
        1,"Haskell custody verification failed") == 1;
}

static int ReadExportRange(uint32_t mode, int32_t start, int32_t count, int32_t activation,
    int32_t tip, int32_t& end)
{
    elements_hs_runtime_init();
    return elements_hs_export_range_v1(mode,start,count,activation,tip,&end);
}

uint32_t PegEventRange(int32_t start, int32_t count, int32_t tip, int32_t& end)
{
    return CheckedStatus(ReadExportRange(2,start,count,0,tip,end),2,"Haskell peg-event range validation failed");
}

int32_t PegEventStart(int32_t tip)
{
    int32_t start{};
    CheckedStatus(ReadExportRange(3,0,0,0,tip,start),0,"Haskell peg-event start selection failed");
    return start;
}

std::pair<bool, int32_t> ExchangeRuntimeActivation(int32_t activation, std::optional<int32_t> private_height)
{
    elements_hs_runtime_init();
    int32_t first{};
    const int code = elements_hs_runtime_activation_v1(private_height.has_value(), activation,
        private_height.value_or(0), &first);
    return {CheckedStatus(code, 1, "Haskell runtime activation selection failed") != 0, first};
}

uint32_t ExchangeExportRange(int32_t start, int32_t count, int32_t activation,
    std::optional<int32_t> tip, int32_t& end)
{
    return CheckedStatus(ReadExportRange(tip.has_value(),start,count,activation,tip.value_or(0),end),
        2,"Haskell export range validation failed");
}

bool ApprovingParentHeight(int64_t parent, uint64_t& successor)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_approving_parent_height_v1(parent);
    if (result == -1) return false;
    if (result < 1 || result > UINT32_MAX) throw std::runtime_error("Haskell approving parent height failed");
    successor = result;
    return true;
}

int64_t BoundedWait(int64_t value, int64_t maximum)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bounded_wait_v1(value, maximum);
    if (result < 1 || result > maximum) throw std::runtime_error("Haskell wait interval bounds failed");
    return result;
}

uint64_t BoundedAppend(uint64_t limit, uint64_t used, int64_t count)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bounded_append_v1(limit, used, count);
    if (result < 0 || result > count) throw std::runtime_error("Haskell output append bounds failed");
    return result;
}

bool FitsU32(std::span<const uint64_t> fields)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_unsigned32_fields_v1(fields.size(), const_cast<uint64_t*>(fields.data())),
        1, "Haskell unsigned field bounds failed") != 0;
}

std::string WideDecimal(std::span<const unsigned char,16> bytes, bool signed_value)
{
    elements_hs_runtime_init();
    std::array<unsigned char,40> text{};
    const auto size = elements_hs_wide_decimal_v1(signed_value, const_cast<unsigned char*>(bytes.data()),
        bytes.size(), text.data(), text.size());
    if (size < 1 || size > static_cast<int32_t>(text.size())) throw std::runtime_error("Haskell wide integer formatting failed");
    return std::string(text.begin(), text.begin()+size);
}

bool AnchorRule(std::span<const std::byte> encoded)
{
    elements_hs_runtime_init();
    if (encoded.size()!=145 && encoded.size()!=290 && encoded.size()!=294 && encoded.size()!=439)
        throw std::invalid_argument("Invalid anchor framing");
    const auto result = elements_hs_anchor_rule_v1(encoded.size(),
        reinterpret_cast<unsigned char*>(const_cast<std::byte*>(encoded.data())));
    return CheckedStatus(result,1,"Haskell anchor evaluation failed") == 1;
}

uint32_t PeerRejectionStrikes(bool complete, bool same_edge, uint32_t count)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_peer_strikes_v1(complete | (same_edge << 1), count);
    if (result < 0 || result > UINT32_MAX) throw std::runtime_error("Haskell peer strike evaluation failed");
    return result;
}

uint32_t NextExtraNonce(bool same_parent, uint32_t current)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_extra_nonce_v1(same_parent, current);
    if (result < 0 || result > UINT32_MAX) throw std::runtime_error("Haskell extra nonce evaluation failed");
    return result;
}

int32_t NextBlockHeight(bool present, int32_t height)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_next_block_height_v1(present, height);
    if (result < INT32_MIN || result > INT32_MAX) throw std::runtime_error("Haskell next block height evaluation failed");
    return result;
}

uint64_t NextBondContextHeight(int32_t height)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_next_block_height_v1(2, height);
    if (result < int64_t{INT32_MIN} + 1 || result > int64_t{INT32_MAX} + 1)
        throw std::runtime_error("Haskell bond context height evaluation failed");
    return static_cast<uint64_t>(result);
}

int32_t ExchangeTrackerHeight(bool previous, int32_t height)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_tracker_height_v1(previous, height);
    if (result < INT32_MIN || result > INT32_MAX) throw std::runtime_error("Haskell tracker height evaluation failed");
    return result;
}

int64_t BmmSelectedBid(int64_t configured, int64_t fees)
{
    elements_hs_runtime_init();
    return elements_hs_bmm_selected_bid_v1(configured,fees,MAX_MONEY);
}

bool BmmWorkQuote(int64_t fees, uint64_t work, int64_t rate, int64_t reserve, std::array<int64_t,3>& fields)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_work_quote_v1(fees,work,rate,reserve,MAX_MONEY,fields.data());
    return CheckedStatus(result,1,"Haskell BMM work quote evaluation failed") == 1;
}

bool BmmWorkQuoteDisplay(int64_t fees, uint64_t work, int64_t rate, int64_t reserve, std::array<int64_t,3>& fields)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_bmm_work_quote_display_v1(fees,work,rate,reserve,MAX_MONEY,fields.data()),
        1,"Haskell work quote display failed") == 1;
}

bool BmmMessageMatches(BmmMessageKind kind, const std::string& message)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_message_v1(static_cast<uint32_t>(kind), message.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(message.data())));
    return CheckedStatus(result,1,kind == BmmMessageKind::DEFINITIVE_WAIT ?
        "Haskell BMM wait error classification failed" : "Haskell BMM duplicate request classification failed") == 1;
}


bool FeeAsset(const std::optional<std::string>& configured, bool canonical,
    std::span<const unsigned char,32> pegged, std::span<unsigned char,32> output, std::string* error)
{
    elements_hs_runtime_init();
    if (error) error->clear();
    const int code = elements_hs_fee_asset_v1(bool(configured) | (canonical << 1),configured ? configured->size() : 0,
        configured ? reinterpret_cast<unsigned char*>(const_cast<char*>(configured->data())) : nullptr,
        const_cast<unsigned char*>(pegged.data()),output.data());
    CheckedStatus(code,2,"Haskell fee asset resolution failed");
    if (code && error) *error = code == 1 ? "-feeasset must be exactly 64 hexadecimal characters" :
        "-feeasset must equal the immutable Elements pegged asset";
    return code == 0;
}

bool BmmReplacementBid(const std::string& message, int64_t current, int64_t maximum, int64_t& replacement)
{
    elements_hs_runtime_init();
    if (message.size() > UINT32_MAX) return false;
    const auto parser = +[](unsigned char* input, uint32_t size) -> int64_t {
        try { return ParseMoney(std::string(reinterpret_cast<const char*>(input),size)).value_or(-1); }
        catch (...) { return -1; }
    };
    const auto result = elements_hs_bmm_replacement_v1(current,maximum,MAX_MONEY,
        reinterpret_cast<unsigned char*>(const_cast<char*>(message.data())),message.size(),reinterpret_cast<HsFunPtr>(parser));
    if (result == -2) throw std::runtime_error("Haskell BMM replacement evaluation failed");
    if (result < 0) return false;
    replacement = result;
    return true;
}

namespace {
constexpr std::array<std::string_view,4> PAYMENT_URI_SCHEMES{"bitcoin","elements","liquidnetwork","liquidtestnet"};
int32_t PaymentUriPolicy(uint32_t flags, uint32_t scheme)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_payment_uri_v1(flags,scheme);
    return CheckedStatus(result,scheme == 4 ? 3 : 1,"Haskell payment URI policy failed");
}
}

bool AcceptPaymentUri(bool elements_mode, bool canonical, std::string_view scheme)
{
    const auto found = std::find(PAYMENT_URI_SCHEMES.begin(),PAYMENT_URI_SCHEMES.end(),scheme);
    const uint32_t code = found == PAYMENT_URI_SCHEMES.end() ? 5 : found - PAYMENT_URI_SCHEMES.begin();
    return PaymentUriPolicy(uint32_t(elements_mode) | (uint32_t(canonical) << 1),code) == 1;
}

std::string_view PaymentUriScheme(bool elements_mode, bool canonical, bool liquid_testnet)
{
    return PAYMENT_URI_SCHEMES.at(PaymentUriPolicy(uint32_t(elements_mode) |
        (uint32_t(canonical) << 1) | (uint32_t(liquid_testnet) << 2),4));
}

bool AcceptAddressAlias(bool parent, bool confidential, const std::string& network, const std::string& prefix)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_address_alias_v1(uint32_t(parent) | (uint32_t(confidential) << 1),
        network.size(), reinterpret_cast<unsigned char*>(const_cast<char*>(network.data())),
        prefix.size(), reinterpret_cast<unsigned char*>(const_cast<char*>(prefix.data())));
    return CheckedStatus(result,1,"Haskell address alias validation failed") == 1;
}

bool RejectWalletIssueAmount(double amount)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_wallet_issue_amount_v1(&amount),1,"Haskell issuance amount evaluation failed") == 1;
}

uint32_t NetworkSelectionStatus(NetworkSelection kind, const std::string& text, bool elements_mode)
{
    if (static_cast<uint32_t>(kind) > 2) throw std::runtime_error("Haskell network selection evaluation failed");
    elements_hs_runtime_init();
    const auto code = elements_hs_network_selection_v1(static_cast<uint32_t>(kind), elements_mode, text.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(text.data())));
    return CheckedStatus(code,5,"Haskell network selection evaluation failed");
}

void ValidateNetworkSelection(NetworkSelection kind, const std::string& text, bool elements_mode)
{
    const auto code = NetworkSelectionStatus(kind, text, elements_mode);
    static constexpr const char* errors[]{
        "This program only supports the canonical -chain=elements production network",
        "The pre-launch 'usdd' chain identity is unsupported; use -chain=elements",
        "-con_elementsmode is not supported with -chain=regtest; use -chain=elementsregtest for Elements/ECX testing",
        "the Simplicity deployment is not supported with -chain=regtest; use an Elements-mode chain",
        "the dynafed deployment is not supported with -chain=regtest; use an Elements-mode chain"};
    if (code) throw std::runtime_error(errors[code - 1]);
}

bool MainchainCookieAtRoot(const std::string& chain)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_network_selection_v1(3,0,chain.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(chain.data())));
    return CheckedStatus(result,1,"Haskell mainchain cookie selection failed") == 1;
}

uint8_t ContextPresence(uint32_t count, uint32_t required)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_context_presence_v1(count, required);
    return static_cast<uint8_t>(CheckedStatus(result,2,"Haskell context presence evaluation failed"));
}

bool TransactionWeight(bool bond, uint64_t total, uint64_t annex, uint64_t ordinary, uint64_t proof)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_transaction_weight_v1(bond, total, annex, ordinary, proof);
    return CheckedStatus(result,1,"Haskell transaction weight policy failed") == 1;
}

bool ReturnMarker(std::span<const unsigned char,4> magic, std::span<const unsigned char> script)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_return_marker_v1(script.size(),
        const_cast<unsigned char*>(script.data()), const_cast<unsigned char*>(magic.data())),
        1, "Haskell return marker policy failed") == 1;
}

bool BondMarkerPolicy(bool exact, std::span<const unsigned char> script)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bond_marker_policy_v1(exact, script.size(),
        const_cast<unsigned char*>(script.data()));
    return CheckedStatus(result,1,"Haskell bond marker policy failed") == 1;
}

uint32_t TaprootWitnessPolicy(bool annex, bool bond, uint64_t count, uint32_t leaf, uint64_t script_size, uint64_t input)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_taproot_witness_policy_v1(annex | (bond << 1), count, leaf, script_size, input);
    return CheckedStatus(result,1,"Haskell Taproot witness policy failed");
}

CtvAction CtvAdmission(uint32_t flags, uint64_t size)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_ctv_admission_v1(flags, size);
    return static_cast<CtvAction>(CheckedStatus(result,3,"Haskell CTV admission failed"));
}

std::vector<unsigned char> ParseConfigurationField(ConfigurationField kind, const std::string& text,
    const std::string& syntax_error, const std::string& value_error)
{
    elements_hs_runtime_init();
    const bool variable = kind==ConfigurationField::SPENDABLE_SCRIPT || kind==ConfigurationField::CONFIGURATION_HEX;
    const bool proposal = kind==ConfigurationField::PROPOSAL_DESCRIPTION;
    const size_t capacity = proposal ? std::min<size_t>(text.size(),65526)+10 : variable
        ? std::max<size_t>(1,std::min<size_t>(kind==ConfigurationField::SPENDABLE_SCRIPT ? 10000 : 65536,text.size()/2))
        : kind==ConfigurationField::CUSTODIAN_REGISTRY ? 325 : kind==ConfigurationField::OUTPOINT ? 36 : 32;
    std::vector<unsigned char> output(capacity);
    const auto result=elements_hs_configuration_field_v1(static_cast<uint32_t>(kind),text.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(text.data())),output.size(),output.data());
    if (result==-2) throw std::runtime_error(syntax_error);
    if (result==-3) throw std::runtime_error(value_error);
    if (result<=0 || static_cast<size_t>(result)>output.size() ||
        (!variable && static_cast<size_t>(result)!=capacity))
        throw std::runtime_error("Haskell configuration parser failed");
    output.resize(result);
    return output;
}

int EvaluatorIdentity(bool frozen, bool private_catalogue, const std::string& catalogue, const std::string& program)
{
    elements_hs_runtime_init();
    const auto code=elements_hs_evaluator_identity_v1(uint32_t(frozen) | (uint32_t(private_catalogue)<<1),
        catalogue.size(),reinterpret_cast<unsigned char*>(const_cast<char*>(catalogue.data())),
        program.size(),reinterpret_cast<unsigned char*>(const_cast<char*>(program.data())));
    if (code!=0 && code!=1 && code!=3) throw std::runtime_error("Haskell evaluator identity validation failed");
    return code;
}

GrpcTextAdmission AdmitGrpcText(const std::string& address, const std::string& authority)
{
    elements_hs_runtime_init();
    const auto mask=elements_hs_grpc_text_v1(address.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(address.data())),authority.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(authority.data())));
    CheckedStatus(mask,7,"invalid Haskell gRPC text admission");
    return {bool(mask&1),bool(mask&2),bool(mask&4)};
}

std::vector<std::string> GrpcPlan(std::span<const std::string> fields)
{
    if (fields.size()!=1 && fields.size()!=2) throw std::invalid_argument("invalid gRPC planner field count");
    std::array<unsigned char*,8> pointers{};
    std::array<uint32_t,8> lengths{};
    uint64_t capacity{256};
    for (size_t i=0; i<fields.size(); ++i) {
        if (capacity>INT32_MAX-4 || fields[i].size()>INT32_MAX-capacity-4) throw std::length_error("gRPC planner input too large");
        capacity+=fields[i].size()+4;
        pointers[i]=reinterpret_cast<unsigned char*>(const_cast<char*>(fields[i].data()));
        lengths[i]=fields[i].size();
    }
    std::vector<unsigned char> reply(capacity);
    elements_hs_runtime_init();
    const auto size=elements_hs_grpc_plan_v1(fields.size(),pointers.data(),lengths.data(),reply.data(),reply.size());
    if (size<1 || size>static_cast<int64_t>(reply.size()) || reply[0]>1)
        throw std::runtime_error("invalid gRPC planner reply");
    if (reply[0]) throw std::invalid_argument(std::string(reply.begin()+1,reply.begin()+size));
    std::vector<std::string> args;
    for (size_t offset=1; offset<static_cast<size_t>(size);) {
        if (size-offset<4) throw std::runtime_error("truncated gRPC planner length");
        const auto length=ReadLE32(reply.data()+offset);
        offset+=4;
        if (length>size-offset) throw std::runtime_error("truncated gRPC planner argument");
        args.emplace_back(reinterpret_cast<const char*>(reply.data()+offset),length);
        offset+=length;
    }
    if ((fields.size()<8 && !args.empty()) || (fields.size()==8 && args.size()!=(fields[6].empty() ? 11U : 13U)))
        throw std::runtime_error("invalid gRPC planner argument count");
    return args;
}

namespace {
int32_t HashUsddPayload(unsigned char* input, uint32_t size, unsigned char* output)
{
    CSHA256().Write(input, size).Finalize(output);
    return 1;
}
template <typename Result, Result fallback = 0, typename Plan, typename Value, typename... Args>
auto ReadAdmission(const Plan& plan, const std::function<Value(Args...)>& read)
{
    elements_hs_runtime_init();
    struct Context { const std::function<Value(Args...)>& read; std::exception_ptr failure; } context{read, {}};
    const auto callback = +[](void* opaque, Args... args) -> Result {
        auto& ctx = *static_cast<Context*>(opaque);
        if (ctx.failure) return fallback;
        try { return ctx.read(args...); }
        catch (...) { ctx.failure = std::current_exception(); return fallback; }
    };
    const auto result = plan(reinterpret_cast<HsFunPtr>(callback), &context);
    if (context.failure) std::rethrow_exception(context.failure);
    return result;
}
template <typename Result, Result fallback, typename Binding, typename Value, typename... Args, typename... Params>
auto ReadBoundAdmission(const Binding& binding, const std::function<Value(Args...)>& read, Params... params)
{
    return ReadAdmission<Result,fallback>([&](HsFunPtr callback, void* context) {
        return binding(params...,callback,context);
    },read);
}

template <typename Binding, typename... Args, typename... Params>
void RequireAdmission(const Binding& binding, const std::function<bool(Args...)>& action,
    const char* rejected, const char* failure, Params... params)
{
    const int code = ReadBoundAdmission<int32_t,-1>(binding,action,params...);
    if (code == 1) throw std::runtime_error(rejected);
    if (code != 0) throw std::runtime_error(failure);
}
using NativeDigestEffect = std::function<int32_t(uint32_t, uint64_t, unsigned char*, unsigned char*)>;


bool ExchangeResult(int code, std::span<const char* const> errors, std::string& error, const char* failure)
{
    if (code < 0 || static_cast<size_t>(code) > errors.size()) throw std::runtime_error(failure);
    if (code && errors[code-1]) error = errors[code-1];
    return code == 0;
}

template <typename Binding, typename... Params>
int ReadWorkflow(const Binding& binding, const NativeWorkflow& native, Params... params)
{
    elements_hs_runtime_init();
    struct Context {
        const NativeWorkflow& native;
        std::vector<unsigned char> reply;
        std::exception_ptr failure;
    } context{native, {}, {}};
    const auto callback = +[](void* opaque, uint32_t step, uint64_t index, uint64_t size,
        unsigned char* input, uint64_t* count, unsigned char** data) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        *count = 0;
        *data = nullptr;
        if (ctx.failure) return 0;
        try {
            if (size > SIZE_MAX || (size && !input)) throw std::logic_error("invalid native workflow request");
            ctx.reply = ctx.native(step, index, {input, static_cast<size_t>(size)});
            *count = ctx.reply.size();
            *data = ctx.reply.data();
            return 1;
        } catch (...) {
            ctx.failure = std::current_exception();
            return 0;
        }
    };
    const int result = binding(params..., reinterpret_cast<HsFunPtr>(callback), &context);
    if (context.failure) std::rethrow_exception(context.failure);
    return result;
}
}

bool ReadAuthFile(AuthFileMode mode, const NativeWorkflow& native)
{
    return CheckedStatus(ReadWorkflow(elements_hs_auth_file_v1,native,static_cast<uint32_t>(mode)),
        1,"Haskell credential file workflow failed")==1;
}

uint32_t RunReplayStore(ReplayStoreWorkflow mode, const NativeWorkflow& native)
{
    return CheckedStatus(ReadWorkflow(elements_hs_replay_store_v1,native,static_cast<uint32_t>(mode),uint64_t{MAX_MONEY}),
        mode == ReplayStoreWorkflow::LOAD || mode == ReplayStoreWorkflow::LOAD_SESSION ||
            mode == ReplayStoreWorkflow::BMM_CONTEXT ? 3 :
            (mode >= ReplayStoreWorkflow::DEPOSIT && mode <= ReplayStoreWorkflow::OCCURRENCE) ||
                (mode >= ReplayStoreWorkflow::DEPOSIT_ADMISSION && mode <= ReplayStoreWorkflow::DEPOSIT_SESSION) ? 2 : 1,
        "Haskell replay store workflow failed");
}

bool RunBitcoinSignature(BitcoinSignatureWorkflow kind, int32_t hash_type, bool witness,
    uint32_t index, uint64_t inputs, uint64_t outputs, std::span<const unsigned char> signature,
    const NativeWorkflow& native)
{
    const int result = ReadWorkflow(elements_hs_bmm_signature_workflow_v1,native,
        static_cast<uint32_t>(kind),hash_type,uint32_t(witness),index,inputs,outputs,
        uint64_t(signature.size()),const_cast<unsigned char*>(signature.data()));
    return CheckedStatus(result,1,"Haskell Bitcoin signature workflow failed") == 1;
}

bool RunParentHeader(ParentHeaderWorkflow kind, uint32_t height,
    const std::function<uint64_t(uint32_t, uint64_t)>& native)
{
    return RunParentHeader(kind, height,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
            if (!input.empty()) throw std::logic_error("invalid parent header workflow input");
            std::vector<unsigned char> bytes(8);
            WriteLE64(bytes.data(), native(step,index));
            return bytes;
        });
}

bool RunParentHeader(ParentHeaderWorkflow kind, uint32_t height, const NativeWorkflow& native)
{
    const auto result = ReadWorkflow(elements_hs_parent_header_v1, native, static_cast<uint32_t>(kind), height);
    return CheckedStatus(result,1,"Haskell parent header workflow failed") == 1;
}


bool MeasureWork(bool saturate, uint64_t count, const std::function<const CTransaction&(uint64_t)>& transaction,
    uint64_t& total, uint64_t* last)
{
    const NativeWorkflow native = [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
        std::vector<unsigned char> bytes;
        if (step == 0) {
            const auto& witnesses = transaction(index).witness.vtxinwit;
            for (const auto& witness : witnesses) {
                const auto& stack = witness.scriptWitness.stack;
                const auto tag = [&](size_t back) -> uint64_t {
                    return stack.size() < back || stack[stack.size()-back].empty() ? 256 : stack[stack.size()-back][0];
                };
                const std::array<uint64_t,5> fields{stack.size(), tag(1), tag(2),
                    stack.size() < 2 ? 0 : stack[stack.size()-2].size(),
                    stack.size() < 3 ? 0 : stack[stack.size()-3].size()};
                const auto offset = bytes.size();
                bytes.resize(offset+40);
                for (size_t i = 0; i < fields.size(); ++i) WriteLE64(bytes.data()+offset+8*i, fields[i]);
            }
        } else if (step == 1 && input.size() == 8) {
            const auto& stack = transaction(ReadLE64(input.data())).witness.vtxinwit.at(index).scriptWitness.stack;
            bytes.resize(8);
            WriteLE64(bytes.data(), ::GetSerializeSize(stack));
        } else throw std::logic_error("invalid work measurement action");
        return bytes;
    };
    std::array<uint64_t,2> fields{};
    const auto code = CheckedStatus(ReadWorkflow(elements_hs_bmm_work_measurement_v1, native,
        uint32_t(saturate), count, total, fields.data()), 1, "Haskell work measurement failed");
    total = fields[0];
    if (last) *last = fields[1];
    return code == 0;
}

bool ValidateWithdrawalEnvelope(bool inactive, const NativeWorkflow& native, std::string& error)
{
    static constexpr const char* errors[]{
        "ECX M6 envelope requires a coinbase transaction", "duplicate ECX M6 envelope",
        "malformed ECX M6 envelope", "invalid ECX M6 envelope length", "noncanonical ECX M6 envelope script",
        "ECX M6 envelope may appear only when hashWithdrawalBundle changes",
        "ECX M6 envelope exists while clearing the withdrawal bundle commitment",
        "withdrawal bundle commitment lacks its ECX M6 envelope",
        "ECX M6 envelope does not hash to hashWithdrawalBundle", "ECX M6 checkpoint is not a prior block",
        "ECX M6 checkpoint is not the committed active-chain state",
        "ECX M6 preimage has a noncanonical transaction prefix", "ECX M6 preimage has an invalid output",
        "ECX M6 commitment outputs must remain zero-valued", "ECX M6 preimage has trailing or noncanonical locktime bytes",
        "ECX M6 preimage lacks its canonical commitment or PXST output",
        "ECX M6 PXST does not bind the selected active-chain checkpoint"};
    return ExchangeResult(ReadWorkflow(elements_hs_exchange_envelope_workflow_v1, native, uint32_t(inactive)),
        errors, error, "Haskell M6 envelope workflow failed");
}

std::optional<std::array<unsigned char,80>> AnchorCheckpoint(std::span<const std::byte> encoded)
{
    if (encoded.size()!=145) throw std::invalid_argument("Invalid checkpoint anchor framing");
    elements_hs_runtime_init();
    std::array<unsigned char,80> output{};
    const auto code=elements_hs_anchor_checkpoint_v1(encoded.size(),
        reinterpret_cast<unsigned char*>(const_cast<std::byte*>(encoded.data())),output.data());
    return CheckedStatus(code,1,"Haskell anchor checkpoint failed")==0 ? std::make_optional(output) : std::nullopt;
}

int BmmRewardAddress(const std::function<bool(uint32_t)>& read)
{
    const int code = ReadAdmission<int32_t,-1>(elements_hs_bmm_reward_address_v1,read);
    return CheckedStatus(code,5,"Haskell BMM reward admission failed");
}

bool BmmWait(const std::function<int32_t(uint32_t)>& action)
{
    const int code = ReadAdmission<int32_t,-1>(elements_hs_bmm_wait_v1,action);
    return CheckedStatus(code,1,"Haskell BMM wait failed") == 1;
}


bool BmmProduction(bool ecx, const std::function<bool(uint32_t)>& action)
{
    const int code = ReadAdmission<int32_t,-1>([&](HsFunPtr callback,void* context) {
        return ecx ? elements_hs_bmm_ecx_production_v1(callback,context) : elements_hs_bmm_native_production_v1(callback,context);
    },action);
    return CheckedStatus(code,ecx ? 14 : 10,ecx ?
        "Haskell ECX BMM production failed" : "Haskell native BMM production failed") == 0;
}

bool BmmSyncTick(int64_t parent, int64_t child, const std::function<bool(uint32_t)>& action)
{
    const int code = ReadBoundAdmission<int32_t,-1>(elements_hs_bmm_sync_heights_v1,action,parent,child);
    return CheckedStatus(code,5,"Haskell BMM sync tick failed") == 0;
}

void BmmProofBuild(uint64_t previous, int64_t parent, const std::function<bool(uint32_t,uint64_t)>& action)
{
    RequireAdmission(elements_hs_bmm_proof_build_v1,action,
        "BMM successor is outside the bounded parent-header window","Haskell BMM proof build failed",previous,parent);
}

MatchResult FindUniqueMatch(uint64_t count, const std::function<bool(uint64_t)>& matches, uint64_t& index)
{
    uint64_t selected{0};
    const std::function<int32_t(uint32_t,uint64_t)> action = [&](uint32_t stage, uint64_t candidate) {
        if (stage == 1) return int32_t{matches(candidate)};
        if (stage == 2) selected = candidate;
        return int32_t{1};
    };
    const auto result = ReadBoundAdmission<int32_t,-1>(elements_hs_deposit_ctip_search_v1,action,count);
    CheckedStatus(result,2,"Haskell unique match scan failed");
    if (result == 0) index = selected;
    return static_cast<MatchResult>(result);
}

void ConstructDepositEvidence(int64_t sequence, int64_t height, uint32_t flags, int32_t slot, const NativeWorkflow& native)
{
    static constexpr const char* errors[]{
        "authenticated deposit cannot form a v2 CTIP transition",
        "L1 deposit transaction does not contain the authenticated outpoint",
        "deposit transaction's prior CTIP transaction is unavailable",
        "deposit transaction spends multiple slot CTIP outputs",
        "deposit confirmation is outside the bounded v2 L1 header window",
        "serialized L1 header contains trailing data"};
    const int code = CheckedStatus(ReadWorkflow(elements_hs_deposit_construction_v1,native,
        sequence,height,flags,slot),std::size(errors),"Haskell deposit reconstruction failed");
    if (code) throw std::runtime_error(errors[code-1]);
}

void DepositVerify(uint64_t index, uint64_t inputs, uint64_t witnesses, const std::function<bool(uint32_t)>& action)
{
    RequireAdmission(elements_hs_deposit_verify_v1,action,
        "drivechain deposit input or witness index is out of range","Haskell live deposit verification failed",index,inputs,witnesses);
}

bool ExchangeFrozenBounds(std::span<const uint64_t> fields)
{
    if (fields.size()!=1 && fields.size()!=2 && fields.size()!=3 && fields.size()!=5 && fields.size()!=9 && fields.size()!=16 && fields.size()!=17)
        throw std::runtime_error("invalid exchange bounds shape");
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_frozen_bounds_v1(fields.size(), const_cast<uint64_t*>(fields.data()));
    return CheckedStatus(code,1,"Haskell frozen exchange bounds failed") == 0;
}

std::optional<std::pair<uint32_t,bool>> ParseHashArguments(bool direct, const std::function<std::string(uint32_t)>& read,
    const std::function<void(uint32_t,std::span<const unsigned char,32>)>& publish)
{
    if (!read || !publish) throw std::invalid_argument("missing hash argument callback");
    const int code=ReadAdmission<int32_t,-1>([&](HsFunPtr callback,void* context) {
        return elements_hs_configuration_hashes_v1(direct,callback,context);
    },std::function<int32_t(uint32_t,unsigned char*)>{[&](uint32_t action,unsigned char* bytes) {
        if (action>=44 || !bytes) throw std::logic_error("invalid hash argument action");
        if (action>=22) publish(action-22,std::span<const unsigned char,32>{bytes,32});
        else {
            const auto text=read(action);
            if (text.size()!=64) return int32_t{1};
            std::copy(text.begin(),text.end(),bytes);
        }
        return int32_t{0};
    }});
    if (!code) return std::nullopt;
    if (code<5 || code>90 || (code%4!=1 && code%4!=2)) throw std::runtime_error("Haskell hash argument parsing failed");
    return std::pair<uint32_t,bool>{code/4-1,code%4==2};
}







namespace {
int ExchangeIdentityRelation(uint32_t mode, std::span<const unsigned char* const> identities)
{
    elements_hs_runtime_init();
    if (identities.size() > 45) throw std::invalid_argument("too many exchange identities");
    std::vector<unsigned char> bytes;
    for (const auto* identity : identities) {
        if (!identity) throw std::invalid_argument("null exchange identity");
        bytes.insert(bytes.end(), identity, identity + 32);
    }
    const int code = elements_hs_exchange_identity_relation_v1(mode, identities.size(), bytes.data());
    return CheckedStatus(code,mode>=5 ? 5 : mode>=3 ? 2 : 1,"Haskell exchange identity uniqueness failed");
}
}

bool ExchangeDistinct(std::span<const unsigned char* const> identities) { return ExchangeIdentityRelation(0, identities) == 0; }
bool ExchangeCarryIdentity(uint32_t profile, std::span<const unsigned char* const,15> identities)
{
    return profile<=1 && ExchangeIdentityRelation(7+profile,identities)==0;
}
void ExchangeDeploymentIdentities(bool direct_price, std::span<const unsigned char* const,22> identities)
{
    const int code=ExchangeIdentityRelation(direct_price ? 6 : 5,identities);
    static constexpr const char* errors[]{
        "finite, activation, and incremental-successor configuration hashes must be distinct",
        "proof program identity is missing",
        "incremental proof program identity collides with another proof role",
        "incremental activation covenant identity is missing or collides",
        "incremental successor state-node identity is missing or collides"};
    if (code) throw std::runtime_error(errors[code-1]);
}

bool ExchangeFrozenIdentities(bool direct_price, std::span<const unsigned char* const,22> identities, std::string& error)
{
    const int code=ExchangeIdentityRelation(direct_price ? 10 : 9,identities);
    static constexpr const char* errors[]{"finite, activation, and incremental-successor configurations collide",
        "incremental proof program identity collides", "frozen ECX bond V2 covenant CMR roles collide",
        "incremental successor state-node identity collides"};
    if (code>4) throw std::runtime_error("invalid frozen identity result");
    error=code ? errors[code-1] : "";
    return code==0;
}

void ExchangeActivationFacts(std::span<const unsigned char* const,40> identities)
{
    const int code=ExchangeIdentityRelation(11,identities);
    if (code>2) throw std::runtime_error("invalid activation facts result");
    if (code) throw std::runtime_error(code==1 ?
        "FrozenConfigurationV2/V18 bond/deployment/covenant identities do not match physical Tx1/Tx2 activation facts" :
        "ECX bond V2 activation lacks a complete frozen covenant CMR tuple");
}

void ExchangeRuntimeIdentities(std::span<const unsigned char* const,16> identities)
{
    if (ExchangeIdentityRelation(12,identities))
        throw std::runtime_error("runtime proof/matcher identities differ from FrozenConfigurationV2/V18");
}

void ExchangeDeploymentBlinders(bool public_deployment, std::span<const unsigned char* const,3> identities)
{
    const int code=ExchangeIdentityRelation(public_deployment ? 1 : 4,identities);
    if (code) throw std::runtime_error(public_deployment ? "public ECX deployment requires zero blinders" :
        code==1 ? "ECX bond V2 issuance blinder must be nonzero and distinct" : "ECX bond V2 inventory blinders must be distinct");
}

int UsddExtractBlock(bool zero_genesis, std::span<const unsigned char,69> profile,
    const std::function<int64_t(uint32_t,uint64_t,uint64_t,uint64_t,unsigned char*)>& effect,
    std::span<const unsigned char> state, std::span<const unsigned char> empty_roots, uint64_t count, uint8_t prefix, bool derive)
{
    if ((derive || !state.empty() || !empty_roots.empty()) && (state.size()!=2080 || empty_roots.size()!=2080))
        throw std::invalid_argument("invalid block accumulator buffers");
    const int code = ReadAdmission<int64_t, -1>([&](HsFunPtr callback, void* context) {
        return elements_hs_usdd_extract_block_v4(derive ? 2 : !state.empty(),zero_genesis,count,prefix,
            const_cast<unsigned char*>(state.data()),const_cast<unsigned char*>(empty_roots.data()),const_cast<unsigned char*>(profile.data()),
            callback,context,reinterpret_cast<HsFunPtr>(HashUsddPayload));
    }, effect);
    return CheckedStatus(code,8,"Haskell block claim extraction failed");
}
uint32_t UsddAdmission(uint32_t lane, std::span<const unsigned char> bytes, uint64_t limit,
    std::array<uint32_t, 3> profile, bool bmm, bool active, const std::function<int32_t(uint32_t)>& identity)
{
    const int code = ReadBoundAdmission<int32_t,-1>(elements_hs_usdd_admission_v4,identity,lane,bytes.size(),limit,
        profile.data(),const_cast<unsigned char*>(bytes.data()),bmm,active);
    return CheckedStatus(code,9,"Haskell USDD admission failed");
}
uint32_t UsddAnnex(std::span<const unsigned char> bytes, uint64_t limit, std::array<uint32_t, 3> profile)
{
    elements_hs_runtime_init();
    const int code = elements_hs_usdd_annex_v1(bytes.size(), limit, profile.data(), const_cast<unsigned char*>(bytes.data()));
    return CheckedStatus(code,15,"Haskell USDD annex validation failed");
}
struct UsddInputs {
    std::array<unsigned char*,7> pointers;
    std::array<uint64_t,7> sizes;
    explicit UsddInputs(const std::array<std::span<const unsigned char>,7>& fields) {
        for (size_t i = 0; i < fields.size(); ++i) Set(i,fields[i]);
    }
    void Set(size_t i, std::span<const unsigned char> bytes) {
        pointers[i] = const_cast<unsigned char*>(bytes.data());
        sizes[i] = bytes.size();
    }
    void Read(const UsddWitness& row, bool parameterized, std::array<uint64_t,4>& shape) {
        Set(0,row.cmr);
        Set(6,row.annex);
        shape = {row.items,row.control.size(),row.control.empty() ? 0U : row.control[0],parameterized};
    }
};
uint32_t UsddLegacy(uint32_t mode, std::array<std::span<const unsigned char>, 7> fields,
    std::array<uint32_t, 5> profile, uint64_t limit, bool bmm, bool active, std::array<uint64_t,4> shape)
{
    elements_hs_runtime_init();
    UsddInputs input{fields};
    const int code = elements_hs_usdd_legacy_v2(mode, input.pointers.data(), input.sizes.data(), profile.data(),
        limit, bmm, active, shape.data(), reinterpret_cast<HsFunPtr>(HashUsddPayload));
    return CheckedStatus(code,mode == 2 ? 511 : mode == 1 ? 9 : 5,"Haskell raw USDD identity failed");
}
std::pair<uint32_t,uint64_t> UsddResources(uint64_t count,
    std::array<std::span<const unsigned char>,7> fields, std::array<uint32_t,5> profile,
    uint64_t limit, bool parameterized, const std::function<UsddWitness(uint64_t)>& read)
{
    UsddInputs input{fields};
    std::array<uint64_t,4> shape{};
    uint64_t total{0};
    const std::function<int32_t(uint64_t)> action = [&](uint64_t index) {
        input.Read(read(index),parameterized,shape);
        return 1;
    };
    const auto flags = ReadBoundAdmission<int32_t,-1>(elements_hs_usdd_resources_v1,action,
        count,input.pointers.data(),input.sizes.data(),profile.data(),limit,shape.data(),&total,
        reinterpret_cast<HsFunPtr>(HashUsddPayload));
    return {CheckedStatus(flags,511,"Haskell USDD resource scan failed"),total};
}
std::array<unsigned char,64> UsddClaimHashes(uint32_t mode, std::span<const unsigned char,69> profile,
    std::span<const unsigned char,168> input)
{
    elements_hs_runtime_init();
    std::array<unsigned char,64> output{};
    if (elements_hs_usdd_claim_hashes_v2(mode, 0, input.size(), const_cast<unsigned char*>(profile.data()),
            const_cast<unsigned char*>(input.data()), output.data(), reinterpret_cast<HsFunPtr>(HashUsddPayload)) != 0)
        throw std::runtime_error("Haskell claim hashing failed");
    return output;
}

int UsddClaimPrefix(uint64_t index, std::span<const unsigned char,69> profile,
    std::span<const unsigned char> input, std::vector<unsigned char>& leaves)
{
    elements_hs_runtime_init();
    std::vector<unsigned char> output(std::max<size_t>(1,input.size()/200*32));
    const int code = elements_hs_usdd_claim_hashes_v2(3,index,input.size(),const_cast<unsigned char*>(profile.data()),
        const_cast<unsigned char*>(input.data()),output.data(),reinterpret_cast<HsFunPtr>(HashUsddPayload));
    if (code < 0 || code > 2) throw std::runtime_error("Haskell claim prefix failed");
    if (!code) { output.resize(input.size()/200*32); leaves = std::move(output); }
    return code;
}

void UsddFrontierWire(uint64_t count, bool reading, const std::function<bool(uint32_t)>& action)
{
    if (ReadBoundAdmission<int32_t,-1>(elements_hs_frontier_wire_v1,action,count,reading ? 1U : 0U) != 1)
        throw std::runtime_error("Haskell withdrawal frontier serialization failed");
}

bool UsddAccumulatorVersion(uint32_t version)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_usdd_accumulator_version_v1(version),1,
        "Haskell accumulator version validation failed") == 1;
}

int64_t WalletBalanceTotal(int64_t trusted, int64_t pending, int64_t immature)
{
    elements_hs_runtime_init();
    return elements_hs_wallet_balance_v1(trusted, pending, immature);
}

bool UsddAccumulator(uint32_t mode, uint64_t count, uint8_t prefix, std::span<unsigned char,2080> state,
    std::span<const unsigned char,2080> empty_roots, std::span<const unsigned char> leaf, uint64_t* next_count)
{
    elements_hs_runtime_init();
    if (leaf.size() % 32) throw std::invalid_argument("partial withdrawal tree leaf");
    unsigned char empty{};
    uint64_t cursor = count;
    const int code = elements_hs_usdd_accumulator_v3(mode, count, prefix, state.data(),
        const_cast<unsigned char*>(empty_roots.data()), leaf.empty() ? &empty : const_cast<unsigned char*>(leaf.data()), leaf.size() / 32,
        reinterpret_cast<HsFunPtr>(HashUsddPayload), &cursor);
    const bool complete = CheckedStatus(code,1,"Haskell USDD accumulator failed") == 0;
    if (next_count) *next_count = cursor;
    return complete;
}
int UsddCheckpoint(uint64_t before_count, uint64_t after_count, uint8_t prefix,
    std::span<const unsigned char,2080> before, std::span<const unsigned char,2080> after,
    std::span<const unsigned char,2080> empty_roots, std::span<const unsigned char> profile,
    std::span<unsigned char,32> output)
{
    elements_hs_runtime_init();
    if (profile.size() > UINT32_MAX) throw std::length_error("USDD checkpoint profile too large");
    const int code = elements_hs_usdd_checkpoint_v1(before_count, after_count, prefix,
        const_cast<unsigned char*>(before.data()), const_cast<unsigned char*>(after.data()),
        const_cast<unsigned char*>(empty_roots.data()), const_cast<unsigned char*>(profile.data()), profile.size(),
        output.data(), reinterpret_cast<HsFunPtr>(HashUsddPayload));
    return CheckedStatus(code,3,"Haskell USDD checkpoint failed");
}
bool ExchangeAbsent(std::span<const unsigned char* const> identities) { return ExchangeIdentityRelation(1, identities) == 0; }

bool ExchangeRegistry(std::span<const std::array<unsigned char, 32>, 5> encryption,
    std::span<const std::array<unsigned char, 32>, 5> attestation, std::string& error)
{
    elements_hs_runtime_init();
    static_assert(sizeof(encryption[0]) == 32);
    const int code = elements_hs_exchange_registry_v1(const_cast<unsigned char*>(encryption[0].data()),
        const_cast<unsigned char*>(attestation[0].data()));
    static constexpr const char* errors[]{"incomplete frozen ECX bond V2 custodian registry",
        "duplicate frozen ECX bond V2 custodian registry key"};
    return ExchangeResult(code, errors, error, "Haskell exchange custodian registry failed");
}

std::vector<unsigned char> ExchangeRegistryEncoding(std::span<const std::array<unsigned char,32>,5> encryption,
    std::span<const std::array<unsigned char,32>,5> attestation)
{
    std::vector<unsigned char> bytes;
    for (const auto& key : encryption) bytes.insert(bytes.end(),key.begin(),key.end());
    for (const auto& key : attestation) bytes.insert(bytes.end(),key.begin(),key.end());
    return ExchangeInboxEntry(InboxCodec::REGISTRY,{}, {},bytes);
}

void ExchangeRegistryDecoding(std::span<const unsigned char> bytes, std::span<std::array<unsigned char,32>,5> encryption,
    std::span<std::array<unsigned char,32>,5> attestation)
{
    std::array<unsigned char,320> decoded{};
    uint64_t count{};
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_registry_decode_v1(bytes.size(),const_cast<unsigned char*>(bytes.data()),decoded.data(),&count);
    if (code<0 || code>2 || count>5) throw std::runtime_error("Haskell registry decoding failed");
    for (size_t i=0;i<count;++i) {
        std::copy_n(decoded.data()+i*64,32,encryption[i].begin());
        std::copy_n(decoded.data()+i*64+32,32,attestation[i].begin());
    }
    if (code) throw std::runtime_error(code==1 ? "ECX bond V2 custodian registry indices/keys are noncanonical" : "ECX bond V2 custodian registry contains duplicate keys");
}

bool ExchangeCustodyCheck(uint32_t mode, std::span<const unsigned char> values,
    std::span<const unsigned char> context)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_exchange_custody_check_v1(mode, values.size(),
        const_cast<unsigned char*>(values.data()), context.size(),
        const_cast<unsigned char*>(context.data())), 1, "Haskell custody projection check failed") == 1;
}

bool ExchangeCapitalIdentity(uint32_t profile, std::span<const unsigned char, 32> program,
    std::span<const unsigned char> values, std::initializer_list<const unsigned char*> identities,
    std::initializer_list<uint64_t> context, std::initializer_list<const unsigned char*> snapshot_context,
    std::span<unsigned char> snapshot)
{
    elements_hs_runtime_init();
    std::vector<unsigned char> expected;
    for (const auto* identity : identities) {
        if (!identity) throw std::invalid_argument("null exchange capital identity");
        expected.insert(expected.end(), identity, identity + 32);
    }
    if (profile>3 || identities.size()!=(profile==0 ? 5U : 7U) || context.size()!=(profile==2 ? 2U : 0U) ||
        (snapshot.empty() ? snapshot_context.size()!=0 : profile==2 || snapshot.size()!=914 || snapshot_context.size()!=3))
        throw std::runtime_error("Haskell exchange capital identity failed");
    for (const auto value : context) {
        const auto offset=expected.size();
        expected.resize(offset+8);
        WriteBE64(expected.data()+offset,value);
    }
    for (const auto* field : snapshot_context) {
        if (!field) throw std::invalid_argument("null capital snapshot context");
        expected.insert(expected.end(),field,field+32);
    }
    const int code = elements_hs_exchange_capital_v2(profile,
        const_cast<unsigned char*>(program.data()), values.size(), const_cast<unsigned char*>(values.data()),
        expected.size(), expected.data(), snapshot.size(), snapshot.data());
    return CheckedStatus(code,1,"Haskell exchange capital identity failed") == 0;
}

bool ExchangeSuccessorBinding(bool incremental, std::span<const unsigned char> values,
    std::span<const unsigned char* const,4> identities, std::span<const uint64_t,3> context)
{
    std::array<unsigned char,128> hashes;
    for (size_t i=0;i<identities.size();++i) {
        if (!identities[i]) throw std::invalid_argument("null successor context identity");
        std::copy_n(identities[i],32,hashes.data()+32*i);
    }
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_exchange_successor_binding_v1(incremental,values.size(),
        const_cast<unsigned char*>(values.data()),hashes.data(),const_cast<uint64_t*>(context.data())),
        1,"Haskell successor context binding failed")==0;
}

bool ExchangeSwapSuccessorBinding(std::span<const unsigned char> values,
    std::span<const unsigned char* const,6> identities, std::span<const uint64_t,4> context)
{
    std::array<unsigned char,192> hashes;
    for (size_t i=0;i<identities.size();++i) {
        if (!identities[i]) throw std::invalid_argument("null swap successor identity");
        std::copy_n(identities[i],32,hashes.data()+32*i);
    }
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_exchange_successor_binding_v1(2,values.size(),
        const_cast<unsigned char*>(values.data()),hashes.data(),const_cast<uint64_t*>(context.data())),
        1,"Haskell swap successor context binding failed")==0;
}

std::optional<std::vector<unsigned char>> ExchangeForcedV3BlockBytes(
    uint32_t mode, std::span<const unsigned char> bytes)
{
    static constexpr std::array<size_t,5> capacities{4199,145,1,1,1};
    if (mode>=capacities.size()) return std::nullopt;
    if ((mode==0 && (bytes.size()<237 || bytes.size()>4301)) ||
        (mode==1 && bytes.size()!=186) || (mode==2 && bytes.size()>14) ||
        (mode==3 && (bytes.size()<96 || bytes.size()>4204)) ||
        (mode==4 && bytes.size()!=1)) return std::nullopt;
    elements_hs_runtime_init();
    std::vector<unsigned char> result(capacities[mode]);
    const unsigned char empty=0;
    const auto size=CheckedStatus(elements_hs_exchange_forced_v3_block_bytes_v1(mode,bytes.size(),
        const_cast<unsigned char*>(bytes.empty() ? &empty : bytes.data()),result.size(),result.data()),
        result.size(),"Haskell exact forced block codec failed");
    if (!size) return std::nullopt;
    if (size<0 || static_cast<size_t>(size)>result.size()) throw std::logic_error("invalid forced V3 block codec size");
    result.resize(size);
    return result;
}

bool ExchangeForcedV3Frame(std::span<const unsigned char> script,
    std::span<const unsigned char,32> economic_hash, std::vector<unsigned char>& payload)
{
    if (script.size()<2 || script.size()>4108) return false;
    std::array<unsigned char,4104> bytes;
    elements_hs_runtime_init();
    const auto size = CheckedStatus(elements_hs_exchange_forced_v3_bytes_v1(0,script.size(),
        const_cast<unsigned char*>(script.data()),const_cast<unsigned char*>(economic_hash.data()),
        bytes.size(),bytes.data()),bytes.size(),"Haskell exact forced frame failed");
    if (!size) return false;
    payload.assign(bytes.begin(),bytes.begin()+size);
    return true;
}

bool RunExchangeSession(ExchangeSession mode, const NativeWorkflow& native)
{
    return CheckedStatus(ReadWorkflow(elements_hs_exchange_session_v1,native,static_cast<uint32_t>(mode)),
        1,"Haskell exchange session failed")==1;
}




std::vector<unsigned char> ExchangeEnvelopePayload(uint32_t height, const unsigned char* checkpoint, std::span<const unsigned char> body)
{
    elements_hs_runtime_init();
    std::vector<unsigned char> payload(45 + std::min<size_t>(body.size(),100000));
    const int code = elements_hs_exchange_envelope_payload_v1(height,const_cast<unsigned char*>(checkpoint),
        body.size(),const_cast<unsigned char*>(body.data()),payload.size(),payload.data());
    if (code == 1) throw std::invalid_argument("ECX M6 envelope preimage size is invalid");
    if (code != 0) throw std::runtime_error("Haskell ECX envelope encoding failed");
    return payload;
}




bool ExchangeSourceMarker(uint32_t& seen, SourceMarker kind, bool present, std::string& error)
{
    elements_hs_runtime_init();
    uint32_t next{0};
    const int code = elements_hs_exchange_source_marker_v1(seen, static_cast<uint32_t>(kind), present, &next);
    static constexpr const char* errors[]{
        "an Elements transaction may contain only one ECX forced action",
        "an Elements transaction may contain only one ECX deposit marker",
        "ECX source transaction is premature before exchange activation"};
    if (!ExchangeResult(code, errors, error, "Haskell exchange source marker failed")) return false;
    seen = next;
    return true;
}

bool ExchangeSourceAdmission(const std::function<uint64_t(uint64_t)>& read, std::string& error)
{
    const int code = ReadAdmission<uint64_t>(elements_hs_exchange_source_admission_v1, read);
    static constexpr const char* errors[]{"ECX bond-inbox relay profile is not frozen",
        "ECX bond-inbox source transaction has an invalid input/output/witness form",
        "ECX bond-inbox source transaction exceeds its frozen exact byte cap",
        "ECX bond-inbox source witness exceeds its frozen exact byte cap"};
    return ExchangeResult(code,errors,error,"Haskell source admission failed");
}

bool AdmitTransaction(TransactionAdmission kind, const CTransaction& tx,
    uint64_t issuance, uint64_t inventory, uint64_t burn, uint64_t authority,
    const std::function<std::array<unsigned char,64>()>& derive)
{
    const bool public_bond = kind == TransactionAdmission::PUBLIC_BOND;
    const bool inputs_only = kind == TransactionAdmission::ORDINARY_INPUTS;
    std::vector<unsigned char> view(32);
    WriteLE64(view.data(), tx.vin.size());
    WriteLE64(view.data()+8, inputs_only ? 0 : tx.vout.size());
    WriteLE64(view.data()+16, inputs_only ? 0 : tx.witness.vtxoutwit.size());
    WriteLE64(view.data()+24, inputs_only ? 0 : tx.witness.vtxinwit.size());
    const auto amount = [&](const CConfidentialValue& value) {
        const auto offset = view.size();
        view.resize(offset+8);
        WriteLE64(view.data()+offset, value.IsExplicit() ? value.GetAmount() : 0);
    };
    // Only total, side-effect-free native predicates are snapshotted eagerly.
    // Cryptographic derivation stays deferred until Haskell admits its inputs.
    for (const auto& input : tx.vin) {
        const auto& issue = input.assetIssuance;
        view.push_back(unsigned(input.m_is_pegin) | (unsigned(issue.IsNull()) << 1) |
            (unsigned(issue.nAmount.IsNull()) << 2) | (unsigned(issue.nAmount.IsExplicit()) << 3) |
            (unsigned(issue.nInflationKeys.IsNull()) << 4) | (unsigned(issue.nInflationKeys.IsExplicit()) << 5) |
            (unsigned(issue.assetBlindingNonce.IsNull()) << 6));
        if (public_bond) { amount(issue.nAmount); amount(issue.nInflationKeys); }
    }
    if (!inputs_only) {
        for (const auto& output : tx.vout) {
            view.push_back(unsigned(output.nAsset.IsExplicit()) | (unsigned(output.nValue.IsExplicit()) << 1) |
                (unsigned(output.nNonce.IsNull()) << 2) | (unsigned(output.scriptPubKey.empty()) << 3) |
                (unsigned(output.scriptPubKey.IsUnspendable()) << 4));
            if (public_bond) {
                const auto offset = view.size();
                view.resize(offset+32);
                if (output.nAsset.IsExplicit()) std::copy_n(output.nAsset.GetAsset().begin(),32,view.begin()+offset);
                amount(output.nValue);
            }
        }
        for (const auto& witness : tx.witness.vtxoutwit)
            view.push_back(unsigned(witness.vchRangeproof.empty()) | (unsigned(witness.vchSurjectionproof.empty()) << 1));
        for (const auto& witness : tx.witness.vtxinwit)
            view.push_back(unsigned(witness.vchIssuanceAmountRangeproof.empty()) | (unsigned(witness.vchInflationKeysRangeproof.empty()) << 1));
    }
    const int code = ReadBoundAdmission<int32_t,-1>(elements_hs_exchange_transaction_admission_v1,
        std::function<int32_t(unsigned char*)>{[&](unsigned char* identities) {
            if (!public_bond || !identities || !derive) throw std::logic_error("invalid transaction asset derivation");
            const auto result = derive();
            std::copy(result.begin(),result.end(),identities);
            return int32_t{1};
        }}, static_cast<uint32_t>(kind),view.size(),view.data(),issuance,inventory,burn,authority);
    return CheckedStatus(code,1,"Haskell transaction admission failed") == 1;
}

bool ExchangeDeriveInbox(uint64_t count, uint64_t forced, uint64_t deposits,
    const std::function<int64_t(uint32_t,uint64_t,uint64_t)>& action, std::string& error)
{
    const int code = ReadBoundAdmission<int64_t,-1>(elements_hs_exchange_derive_inbox_v1,action,count,forced,deposits);
    static constexpr const char* errors[]{nullptr,
        "an Elements transaction may contain only one ECX forced action",
        "an Elements transaction may contain only one ECX deposit marker",
        "ECX forced inbox index overflow", "ECX deposit inbox index overflow",
        "ECX forced-action source tranche is overweight: unknown ECX forced-action kind",
        "ECX forced-action source tranche is overweight: parent-height tranche exceeds the 64-operation budget"};
    return ExchangeResult(code,errors,error,"Haskell inbox derivation failed");
}

bool ExchangeParentTarget(std::optional<uint64_t>& height,
    const std::function<uint64_t(uint32_t)>& read, std::string& error)
{
    uint64_t output{0};
    const int code = ReadAdmission<uint64_t>([&](HsFunPtr callback, void* context) {
        return elements_hs_exchange_parent_target_v1(height.has_value(), height.value_or(0), callback, context, &output);
    }, read);
    if (code < 0 || code > 2) throw std::runtime_error("Haskell exchange parent target validation failed");
    if (code) {
        error = code == 1 ? "ECX block assembly requires an authenticated target parent height"
                          : "ECX target parent height is outside the committed 32-bit range";
        return false;
    }
    height = output;
    return true;
}

bool ExchangeTranche(std::span<const uint8_t> kinds, uint32_t& work, std::string& error)
{
    work = 0;
    error.clear();
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_tranche_v1(kinds.size(), const_cast<uint8_t*>(kinds.data()), &work);
    if (code < 0 || code > 2) throw std::runtime_error("Haskell exchange tranche validation failed");
    if (code) error = code == 1 ? "unknown ECX forced-action kind" : "parent-height tranche exceeds the 64-operation budget";
    return code == 0;
}

int ExchangeForcedBody(uint32_t kind, std::span<const unsigned char> body,
    std::span<const unsigned char, 32> chain, std::span<const unsigned char, 16> market)
{
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_forced_body_v1(kind, body.size(),
        const_cast<unsigned char*>(body.data()), const_cast<unsigned char*>(chain.data()),
        const_cast<unsigned char*>(market.data()));
    return CheckedStatus(code,5,"Haskell forced body validation failed");
}

bool ExchangeSpendScan(bool unique, uint64_t start, uint64_t end,
    const std::function<uint64_t(uint64_t)>& read, std::optional<uint64_t>& match)
{
    uint64_t index{0};
    const int code = ReadAdmission<uint64_t, UINT64_MAX>([&](HsFunPtr callback, void* context) {
        return elements_hs_exchange_spend_scan_v1(unique, start, end, callback, context, &index);
    }, read);
    if (code < 0 || code > 2) throw std::runtime_error("Haskell exchange spend scan failed");
    if (code == 2) return false;
    match = code == 1 ? std::optional<uint64_t>{index} : std::nullopt;
    return true;
}

bool ExchangeDeploymentOutputs(uint64_t skipped, uint64_t count, const std::function<uint64_t(uint64_t)>& read)
{
    uint64_t unused{0};
    const int code=ReadAdmission<uint64_t,UINT64_MAX>([&](HsFunPtr callback,void* context) {
        return elements_hs_exchange_spend_scan_v1(2,skipped,count,callback,context,&unused);
    },read);
    if (code!=0 && code!=2) throw std::runtime_error("Haskell deployment output scan failed");
    return code==0;
}


std::vector<unsigned char> ExchangeGenesisState(GenesisCodec codec, uint64_t height, uint64_t price,
    std::initializer_list<const unsigned char*> hashes, std::span<const unsigned char> bond, std::span<const unsigned char> funding)
{
    const auto mode = static_cast<uint32_t>(codec);
    const bool private_state = codec == GenesisCodec::PRIVATE_STATE;
    static constexpr size_t hash_counts[]{4,8,11,1,2,0,0,0,10,10,10,15}, output_sizes[]{242,1713,468,34,64,383,100,41,914,914,914,914};
    static constexpr size_t body_sizes[]{0,242,0,0,0,0,0,0,850,1627,364,8};
    if (mode >= std::size(hash_counts) || hashes.size() != hash_counts[mode] || bond.size() != body_sizes[mode] ||
        funding.size() != (private_state ? 725U : 0U)) throw std::runtime_error("invalid genesis codec inputs");
    std::vector<unsigned char> input;
    input.reserve(hashes.size()*32 + bond.size() + funding.size());
    for (const auto* hash : hashes) {
        if (!hash) throw std::runtime_error("null genesis codec identity");
        input.insert(input.end(), hash, hash+32);
    }
    input.insert(input.end(), bond.begin(), bond.end());
    input.insert(input.end(), funding.begin(), funding.end());
    std::vector<unsigned char> output(output_sizes[mode]);
    elements_hs_runtime_init();
    if (elements_hs_exchange_genesis_state_v1(mode, height, price, input.size(), input.data(), output.size(), output.data()) != 0)
        throw std::runtime_error("Haskell exchange genesis state encoding failed");
    return output;
}

std::vector<unsigned char> ExchangeInboxEntry(InboxCodec codec, std::array<uint64_t, 7> fields,
    std::initializer_list<const unsigned char*> hashes, std::span<const unsigned char> body)
{
    const auto mode = static_cast<uint32_t>(codec);
    static constexpr size_t hash_counts[]{3,5,2,2,5,5,0,0,0,4,2,0,0,4,6,6}, overhead[]{30,33,8,0,41,33,0,0,0,4,12,5,0,2,12,21}, body_sizes[]{0,0,0,16,499,515,503,0,0,0,0,320,0,0,0,0};
    if (mode > 15 || mode == 7 || mode == 8 || mode == 12 || hashes.size() != hash_counts[mode] ||
        (mode != 0 && mode != 10 && body.size() != body_sizes[mode]))
        throw std::runtime_error("invalid inbox entry inputs");
    std::vector<unsigned char> input;
    for (const auto* hash : hashes) {
        if (!hash) throw std::runtime_error("null inbox entry identity");
        input.insert(input.end(), hash, hash+32);
    }
    input.insert(input.end(), body.begin(), body.end());
    std::vector<unsigned char> output(mode == 6 ? 236 : input.size() + overhead[mode]);
    elements_hs_runtime_init();
    if (elements_hs_exchange_inbox_entry_v1(mode, fields.data(), input.size(), input.data(), output.size(), output.data()) != 0)
        throw std::runtime_error("Haskell inbox entry encoding failed");
    return output;
}


bool ExchangeHeader(HeaderPhase phase, const std::function<bool(uint32_t)>& read, std::string& error)
{
    const auto mode = static_cast<uint32_t>(phase);
    if (mode>2) throw std::runtime_error("Haskell exchange header validation failed");
    static constexpr ReplayStoreFlow flows[]{ReplayStoreFlow::HEADER_INACTIVE,ReplayStoreFlow::HEADER_ACTIVE,ReplayStoreFlow::HEADER_GENESIS};
    const auto result=ParentReplayStore(flows[mode],[&](uint32_t step) { return read(step-1); });
    static constexpr const char* errors[]{
        "ECX header extensions are forbidden before activation",
        "all ECX header extensions are required and nonzero after activation",
        "ECX activation header does not commit the frozen genesis roots"};
    if (result) error = errors[mode];
    return result == 0;
}

bool ExchangeConnection(bool activation, const std::function<bool(uint32_t)>& read, std::string& error)
{
    const int result = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_connection_v1,read,activation);
    if (result < 0 || result > 2) throw std::runtime_error("Haskell exchange connection validation failed");
    if (result) error = result == 1 ? "ECX header roots do not match deterministic singleton and inbox derivation"
                                   : "ECX activation cannot overwrite a reserved chainstate outpoint";
    return result == 0;
}

bool ExchangeDisconnect(DisconnectPhase phase, const std::function<bool(uint32_t)>& perform, std::string& error)
{
    const int result = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_disconnect_v1,perform,static_cast<uint32_t>(phase));
    static constexpr const char* errors[]{
        "prior ECX header state is unavailable during disconnect",
        "prior ECX inbox header state is unavailable during disconnect",
        "ECX inbox undo does not reproduce the disconnected header state",
        "ECX activation tracker could not be removed",
        "ECX activation inbox trackers could not be removed",
        "ECX inbox count underflow during disconnect"};
    return ExchangeResult(result, errors, error, "Haskell exchange disconnect failed");
}

bool ProductionIdentity(const std::function<bool(uint32_t)>& read, std::string* error)
{
    const int code = CheckedStatus(ReadAdmission<int32_t>(elements_hs_production_identity_v1, read),
        32, "Haskell production identity validation failed");
    static constexpr const char* fields[]{
        "network id",
        "data directory",
        "RPC port",
        "parent RPC port",
        "onion target port",
        "P2P port",
        "P2P message-magic derivation",
        "local enforcer-rule derivation",
        "P2P message magic",
        "P2PKH prefix",
        "P2SH prefix",
        "WIF prefix",
        "extended public key prefix",
        "extended secret key prefix",
        "blinded address prefix",
        "parent P2PKH prefix",
        "parent P2SH prefix",
        "bech32/blech32 namespaces",
        "Elements/parent/slot mode",
        "runtime Elements/header/signed-block codecs",
        "parent-chain identity",
        "signed-block/genesis mode",
        "child genesis/asset identity",
        "peer seeds/genesis checkpoint",
        "Elements M1 proposal identity",
        "historical parent proposal milestones",
        "parent replay checkpoint assertions",
        "replay/annex identity",
        "SP1 resource schedule",
        "SP1 V7 controller-bound activation",
        "Taproot/Simplicity activation",
        "issuance/policy identity",
    };
    if (code && error) *error = std::string("Elements production identity mismatch: ") + fields[code-1];
    return code == 0;
}

static bool VerifierStartupResult(int result, std::string* error)
{
    const int code = CheckedStatus(result, 6, "Haskell verifier startup validation failed");
    static constexpr const char* errors[]{
        "USDD SP1 activation has no frozen verifier semantic identity",
        "linked USDD SP1 verifier ABI does not match the production identity",
        "linked USDD SP1 verifier semantic-identity format does not match the production identity",
        "linked USDD SP1 verifier could not export its semantic identity",
        "linked USDD SP1 verifier semantics do not match the production identity",
        "USDD SP1 activation requires the pinned verifier, but this binary was built without it"};
    if (code && error) *error = errors[code-1];
    return code == 0;
}


bool VerifierIdentity(bool active, uint32_t abi, uint32_t format,
    const std::array<unsigned char,32>& expected, RustVerifierVersion version,
    RustVerifierVersion identity_version, RustVerifierIdentity identity, std::string* error)
{
    if (error) error->clear();
    elements_hs_runtime_init();
    return VerifierStartupResult(elements_hs_verifier_identity_v1(active, abi, format,
        const_cast<unsigned char*>(expected.data()), reinterpret_cast<HsFunPtr>(version),
        reinterpret_cast<HsFunPtr>(identity_version), reinterpret_cast<HsFunPtr>(identity)), error);
}

bool ActivationShape(const std::function<int64_t(uint32_t)>& read)
{
    return CheckedStatus(ReadAdmission<int64_t,-1>(elements_hs_activation_shape_v1, read),
        1, "Haskell activation shape validation failed") == 1;
}

int64_t ActivationBudget(int64_t ordinary, uint32_t input, const std::function<bool(uint32_t)>& read)
{
    int64_t budget{};
    CheckedStatus(ReadBoundAdmission<int32_t,-1>(elements_hs_activation_budget_v1, read, ordinary, input, &budget),
        0, "Haskell activation budget validation failed");
    return budget;
}

bool ExchangeConfiguration(const std::function<bool(uint32_t)>& read, std::string& error)
{
    const int result = ReadAdmission<int32_t>(elements_hs_exchange_configuration_v1,read);
    static constexpr const char* errors[]{
        nullptr,
        "ECX genesis state outpoint collides with a reserved chainstate record",
        "ECX activation parameters are incomplete",
        "ECX collateral vault script hash does not match its frozen bytes"};
    return ExchangeResult(result, errors, error, "Haskell exchange configuration failed");
}

uint32_t ExchangeTracker(TrackerPhase phase, const std::function<bool(uint32_t)>& read)
{
    const int result = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_tracker_v1,read,static_cast<uint32_t>(phase));
    return CheckedStatus(result,phase == TrackerPhase::ENCODING ? 2 : 1,"Haskell exchange tracker validation failed");
}

bool ExchangeAvailable(Availability kind, const std::function<bool(uint32_t)>& read)
{
    const int result = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_availability_v1,read,static_cast<uint32_t>(kind));
    return CheckedStatus(result,1,"Haskell exchange availability failed") == 0;
}

bool ExchangeSnapshot(const std::function<bool(uint32_t)>& read, std::string& error)
{
    static constexpr const char* errors[]{"active tip has no complete ECX consensus context", nullptr,
        "persisted ECX context disagrees with the active tip"};
    return ExchangeResult(ReadAdmission<int32_t>(elements_hs_exchange_snapshot_v1,read),errors,error,
        "Haskell exchange snapshot evaluation failed");
}


bool ExchangeGenesisInitialization(uint32_t version, const std::function<bool(uint32_t)>& read, std::string& error)
{
    const int code = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_genesis_initialization_v1,read,version);
    static constexpr const char* errors[]{
        "ECX genesis initialization requires nonzero authenticated context",
        "ECX legacy genesis cannot contain checkpoint initialization fields",
        "ECX checkpoint genesis initialization has invalid ordering or version",
        "ECX genesis initialization is not the pinned authenticated ancestor"};
    return ExchangeResult(code, errors, error, "Haskell exchange genesis initialization failed");
}

bool ExchangeDeployment(uint32_t version, const std::function<bool(uint32_t)>& read, std::string& error)
{
    const int code = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_deployment_v1,read,version);
    static constexpr const char* errors[]{
        "unsupported ECX deployment version",
        "public ECX deployment requires zero blinders",
        "ECX bond V2 activation is disabled",
        "ECX bond V2 identities are not source-frozen"};
    return ExchangeResult(code, errors, error, "Haskell exchange deployment validation failed");
}

int ExchangeRequiredIdentity(bool public_deployment, bool direct_price, const std::function<bool(uint32_t)>& read)
{
    const int code = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_required_identities_v1,read,
        unsigned(public_deployment) | (unsigned(direct_price) << 1));
    return CheckedStatus(code,45,"Haskell required exchange identities failed");
}

static int ReadTransactionShape(uint32_t phase, const std::function<bool(uint32_t)>& read)
{
    return ReadBoundAdmission<int32_t,0>(elements_hs_exchange_transaction_shape_v1,read,phase);
}

bool ExchangeTransactionShape(TransactionShape phase, const std::function<bool(uint32_t)>& read, std::string& error)
{
    const int code = phase==TransactionShape::ISSUANCE ?
        (ParentReplayStore(ReplayStoreFlow::EXCHANGE_ISSUANCE,[&](uint32_t step) { return read(step-1); }) ? 4 : 0) :
        ReadTransactionShape(static_cast<uint32_t>(phase),read);
    static constexpr const char* errors[]{
        "ECX singleton must be transition input zero",
        "ECX transition has no successor output zero",
        "ECX bond V2 physical deployment/genesis linkage changed",
        "ECX bond V2 deployment/genesis issuance shape changed",
        "ECX bond V2 deployment outputs differ from the authorized facts",
        "ECX bond V2 activation requires confirmed ordered deployment and genesis UTXOs",
        "ECX bond V2 genesis singleton is not the exact derived empty state",
        "ECX bond-inbox source lacks its designated Taproot annex input",
        "ECX bond-inbox designated input is not an exact key-path annex spend",
        "ECX bond-inbox source contains a second Taproot annex",
        "ECX bond-inbox source has too many or duplicate markers",
        "ECX bond-inbox staging output index is invalid",
        "ECX bond-inbox staging output is not the exact confidential frozen descriptor form",
        "ECX bond-inbox staging output serialization is invalid",
        "ECX bond-inbox marker source authorization is invalid",
        "ECX bond-inbox source transaction must contain exactly one marker",
        "ECX V18 staging renderer inputs or frozen identity are invalid",
        "private ECX BMM parameters require a private-E2E build",
        "private ECX BMM parameters are restricted to elementsregtest",
        "-ecxprivatebmmcheckpoint requires an explicit -ecxprivatebmmactivationheight",
        "-ecxprivatebmmactivationheight requires -ecxprivatebmmcheckpoint=1",
        "invalid -ecxprivatebmmactivationheight",
        "ECX bond V2 deployment transaction shape is invalid",
        "ECX forced-action output index is out of range",
        nullptr,
        "output is not a canonical ECX forced action",
        "ECX forced action marker envelope is non-canonical",
        "ECX deposit marker envelope or chain id is non-canonical",
        "ECX deposit marker has an invalid trader or referenced vout",
        "ECX deposit does not match the confidential collateral vault profile",
        "ECX forced action contains an invalid x-only trader key",
        "ECX forced action signature is invalid",
        "tracked ECX singleton is missing from the UTXO set",
        "tracked ECX singleton does not match its persisted root"};
    return ExchangeResult(code, errors, error, "Haskell exchange transaction shape failed");
}

bool ExchangeActivationSettings(const std::function<bool(uint32_t)>& read)
{
    const int code = ReadTransactionShape(16,read);
    if (code == 0 || code == 25) return code == 25;
    if (code == 23) throw std::runtime_error(
        "ECX runtime activation parameters are restricted to elementsregtest; "
        "production deployments must freeze them in source");
    if (code == 24) throw std::runtime_error(
        "ECX regtest activation requires -ecxactivationheight, "
        "-ecxgenesisstateoutpoint, -ecxgenesisstateroot, -ecxchainid, "
        "-ecxforcedactiondomain, -ecxdepositinboxdomain, "
        "-ecxcollateralvaultscript, and -ecxcollateralvaultscripthash together");
    throw std::runtime_error("Haskell exchange activation settings failed");
}

uint32_t ExchangeBondSettings(const std::function<bool(uint32_t)>& read)
{
    const int code = ReadTransactionShape(17,read);
    return CheckedStatus(code,38,"Haskell exchange bond settings failed");
}

bool ExchangePhysicalInputs(bool public_deployment, const std::function<bool(uint32_t)>& read)
{
    const int code = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_physical_inputs_v1,read,public_deployment);
    return CheckedStatus(code,1,"Haskell exchange physical inputs failed") == 0;
}

bool ExchangeProfile(bool collateral, const std::function<bool(uint32_t)>& read)
{
    const int result = ReadBoundAdmission<int32_t,0>(elements_hs_exchange_profile_v1,read,collateral);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell exchange output profile failed");
    return result == 0;
}

static constexpr const char* CURSOR_ERRORS[]{
    "ECX state transition is missing its processed-cursor marker",
    "ECX processed-cursor marker requires a state transition",
    "ECX processed cursors are not monotonic or are outside the state transition",
    nullptr,
    "an ECX block may contain only one processed-cursor marker"};


bool ExchangeDeriveCursors(uint64_t count, uint32_t flags, uint64_t previous_forced, uint64_t previous_deposit,
    const std::function<int32_t(uint32_t, uint64_t, uint64_t, uint64_t*)>& read,
    uint64_t& forced, uint64_t& deposit, std::string& error)
{
    std::array<uint64_t, 2> result{};
    const int code = ReadBoundAdmission<int32_t,-1>(elements_hs_exchange_derive_cursors_v1,read,
        count,flags,previous_forced,previous_deposit,result.data());
    if (!ExchangeResult(code,CURSOR_ERRORS,error,"Haskell cursor derivation failed")) return false;
    forced = result[0];
    deposit = result[1];
    return true;
}

template <typename Binding, typename... Params>
static int ReadScalarAdmission(const Binding& binding,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read, Params... params)
{
    const std::function<int32_t(uint32_t,uint64_t,uint64_t,uint64_t*)> action =
        [&](uint32_t step, uint64_t a, uint64_t b, uint64_t* field) { *field=read(step,a,b); return 1; };
    return ReadBoundAdmission<int32_t,-1>(binding,action,params...);
}

bool StartupArgs(uint32_t slot, uint32_t timeout_maximum, const std::function<uint64_t(uint32_t)>& read)
{
    return CheckedStatus(ReadScalarAdmission(elements_hs_startup_args_v1,
        [&](uint32_t step, uint64_t, uint64_t) { return read(step); }, slot,
        uint64_t{MAX_MONEY}, uint64_t{timeout_maximum}), 1, "Haskell startup admission failed")==0;
}

void FeeFreeSelection(int64_t age, const std::function<uint64_t(uint32_t)>& read)
{
    if (ReadScalarAdmission(elements_hs_fee_free_selection_v1,
        [&](uint32_t step, uint64_t, uint64_t) { return read(step); }, age)!=1)
        throw std::runtime_error("Haskell fee-free selection failed");
}


bool DepositInputLimit(bool enabled, uint64_t count, uint64_t limit,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& read)
{
    return CheckedStatus(ReadScalarAdmission(elements_hs_deposit_input_limit_v1,
        read,uint32_t{enabled},count,limit),1,"Haskell deposit input limit failed") == 1;
}

static uint32_t ResourceAdmission(std::array<uint64_t,6> options, const UsddResourceSource& source,
    const std::function<uint64_t(uint32_t,uint64_t)>& read)
{
    UsddInputs input{source.fields};
    auto profile = source.profile;
    std::array<uint64_t,4> shape{};
    uint64_t total{0};
    const auto result = ReadScalarAdmission(elements_hs_usdd_resource_workflow_v1,
        [&](uint32_t step,uint64_t index,uint64_t) {
            if (step!=6) return read(step,index);
            input.Read(source.read(index),source.parameterized,shape);
            return uint64_t{1};
        },options.data(),input.pointers.data(),input.sizes.data(),profile.data(),source.limit,
        shape.data(),&total,reinterpret_cast<HsFunPtr>(HashUsddPayload));
    return CheckedStatus(result,options[0]==2 ? 8 : options[0]==1 ? 1 : 10,"Haskell USDD resource admission failed");
}

uint32_t UsddBlockResources(uint64_t count, uint64_t lane, uint64_t weight,
    const std::function<uint64_t(uint32_t,uint64_t)>& read, const UsddResourceSource* source)
{
    if (source) return ResourceAdmission({0,0,count,0,lane,weight},*source,read);
    uint64_t total{0};
    return CheckedStatus(ReadScalarAdmission(elements_hs_usdd_block_resources_v1,
        [&](uint32_t step,uint64_t index,uint64_t) { return read(step,index); },
        count,lane,weight,&total),10,"Haskell USDD block resource admission failed");
}

bool UsddPackageResources(uint32_t flags, uint64_t count, uint64_t initial, uint64_t lane,
    const std::function<uint64_t(uint32_t,uint64_t)>& read, const UsddResourceSource* source)
{
    if (source) return ResourceAdmission({1,flags,count,initial,lane,0},*source,read)==0;
    uint64_t total{0};
    return CheckedStatus(ReadScalarAdmission(elements_hs_usdd_package_resources_v1,
        [&](uint32_t step,uint64_t index,uint64_t) { return read(step,index); },
        flags,count,initial,lane,&total),1,"Haskell USDD package admission failed")==0;
}

uint32_t UsddPolicyWeight(uint32_t flags, uint64_t count,
    const std::function<uint64_t(uint32_t,uint64_t)>& read, bool expanded_activation, const UsddResourceSource* source)
{
    if (source) return ResourceAdmission({2,0,count,0,0,0},*source,read);
    const auto run = [&](const auto& binding) {
        return ReadScalarAdmission(binding,
            [&](uint32_t step,uint64_t index,uint64_t) { return read(step,index); },flags,count);
    };
    return CheckedStatus(expanded_activation ? run(elements_hs_usdd_policy_weight_v2) :
        run(elements_hs_usdd_policy_weight_v1),8,"Haskell USDD policy admission failed");
}

bool ExchangeSourcePackage(bool enabled, uint64_t count,
    const std::function<uint64_t(uint32_t,uint64_t)>& action, uint64_t& selected, bool modified)
{
    uint64_t next{0};
    const auto code = CheckedStatus(ReadScalarAdmission(elements_hs_source_selection_v1,
        [&](uint32_t step,uint64_t index,uint64_t) { return action(step,index); },
        static_cast<uint32_t>(enabled),static_cast<uint32_t>(modified),count,&next),1,"Haskell source package evaluation failed");
    if (code==0) selected=next;
    return code==0;
}

bool AdmitTlsCredentialFile(bool private_key, const std::function<uint64_t(uint32_t)>& read)
{
    return CheckedStatus(ReadScalarAdmission(elements_hs_tls_file_admission_v1,
        [&](uint32_t step,uint64_t,uint64_t) { return read(step); },static_cast<uint32_t>(private_key)),
        1,"Haskell mTLS credential admission failed") == 1;
}



bool RunExchangeStateWorkflow(ExchangeStateWorkflow kind, uint64_t count,
    const std::function<uint64_t(uint32_t,uint64_t,uint64_t)>& action, std::string& error)
{
    const int code = ReadScalarAdmission(elements_hs_exchange_state_workflow_v1,action,static_cast<uint32_t>(kind),count);
    const bool successor = kind == ExchangeStateWorkflow::TRANSITION || kind == ExchangeStateWorkflow::SUCCESSOR_AUTHORITY;
    if (code >= 101 && code <= 104) {
        static constexpr const char* errors[]{
            "ECX transition changed the state authority asset",
            "ECX transition changed the state authority value"};
        if (code == 101) error = successor ? "ECX successor authority must use an explicit asset/value and null nonce" :
            "ECX state authority must use an explicit asset/value and null nonce";
        else if (code == 104) error = successor ? "ECX successor state authority must be a P2TR output" :
            "ECX state authority must be a P2TR output";
        else error = errors[code-102];
        return false;
    }
    if (code == 233 || code == 234) {
        error = code == 233 ? "tracked ECX singleton is missing from the UTXO set" :
            "tracked ECX singleton does not match its persisted root";
        return false;
    }
    static constexpr const char* errors[]{
        "more than one transaction spends the ECX singleton",
        "ECX singleton must be transition input zero",
        "ECX transition has no successor output zero",
        nullptr,
        "a block may contain at most one ECX state transition"};
    if (code == 4) throw std::runtime_error("missing exchange authority rejection");
    return ExchangeResult(code,errors,error,"Haskell exchange state workflow failed");
}

static bool SourceResult(int code, bool successor, std::string& error)
{
    if (code < 0 || code > 3) throw std::runtime_error("Haskell source tracking failed");
    if (!code) return true;
    error = successor ? "ECX successor bond-inbox " : "ECX bond-inbox ";
    if (code == 3) error += "duplicate wtxid has inconsistent source facts";
    else {
        error += "block ";
        error += code == 1 ? "source byte accounting overflowed" :
            successor ? "exceeds source byte caps" : "exceeds deduplicated source byte caps";
    }
    return false;
}

bool ExchangeSourcePredecessor(bool successor, uint64_t proof_profile, uint64_t height, uint64_t parent,
    std::span<const unsigned char,32> head, std::span<const unsigned char,16> count,
    std::span<const unsigned char,16> processed, std::string& error)
{
    std::array<uint64_t,7> fields{successor,proof_profile,height,parent};
    std::array<unsigned char,64> input{};
    std::copy(head.begin(),head.end(),input.begin());
    std::copy(count.begin(),count.end(),input.begin()+32);
    std::copy(processed.begin(),processed.end(),input.begin()+48);
    std::array<unsigned char,48> output{};
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_inbox_entry_v1(12,fields.data(),input.size(),input.data(),output.size(),output.data());
    if (code < 0 || code > 2) throw std::runtime_error("Haskell source predecessor failed");
    if (code == 1) error = std::string(successor ? "ECX successor bond-inbox" : "ECX bond-inbox") + " source tracker has no canonical predecessor";
    if (code == 2) error = "finite ECX bond-inbox source tracker exceeds its u64 wire";
    return code == 0;
}

bool ExchangeTrackSource(bool successor, std::array<uint64_t, 4> fields,
    std::initializer_list<const unsigned char*> hashes, std::vector<unsigned char>& state, std::string& error)
{
    if (hashes.size() != 3 || state.size() > state.max_size()-104)
        throw std::runtime_error("invalid source tracking input");
    std::array<unsigned char,96> identities{};
    auto destination = identities.begin();
    for (const auto* hash : hashes) {
        if (!hash) throw std::runtime_error("null source tracking hash");
        destination = std::copy_n(hash,32,destination);
    }
    std::vector<unsigned char> next(state.size()+104);
    uint64_t written{0};
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_sources_v1(fields.data(),identities.data(),state.size(),state.data(),next.data(),&written);
    if (!SourceResult(code,successor,error)) return false;
    if (written != state.size() && written != next.size()) throw std::runtime_error("invalid source tracking output");
    next.resize(written);
    state = std::move(next);
    return true;
}

static bool MarkerResult(int code, bool wide, std::string& error)
{
    static constexpr const char* finite[]{"ECX bond-inbox process deadline overflows u64",
        "ECX bond-inbox enqueue refund boundary is earlier than the frozen observed-parent delay",
        "ECX bond-inbox block exceeds its marker/index bounds",
        "ECX bond-inbox marker changed after source verification"};
    static constexpr const char* successor[]{"ECX successor bond-inbox process deadline overflows u64",
        "ECX successor bond-inbox enqueue refund boundary is too early",
        "ECX successor bond-inbox block exceeds marker/index bounds",
        "ECX successor bond-inbox marker changed after source verification",
        "ECX successor bond-inbox entry count overflows u128"};
    if (code < 0 || code > (wide ? 5 : 4)) throw std::runtime_error("Haskell marker append failed");
    if (code) error = (wide ? successor : finite)[code-1];
    return code == 0;
}

bool ExchangeAppendMarker(std::array<uint64_t, 14> fields,
    std::initializer_list<const unsigned char*> hashes, std::span<const unsigned char, 16> count,
    std::span<const unsigned char> script,
    const std::function<void(uint32_t, std::span<const unsigned char>, std::span<unsigned char, 32>)>& effect,
    std::array<unsigned char, 48>& state, std::string& error)
{
    if (hashes.size() != 5 || script.size() != 507) throw std::runtime_error("invalid marker append input");
    std::vector<unsigned char> input;
    for (const auto* hash : hashes) {
        if (!hash) throw std::runtime_error("null marker append hash");
        input.insert(input.end(), hash, hash+32);
    }
    input.insert(input.end(), count.begin(), count.end());
    input.insert(input.end(), script.begin(), script.end());
    const int code = ReadAdmission<int32_t, -1>([&](HsFunPtr callback, void* context) {
        return elements_hs_exchange_append_marker_v1(fields.data(), input.data(), callback, context, state.data());
    }, NativeDigestEffect{[&](uint32_t kind, uint64_t size, unsigned char* bytes, unsigned char* digest) {
        if (kind > 2 || size > 716 || !bytes || !digest) return int32_t{-1};
        effect(kind, {bytes, static_cast<size_t>(size)}, std::span<unsigned char,32>{digest,32});
        return int32_t{0};
    }});
    return MarkerResult(code, fields[0], error);
}

bool ExchangeBondMarker(uint64_t limit, std::span<const unsigned char> payload,
    std::initializer_list<const unsigned char*> identities, std::string& error)
{
    if (identities.size() != 4) throw std::runtime_error("invalid marker identities");
    std::vector<unsigned char> expected;
    for (const auto* hash : identities) {
        if (!hash) throw std::runtime_error("null marker identity");
        expected.insert(expected.end(),hash,hash+32);
    }
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_bond_marker_v1(limit,payload.size(),const_cast<unsigned char*>(payload.data()),expected.data());
    static constexpr const char* errors[]{"ECX bond-inbox marker identities/availability claim are invalid",
        "ECX bond-inbox marker staging sentinels are invalid"};
    return ExchangeResult(code,errors,error,"Haskell marker validation failed");
}

static bool DecodeExchangeMarker(uint32_t mode, size_t size, std::span<const unsigned char> script, std::vector<unsigned char>& payload)
{
    std::array<uint64_t,7> fields{};
    std::vector<unsigned char> decoded(size);
    elements_hs_runtime_init();
    if (elements_hs_exchange_inbox_entry_v1(mode,fields.data(),script.size(),
            const_cast<unsigned char*>(script.data()),decoded.size(),decoded.data()) != 0) return false;
    payload = std::move(decoded);
    return true;
}

bool ExchangeMarkerFrame(bool successor, std::span<const unsigned char> script, std::vector<unsigned char>& payload)
{
    return DecodeExchangeMarker(successor ? 8 : 7,503,script,payload);
}

bool ExchangeLegacyMarkerFrame(bool forced, std::span<const unsigned char> script, std::vector<unsigned char>& payload)
{
    // Bound allocation before crossing the FFI; Haskell checks the exact frame.
    if (script.size() < 11 || script.size() > 258) return false;
    return DecodeExchangeMarker(forced ? 16 : 17,forced ? script.size()-3 : 73,script,payload);
}

bool ExchangeCursorPayload(std::span<const unsigned char> payload, bool& marker,
    uint64_t& forced, uint64_t& deposit, std::string& error)
{
    // One excess byte preserves invalid-length recognition without copying large pushes.
    std::array<unsigned char,22> input{};
    const size_t size = std::min(payload.size(),input.size());
    std::copy_n(payload.begin(),size,input.begin());
    std::vector<unsigned char> decoded;
    marker = false;
    if (!DecodeExchangeMarker(18,17,std::span{input}.first(size),decoded)) {
        error = "Haskell cursor payload decoding failed";
        return false;
    }
    marker = decoded[0] != 0;
    if (decoded[0] == 2) {
        error = "ECX processed-cursor marker has an invalid version or length";
        return false;
    }
    if (marker) {
        forced = ReadLE64(decoded.data()+1);
        deposit = ReadLE64(decoded.data()+9);
    }
    return true;
}

bool ExchangeAnnexHeader(std::span<const unsigned char> annex, uint64_t expected, uint64_t limit,
    uint32_t& bundle_length, uint8_t& receipt_count, std::string& error)
{
    unsigned char empty{};
    std::array<uint64_t,2> decoded{};
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_annex_header_v1(expected,limit,annex.size(),
        annex.empty() ? &empty : const_cast<unsigned char*>(annex.data()),decoded.data());
    static constexpr const char* errors[]{"ECX bond-inbox source annex has a noncanonical prefix/version",
        "ECX bond-inbox source annex has invalid bundle/receipt lengths"};
    if (!ExchangeResult(code,errors,error,"Haskell annex header failed")) return false;
    bundle_length = decoded[0];
    receipt_count = decoded[1];
    return true;
}

std::string ConfigurationIdentity(const std::string& network, std::span<const unsigned char,64> identities, const CustodyHash& hash)
{
    if (!hash || network.size()>std::numeric_limits<size_t>::max()-258) throw std::invalid_argument("invalid identity inputs");
    std::string record(network.size()+258,'\0');
    uint64_t written{0};
    const int code=ReadAdmission<int32_t,-1>([&](HsFunPtr callback,void* context) {
        return elements_hs_configuration_identity_v1(network.size(),reinterpret_cast<unsigned char*>(const_cast<char*>(network.data())),
            const_cast<unsigned char*>(identities.data()),callback,context,record.size(),reinterpret_cast<unsigned char*>(record.data()),&written);
    },NativeDigestEffect{[&](uint32_t kind,uint64_t size,unsigned char* input,unsigned char* output) {
        if (kind!=0 || size>record.size() || !input || !output) return int32_t{-1};
        const auto digest=hash(kind,{input,static_cast<size_t>(size)});
        std::copy(digest.begin(),digest.end(),output);
        return int32_t{0};
    }});
    if (code!=0 || written>record.size()) throw std::runtime_error("Haskell identity record failed");
    record.resize(written);
    return record;
}

bool MaterialName(bool chainstates, const std::string& filename)
{
    elements_hs_runtime_init();
    const auto result=elements_hs_material_name_v1(chainstates,filename.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(filename.data())));
    return CheckedStatus(result,1,"Haskell material filename failed") == 1;
}

bool IdentityWrite(const std::function<bool(uint32_t)>& perform)
{
    if (!perform) throw std::invalid_argument("missing identity write actions");
    const auto result=ReadAdmission<int32_t,-1>(elements_hs_identity_write_v1,perform);
    return CheckedStatus(result,1,"Haskell identity write failed") == 1;
}

std::array<unsigned char,32> ExchangeCustodyRoot(uint64_t bundle_length,
    std::initializer_list<const unsigned char*> identities, std::span<const unsigned char> receipts, const CustodyHash& hash)
{
    if (identities.size()!=6 || !hash) throw std::invalid_argument("invalid custody root inputs");
    std::vector<unsigned char> fields;
    for (const auto* field : identities) {
        if (!field) throw std::invalid_argument("null custody identity");
        fields.insert(fields.end(),field,field+32);
    }
    std::array<unsigned char,32> root{};
    unsigned char empty{};
    const int code = ReadAdmission<int32_t, -1>([&](HsFunPtr callback, void* context) {
        return elements_hs_exchange_custody_root_v1(bundle_length,fields.data(),receipts.size(),
            receipts.empty() ? &empty : const_cast<unsigned char*>(receipts.data()),callback,context,root.data());
    }, NativeDigestEffect{[&](uint32_t kind, uint64_t size, unsigned char* input, unsigned char* output) {
        if (kind>5 || size>229 || !input || !output) return int32_t{-1};
        const auto digest = hash(kind,{input,static_cast<size_t>(size)});
        std::copy(digest.begin(),digest.end(),output);
        return int32_t{0};
    }});
    if (code!=0) throw std::runtime_error("Haskell custody root failed");
    return root;
}

std::array<unsigned char,128> ExchangeGenesisRoots(uint64_t height, uint64_t mtp, uint64_t price,
    std::initializer_list<const unsigned char*> identities, const CustodyHash& hash)
{
    if (identities.size()!=12 || !hash) throw std::invalid_argument("invalid genesis root inputs");
    std::array<unsigned char,384> fields;
    size_t offset=0;
    for (const auto* field : identities) {
        if (!field) throw std::invalid_argument("null genesis root identity");
        std::copy_n(field,32,fields.begin()+offset);
        offset+=32;
    }
    std::array<unsigned char,128> roots{};
    const int code=ReadAdmission<int32_t,-1>([&](HsFunPtr callback, void* context) {
        return elements_hs_exchange_genesis_roots_v1(height,mtp,price,fields.data(),callback,context,roots.data());
    },NativeDigestEffect{[&](uint32_t kind,uint64_t size,unsigned char* input,unsigned char* output) {
        if (kind>9 || size>1713 || !output || (!input && size)) return int32_t{-1};
        const auto digest=hash(kind,{input,static_cast<size_t>(size)});
        std::copy(digest.begin(),digest.end(),output);
        return int32_t{0};
    }});
    if (code!=0) throw std::runtime_error("Haskell genesis root construction failed");
    return roots;
}

bool ExchangeFrozenConfiguration(std::span<const unsigned char> input, std::span<const unsigned char,16> market,
    const CustodyHash& effect, std::string& error)
{
    error.clear();
    if (!effect) throw std::invalid_argument("missing frozen configuration effect");
    const int code=ReadAdmission<int32_t,-1>([&](HsFunPtr callback, void* context) {
        return elements_hs_exchange_frozen_configuration_v1(input.size(),const_cast<unsigned char*>(input.data()),
            const_cast<unsigned char*>(market.data()),callback,context);
    },NativeDigestEffect{[&](uint32_t kind,uint64_t size,unsigned char* bytes,unsigned char* output) {
        static constexpr size_t sizes[]{383,100,130,32,160,64,32,1,32,96,485,260};
        if (kind>=std::size(sizes) || size!=sizes[kind] || !bytes || !output) return int32_t{-1};
        const auto result=effect(kind,{bytes,static_cast<size_t>(size)});
        std::copy(result.begin(),result.end(),output);
        return int32_t{0};
    }});
    static constexpr const char* reasons[]{"outer/base identity","USDD checkpoint profile","risk profile",
        "availability profile","Truthcoin authentication profile","Truthcoin anchor deployment","hybrid oracle profile",
        "direct native price lane","central matcher profile","base accumulator profile","duplicate base identity",
        "policy asset aliases an unrelated base identity","bond/covenant identities","staging descriptor commitment",
        "bond inbox/matcher limits","versioned oracle conversion identities","recursive proof/bond constants or trailing bytes",
        "duplicate outer identity","cross-role identity collision"};
    if (code==0) return true;
    if (code<1 || code>20) throw std::runtime_error("Haskell frozen configuration decoding failed");
    error=code==1 ? "canonical FrozenConfigurationV2/V18 must be exactly 1977 bytes" :
        std::string("noncanonical FrozenConfigurationV2/V18: ")+reasons[code-2];
    return false;
}

bool ExchangeCustodyReceipts(uint32_t count, std::span<const unsigned char> encoded,
    std::vector<unsigned char>& receipts, uint8_t& bitmap, std::string& error)
{
    if (count < 3 || count > 5) throw std::invalid_argument("invalid custody receipt count");
    std::vector<unsigned char> decoded(count * 138 + 1);
    unsigned char empty{};
    elements_hs_runtime_init();
    const int code = elements_hs_exchange_receipts_v1(count,encoded.size(),
        encoded.empty() ? &empty : const_cast<unsigned char*>(encoded.data()),decoded.size(),decoded.data());
    static constexpr const char* errors[]{
        "ECX bond-inbox source annex truncated a receipt length",
        "ECX bond-inbox source annex receipt length is noncanonical",
        "ECX bond-inbox source annex receipts are not registry ordered",
        "ECX bond-inbox source annex receipt evidence is invalid"};
    if (!ExchangeResult(code,errors,error,"Haskell custody receipt decoding failed")) return false;
    bitmap = decoded.back();
    decoded.pop_back();
    receipts = std::move(decoded);
    return true;
}

static const char* SourceBudgetError(bool invalid_cursor)
{
    return invalid_cursor ? "ECX source backlog cursors are invalid" : "ECX source backlog exceeds consensus bounds";
}

bool ExchangeTemplateBudget(int64_t height, int64_t activation, const std::function<uint64_t(uint32_t)>& read,
    uint64_t& budget, std::string& error)
{
    const auto code = CheckedStatus(ReadScalarAdmission(elements_hs_template_budget_v1,
        [&](uint32_t step, uint64_t, uint64_t) { return read(step); }, height, activation, &budget),
        3, "Haskell template budget evaluation failed");
    if (code==0) error.clear();
    else error = code==1 ? "cannot read ECX source backlog: "+error : SourceBudgetError(code==2);
    return code==0;
}

std::array<uint64_t, 2> ExchangePending(std::array<uint64_t, 4> fields)
{
    elements_hs_runtime_init();
    std::array<uint64_t, 2> result{};
    if (elements_hs_exchange_inbox_v1(5, fields.size(), fields.data(), result.data()) != 0)
        throw std::logic_error("invalid checked exchange inbox counts");
    return result;
}

bool ExchangeInbox(std::span<const uint64_t> fields, uint64_t& output, std::string& error)
{
    if (fields.size() != 3 && fields.size() != 4 && fields.size() != 12) throw std::invalid_argument("invalid exchange inbox projection");
    const bool budget = fields.size() == 4;
    if (budget) { output = 0; error.clear(); }
    elements_hs_runtime_init();
    std::array<uint64_t, 2> result{};
    const int code = elements_hs_exchange_inbox_v1(fields.size()==3 ? 4 : !budget, fields.size(),
        const_cast<uint64_t*>(fields.data()), result.data());
    if (code < 0 || code > 8 || result[0] > 1) throw std::runtime_error("Haskell exchange inbox validation failed");
    if (result[0]) output = result[1];
    static constexpr const char* errors[]{
        "ECX processed cursor exceeds its source entry count",
        "ECX source appends exceed the combined same-parent limit",
        "ECX source suffix exceeds the maximum transition witness profile",
        "ECX combined unconsumed source backlog exceeds consensus bounds",
        "ECX pending source backlog has no authenticated parent height",
        "ECX prior backlog age commitment is missing or invalid",
        "ECX source backlog exceeded the forced-inclusion deadline",
        "ECX activation block must carry the frozen inbox genesis state"};
    if (code) error = budget
        ? SourceBudgetError(code == 1)
        : errors[code-1];
    return code == 0;
}

void BmmFixedIdentity(std::span<uint32_t, 2> fields, std::span<unsigned char, 121> payload)
{
    elements_hs_runtime_init();
    if (elements_hs_bmm_identity_v1(fields.data(), payload.data()) != 0)
        throw std::runtime_error("Haskell BMM fixed identity failed");
}

void BmmCheckpointPreset(uint32_t mode, std::span<uint32_t, 16> fields,
    std::span<unsigned char, 32> block_hash)
{
    elements_hs_runtime_init();
    if (elements_hs_bmm_checkpoint_v1(mode, fields.data(), block_hash.data()) != 0)
        throw std::runtime_error("Haskell BMM checkpoint failed");
}

uint32_t BmmConsensusPreset(uint32_t mode, std::span<uint64_t, 6> fields,
    std::span<unsigned char, 32> pow_limit, std::span<unsigned char, 22> challenge)
{
    elements_hs_runtime_init();
    const auto size = elements_hs_bmm_preset_v1(mode, fields.data(), pow_limit.data(), challenge.data());
    if (size < 0 || size > 22) throw std::runtime_error("Haskell BMM preset failed");
    return size;
}

int64_t BmmDifficultyInterval(int64_t timespan, int64_t spacing)
{
    elements_hs_runtime_init();
    int64_t interval{0};
    if (elements_hs_bmm_interval_v1(timespan, spacing, &interval) != 0)
        throw std::runtime_error("Haskell difficulty interval failed");
    return interval;
}

std::array<uint32_t,2> BmmHeaderLayout(uint32_t version, uint32_t flags)
{
    elements_hs_runtime_init();
    std::array<uint32_t,2> layout{};
    // The fresh header field is available only under its explicit wire mode.
    constexpr uint32_t legacy_fields{0x1ffU};
    constexpr uint32_t swap_forced_field{1U << 9};
    const uint32_t allowed_fields = legacy_fields | ((flags & (1U << 6)) ? swap_forced_field : 0U);
    if (elements_hs_bmm_header_layout_v1(version,flags,layout.size(),layout.data()) != 0 ||
        (layout[1] & ~allowed_fields) != 0)
        throw std::runtime_error("Haskell header layout failed");
    return layout;
}

bool MerkleReplacement(uint32_t mode, uint32_t index, uint32_t position, uint32_t flags)
{
    elements_hs_runtime_init();
    const int result = elements_hs_merkle_replacement_v1(mode,index,position,flags);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell Merkle replacement failed");
    return result == 1;
}

void BmmPrivateTemplate(uint32_t height, uint32_t time, uint32_t median, uint32_t slot,
    std::span<const unsigned char, 32> critical, std::span<uint32_t, 4> fields,
    std::span<unsigned char, 37> commitment)
{
    elements_hs_runtime_init();
    if (elements_hs_bmm_private_template_v1(height, time, median, slot,
            const_cast<unsigned char*>(critical.data()), fields.data(), commitment.data()) != 0)
        throw std::runtime_error("Haskell private BMM template failed");
}

std::vector<unsigned char> BmmFingerprint(const FingerprintReader& reader, uint32_t profile)
{
    elements_hs_runtime_init();
    struct Context {
        const FingerprintReader& reader;
        std::vector<unsigned char> bytes;
        std::exception_ptr failure;
    } context{reader, {}, {}};
    const auto read = +[](void* opaque, uint32_t group, uint32_t index, uint64_t* value, unsigned char** bytes) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        try {
            const unsigned char* borrowed{nullptr};
            const bool ok = ctx.reader(group, index, *value, borrowed);
            *bytes = const_cast<unsigned char*>(borrowed);
            return ok;
        } catch (...) { ctx.failure = std::current_exception(); return 0; }
    };
    const auto write = +[](void* opaque, unsigned char* bytes, uint64_t size) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        try {
            if (size > ctx.bytes.max_size()) throw std::length_error("BMM fingerprint too large");
            ctx.bytes.assign(bytes, bytes + size);
            return 1;
        } catch (...) { ctx.failure = std::current_exception(); return 0; }
    };
    const auto result = elements_hs_fingerprint_v2(profile, reinterpret_cast<HsFunPtr>(read), reinterpret_cast<HsFunPtr>(write), &context);
    if (context.failure) std::rethrow_exception(context.failure);
    if (result != 1) throw std::runtime_error("Haskell BMM fingerprint failed");
    return std::move(context.bytes);
}

namespace {
struct BorrowedStack {
    std::vector<uint32_t> sizes;
    std::vector<unsigned char*> fields;
    explicit BorrowedStack(std::span<const std::vector<unsigned char>> stack)
    {
        if (stack.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("Haskell deposit stack too large");
        for (const auto& item : stack) {
            if (item.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("Haskell deposit field too large");
            sizes.push_back(item.size());
            fields.push_back(const_cast<unsigned char*>(item.data()));
        }
    }
};

bool DepositProofResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 7> errors{{
        "drivechain deposit outpoint is absent from the authenticated L1 transaction",
        "drivechain deposit merkle proof does not authenticate the exact L1 transaction",
        "drivechain deposit evidence contains an invalid L1 proof-of-work header",
        "drivechain deposit L1 header evidence is not a contiguous chain",
        "drivechain deposit outpoint is not the slot-24 CTIP output",
        "drivechain deposit transaction does not spend exactly one authenticated prior CTIP",
        "drivechain deposit value does not equal the authenticated CTIP increase",
    }};
    return ExchangeResult(result, errors, error, "Haskell deposit proof evaluation failed");
}
} // namespace

bool BmmState(bool hash, int64_t interval, uint32_t height, uint32_t time, uint32_t bits,
    uint32_t start, uint32_t start_time, uint64_t count, uint32_t latest, std::string& error)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_state_v1(hash, interval, height, time, bits, start, start_time, count, latest);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell BMM state evaluation failed");
    if (result) error = "BMM parent-chain state is malformed";
    return result == 0;
}

int32_t BmmActivation(uint32_t phase, uint32_t facts, int64_t height, int64_t activation)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_bmm_activation_v1(phase, facts, height, activation);
    if (result == -2) throw std::runtime_error("-ecxprivatebmmcheckpoint requires an explicit -ecxprivatebmmactivationheight");
    if (result == -3) throw std::runtime_error("invalid -ecxprivatebmmactivationheight");
    if (result < 0 || result > 2) throw std::runtime_error("Haskell BMM activation evaluation failed");
    return result;
}

void RunBmmRetarget(uint32_t height, int64_t interval, int64_t target, uint32_t time, uint32_t start,
    const NativeWorkflow& native)
{
    const int result = ReadWorkflow(elements_hs_bmm_retarget_workflow_v1, native, height, interval, target, time, start);
    if (result == -2) throw std::runtime_error("Haskell BMM retarget evaluation failed");
    if (result == -3) throw std::runtime_error("Haskell BMM target scaling failed");
    if (result != 0) throw std::runtime_error("Haskell BMM state flow failed");
}

uint32_t BmmMedian(std::span<const uint32_t> times)
{
    elements_hs_runtime_init();
    if (times.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("BMM median history too large");
    const auto result = elements_hs_bmm_median_v1(times.size(), const_cast<uint32_t*>(times.data()));
    if (result < 0 || result > std::numeric_limits<uint32_t>::max()) throw std::runtime_error("Haskell BMM median evaluation failed");
    return result;
}

bool RunBmmStateFlow(BmmStateStep start, const std::function<int32_t(BmmStateStep)>& action)
{
    static_assert(static_cast<uint32_t>(BmmStateStep::SIGNATURE_MODE) == 114);
    const std::function<int32_t(uint32_t)> read = [&](uint32_t step) { return action(static_cast<BmmStateStep>(step)); };
    return CheckedStatus(ReadBoundAdmission<int64_t,INT64_MIN>(elements_hs_bmm_state_run_v1,read,
        static_cast<uint32_t>(start)),1,"Haskell BMM state flow failed") == 0;
}


void EventFields(EventLayoutKind kind, uint32_t status,
    const std::function<void(uint32_t, std::string_view, std::optional<std::string_view>)>& append)
{
    elements_hs_runtime_init();
    for (uint32_t index = 0;; ++index) {
        std::array<char, 32> key{}, value{};
        std::array<uint32_t, 2> sizes{};
        const auto result = elements_hs_event_layout_v1(static_cast<uint32_t>(kind), index, status,
            reinterpret_cast<unsigned char*>(key.data()), reinterpret_cast<unsigned char*>(value.data()), key.size(), sizes.data());
        if (result == 0) return;
        if ((result != 1 && result != 2 && result != 257 && result != 258) ||
            sizes[0] > key.size() || sizes[1] > value.size()) throw std::runtime_error("Haskell event layout evaluation failed");
        append(index, std::string_view(key.data(), sizes[0]), (result & 255) == 2 ?
            std::optional<std::string_view>{std::string_view(value.data(), sizes[1])} : std::nullopt);
        if (result & 256) return;
    }
}

std::string EventIdentity(EventIdentityKind kind, const std::string& hash, uint64_t number, uint32_t status)
{
    if (hash.size() > 64) throw std::length_error("Haskell event identity hash exceeds bounds");
    elements_hs_runtime_init();
    std::array<char, 128> output{};
    const auto size = elements_hs_event_identity_v1(static_cast<uint32_t>(kind),
        reinterpret_cast<unsigned char*>(const_cast<char*>(hash.data())), hash.size(), number, status,
        reinterpret_cast<unsigned char*>(output.data()), output.size());
    if (size < 0 || static_cast<size_t>(size) > output.size()) throw std::runtime_error("Haskell event identity evaluation failed");
    return {output.data(), static_cast<size_t>(size)};
}

static int64_t PegEventResult(int64_t result)
{
    constexpr std::array<const char*, 5> errors{{
        "withdrawal bundle event must contain exactly one lifecycle state",
        "withdrawal bundle lifecycle state must be an object",
        "deposit contains an invalid negative or zero numeric field",
        "normalized withdrawal event has an unknown lifecycle status",
        "withdrawal bundle has conflicting succeeded and failed events",
    }};
    if (result < -5 || result > 3) throw std::runtime_error("Haskell peg event evaluation failed");
    if (result < 0) throw std::runtime_error(errors[-result - 1]);
    return result;
}

int64_t PegEvent(PegEventKind kind, int64_t a, int64_t b, int64_t c)
{
    elements_hs_runtime_init();
    return PegEventResult(elements_hs_peg_event_v1(static_cast<uint32_t>(kind), a, b, c));
}

int64_t WithdrawalStatus(int64_t state, const std::string& status)
{
    if (status.size() > UINT32_MAX) throw std::runtime_error("withdrawal status exceeds FFI bounds");
    elements_hs_runtime_init();
    return PegEventResult(elements_hs_withdrawal_status_v1(state,
        reinterpret_cast<unsigned char*>(const_cast<char*>(status.data())), static_cast<uint32_t>(status.size())));
}

bool LiveEvidence(LiveEvidencePhase phase, PegFields read, void* context,
    const std::string& parse_error, std::string& error)
{
    elements_hs_runtime_init();
    const std::function<int32_t(uint32_t,int64_t*)> reader = [&](uint32_t step, int64_t* fields) {
        return read ? read(context, step, fields) : -2;
    };
    const int32_t result = ReadBoundAdmission<int32_t,-2>(elements_hs_live_evidence_v3,
        reader, static_cast<uint32_t>(phase));
    constexpr std::array<const char*, 37> errors{{
        "configured sidechain slot is out of range",
        "sidechain network does not match the configured identity",
        "mainchain genesis does not match the configured network",
        "mainchain blockchain info is missing",
        "mainchain network does not match the configured network",
        "mainchain signet challenge does not match the configured network",
        "mainchain is not fully synchronized",
        "enforcer network does not match the configured mainchain",
        "enforcer tip is not synchronized with the canonical mainchain tip",
        "mainchain deposit block header is missing",
        "mainchain deposit block is no longer confirmed",
        "mainchain deposit block height changed",
        "mainchain deposit block hash is missing or malformed",
        "mainchain deposit block hash changed",
        "current CTIP outpoint is not unspent on the canonical mainchain",
        "current CTIP outpoint is not confirmed",
        "current CTIP value does not match the enforcer",
        "CTIP state contains an invalid value or sequence",
        "CTIP sequence predates the confirmed deposit",
        "CTIP outpoint does not match the deposit at the same sequence",
        "sidechain entry must be an object",
        "enforcer returned duplicate sidechain slot",
        "expected sidechain slot is not active",
        "sidechain activation height is not active at the enforcer tip",
        "sidechain declaration identity does not match the configured slot",
        "GetTwoWayPegData block must be an object",
        "GetTwoWayPegData events must be an array",
        "GetTwoWayPegData event must be an object",
        "deposit event must be an object",
        "duplicate confirmed deposit event for outpoint",
        "confirmed deposit value does not match the sidechain claim",
        "deposit sequence number is negative",
        "confirmed deposit address is not valid for this sidechain network",
        "confirmed deposit outpoint is absent from canonical two-way-peg data",
        "deposit vout is out of range",
        "deposit address is empty",
        "deposit address contains non-printable bytes",
    }};
    if (result < -1 || result > static_cast<int32_t>(errors.size()) || (result == -1 && parse_error.empty()))
        throw std::runtime_error("Haskell live evidence evaluation failed");
    if (result) error = result == -1 ? parse_error : errors[result - 1];
    return result == 0;
}

static bool LegacyClaimResult(int32_t result, std::string& error)
{
    if (result < 0 || result > 2) throw std::runtime_error("Haskell legacy claim evaluation failed");
    if (result) error = result == 1 ? "historical drivechain checkpoint witness does not match its immutable value"
                                  : "historical drivechain checkpoint destination is invalid for this network";
    return result == 0;
}

uint64_t CountMatches(uint64_t count, const std::function<bool(uint64_t)>& matches)
{
    const std::function<bool(uint32_t,uint64_t)> read = [&](uint32_t, uint64_t index) { return matches(index); };
    const auto result = ReadBoundAdmission<int32_t,-1>(elements_hs_count_matches_v1,read,count);
    if (result < 0) throw std::runtime_error("Haskell match scan failed");
    return result;
}

int DepositMatch(int64_t slot, int64_t amount, int64_t bound, bool has_address, const std::function<int64_t(uint32_t)>& fact)
{
    return CheckedStatus(ReadBoundAdmission<int64_t,-1>(elements_hs_deposit_match_v1,fact,slot,amount,bound,has_address),
        9,"Haskell raw deposit match failed");
}











int M6Id(uint64_t outputs, uint64_t inputs, int64_t previous, int64_t maximum, bool has_slot,
    const std::function<int64_t(uint32_t,uint64_t)>& action)
{
    return CheckedStatus(ReadBoundAdmission<int64_t,-1>(elements_hs_m6_id_v1,action,outputs,inputs,previous,maximum,has_slot),
        6,"Haskell M6 id preparation failed");
}







bool TreasuryDelta(int64_t previous, int64_t current, int64_t claimed, int64_t maximum)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_treasury_delta_v1(previous,current,claimed,maximum),1,
        "Haskell treasury delta failed") == 1;
}

bool DepositPreflight(uint32_t rule, int64_t amount, int64_t bound)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_deposit_preflight_v1(rule, amount, bound);
    if (result != 0 && result != 1) throw std::runtime_error("Invalid Haskell deposit preflight result");
    return result == 1;
}

bool DepositMessageMatches(uint32_t kind, const std::string& message)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_deposit_broadcast_message_v1(kind, message.size(),
        reinterpret_cast<unsigned char*>(const_cast<char*>(message.data()))),1,
        "Invalid Haskell deposit message result") == 1;
}


static bool PredicateResult(int code, const char* invalid, const char* failed)
{
    if (code == -2) throw std::runtime_error(invalid);
    return CheckedStatus(code,1,failed) == 0;
}

static bool RunDepositFlow(uint32_t start, const std::function<bool(DepositVerifyStep)>& action)
{
    const std::function<bool(uint32_t)> read = [&](uint32_t step) { return action(static_cast<DepositVerifyStep>(step)); };
    return PredicateResult(ReadBoundAdmission<int64_t,-1>(elements_hs_deposit_run_v1,read,0,start),
        "Haskell deposit flow action invalid","Haskell deposit verification failed");
}

uint32_t ParentReplayStore(ReplayStoreFlow kind, const std::function<int64_t(uint32_t)>& action)
{
    return CheckedStatus(ReadBoundAdmission<int64_t,-1>(elements_hs_parent_replay_run_v1,
        action,static_cast<uint32_t>(kind)),3,"Haskell parent replay store evaluation failed");
}

bool ParentReplayChoose(const std::array<std::function<bool()>,3>& actions)
{
    return ParentReplayStore(ReplayStoreFlow::BRANCH_CHOICE, [&](uint32_t step) -> uint32_t {
        if (step < 1 || step > actions.size()) throw std::logic_error("invalid branch choice action");
        return actions[step-1]();
    });
}

static void RunPegFlow(uint32_t kind, const std::function<bool(uint32_t)>& action)
{
    if (!PredicateResult(ReadBoundAdmission<int64_t,-1>(elements_hs_deposit_run_v1,action,kind,0),
        "Haskell peg event action invalid","Haskell peg event flow failed"))
        throw std::runtime_error("Haskell peg event flow failed");
}

int BmmWorkBid(uint32_t hashes, int64_t height, int64_t fees, int64_t work, int64_t reserve,
    int64_t requested, const std::function<int64_t(uint32_t)>& rate, std::array<int64_t,4>& fields)
{
    std::array<int64_t,4> result{};
    const int code = CheckedStatus(ReadBoundAdmission<int64_t,-1>(elements_hs_bmm_work_bid_v1,
        rate,hashes,height,fees,work,reserve,requested,MAX_MONEY,result.data()),5,"Haskell BMM work bid failed");
    fields = result;
    return code;
}

void WithdrawalStatusFlow(const std::function<bool(uint32_t)>& action)
{
    RunPegFlow(1, action);
}

void L1NormalizationFlow(const std::function<bool(uint32_t)>& action)
{
    RunPegFlow(2, action);
}

void SidechainEventFlow(const std::function<bool(uint32_t)>& action)
{
    RunPegFlow(3, action);
}

void L1LocationFlow(const std::function<bool(uint32_t)>& action)
{
    RunPegFlow(4, action);
}

static int32_t RunPegRead(uint32_t mode, uint32_t kind, uint64_t limit, const std::function<uint64_t(uint32_t)>& read)
{
    const std::function<int32_t(uint32_t,uint64_t*)> action = [&](uint32_t step, uint64_t* fields) {
        fields[0] = read(step);
        return 1;
    };
    return ReadBoundAdmission<int32_t,-1>(elements_hs_peg_read_run_v1,action,mode,kind,limit);
}

bool PegSchema(PegSchemaKind kind, uint64_t limit, const std::function<uint64_t(uint32_t)>& read)
{
    return CheckedStatus(RunPegRead(0,static_cast<uint32_t>(kind),limit,read),1,"Haskell peg schema evaluation failed") == 0;
}

void ReadWhen(bool present, const std::function<void()>& read)
{
    PegSchema(PegSchemaKind::GUARDED, 0, [&](uint32_t step) -> uint64_t {
        if (step == 1) return present;
        read();
        return 1;
    });
}

static int64_t ReadReplayRecord(uint32_t kind, uint32_t flags, int64_t value, uint64_t first, uint64_t second)
{
    elements_hs_runtime_init();
    return elements_hs_parent_replay_record_v1(kind,flags,value,first,second);
}

uint32_t ParentReplaySchema(uint32_t rule, uint32_t unique_version, uint32_t reproposal_version)
{
    const auto version = ReadReplayRecord(0, rule, 0, unique_version, reproposal_version);
    if (version < 0) throw std::invalid_argument("unknown parent replay withdrawal history rule");
    return version;
}

bool ParentReplayRecord(ReplayRecordKind kind, uint32_t flags, int64_t value, uint64_t first, uint64_t second)
{
    const auto result = ReadReplayRecord(static_cast<uint32_t>(kind), flags, value, first, second);
    if (result < 0 || result > 1) throw std::runtime_error("Haskell parent replay record evaluation failed");
    return result == 1;
}

OutputTotalMode SelectOutputTotalMode(bool deferred, bool per_asset, bool explicit_asset)
{
    return static_cast<OutputTotalMode>(CheckedStatus(ReadReplayRecord(
        25, deferred | (per_asset << 1) | (explicit_asset << 2), 0, 0, 0), 3, "Haskell output total mode failed"));
}

DepositRouting SelectDepositRoute(uint64_t count, bool legacy_marker, bool native_marker, bool configured_slot)
{
    const auto plan = CheckedStatus(ReadReplayRecord(
        30, legacy_marker | (native_marker << 1) | (configured_slot << 2), 0, count, 0), 0xb04, "Haskell deposit routing failed");
    if ((plan & 255) > 4) throw std::runtime_error("Invalid Haskell deposit route");
    return {static_cast<DepositRoute>(plan & 255),static_cast<uint32_t>(plan >> 8)};
}

bool RejectParentResult(bool invalid, bool unavailable)
{
    return CheckedStatus(ReadReplayRecord(26, invalid | (unavailable << 1), 0, 0, 0),
        1, "Haskell parent result admission failed") == 1;
}





bool RunDepositAuthentication(const std::function<bool(DepositVerifyStep)>& action)
{
    return RunDepositFlow(61, action);
}

bool RunCtipRead(const std::function<bool(DepositVerifyStep)>& action)
{
    return RunDepositFlow(77, action);
}

static bool DepositStateResult(int32_t result, const std::string& decode_error, std::string& error)
{
    constexpr std::array<const char*, 11> errors{{
        "historical drivechain checkpoint cannot overwrite authenticated CTIP state",
        "", // Preserve the upstream decoding error verbatim.
        "drivechain deposit has no authenticated prior CTIP state",
        "drivechain deposit evidence is stale or does not extend the authenticated CTIP state",
        "cannot connect drivechain deposit over missing authenticated CTIP state",
        "cannot connect drivechain deposit over stale CTIP state",
        "cannot disconnect drivechain deposit without authenticated CTIP state",
        "historical drivechain checkpoint CTIP state is inconsistent during disconnect",
        "drivechain deposit CTIP state is inconsistent during disconnect",
        "historical drivechain checkpoint is not in its immutable L1 parent block",
        "drivechain deposit evidence anchor does not match sidechain block L1 parent",
    }};
    if (result < 0 || result > static_cast<int32_t>(errors.size())) throw std::runtime_error("Haskell deposit state evaluation failed");
    if (result) error = result == 2 ? decode_error : errors[result - 1];
    return result == 0;
}

uint32_t DepositStateFacts(bool present, bool matches, const std::string& decode_error)
{
    return uint32_t{present} | (uint32_t{!decode_error.empty()} << 1) | (uint32_t{matches} << 2);
}


bool RunDepositStateWorkflow(DepositWorkflow kind, const std::function<uint32_t(DepositVerifyStep)>& action,
    const std::string& decode_error, std::string& error)
{
    const std::function<int64_t(uint32_t)> read = [&](uint32_t step) -> int64_t {
        if (step >= 83 && step <= 93) {
            DepositStateResult(step-82, decode_error, error);
            return 1;
        }
        return action(static_cast<DepositVerifyStep>(step));
    };
    return PredicateResult(ReadBoundAdmission<int64_t,-1>(elements_hs_deposit_run_v1, read,
        uint32_t{5}, static_cast<uint32_t>(kind)), "Haskell deposit action invalid", "Haskell deposit state workflow failed");
}




bool ReadPersistedCtip(uint32_t facts, int64_t amount, const std::function<int32_t(uint32_t)>& read,
    EvidenceDecode decode, void* context, std::string& error)
{
    const auto result = ReadAdmission<int32_t,-1>([&](HsFunPtr callback, void* cursor) {
        return elements_hs_persisted_ctip_workflow_v1(facts,amount,callback,cursor,reinterpret_cast<HsFunPtr>(decode),context);
    },read);
    constexpr std::array<const char*,4> errors{{
        "persisted drivechain CTIP state has invalid asset or value encoding",
        "persisted drivechain CTIP state script is malformed",
        "persisted drivechain CTIP state payload is invalid",
        "persisted drivechain CTIP state payload cannot be decoded"}};
    return ExchangeResult(result,errors,error,"Haskell persisted CTIP workflow failed");
}


static bool DepositEvidenceResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 6> errors{{
        "drivechain deposit witness does not contain deterministic v2 evidence",
        "drivechain deposit evidence field is empty or exceeds its consensus bound",
        "drivechain deposit transaction encoding or txid is invalid",
        "drivechain deposit sequence or header encoding is non-canonical",
        "drivechain deposit sequence transition is invalid",
        "drivechain deposit header chain length is invalid",
    }};
    return ExchangeResult(result, errors, error, "Haskell deposit evidence evaluation failed");
}

bool DepositEvidence(std::span<const std::vector<unsigned char>> stack, const unsigned char* prevout,
    TransactionHash hash_transaction, EvidenceDecode decode, void* context, std::string& error)
{
    elements_hs_runtime_init();
    BorrowedStack borrowed{stack};
    return DepositEvidenceResult(elements_hs_deposit_evidence_v1(MAX_BLOCK_SERIALIZED_SIZE, stack.size(),
        borrowed.sizes.data(), borrowed.fields.data(), const_cast<unsigned char*>(prevout),
        reinterpret_cast<HsFunPtr>(hash_transaction), reinterpret_cast<HsFunPtr>(decode), context),error);
}

bool ParseDeterministicDeposit(uint64_t inputs, uint64_t index, uint64_t witnesses,
    std::span<const std::vector<unsigned char>> stack, const unsigned char* asset,
    const unsigned char* genesis, const unsigned char* prevout, TransactionHash hash_transaction,
    EvidenceDecode decode, void* context, const NativeWorkflow& native, std::string& error)
{
    BorrowedStack borrowed{stack};
    const auto result = ReadWorkflow(elements_hs_deposit_parsing_v1,native,inputs,index,witnesses,
        MAX_MONEY,MAX_BLOCK_SERIALIZED_SIZE,static_cast<uint32_t>(stack.size()),
        borrowed.sizes.data(),borrowed.fields.data(),const_cast<unsigned char*>(asset),
        const_cast<unsigned char*>(genesis),const_cast<unsigned char*>(prevout),
        reinterpret_cast<HsFunPtr>(hash_transaction),reinterpret_cast<HsFunPtr>(decode),context);
    if (result == -2) return DepositEvidenceResult(-1,error);
    if (result == -3) return DepositProofResult(-1,error);
    if (result == -4) throw std::runtime_error("Haskell destination evaluation failed");
    if (result == -5) throw std::runtime_error("Haskell deposit witness evaluation failed");
    if (result > 0x100 && result <= 0x106) return DepositEvidenceResult(result-0x100,error);
    if (result > 0x200 && result <= 0x207) return DepositProofResult(result-0x200,error);
    if (result == 0x301 || result == 0x302) {
        error = result == 0x301 ? "deposit transaction does not commit a valid sidechain destination"
            : "deposit transaction contains multiple valid sidechain destinations";
        return false;
    }
    constexpr const char* errors[]{"drivechain deposit input index is out of range",
        "drivechain deposit evidence contains malformed transaction or merkle proof data"};
    return ExchangeResult(result,errors,error,"Haskell deposit parsing failed");
}

static bool AuthenticatedDepositResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 8> errors{{
        "drivechain deposit transaction must contain exactly one input",
        "drivechain deposit transaction has an invalid input witness count",
        "drivechain deposit input does not match the authenticated outpoint",
        "drivechain deposit witness does not match the authenticated deposit",
        "drivechain deposit transaction must contain one credit output and at most one fee output",
        "drivechain deposit outputs must use explicit native asset values",
        "drivechain deposit destination script does not match enforcer data",
        "drivechain deposit output value and fee do not equal the authenticated deposit value",
    }};
    return ExchangeResult(result, errors, error, "Haskell authenticated deposit evaluation failed");
}


bool RunDepositClaim(DepositClaimWorkflow kind, uint64_t inputs, uint64_t index, uint64_t witnesses,
    uint64_t outputs, std::span<const std::vector<unsigned char>> stack, const unsigned char* asset,
    const unsigned char* genesis, const unsigned char* prevout, TransactionHash hash_transaction,
    const NativeWorkflow& native, std::string& error)
{
    BorrowedStack borrowed{stack};
    const auto result = ReadWorkflow(elements_hs_deposit_claim_v1,native,static_cast<uint32_t>(kind),
        inputs,index,witnesses,outputs,MAX_MONEY,MAX_BLOCK_SERIALIZED_SIZE,static_cast<uint32_t>(stack.size()),
        borrowed.sizes.data(),borrowed.fields.data(),const_cast<unsigned char*>(asset),
        const_cast<unsigned char*>(genesis),const_cast<unsigned char*>(prevout),reinterpret_cast<HsFunPtr>(hash_transaction));
    if (result == -5) throw std::runtime_error("Haskell deposit witness evaluation failed");
    switch (kind) {
    case DepositClaimWorkflow::CHECKPOINT:
        if (result < 0 || result > 1) throw std::runtime_error("Haskell checkpoint lookup failed");
        return result == 0;
    case DepositClaimWorkflow::LEGACY: return LegacyClaimResult(result,error);
    case DepositClaimWorkflow::TRANSACTION: return AuthenticatedDepositResult(result,error);
    default: throw std::logic_error("invalid deposit claim workflow");
    }
}

int32_t DepositWitness(std::span<const std::vector<unsigned char>> stack, uint32_t mode,
    const unsigned char* asset, const unsigned char* genesis, const unsigned char* prevout,
    TransactionHash hash_transaction, int64_t& value)
{
    elements_hs_runtime_init();
    BorrowedStack borrowed{stack};
    const auto result = elements_hs_deposit_witness_v1(MAX_MONEY, MAX_BLOCK_SERIALIZED_SIZE, mode,
        stack.size(), borrowed.sizes.data(), borrowed.fields.data(), const_cast<unsigned char*>(asset),
        const_cast<unsigned char*>(genesis), const_cast<unsigned char*>(prevout),
        reinterpret_cast<HsFunPtr>(hash_transaction), &value);
    if (result < 0 || result > 3) throw std::runtime_error("Haskell deposit witness evaluation failed");
    return result;
}

static bool DepositOutputsResult(int32_t result, std::string& error)
{
    constexpr std::array<const char*, 8> errors{{
        "Drivechain deposit transactions cannot mix deposit and legacy pegin inputs.",
        "Drivechain deposit transactions must contain exactly one drivechain pegin input.",
        "Drivechain deposit inputs cannot contain an asset issuance.",
        "Invalid drivechain deposit witness while checking outputs.",
        "Drivechain deposit claim script must be OP_TRUE.",
        "BIP300 deposit commits to an invalid Elements destination address.",
        "The committed deposit recipient must receive the exact explicit pegged-asset amount.",
        "Drivechain deposit transaction must contain exactly one recipient output.",
    }};
    return ExchangeResult(result, errors, error, "Haskell deposit output evaluation failed");
}

bool RunNativeRecipient(NativeRecipient kind, int64_t amount, std::string_view source, const NativeWorkflow& native)
{
    const auto result = ReadWorkflow(elements_hs_native_recipient_v1,native,static_cast<uint32_t>(kind),
        MAX_MONEY,amount,source.size(),reinterpret_cast<unsigned char*>(const_cast<char*>(source.data())));
    if (result < 0 || result > 3) throw std::runtime_error("Haskell native deposit recipient failed");
    if (kind == NativeRecipient::CONSTRUCT && result)
        throw std::invalid_argument("invalid native deposit destination or value");
    if (kind == NativeRecipient::ENCODE && result)
        throw std::invalid_argument(result == 2 ? "drivechain deposit destination exceeds 128 bytes"
            : "invalid drivechain deposit address or fee");
    return result == 0;
}

bool CheckNativeDeposit(const CTransaction& tx, uint64_t index, bool canonical,
    const unsigned char* asset, const unsigned char* genesis, TransactionHash hash_transaction,
    const NativeWorkflow& native, std::string& error)
{
    std::vector<uint64_t> offsets{0};
    std::vector<uint32_t> sizes;
    std::vector<unsigned char*> fields, prevouts;
    // Only pointer/length metadata crosses here; witness parsing stays lazy.
    for (size_t i = 0; i < std::min(tx.vin.size(),tx.witness.vtxinwit.size()); ++i) {
        BorrowedStack stack{tx.witness.vtxinwit[i].m_pegin_witness.stack};
        sizes.insert(sizes.end(),stack.sizes.begin(),stack.sizes.end());
        fields.insert(fields.end(),stack.fields.begin(),stack.fields.end());
        offsets.push_back(sizes.size());
        prevouts.push_back(const_cast<unsigned char*>(tx.vin[i].prevout.hash.ToUint256().begin()));
    }
    const auto result = ReadWorkflow(elements_hs_native_outputs_v1,native,uint32_t{canonical},
        tx.vin.size(),index,tx.witness.vtxinwit.size(),tx.vout.size(),MAX_MONEY,MAX_BLOCK_SERIALIZED_SIZE,
        offsets.data(),sizes.data(),fields.data(),prevouts.data(),const_cast<unsigned char*>(asset),
        const_cast<unsigned char*>(genesis),reinterpret_cast<HsFunPtr>(hash_transaction));
    if (result == -5) throw std::runtime_error("Haskell deposit witness evaluation failed");
    if (result > 0x100 && result <= 0x108) return DepositOutputsResult(result-0x100,error);
    if (result > 0x200 && result <= 0x208) return AuthenticatedDepositResult(result-0x200,error);
    if (canonical && result == 3) return false;
    constexpr const char* errors[]{"Drivechain deposit input or witness index is out of range.",
        "Committed Elements fee must be less than the authenticated deposit value."};
    return ExchangeResult(result,errors,error,"Haskell native deposit output workflow failed");
}

int32_t TreasurySlot(uint32_t script, uint32_t opcode)
{
    elements_hs_runtime_init();
    const auto result = elements_hs_treasury_slot_v1(script, opcode);
    if (result < -1 || result > 255) throw std::runtime_error("Haskell treasury evaluation failed");
    return result;
}

bool TreasuryMatches(std::span<const unsigned char> script, uint32_t opcode, int32_t expected)
{
    elements_hs_runtime_init();
    return CheckedStatus(elements_hs_treasury_match_v1(expected,opcode,script.size(),
        const_cast<unsigned char*>(script.data())),1,"Haskell treasury matching failed") == 1;
}


bool WithdrawalBytes(WithdrawalOp op, std::span<const unsigned char> input,
                     std::vector<unsigned char>& output, std::string* error)
{
    elements_hs_runtime_init();
    output.clear();
    if (error) error->clear();
    if (op == WithdrawalOp::WALLET_TRANSPORT || op == WithdrawalOp::JOURNAL_LEGACY) {
        output = WithdrawalTransport(input, op == WithdrawalOp::JOURNAL_LEGACY);
        return true;
    }
    if (input.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("Haskell withdrawal input too large");
    std::array<unsigned char, 256> reply{};
    const auto size = elements_hs_withdrawal_bytes_v1(static_cast<uint32_t>(op), MAX_MONEY,
        const_cast<unsigned char*>(input.data()), input.size(), reply.data(), reply.size());
    if (size < 1 || size > static_cast<int32_t>(reply.size()) || reply[0] > 1)
        throw std::runtime_error("Haskell withdrawal byte evaluation failed");
    if (reply[0]) {
        if (error) error->assign(reply.begin() + 1, reply.begin() + size);
        return false;
    }
    constexpr std::array<std::pair<int, int>, 35> lengths{{
        {45, 173}, {9, 136}, {74, 74}, {69, 69}, {0, 0}, {8, 8}, {8, 8},
        {45, 173}, {17, 144}, {124, 251}, {16, 16}, {0, 60}, {134, 134}, {18, 18}, {134, 134}, {39, 39},
        {0, 0}, {8, 8}, {2, 2}, {2, 2}, {8, 8}, {8, 8}, {0, 0}, {4, 255}, {73, 73}, {12, 12}, {4, 185}, {8, 128}, {0, 0}, {9, 9}, {4, 255}, {1, 1}, {4, 255}, {0, 0}, {0, 0},
    }};
    const auto command = static_cast<uint32_t>(op) - 1;
    if (command >= lengths.size() || size - 1 < lengths[command].first || size - 1 > lengths[command].second)
        throw std::runtime_error("Haskell withdrawal reply has invalid length");
    if (op == WithdrawalOp::EXTRACT_ETHEREUM_CLAIM && size != 1 && size != 61)
        throw std::runtime_error("Haskell withdrawal claim reply has invalid length");
    output.assign(reply.begin() + 1, reply.begin() + size);
    return true;
}



std::vector<unsigned char> WithdrawalTransport(std::span<const unsigned char> transaction, bool strip_marker)
{
    elements_hs_runtime_init();
    if (transaction.size() > std::numeric_limits<int32_t>::max() - 3)
        throw std::length_error("Haskell withdrawal transport input too large");
    std::vector<unsigned char> reply(transaction.size() + 3);
    const auto size = elements_hs_withdrawal_bytes_v1(static_cast<uint32_t>(strip_marker ? WithdrawalOp::JOURNAL_LEGACY : WithdrawalOp::WALLET_TRANSPORT), MAX_MONEY,
        const_cast<unsigned char*>(transaction.data()), transaction.size(), reply.data(), reply.size());
    if (size < 1 || size != static_cast<int32_t>(reply.size()) - (strip_marker ? 4 : 0) || reply[0] != 0)
        throw std::runtime_error("Haskell withdrawal transport evaluation failed");
    reply.resize(size);
    reply.erase(reply.begin());
    return reply;
}



WithdrawalBundleAdmission AdmitWithdrawalBundle(bool busy, const unsigned char* current, const unsigned char* requested)
{
    std::array<unsigned char,65> input{};
    input[0] = busy;
    std::copy_n(current, 32, input.begin() + 1);
    std::copy_n(requested, 32, input.begin() + 33);
    std::vector<unsigned char> output;
    if (!WithdrawalBytes(WithdrawalOp::BUNDLE_ADMISSION, input, output, nullptr) ||
        output[0] > 1 || output[1] > 1) throw std::runtime_error("Haskell withdrawal bundle admission failed");
    return {output[0] != 0, output[1] != 0};
}
} // namespace drivechain::haskell
