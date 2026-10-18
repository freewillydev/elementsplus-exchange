// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <wallet/drivechain_withdrawal.h>
#include <crypto/common.h>
#include <drivechain_withdrawal.h>
#include <hash.h>
#include <haskell/bridge.h>
#include <haskell/bmm_constants.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/bitcoin/transaction.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <stdexcept>
#include <optional>

namespace wallet {
void CheckWithdrawal(WithdrawalCheck check, bool value)
{
    const std::array<unsigned char,2> input{static_cast<unsigned char>(check),value};
    std::vector<unsigned char> output;
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_GUARD_RESULT,input,output,nullptr))
        throw std::runtime_error("Haskell withdrawal guard evaluation failed");
    if (const auto code = static_cast<int32_t>(ReadLE32(output.data())); code != 0)
        throw JSONRPCError(code,std::string(output.begin()+4,output.end()));
}

CAmount ValidateNativePayout(const CScript& destination, CAmount payout)
{
    static_assert(DUST_RELAY_TX_FEE_BITCOIN == 3000);
    std::array<unsigned char,13> input{};
    int version{0};
    std::vector<unsigned char> program, output;
    WriteLE64(input.data(),payout);
    input[12] = destination.IsWitnessProgram(version,program);
    WriteLE32(input.data()+8, static_cast<uint32_t>(GetSerializeSize(Sidechain::Bitcoin::CTxOut(0,destination))));
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_PAYOUT,input,output,nullptr) || output.size()!=12)
        throw std::runtime_error("Haskell native payout evaluation failed");
    const auto code=static_cast<int32_t>(ReadLE32(output.data()));
    if (code == RPC_TYPE_ERROR) throw JSONRPCError(code,"Invalid withdrawal payout amount");
    if (code == RPC_INVALID_PARAMETER) throw JSONRPCError(code,strprintf(
        "Bitcoin withdrawal payout is dust for this destination (minimum %s)",FormatMoney(ReadLE64(output.data()+4))));
    if (code != 0) throw std::runtime_error("Invalid Haskell native payout result");
    return payout;
}

CAmount PrepareNativeBurn(const uint256& parent, const CScript& destination,
    CAmount payout, CAmount fee, CScript& burn)
{
    std::vector<unsigned char> input(16), output;
    WriteLE64(input.data(),payout);
    WriteLE64(input.data()+8,fee);
    input.insert(input.end(),parent.begin(),parent.end());
    input.insert(input.end(),destination.begin(),destination.end());
    burn.clear();
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_BURN_PLAN,input,output,nullptr))
        throw std::runtime_error("Haskell native burn planning failed");
    const auto code=static_cast<int32_t>(ReadLE32(output.data()));
    if (code == RPC_TYPE_ERROR || code == RPC_INVALID_PARAMETER)
        throw JSONRPCError(code,std::string(output.begin()+4,output.end()));
    if (code != 0 || output.size()<12) throw std::runtime_error("Invalid Haskell native burn plan");
    burn.assign(output.begin()+12,output.end());
    return static_cast<CAmount>(ReadLE64(output.data()+4));
}

CAmount LegacyWithdrawalAmount(CAmount payout)
{
    std::array<unsigned char,17> input{};
    input[0] = 2;
    WriteLE64(input.data()+1, payout);
    std::vector<unsigned char> output;
    std::string error;
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_AMOUNT, input, output, &error))
        throw JSONRPCError(RPC_TYPE_ERROR, error);
    return static_cast<CAmount>(ReadLE64(output.data()));
}

uint32_t FindNativeWithdrawalOutput(const CTransaction& tx, const CScript& burn_script,
    const CAsset& asset, const uint256& parent_genesis, CAmount burn, CAmount payout, CAmount fee)
{
    std::vector<unsigned char> input(asset.begin(),asset.end()), output;
    input.insert(input.end(),parent_genesis.begin(),parent_genesis.end());
    input.resize(92);
    WriteLE64(input.data()+64,burn); WriteLE64(input.data()+72,payout); WriteLE64(input.data()+80,fee);
    WriteLE32(input.data()+88,static_cast<uint32_t>(burn_script.size()));
    input.insert(input.end(),burn_script.begin(),burn_script.end());
    for (uint32_t index=0; index<tx.vout.size(); ++index) {
        const auto& candidate=tx.vout[index];
        const size_t offset=input.size();
        input.resize(offset+49);
        WriteLE32(input.data()+offset,index);
        const CAsset actual=candidate.nAsset.IsExplicit() ? candidate.nAsset.GetAsset() : CAsset{};
        std::copy(actual.begin(),actual.end(),input.begin()+offset+4);
        input[offset+36]=candidate.nAsset.IsExplicit(); input[offset+37]=candidate.nValue.IsExplicit();
        input[offset+38]=candidate.nNonce.IsNull();
        input[offset+39]=index>=tx.witness.vtxoutwit.size() || tx.witness.vtxoutwit[index].IsNull();
        WriteLE64(input.data()+offset+40,candidate.nValue.IsExplicit() ? candidate.nValue.GetAmount() : 0);
        input[offset+48]=candidate.scriptPubKey == burn_script;
    }
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::NATIVE_OUTPUT_SELECTION,input,output,nullptr))
        throw std::runtime_error("Haskell native output selection failed");
    const auto code=static_cast<int32_t>(ReadLE32(output.data()));
    if (code == RPC_WALLET_ERROR) throw JSONRPCError(code,std::string(output.begin()+4,output.end()));
    if (code != 0 || output.size()!=8) throw std::runtime_error("Invalid Haskell native output selection");
    return ReadLE32(output.data()+4);
}

namespace {
static std::array<unsigned char,40> WithdrawalInputContext(const COutPoint& outpoint, uint32_t height)
{
    std::array<unsigned char,40> context{};
    std::copy_n(UCharCast(outpoint.hash.begin()),32,context.begin());
    WriteLE32(context.data()+32,outpoint.n);
    WriteLE32(context.data()+36,height);
    return context;
}

DrivechainWithdrawalBundle BuildBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height,
    std::span<const unsigned char> anchor_context)
{
    static_assert(MAX_SCRIPT_SIZE == 10000);
    Sidechain::Bitcoin::CMutableTransaction tx;
    DrivechainWithdrawalBundle result;
    result.bytes = drivechain::haskell::BuildWithdrawalBundle(amount, mainchain_fee,
        payout_script.size(), !withdrawal_outpoint.IsNull(), [&](const auto& plan) -> const std::vector<unsigned char>& {
        tx.version = plan.version;
        for (const auto role : plan.outputs) {
            switch (role) {
            case 0: tx.vout.emplace_back(0, CScript(plan.fee_script.begin(),plan.fee_script.end())); break;
            case 1: tx.vout.emplace_back(0, CScript() << OP_RETURN << ToByteVector(Hash(plan.inputs))); break;
            case 2: tx.vout.emplace_back(plan.payout,payout_script); break;
            case 3: tx.vout.emplace_back(0, CScript(plan.marker.begin(),plan.marker.end())); break;
            default: throw std::logic_error("invalid withdrawal output role");
            }
        }
        VectorWriter{result.no_witness_bytes, 0, TX_NO_WITNESS(tx)};
        result.m6id = tx.GetHash();
        return result.no_witness_bytes;
    }, WithdrawalInputContext(withdrawal_outpoint,sidechain_block_height), anchor_context);
    return result;
}
} // namespace

std::string FindWithdrawalBundleEventStatus(const UniValue& peg_data, const std::string& m6id_hex)
{
    const UniValue& blocks = peg_data["blocks"];
    std::vector<UniValue>::const_iterator block_it, event_it;
    const UniValue *events{nullptr}, *bundle{nullptr}, *m6id{nullptr}, *status{nullptr};
    std::vector<unsigned char> bytes;
    uint256 event_m6id;
    const auto selected = drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_EVENT,
        [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return blocks.isArray();
        case 2: block_it = blocks.getValues().begin(); return 1;
        case 3: return block_it != blocks.getValues().end();
        case 4: events = &(*block_it)["blockInfo"]["events"]; return events->isArray();
        case 5: event_it = events->getValues().begin(); return 1;
        case 6: ++block_it; return 1;
        case 7: return event_it != events->getValues().end();
        case 8: bundle = &(*event_it)["withdrawalBundle"]; return bundle->isObject();
        case 9: m6id = &(*bundle)["m6id"]["hex"]; return m6id->isStr();
        case 10: ++event_it; return 1;
        case 11: bytes = ParseHex(m6id->get_str()); return std::min<size_t>(bytes.size(), UINT32_MAX);
        case 12: std::copy(bytes.begin(), bytes.end(), event_m6id.begin()); return event_m6id.GetHex() == m6id_hex;
        case 13: status = &(*bundle)["event"]; return status->isObject();
        case 14: return !(*status)["submitted"].isNull();
        case 15: return !(*status)["succeeded"].isNull();
        case 16: return !(*status)["failed"].isNull();
        default: throw std::logic_error("invalid withdrawal event step");
        }
    });
    return drivechain::WITHDRAWAL_STATE_NAMES[selected];
}

CScript DecodeDrivechainWithdrawalDestination(const std::string& destination)
{
    static_assert(static_cast<int>(TxoutType::PUBKEY) == 2 && static_cast<int>(TxoutType::PUBKEYHASH) == 3 &&
        static_cast<int>(TxoutType::SCRIPTHASH) == 4 && static_cast<int>(TxoutType::MULTISIG) == 5 &&
        static_cast<int>(TxoutType::WITNESS_V0_SCRIPTHASH) == 7 && static_cast<int>(TxoutType::WITNESS_V0_KEYHASH) == 8 &&
        static_cast<int>(TxoutType::WITNESS_V1_TAPROOT) == 9);
    static_assert(drivechain::NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE == 128);
    CScript script;
    std::string hex, error;
    CTxDestination address;
    TxoutType type{TxoutType::NONSTANDARD};
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::WITHDRAWAL_DESTINATION, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return destination.starts_with("hex:");
        case 2: hex = destination.substr(4); return std::min<size_t>(hex.size(), UINT32_MAX);
        case 3: return IsHex(hex);
        case 4: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "hex: destination must be a nonempty, bounded hexadecimal scriptPubKey");
        case 5: address = DecodeParentDestination(destination, error); return IsValidDestination(address);
        case 6: {
            const auto bytes = ParseHex(hex);
            script = CScript(bytes.begin(), bytes.end()); return 1;
        }
        case 8: script = GetScriptForDestination(address); return 1;
        case 9: return std::min<size_t>(script.size(), UINT32_MAX);
        case 10: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address: " + error);
        case 11: return IsStandard(script, std::nullopt, type);
        case 12: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bitcoin destination must be a standard script of 1..128 bytes");
        case 13: return static_cast<uint32_t>(type);
        case 14: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Bitcoin destination must be a recognized spendable script");
        default: throw std::logic_error("invalid withdrawal destination step");
        }
    });
    return script;
}

DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height)
{
    return BuildBundle(amount, mainchain_fee, payout_script, withdrawal_outpoint,
                       sidechain_block_height, {});
}

DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    CAmount amount, CAmount mainchain_fee, const CScript& payout_script,
    const COutPoint& withdrawal_outpoint, uint32_t sidechain_block_height,
    const uint256& child_genesis, const uint256& previous_child_hash,
    const uint256& exchange_state_root)
{
    std::array<unsigned char,96> anchor_context{};
    std::copy_n(child_genesis.begin(),32,anchor_context.begin());
    std::copy_n(previous_child_hash.begin(),32,anchor_context.begin()+32);
    std::copy_n(exchange_state_root.begin(),32,anchor_context.begin()+64);
    try {
        return BuildBundle(amount, mainchain_fee, payout_script, withdrawal_outpoint,
                           sidechain_block_height, anchor_context);
    } catch (const drivechain::haskell::WithdrawalAnchorError& error) {
        throw JSONRPCError(RPC_MISC_ERROR,error.what());
    }
}
} // namespace wallet
