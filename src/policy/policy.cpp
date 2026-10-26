// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include <policy/policy.h>
#include <haskell/bridge.h>
#include <script/ecx_activation_annex.h>

#include <coins.h>
#include <ecx_exchange_state.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <primitives/pak.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pegins.h>
#include <script/usdd_sp1_annex.h>
#include <usdd_sp1_resources.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <chainparams.h> // Peg-out enforcement
#include <chainparamsbase.h>

#include <limits>

// ELEMENTS:
CAsset policyAsset;

#include <algorithm>
#include <cstddef>
#include <optional>
#include <vector>

namespace {

static_assert(OP_RETURN == 106 && OP_PUSHDATA2 == 77);

bool HasSp1Annex(const auto& stack)
{
    return drivechain::haskell::ParentReplayAll<3>({
        [&] { return stack.size() >= 2; },
        [&] { return !stack.back().empty(); },
        [&] { return stack.back()[0] == usdd::SP1_ANNEX_TAG; },
    });
}

struct ActivationPolicyReads {
    const CTransaction& tx;
    size_t input;
    const ecx::ExchangeConsensus* consensus;
    std::array<unsigned char, 32> program{};
    std::array<unsigned char, 364> values{};
    uint32_t operator()(uint32_t step)
    {
        const auto* frozen = consensus ? &consensus->bond_v2 : nullptr;
        switch (step) {
        case 1: return frozen != nullptr;
        case 2: return input == 0;
        case 3: return !tx.witness.vtxinwit.empty();
        case 4: return frozen->activation_enabled;
        case 5: return frozen->identities_frozen;
        case 6: return ecx::ParseActivationAnnex(tx.witness.vtxinwit.at(input).scriptWitness.stack, program, values);
        case 7: return !frozen->incremental_activation_cmr.IsNull();
        case 8: {
            const auto& cmr = tx.witness.vtxinwit.at(input).scriptWitness.stack[2];
            return std::equal(cmr.begin(), cmr.end(), frozen->incremental_activation_cmr.begin());
        }
        case 9: return std::equal(program.begin(), program.end(), frozen->incremental_activation_program_id.begin());
        case 10: return std::equal(values.begin()+4, values.begin()+36, frozen->incremental_activation_configuration_hash.begin());
        case 11: return std::equal(values.begin()+36, values.begin()+68, frozen->configuration_hash.begin());
        case 12: return std::equal(values.begin()+100, values.begin()+132, frozen->incremental_successor_configuration_hash.begin());
        case 13: return std::equal(values.begin()+164, values.begin()+196, tx.GetHash().begin(),
            [](unsigned char a, std::byte b) { return a == std::to_integer<unsigned char>(b); });
        case 14: return std::equal(values.begin()+228, values.begin()+260, consensus->chain_id.begin());
        default: throw std::runtime_error("Unknown activation policy read");
        }
    }
};

bool IsFrozenActivationAnnex(const CTransaction& tx, size_t input,
    const ecx::ExchangeConsensus* consensus)
{
    ActivationPolicyReads facts{tx,input,consensus};
    return drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::ACTIVATION_POLICY,std::ref(facts)) == 0;
}

bool UsddSp1AnnexPolicyEnabled()
{
    const CChainParams& params = Params();
    return drivechain::haskell::AdmitStandardness(drivechain::haskell::StandardnessGate::ANNEX_NETWORK,
        (params.NetworkIDString() == CBaseChainParams::ELEMENTS) |
        (params.GetConsensus().drivechain_slot.has_value() << 1) |
        (params.GetConsensus().enable_usdd_sp1_annex << 2));
}

/**
 * Classify BIP341-shaped annex items before UTXO lookup and return the exact
 * witness weight attributable to one canonical USDD proof annex. The caller
 * can subtract only this amount from total transaction weight; all other
 * witness bytes remain subject to the ordinary standardness cap.
 */
bool GetUsddSp1AnnexPolicyWeight(const CTransaction& tx,
                                 uint64_t& annex_weight,
                                 std::string& reason,
                                 const ecx::ExchangeConsensus* consensus)
{
    annex_weight = 0;
    usdd::ResourceReader resources;
    const auto source = resources.Source();
    std::optional<ActivationPolicyReads> activation;
    const auto result = drivechain::haskell::UsddPolicyWeight(0,
        tx.witness.vtxinwit.size(), [&](uint32_t step, uint64_t input) -> uint64_t {
            if (step==7) return resources.Select(tx);
            if (step >= 17) {
                if (step == 17) activation.emplace(ActivationPolicyReads{tx,input,consensus});
                auto& facts = activation.value();
                if (facts.input != input) throw std::logic_error("Activation policy input changed");
                return facts(step-16);
            }
            const auto& stack = tx.witness.vtxinwit.at(input).scriptWitness.stack;
            switch (step) {
            case 0: return HasSp1Annex(stack);
            case 2: return UsddSp1AnnexPolicyEnabled();
            case 3: return usdd::IsUsddSp1ProofAnnex(stack.back());
            case 4:
                // Keep CompactSize accounting native, including stack-count shrinkage.
                annex_weight = GetSizeOfCompactSize(stack.back().size()) + stack.back().size() +
                    GetSizeOfCompactSize(stack.size()) - GetSizeOfCompactSize(stack.size() - 1);
                return 1;
            default: throw std::runtime_error("Unknown USDD policy read");
            }
        }, /*expanded_activation=*/true,&source);
    static constexpr const char* errors[]{
        "usdd-sp1-annex", "usdd-sp1-annex-shape", "usdd-sp1-annex-controller-cmr",
        "usdd-sp1-annex-guest-program-id", "usdd-sp1-annex-public-values",
        "usdd-sp1-deployment-unconfigured", "usdd-sp1-annex-inbound-domain", "usdd-sp1-annex-multiple"};
    if (result != 0) reason = errors[result-1];
    return result == 0;
}

} // namespace

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kvB.
    // A typical spendable segwit P2WPKH txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kvB.
    if (txout.scriptPubKey.IsUnspendable())
        return 0;

    size_t nSize = GetSerializeSize(txout);
    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    // Note this computation is for spending a Segwit v0 P2WPKH output (a 33 bytes
    // public key + an ECDSA signature). For Segwit v1 Taproot outputs the minimum
    // satisfaction is lower (a single BIP340 signature) but this computation was
    // kept to not further reduce the dust level.
    // See discussion in https://github.com/bitcoin/bitcoin/pull/22779 for details.
    if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        // sum the sizes of the parts of a transaction input
        // with 75% segwit discount applied to the script size.
        nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
    } else {
        nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
    }

    return dustRelayFeeIn.GetFee(nSize);
}

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    if (!txout.nValue.IsExplicit())
        return false; // FIXME
    if (!txout.nAsset.IsExplicit())
        return false;
    if (txout.IsFee())
        return false;
    return (txout.nValue.GetAmount() < GetDustThreshold(txout, dustRelayFeeIn));
}

std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate)
{
    std::vector<uint32_t> dust_outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        // ELEMENTS: check explicitly
        const auto& output = tx.vout[i];
        if (output.nAsset.IsExplicit() && output.nAsset.GetAsset() != ::policyAsset) continue;
        if (IsDust(output, dust_relay_rate)) dust_outputs.push_back(i);
    }
    return dust_outputs;
}

bool IsStandard(const CScript& scriptPubKey, const std::optional<unsigned>& max_datacarrier_bytes, TxoutType& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    whichType = Solver(scriptPubKey, vSolutions);

    const CChainParams& params = Params();
    if (whichType == TxoutType::NONSTANDARD) {
        return false;
    } else if (whichType == TxoutType::MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    } else if (whichType == TxoutType::NULL_DATA && params.GetEnforcePak() &&
            scriptPubKey.IsPegoutScript(Params().ParentGenesisBlockHash()) ) {
        // If we're enforcing pak let through larger peg-out scripts
        return true;
    } else if (whichType == TxoutType::NULL_DATA) {
        if (!max_datacarrier_bytes || scriptPubKey.size() > *max_datacarrier_bytes) {
            return false;
        }
    }

    return true;
}

bool IsStandardTx(
    const CTransaction& tx,
    const std::optional<unsigned>& max_datacarrier_bytes,
    bool permit_bare_multisig,
    const CFeeRate& dust_relay_fee,
    std::string& reason,
    const ecx::ExchangeConsensus* ecx_consensus)
{
    if (tx.version > TX_MAX_STANDARD_VERSION || tx.version < 1) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    std::string bond_inbox_error;
    const bool canonical_bond_inbox_source = drivechain::haskell::ParentReplayAll<3>({
        [&] { return ecx_consensus != nullptr; },
        [&] {
            std::optional<uint64_t> unused;
            // Non-unique scan rejects at the first marker, equivalent to any_of.
            return !drivechain::haskell::ExchangeSpendScan(false, 0, tx.vout.size(), [&](uint64_t index) {
                return drivechain::haskell::BondMarkerPolicy(false, tx.vout[index].scriptPubKey);
            }, unused);
        },
        [&] { return ecx::IsCanonicalBondInboxSourceTransaction(tx, bond_inbox_error, *ecx_consensus); },
    });
    const uint64_t total_weight = GetTransactionWeight(tx);
    uint64_t usdd_annex_weight{0};
    if (drivechain::haskell::ParentReplayAll<2>({
        [&] { return Params().GetConsensus().drivechain_slot.has_value(); },
        [&] { return !GetUsddSp1AnnexPolicyWeight(tx, usdd_annex_weight, reason, ecx_consensus); },
    })) {
        return false;
    }
    // Exceptions are independently bounded and cannot be combined to bypass
    // either application's cap. Ordinary non-annex bytes retain their limit.
    if (!drivechain::haskell::TransactionWeight(canonical_bond_inbox_source,
            total_weight, usdd_annex_weight, MAX_STANDARD_TX_WEIGHT, usdd::SP1_PROOF_TX_MAX_WEIGHT)) {
        reason = "tx-size";
        return false;
    }

    for (const CTxIn& txin : tx.vin)
    {
        // Biggest 'standard' txin involving only keys is a 15-of-15 P2SH
        // multisig with compressed keys (remember the MAX_SCRIPT_ELEMENT_SIZE byte limit on
        // redeemScript size). That works out to a (15*(33+1))+3=513 byte
        // redeemScript, 513+1+15*(73+1)+3=1627 bytes of scriptSig, which
        // we round off to 1650(MAX_STANDARD_SCRIPTSIG_SIZE) bytes for
        // some minor future-proofing. That's also enough to spend a
        // 20-of-20 CHECKMULTISIG scriptPubKey, though such a scriptPubKey
        // is not considered standard.
        if (txin.scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    const CChainParams& params = Params();
    unsigned int nDataOut = 0;
    TxoutType whichType;
    for (size_t output_index = 0; output_index < tx.vout.size(); ++output_index) {
        const CTxOut& txout = tx.vout[output_index];
        if (!::IsStandard(txout.scriptPubKey, max_datacarrier_bytes, whichType)) {
            std::string ecx_error;
            const bool drivechain_pegout = drivechain::haskell::ParentReplayAll<2>({
                [&] { return ecx_consensus != nullptr; },
                [&] { return txout.scriptPubKey.IsPegoutScript(Params().ParentGenesisBlockHash()); },
            });
            const bool forced_action = drivechain::haskell::ParentReplayAll<2>({
                [&] { return ecx_consensus != nullptr; },
                [&] { return ecx::IsCanonicalForcedActionOutput(tx, output_index, ecx_error, *ecx_consensus); },
            });
            const bool bond_inbox_marker = drivechain::haskell::ParentReplayAll<2>({
                [&] { return canonical_bond_inbox_source; },
                [&] { return drivechain::haskell::BondMarkerPolicy(true, txout.scriptPubKey); },
            });
            if (!drivechain::haskell::AdmitStandardness(drivechain::haskell::StandardnessGate::OUTPUT_EXCEPTIONS,
                    drivechain_pegout | (forced_action << 1) | (bond_inbox_marker << 2))) {
                reason = "scriptpubkey";
                return false;
            }
            whichType = TxoutType::NULL_DATA;
        }

        if (whichType == TxoutType::NULL_DATA) {
            nDataOut++;
        } else if ((whichType == TxoutType::MULTISIG) && (!permit_bare_multisig)) {
            reason = "bare-multisig";
            return false;
        }
    }

    // Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
    if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
        reason = "dust";
        return false;
    }

    // only one OP_RETURN txout is permitted
    if (!params.GetMultiDataPermitted() && nDataOut > 1) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

/**
 * Check transaction inputs to mitigate two
 * potential denial-of-service attacks:
 *
 * 1. scriptSigs with extra data stuffed into them,
 *    not consumed by scriptPubKey (or P2SH script)
 * 2. P2SH scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations
 *
 * Why bother? To avoid denial-of-service attacks; an attacker
 * can submit a standard HASH... OP_EQUAL transaction,
 * which will get accepted into blocks. The redemption
 * script can be anything; an attacker could use a very
 * expensive-to-check-upon-redemption script like:
 *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
 *
 * Note that only the non-witness portion of the transaction is checked here.
 */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase()) {
        return true; // Coinbases don't use vin normally
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        if (tx.vin[i].m_is_pegin) {
            // This deals with p2sh in general only
            continue;
        }

        const CTxOut& prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        std::vector<std::vector<unsigned char> > vSolutions;
        TxoutType whichType = Solver(prev.scriptPubKey, vSolutions);
        if (whichType == TxoutType::NONSTANDARD || whichType == TxoutType::WITNESS_UNKNOWN) {
            // WITNESS_UNKNOWN failures are typically also caught with a policy
            // flag in the script interpreter, but it can be helpful to catch
            // this type of NONSTANDARD transaction earlier in transaction
            // validation.
            return false;
        } else if (whichType == TxoutType::SCRIPTHASH) {
            std::vector<std::vector<unsigned char> > stack;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            if (subscript.GetSigOpCount(true) > MAX_P2SH_SIGOPS) {
                return false;
            }
        }
    }

    return true;
}

bool IsWitnessStandard(
    const CTransaction& tx,
    const CCoinsViewCache& mapInputs,
    const ecx::ExchangeConsensus* ecx_consensus)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    std::string bond_inbox_error;
    const bool canonical_bond_inbox_source = drivechain::haskell::ParentReplayAll<2>({
        [&] { return ecx_consensus != nullptr; },
        [&] { return ecx::IsCanonicalBondInboxSourceTransaction(tx, bond_inbox_error, *ecx_consensus); },
    });

    const usdd::Sp1AnnexResourceUsage resource_usage =
        usdd::GetUsddSp1AnnexResourceUsage(tx);
    if (!drivechain::haskell::AdmitStandardness(drivechain::haskell::StandardnessGate::WITNESS_RESOURCES,
            resource_usage.Flags(), resource_usage.namespace_annexes, usdd::SP1_ANNEXES_PER_BLOCK)) {
        return false;
    }

    bool found_usdd_sp1_annex{false};
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.witness.vtxinwit.size() <= i || tx.witness.vtxinwit[i].scriptWitness.IsNull()) {
            continue;
        }

        const CTxOut &prev = tx.vin[i].m_is_pegin ? GetPeginOutputFromWitness(tx.witness.vtxinwit[i].m_pegin_witness) : mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;

        // witness stuffing detected
        if (prevScript.IsPayToAnchor()) {
            return false;
        }

        bool p2sh = false;
        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            prevScript = CScript(stack.back().begin(), stack.back().end());
            p2sh = true;
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        Span stack{tx.witness.vtxinwit[i].scriptWitness.stack};
        const bool has_annex = HasSp1Annex(stack);
        const bool is_native_taproot = witnessversion == 1 &&
            witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh;
        using namespace drivechain::haskell;
        switch (ParentReplayStore(ReplayStoreFlow::WITNESS_ANNEX, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return has_annex;
            case 2: case 5: return is_native_taproot;
            case 3: return IsFrozenActivationAnnex(tx, i, ecx_consensus);
            case 4: return Params().GetConsensus().drivechain_slot.has_value();
            case 6: return UsddSp1AnnexPolicyEnabled();
            case 7: return found_usdd_sp1_annex;
            case 8: return usdd::IsUsddSp1ProofAnnex(stack.back());
            default: throw std::logic_error("invalid witness annex policy read");
            }
        })) {
        case 0: break;
        case 1: return false;
        case 3: found_usdd_sp1_annex = true; [[fallthrough]];
        case 2: SpanPopBack(stack); break;
        }

        // Check P2WSH standard limits
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            const CScriptWitness& scriptWitness = tx.witness.vtxinwit[i].scriptWitness;
            if (scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                return false;
            size_t sizeWitnessStack = scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                return false;
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    return false;
            }
        }

        if (is_native_taproot) {
            static_assert(TAPROOT_LEAF_MASK == 0xfe && TAPROOT_LEAF_TAPSCRIPT == 0xc4 &&
                TAPROOT_LEAF_TAPSIMPLICITY == 0xbe);
            // Inherited witness checks stay native; only fork extensions cross the ABI.
            if (stack.empty()) return false;
            const auto count = stack.size();
            uint32_t leaf{0};
            size_t script_size{0};
            if (count >= 2) {
                const auto& control = SpanPopBack(stack);
                const auto& script = SpanPopBack(stack);
                if (control.empty()) return false;
                leaf = control[0] & TAPROOT_LEAF_MASK;
                script_size = script.size();
            }
            if (!TaprootWitnessPolicy(has_annex, canonical_bond_inbox_source,
                    count, leaf, script_size, i)) return false;
            if (count >= 2 && leaf == TAPROOT_LEAF_TAPSCRIPT) {
                for (const auto& item : stack) {
                    if (item.size() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) return false;
                }
            }
        }
    }
    return true;
}

bool IsIssuanceInMoneyRange(const CTransaction& tx)
{
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const CAssetIssuance& issuance = tx.vin[i].assetIssuance;
        if (issuance.IsNull()) {
            continue;
        }
        if (issuance.nAmount.IsExplicit() && !MoneyRange(issuance.nAmount.GetAmount())) {
            return false;
        }
        // check the reissuance token is in range
        if (!issuance.nInflationKeys.IsNull() && issuance.nInflationKeys.IsExplicit() && !MoneyRange(issuance.nInflationKeys.GetAmount())) {
            return false;
        }
    }
    return true;
}

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return (std::max(nWeight, nSigOpCost * bytes_per_sigop) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

uint64_t GetSimplicityValidationMilliweight(const CTransaction& tx, uint64_t* cumulative)
{
    static_assert(ANNEX_TAG == 0x50 && TAPROOT_LEAF_MASK == 0xfe &&
        TAPROOT_LEAF_TAPSIMPLICITY == 0xbe && VALIDATION_WEIGHT_OFFSET == 50);
    uint64_t total{cumulative ? *cumulative : 0}, work{0};
    drivechain::haskell::MeasureWork(true, 1, [&](uint64_t) -> const CTransaction& { return tx; }, total, &work);
    if (cumulative) *cumulative = total;
    return work;
}

bool CalculateBmmWorkFeeQuote(
    const CAmount collected_fees,
    const uint64_t simplicity_milliweight,
    const CAmount work_sats_per_kwu,
    const CAmount producer_reserve,
    BmmWorkFeeQuote& quote)
{
    quote = {};
    std::array<int64_t,3> fields{};
    const bool accepted = drivechain::haskell::BmmWorkQuote(
        collected_fees, simplicity_milliweight, work_sats_per_kwu, producer_reserve, fields);
    quote.verification_fee = fields[0];
    quote.producer_reserve = fields[1];
    quote.bid = fields[2];
    return accepted;
}

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx), nSigOpCost, bytes_per_sigop);
}

int64_t GetVirtualTransactionInputSize(const CTransaction& tx, const size_t nIn, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionInputWeight(tx, nIn), nSigOpCost, bytes_per_sigop);
}
