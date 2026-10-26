// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <ecx_exchange_state.h>
#include <haskell/bridge.h>
#include <streams.h>
#include <pegins.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pegins.h>
#include <util/check.h>
#include <util/moneystr.h>

bool Consensus::HasOnlyExplicitCreations(const CTransaction& tx)
{
    return drivechain::haskell::AdmitTransaction(drivechain::haskell::TransactionAdmission::EXPLICIT_CREATIONS,tx);
}

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;

    // Even if tx.nLockTime isn't satisfied by nBlockHeight/nBlockTime, a
    // transaction is still considered final if all inputs' nSequence ==
    // SEQUENCE_FINAL (0xffffffff), in which case nLockTime is ignored.
    //
    // Because of this behavior OP_CHECKLOCKTIMEVERIFY/CheckLockTime() will
    // also check that the spending input's nSequence != SEQUENCE_FINAL,
    // ensuring that an unsatisfied nLockTime value will actually cause
    // IsFinalTx() to return false here:
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    assert(prevHeights.size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    bool fEnforceBIP68 = tx.version >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Peg-ins have no output height
        if (txin.m_is_pegin) {
            continue;
        }

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            prevHeights[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = prevHeights[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            const int64_t nCoinTime{Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))->GetMedianTimePast()};
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // Peg-in inputs are segwit-only
        if (tx.vin[i].m_is_pegin) {
            continue;
        }

        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, uint32_t flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    // Note that we only count segwit sigops for peg-in inputs
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        CScript scriptPubKey;
        if (tx.vin[i].m_is_pegin) {
            std::string err;
            // Make sure witness exists and has enough peg-in witness fields for
            // the claim_script
            if (tx.witness.vtxinwit.size() != tx.vin.size() ||
                    tx.witness.vtxinwit[i].m_pegin_witness.stack.size() < 4) {
                continue;
            }
            const auto pegin_witness = tx.witness.vtxinwit[i].m_pegin_witness;
            scriptPubKey = CScript(pegin_witness.stack[3].begin(), pegin_witness.stack[3].end());
        } else {
            const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
            assert(!coin.IsSpent());
            scriptPubKey = coin.out.scriptPubKey;
        }

        const CScriptWitness* pScriptWitness = tx.witness.vtxinwit.size() > i ? &tx.witness.vtxinwit[i].scriptWitness : nullptr;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, scriptPubKey, pScriptWitness, flags);
    }
    return nSigOps;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmountMap& fee_map, std::set<std::pair<uint256, COutPoint>>& setPeginsSpent, std::vector<CCheck*> *pvChecks, const bool cacheStore, bool fScriptChecks, const std::vector<std::pair<CScript, CScript>>& fedpegscripts)
{
    size_t reserved_input{0};
    const auto reserved = drivechain::haskell::ParentReplayStore(
        drivechain::haskell::ReplayStoreFlow::RESERVED_INPUTS, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return g_con_elementsmode;
        case 2: return reserved_input < tx.vin.size();
        case 3: return tx.vin[reserved_input].m_is_pegin;
        case 4: return ecx::IsExchangeStateInternalOutpoint(tx.vin[reserved_input].prevout);
        case 5: return drivechain::IsBmmStateInternalOutpoint(tx.vin[reserved_input].prevout);
        case 6: return drivechain::IsCtipStateInternalOutpoint(tx.vin[reserved_input].prevout);
        case 7: ++reserved_input; return 1;
        default: throw std::logic_error("Invalid Haskell reserved-input step");
        }
    });
    if (reserved == 1) return state.Invalid(TxValidationResult::TX_CONSENSUS,
        "bad-ecx-internal-state-spend", "transaction attempted to spend the reserved ECX chainstate record");
    if (reserved == 2) return state.Invalid(TxValidationResult::TX_CONSENSUS,
        "bad-drivechain-internal-state-spend", "transaction attempted to spend a reserved drivechain chainstate record");
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent",
                         strprintf("%s: inputs missing/spent", __func__));
    }

    std::vector<CTxOut> spent_inputs;
    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        if (tx.vin[i].m_is_pegin) {
            // Check existence and validity of pegin witness
            std::string err;
            bool parent_unavailable{false};
            if (tx.witness.vtxinwit.size() <= i ||
                !IsValidPeginWitness(tx.witness.vtxinwit[i].m_pegin_witness, fedpegscripts,
                                     prevout, err, true, nullptr, &parent_unavailable,
                                     nSpendHeight)) {
                if (parent_unavailable) {
                    return state.Error(strprintf("drivechain parent state unavailable: %s", err));
                }
                return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-pegin-witness", err);
            }
            CAmount deposit_value;
            if (const auto kind = DepositWitnessKind(tx.witness.vtxinwit[i].m_pegin_witness, prevout, 0, deposit_value)) {
                if (kind == 2 ? !CheckDrivechainDepositOutputs(tx, i, err)
                                   : !drivechain::VerifyDeterministicDeposit(tx, i, inputs, err)) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-drivechain-deposit", err);
                }
            }
            std::pair<uint256, COutPoint> pegin = GetPeginSpentKey(tx.witness.vtxinwit[i].m_pegin_witness, prevout);
            if (inputs.IsPeginSpent(pegin)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-double-pegin", strprintf("Double-pegin of %s:%d", prevout.hash.ToString(), prevout.n));
            }
            if (setPeginsSpent.count(pegin)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-double-pegin-in-obj",
                    strprintf("Double-pegin of %s:%d in single tx/block", prevout.hash.ToString(), prevout.n));
            }
            setPeginsSpent.insert(pegin);

            // Tally the input amount.
            spent_inputs.push_back(GetPeginOutputFromWitness(tx.witness.vtxinwit[i].m_pegin_witness));
            const CTxOut& out = spent_inputs.back();
            nValueIn += out.nValue.GetAmount(); // Non-explicit already filtered by IsValidPeginWitness
            if (!MoneyRange(out.nValue.GetAmount())) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
            }
        } else {
            const Coin& coin = inputs.AccessCoin(prevout);
            assert(!coin.IsSpent());

            // If prev is coinbase, check that it's matured
            if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
                return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                    strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
            }
            spent_inputs.push_back(coin.out);
            if (coin.out.nValue.IsExplicit()) {
                nValueIn += coin.out.nValue.GetAmount();
            }
        }
    }

    if (g_con_elementsmode) {
        // Tally transaction fees
        if (!HasValidFee(tx)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-outofrange");
        }

        // Verify that amounts add up.
        if (fScriptChecks && !VerifyAmounts(spent_inputs, tx, pvChecks, cacheStore)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-ne-out", "value in != value out");
        }
        fee_map += GetFeeMap(tx);
        if (!MoneyRange(fee_map)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-block-total-fee-outofrange");
        }
    } else {
        const CAmount value_out = tx.GetValueOutMap()[CAsset()];
        if (nValueIn < value_out) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
        }

        // Tally transaction fees
        const CAmount txfee_aux = nValueIn - value_out;
        if (!MoneyRange(txfee_aux)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-outofrange");
        }

        fee_map[CAsset()] += txfee_aux;
    }

    return true;
}

// Fork-specific ecx_custody_projection adapters.
// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <ecx_exchange_state.h>
#include <ecx_forced_v3_block.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <crypto/common.h>
#include <hash.h>
#include <haskell/bridge.h>
extern "C" {
#include <simplicity/elements/env.h>
}
#include <undo.h>

namespace ecx {
namespace {
void HashBytes(std::vector<unsigned char>& out, const uint256& hash)
{
    out.insert(out.end(),hash.begin(),hash.end());
}
void Number(std::vector<unsigned char>& out, uint64_t value)
{
    const auto offset=out.size(); out.resize(offset+8); WriteBE64(out.data()+offset,value);
}
uint256 Tagged(const char* domain, std::span<const unsigned char> bytes)
{
    auto hash=::TaggedHash(domain);
    hash.write(AsBytes(Span{bytes.data(),bytes.size()}));
    return hash.GetSHA256();
}
uint256 ScriptHash(const CScript& script)
{
    auto hash=HashWriter{};
    hash.write(AsBytes(Span{script.data(),script.size()}));
    return hash.GetSHA256();
}
std::vector<unsigned char> PriorContext(const CustodyProjection& prior)
{
    std::vector<unsigned char> bytes;
    for (const auto* h : {&prior.outer_state_root,&prior.custody_history_root,&prior.forced_processed_root}) HashBytes(bytes,*h);
    bytes.insert(bytes.end(),prior.forced_cursor.bytes.begin(),prior.forced_cursor.bytes.end());
    Number(bytes,prior.sequence); bytes.push_back(prior.profit_lock_insolvent);
    return bytes;
}
bool ExplicitCoin(const CTxOut& out, const uint256& asset, uint64_t value)
{
    return drivechain::haskell::ParentReplayAll<4>({
        [&] { return out.nAsset.IsExplicit(); },
        [&] { return out.nAsset.GetAsset().id==asset; },
        [&] { return out.nValue.IsExplicit() && out.nValue.GetAmount()>=0; },
        [&] { return static_cast<uint64_t>(out.nValue.GetAmount())==value && out.nNonce.IsNull(); },
    });
}
struct CustodyIdentityNative {
    const ExchangeConsensus& consensus;
    const CustodyProjection* projection{nullptr};
    const uint256* root{nullptr};
    const std::vector<unsigned char>* annex{nullptr};
    CustodyProjection* result{nullptr};
    std::string* error{nullptr};

    std::vector<unsigned char> operator()(uint32_t step,uint64_t index,std::span<const unsigned char> bytes) const
    {
        const auto& p=consensus.custody_successor;
        std::vector<unsigned char> out;
        DataStream stream;
        switch(step) {
        case 0:return {static_cast<unsigned char>(p.identities_frozen)};
        case 1:
            for(const auto* h:{&p.program_id,&p.composition_policy,&p.ecx_configuration,&p.clearing_policy,
                &p.source_configuration,&p.custodian_registry,&p.vault_asset,&p.vault_script,
                &p.transition_cmr,&p.state_node_domain_sha256,&p.forced_source_domain}) HashBytes(out,*h);
            return out;
        case 2:
            for(const auto* h:{&consensus.swap_successor.program_id,&consensus.bond_v2.incremental_successor_program_id,
                &consensus.swap_successor.transition_cmr,&consensus.bond_v2.incremental_successor_transition_cmr}) HashBytes(out,*h);
            return out;
        case 3:return {p.canonical_economics.begin(),p.canonical_economics.end()};
        case 4:
            if(index>1) throw std::runtime_error("invalid custody identity hash");
            HashBytes(out,Tagged(index==0 ? "ECX/linear-ecx-settlement-configuration/mainchain-v2" :
                "ECX/exact-forced-genesis/v3-u128",bytes));return out;
        case 5:HashBytes(out,*root);return out;
        case 6: {
            const auto& s=*projection;
            // Observe invalid fields too: the checked disk serializer rejects them
            // before Haskell can preserve the original false-return semantics.
            stream << s.version << s.exchange_state_root << s.state_outpoint << s.outer_state_root
                << s.custody_history_root << s.program_id << s.transition_cmr << s.composition_policy
                << s.ecx_configuration << s.clearing_policy << s.source_configuration << s.custodian_registry
                << s.vault_asset << s.vault_script << s.forced_head << s.forced_processed_root
                << s.forced_count << s.forced_cursor << s.sequence << s.controlled_ecx_atoms << s.profit_lock_insolvent;
            break;
        }
        case 7:return {static_cast<unsigned char>(p.genesis_projection.has_value())};
        case 8:return {static_cast<unsigned char>(consensus.bond_v2.activation_enabled)};
        case 9:stream << consensus.genesis_state_outpoint;break;
        case 10:return {p.genesis_forced_state.begin(),p.genesis_forced_state.end()};
        case 11: {
            std::array<unsigned char,32> program{},digest{};
            std::array<unsigned char,ECX_SP1_CUSTODY_SUCCESSOR_PUBLIC_VALUES_LEN> values{};
            if(!simplicity_elements_parse_sp1_groth16_v8_custody_successor_annex(
                annex->data(),annex->size(),program.data(),digest.data(),values.data())) return {};
            out.assign(program.begin(),program.end());out.insert(out.end(),values.begin(),values.end());return out;
        }
        case 12: {
            if(bytes.size()!=535) throw std::runtime_error("invalid custody projection publication");
            DataStream input{Span{bytes.data(),bytes.size()}};
            CustodyProjection staged;input >> staged;
            if(!input.empty()) throw std::runtime_error("trailing custody projection bytes");
            *result=std::move(staged);return {1};
        }
        case 13:error->assign(bytes.begin(),bytes.end());return {1};
        default:throw std::runtime_error("invalid custody identity effect");
        }
        return {UCharCast(stream.data()),UCharCast(stream.data())+stream.size()};
    }
};
} // namespace

bool CheckCustodyReservedSpendPolicy(const CTransaction& tx,const CBlockIndex* previous,
    std::string& error,const ExchangeConsensus& consensus,
    const std::function<CTransactionRef(const Txid&)>& unconfirmed_parent)
{
    const CustodyProjection* prior=nullptr;
    CTransactionRef parent; // Own each lookup result until Haskell finishes inspecting it.
    const auto outpoint=[](const COutPoint& p) {
        std::vector<unsigned char> out;HashBytes(out,p.hash);
        out.resize(36);WriteBE32(out.data()+32,p.n);return out;
    };
    return drivechain::haskell::RunExchangeSession(drivechain::haskell::ExchangeSession::CUSTODY_RESERVED,
        [&](uint32_t step,uint64_t index,std::span<const unsigned char> bytes)->std::vector<unsigned char> {
            std::vector<unsigned char> out;
            switch(step) {
            case 0:
                out={static_cast<unsigned char>(consensus.custody_successor.activation_enabled),static_cast<unsigned char>(previous!=nullptr)};
                Number(out,previous ? static_cast<int64_t>(previous->nHeight) : 0);Number(out,consensus.activation_height);return out;
            case 1:return {static_cast<unsigned char>(previous && previous->ecxCustodyProjection.has_value())};
            case 2:return {static_cast<unsigned char>(consensus.custody_successor.genesis_projection.has_value())};
            case 3:
                prior=index==0 ? &previous->ecxCustodyProjection.value() : &consensus.custody_successor.genesis_projection.value();return {1};
            case 4:Number(out,tx.vin.size());return out;
            case 5:return outpoint(tx.vin.at(index).prevout);
            case 6:Number(out,tx.vout.size());return out;
            case 7:return {static_cast<unsigned char>(tx.vout.at(1).nAsset.IsExplicit())};
            case 8:HashBytes(out,tx.vout.at(1).nAsset.GetAsset().id);return out;
            case 9:return {static_cast<unsigned char>(tx.vout.at(1).nValue.IsExplicit())};
            case 10:Number(out,tx.vout.at(1).nValue.GetAmount());return out;
            case 11:return {static_cast<unsigned char>(tx.vout.at(1).nNonce.IsNull())};
            case 12:HashBytes(out,ScriptHash(tx.vout.at(1).scriptPubKey));return out;
            case 13:return {static_cast<unsigned char>(bool(unconfirmed_parent))};
            case 14:
                parent=unconfirmed_parent(tx.vin.at(index).prevout.hash);
                if(parent) {HashBytes(out,parent->GetHash());Number(out,parent->vin.size());}return out;
            case 15:return outpoint(parent->vin.at(index).prevout);
            case 16:error.assign(bytes.begin(),bytes.end());return {1};
            case 19:
                out=outpoint(prior->state_outpoint);HashBytes(out,prior->vault_asset);
                Number(out,prior->controlled_ecx_atoms);HashBytes(out,prior->vault_script);return out;
            default:throw std::runtime_error("invalid custody policy effect");
            }
        });
}

bool CustodySourceAppendBudget(const CBlockIndex& previous,uint64_t parent,uint64_t& budget)
{
    return drivechain::haskell::RunExchangeSession(drivechain::haskell::ExchangeSession::CUSTODY_BUDGET,
        [&](uint32_t step,uint64_t,std::span<const unsigned char> bytes)->std::vector<unsigned char> {
            if(step==17) {
                std::vector<unsigned char> out(previous.swapForcedState.begin(),previous.swapForcedState.end());
                Number(out,parent);return out;
            }
            if(step!=18 || bytes.size()!=8) throw std::runtime_error("invalid custody budget publication");
            budget=ReadBE64(bytes.data());return {1};
        });
}

bool PrepareCustodyHeader(CBlock& block,const CBlockIndex* previous,uint64_t height,uint64_t parent,
    std::string& error,const ExchangeConsensus& consensus)
{
    const auto& p=consensus.custody_successor;
    if (!CustodyGenesisConfigured(consensus)) {error="custody template requires pinned genesis";return false;}
    block.nVersion|=CBlockHeader::SWAP_FORCED_STATE_HF_MASK;
    if (height==static_cast<uint64_t>(consensus.activation_height)) {
        block.swapForcedState=p.genesis_forced_state;block.sourceBacklogOldestParentHeight=0;return true;
    }
    if (!previous || !previous->ecxCustodyProjection) {error="custody template predecessor missing";return false;}
    block.swapForcedState=previous->swapForcedState;
    uint256 proposed_tx,proposed_root;
    std::array<unsigned char,16> proposed_cursor{};
    uint64_t remaining_oldest=previous->sourceBacklogOldestParentHeight;
    if (block.hashExchangeStateRoot!=previous->hashExchangeStateRoot) {
        for (const auto& tx:block.vtx) {
            if (tx->vin.empty() || tx->vin[0].prevout!=previous->ecxCustodyProjection->state_outpoint) continue;
            if (tx->witness.vtxinwit.empty()) {error="custody template transition lacks witness";return false;}
            const auto& stack=tx->witness.vtxinwit[0].scriptWitness.stack;
            if (stack.empty() || stack.back().empty() || stack.back()[0]!=0x50) {error="custody template annex missing";return false;}
            const std::vector<unsigned char> annex(stack.back().begin()+1,stack.back().end());
            CustodyProjection proposed;
            if (!DecodeCustodyProjection(annex,block.hashExchangeStateRoot,proposed,error,consensus)) return false;
            proposed_tx=tx->GetHash();proposed_root=proposed.forced_processed_root;proposed_cursor=proposed.forced_cursor.bytes;
            remaining_oldest=ReadBE64(annex.data()+435+783);
        }
        if (proposed_tx.IsNull()) {error="custody template transition not found";return false;}
    }
    if (!PrepareCustodySourceAppend(block,*previous,CAsset{p.vault_asset},p.canonical_economics,
            std::span<const unsigned char,32>{p.ecx_configuration.begin(),32},height,parent,
            proposed_tx,proposed_root,proposed_cursor,block.swapForcedState,error)) return false;
    const bool prior_remaining = !std::equal(block.swapForcedState.begin()+113,block.swapForcedState.begin()+129,previous->swapForcedState.begin()+65);
    const bool appended = !std::equal(block.swapForcedState.begin()+65,block.swapForcedState.begin()+81,previous->swapForcedState.begin()+65);
    block.sourceBacklogOldestParentHeight=prior_remaining ? remaining_oldest : (appended ? parent : 0);
    std::vector<unsigned char> bytes(previous->swapForcedState.begin(),previous->swapForcedState.end());
    bytes.insert(bytes.end(),block.swapForcedState.begin(),block.swapForcedState.end());
    Number(bytes,previous->sourceBacklogOldestParentHeight);Number(bytes,remaining_oldest);
    Number(bytes,parent);Number(bytes,block.sourceBacklogOldestParentHeight);bytes.push_back(!proposed_tx.IsNull());
    if (!drivechain::haskell::ExchangeCustodyCheck(5,{},bytes)) {error="custody template exceeds forced inclusion deadline";return false;}
    return true; // The normal block validator must still verify all scripts/proofs.
}

bool CustodySuccessorAvailable(const ExchangeConsensus& consensus)
{
    return drivechain::haskell::RunExchangeSession(drivechain::haskell::ExchangeSession::CUSTODY_AVAILABLE,
        CustodyIdentityNative{consensus});
}

bool CustodyGenesisConfigured(const ExchangeConsensus& consensus)
{
    const auto& initial=consensus.custody_successor.genesis_projection;
    return drivechain::haskell::RunExchangeSession(drivechain::haskell::ExchangeSession::CUSTODY_GENESIS,
        CustodyIdentityNative{consensus,initial ? &*initial : nullptr,&consensus.genesis_state_root});
}

bool InitializeCustodyProjection(const CBlock& block, const CCoinsViewCache& view,
    uint64_t height, CustodyProjection& result, std::string& error, const ExchangeConsensus& consensus)
{
    const auto& p=consensus.custody_successor;
    if (!CustodyGenesisConfigured(consensus) || height!=static_cast<uint64_t>(consensus.activation_height) ||
        !block.HasSwapForcedState() || block.swapForcedState!=p.genesis_forced_state ||
        block.hashExchangeStateRoot!=consensus.genesis_state_root) {
        error="fresh custody activation does not match exact pinned genesis and native source state"; return false;
    }
    const auto& initial=*p.genesis_projection;
    const auto state=view.GetCoin(initial.state_outpoint);
    const auto vault=view.GetCoin(COutPoint{initial.state_outpoint.hash,1});
    CScript expected;
    if (!state || !vault || state->IsSpent() || vault->IsSpent() ||
        !ComputeCustodySuccessorScript(consensus,initial.outer_state_root,expected) || state->out.scriptPubKey!=expected ||
        ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,initial.state_outpoint,state->out)!=initial.exchange_state_root ||
        !ExplicitCoin(vault->out,p.vault_asset,initial.controlled_ecx_atoms) || ScriptHash(vault->out.scriptPubKey)!=p.vault_script) {
        error="fresh custody genesis has no exact unspent singleton/vault backing"; return false;
    }
    for (const auto& tx : block.vtx) for (const auto& output : tx->vout) {
        const auto kind=drivechain::haskell::ExchangeForcedV3BlockBytes(2,
            std::span<const unsigned char>{output.scriptPubKey}.first(std::min<size_t>(output.scriptPubKey.size(),14)));
        if (!kind || (*kind)[0]!=0) { error="custody genesis cannot include pending source/cursor markers"; return false; }
    }
    result=initial; return true;
}

bool ComputeCustodySuccessorScript(const ExchangeConsensus& consensus, const uint256& root, CScript& script)
{
    if (!CustodySuccessorAvailable(consensus)) return false;
    // The renderer is shared cryptography, not a shared economic ledger.
    auto renderer=consensus;
    renderer.bond_v2.incremental_successor_transition_cmr=consensus.custody_successor.transition_cmr;
    renderer.bond_v2.incremental_successor_state_node_domain_sha256=consensus.custody_successor.state_node_domain_sha256;
    renderer.bond_v2.keyless_internal_key=consensus.custody_successor.keyless_internal_key;
    return ComputeBondV2IncrementalSuccessorScript(renderer,root,script);
}

bool CheckCustodyProjectionIdentity(const CustodyProjection& s, const uint256& root, const ExchangeConsensus& consensus)
{
    return drivechain::haskell::RunExchangeSession(drivechain::haskell::ExchangeSession::CUSTODY_IDENTITY,
        CustodyIdentityNative{consensus,&s,&root});
}

bool DecodeCustodyProjection(const std::vector<unsigned char>& annex, const uint256& root,
    CustodyProjection& result, std::string& error, const ExchangeConsensus& consensus)
{
    return drivechain::haskell::RunExchangeSession(drivechain::haskell::ExchangeSession::CUSTODY_DECODE,
        CustodyIdentityNative{consensus,nullptr,&root,&annex,&result,&error});
}

bool DeriveCustodyProjectionAfterScripts(const CBlock& block, const CBlockIndex* previous,
    const CBlockUndo& undo, uint64_t height, const uint256& parent_hash,
    uint64_t parent_height, uint64_t parent_mtp, CustodyProjection& result,
    std::string& error, const ExchangeConsensus& consensus)
{
    const auto& p=consensus.custody_successor;
    if (!previous || !previous->ecxCustodyProjection || !block.HasSwapForcedState() ||
        !previous->GetBlockHeader().HasSwapForcedState() ||
        !CheckCustodyProjectionIdentity(*previous->ecxCustodyProjection,previous->hashExchangeStateRoot,consensus)) {
        error="custody successor requires its own verified predecessor and native source header"; return false;
    }
    const auto& prior=*previous->ecxCustodyProjection;
    auto context=PriorContext(prior);
    context.insert(context.end(),previous->swapForcedState.begin(),previous->swapForcedState.end());
    if (!std::equal(prior.ecx_configuration.begin(),prior.ecx_configuration.end(),previous->swapForcedState.begin()+1) ||
        !drivechain::haskell::ExchangeCustodyCheck(3,{},context)) {
        error="custody predecessor processing state differs from actual native header"; return false;
    }
    const COutPoint prior_vault{prior.state_outpoint.hash,1};
    const auto spends_reserved = [&](const CTransaction& candidate) {
        return std::any_of(candidate.vin.begin(),candidate.vin.end(),[&](const auto& input) {
            return input.prevout==prior.state_outpoint || input.prevout==prior_vault;
        });
    };
    std::array<unsigned char,145> next_sources;
    const auto check_backlog = [&](uint64_t remaining_oldest, bool consumed) {
        std::vector<unsigned char> bytes(previous->swapForcedState.begin(),previous->swapForcedState.end());
        bytes.insert(bytes.end(),next_sources.begin(),next_sources.end());
        Number(bytes,previous->sourceBacklogOldestParentHeight); Number(bytes,remaining_oldest);
        Number(bytes,parent_height); Number(bytes,block.sourceBacklogOldestParentHeight);
        bytes.push_back(consumed);
        if (drivechain::haskell::ExchangeCustodyCheck(5,{},bytes)) return true;
        error="custody source backlog age or six-parent forced-inclusion deadline mismatch";
        return false;
    };
    if (block.hashExchangeStateRoot==previous->hashExchangeStateRoot) {
        for (const auto& candidate : block.vtx) if (spends_reserved(*candidate)) {
            error="custody carry cannot spend its reserved singleton or physical vault"; return false;
        }
        if (!DeriveCustodyForcedV3SourceAppend(block,*previous,CAsset{p.vault_asset},p.canonical_economics,
                std::span<const unsigned char,32>{p.ecx_configuration.begin(),32},height,parent_height,nullptr,next_sources,error) ||
            next_sources!=block.swapForcedState) { if(error.empty()) error="custody carry source header mismatch"; return false; }
        if (!check_backlog(previous->sourceBacklogOldestParentHeight,false)) return false;
        result=prior; return true;
    }
    const CTransaction* tx=nullptr; size_t index=0;
    for (size_t i=1;i<block.vtx.size();++i) {
        const auto& candidate=*block.vtx[i];
        if (candidate.vout.empty() || ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,
                COutPoint{candidate.GetHash(),0},candidate.vout[0])!=block.hashExchangeStateRoot) continue;
        if (tx) { error="multiple custody singleton transitions"; return false; }
        tx=&candidate; index=i;
    }
    if (!tx || tx->vin.size()<2 || tx->vout.size()<2 || tx->witness.vtxinwit.empty() ||
        undo.vtxundo.size()!=block.vtx.size()-1 || undo.vtxundo[index-1].vprevout.size()!=tx->vin.size()) {
        error="custody transition lacks exact singleton/vault inputs or consumed-coin context"; return false;
    }
    if (tx->vin[0].prevout!=prior.state_outpoint || tx->vin[1].prevout!=prior_vault) {
        error="custody transition does not consume the persisted state/vault pair"; return false;
    }
    const COutPoint next_state{tx->GetHash(),0}, next_vault{tx->GetHash(),1};
    for (const auto& candidate : block.vtx) {
        if (candidate.get()!=tx && spends_reserved(*candidate)) {
            error="independent reserved custody coin spend"; return false;
        }
        for (const auto& input : candidate->vin) if (input.prevout==next_state || input.prevout==next_vault) {
            error="custody successor pair must remain unspent at this block boundary"; return false;
        }
    }
    const auto& stack=tx->witness.vtxinwit[0].scriptWitness.stack;
    if (stack.size()!=5 || stack[2].size()!=32 || stack[3].size()!=65 ||
        (stack[3][0]&0xfe)!=0xbe || stack[4].empty() || stack[4][0]!=0x50 ||
        !std::equal(p.transition_cmr.begin(),p.transition_cmr.end(),stack[2].begin())) {
        error="custody transition must execute its exact pinned Simplicity proof leaf"; return false;
    }
    const auto& coins=undo.vtxundo[index-1].vprevout;
    CScript before_script,after_script;
    if (!ComputeCustodySuccessorScript(consensus,prior.outer_state_root,before_script) ||
        coins[0].out.scriptPubKey!=before_script ||
        ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,tx->vin[0].prevout,coins[0].out)!=previous->hashExchangeStateRoot ||
        tx->vin[1].prevout!=COutPoint{tx->vin[0].prevout.hash,1} ||
        !ExplicitCoin(coins[1].out,p.vault_asset,prior.controlled_ecx_atoms) ||
        ScriptHash(coins[1].out.scriptPubKey)!=p.vault_script ||
        !ExplicitCoin(tx->vout[1],p.vault_asset,prior.controlled_ecx_atoms) ||
        tx->vout[1].scriptPubKey!=coins[1].out.scriptPubKey) {
        error="custody transition does not spend/recreate its authenticated singleton and physical vault"; return false;
    }
    std::vector<unsigned char> annex(stack[4].begin()+1,stack[4].end());
    CustodyProjection next;
    if (!DecodeCustodyProjection(annex,block.hashExchangeStateRoot,next,error,consensus) ||
        !ComputeCustodySuccessorScript(consensus,next.outer_state_root,after_script) || tx->vout[0].scriptPubKey!=after_script ||
        next.controlled_ecx_atoms!=prior.controlled_ecx_atoms) { if(error.empty()) error="custody successor/vault output mismatch"; return false; }
    HashBytes(context,tx->GetHash()); HashBytes(context,previous->hashExchangeStateRoot); HashBytes(context,parent_hash);
    HashBytes(context,Tagged("ECX/exact-forced-state/v3-u128",previous->swapForcedState));
    Number(context,parent_height); Number(context,parent_mtp); Number(context,height);
    const auto values=std::span<const unsigned char>{annex}.subspan(435);
    if (!drivechain::haskell::ExchangeCustodyCheck(2,values,context)) { error="custody proof does not bind actual predecessor/source/transaction/BMM"; return false; }
    const VerifiedCustodySource receipt{tx->GetHash(),next.forced_processed_root,next.forced_cursor.bytes};
    if (!DeriveCustodyForcedV3SourceAppend(block,*previous,CAsset{p.vault_asset},p.canonical_economics,
            std::span<const unsigned char,32>{p.ecx_configuration.begin(),32},height,parent_height,&receipt,next_sources,error) ||
        next_sources!=block.swapForcedState) { if(error.empty()) error="custody transition source header mismatch"; return false; }
    if (!check_backlog(ReadBE64(values.data()+783),true)) return false;
    result=std::move(next); return true;
}
} // namespace ecx

// Fork-specific ecx_forced_v3 adapters.
#include <algorithm>
#include <crypto/common.h>
#include <ecx_forced_v3.h>
#include <haskell/bridge.h>
#include <primitives/transaction.h>
#include <stdexcept>

#ifdef HAVE_ECX_FORCED_V3_ADMISSION
extern "C" uint32_t ecx_forced_v3_abi_version();
extern "C" int32_t ecx_forced_v3_verify_payload(const uint8_t*, size_t, const uint8_t*,
                                                const uint8_t*, size_t, uint8_t*, size_t);
#endif

namespace ecx {
bool ForcedActionV3BackendAvailable()
{
#ifdef HAVE_ECX_FORCED_V3_ADMISSION
    return ecx_forced_v3_abi_version() == 1;
#else
    return false;
#endif
}

std::vector<unsigned char> ReadForcedActionV3Output(
    const CTransaction& transaction, size_t output, const CAsset& policy_asset,
    std::span<const unsigned char, 259> economics,
    std::span<const unsigned char, 32> economic_hash, std::optional<uint64_t> parent,
    uint32_t step, std::span<const unsigned char> input)
{
        if (!input.empty() && step != 10)
            throw std::logic_error("invalid forced output callback request");
        switch (step) {
        case 0: return {static_cast<unsigned char>(ForcedActionV3BackendAvailable())};
        case 1: return {static_cast<unsigned char>(output < transaction.vout.size())};
        case 2: return {static_cast<unsigned char>(transaction.vout.at(output).nAsset.IsExplicit())};
        case 3: return {static_cast<unsigned char>(transaction.vout.at(output).nAsset.GetAsset() == policy_asset &&
            std::equal(policy_asset.begin(), policy_asset.end(), economics.begin() + 50))};
        case 4: return {static_cast<unsigned char>(transaction.vout.at(output).nValue.IsExplicit())};
        case 5: return {static_cast<unsigned char>(transaction.vout.at(output).nValue.GetAmount() == 0)};
        case 6: return {static_cast<unsigned char>(transaction.vout.at(output).nNonce.IsNull())};
        case 7: return {static_cast<unsigned char>(output >= transaction.witness.vtxoutwit.size() || transaction.witness.vtxoutwit[output].IsNull())};
        case 8: return {economic_hash.begin(), economic_hash.end()};
        case 9: {
            const auto& script = transaction.vout.at(output).scriptPubKey;
            return {script.begin(), script.begin() + std::min<size_t>(script.size(), 4109)};
        }
        case 10: {
            if (input.size() < 40 || input.size() > 4104) throw std::logic_error("invalid forced payload length");
#ifdef HAVE_ECX_FORCED_V3_ADMISSION
            std::vector<unsigned char> reply(51,0);
            if (ecx_forced_v3_verify_payload(economics.data(), economics.size(), economic_hash.data(),
                    input.data(), input.size(), reply.data()+1, 50) == 1) {
                reply[0] = 1;
                return reply;
            }
#endif
            return {0};
        }
        case 11: {
            std::vector<unsigned char> bytes(8);
            WriteLE64(bytes.data(), parent.value());
            return bytes;
        }
        default: throw std::logic_error("invalid forced output read step");
        }
}

static std::optional<std::pair<std::vector<unsigned char>,std::array<unsigned char,50>>> CheckOutput(
    const CTransaction& transaction, size_t output, const CAsset& policy_asset,
    std::span<const unsigned char,259> economics, std::span<const unsigned char,32> economic_hash,
    std::optional<uint64_t> parent, std::string& error)
{
    std::optional<std::pair<std::vector<unsigned char>,std::array<unsigned char,50>>> result;
    using Session = drivechain::haskell::ExchangeSession;
    drivechain::haskell::RunExchangeSession(parent ? Session::FORCED_ADMISSION : Session::FORCED_CANONICAL,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
        if (index) throw std::logic_error("invalid forced output callback index");
        switch (step) {
        case 12: {
            if (input.size() < 90 || input.size() > 4154) throw std::logic_error("invalid forced publication length");
            std::array<unsigned char,50> metadata;
            std::copy(input.end()-50,input.end(),metadata.begin());
            result.emplace(std::vector<unsigned char>(input.begin(),input.end()-50),metadata);
            return {1};
        }
        case 13: error.assign(input.begin(),input.end()); return {1};
        default: return ReadForcedActionV3Output(transaction,output,policy_asset,economics,economic_hash,parent,step,input);
        }
    });
    return result;
}
bool IsCanonicalForcedActionV3Output(const CTransaction& tx,size_t output,const CAsset& asset,
    std::span<const unsigned char,259> economics,std::span<const unsigned char,32> pin,std::string& error)
{
    return CheckOutput(tx,output,asset,economics,pin,std::nullopt,error).has_value();
}
std::optional<VerifiedForcedActionV3> VerifyForcedActionV3Output(const CTransaction& tx,size_t output,const CAsset& asset,
    std::span<const unsigned char,259> economics,std::span<const unsigned char,32> pin,uint64_t parent,std::string& error)
{
    auto checked=CheckOutput(tx,output,asset,economics,pin,parent,error);
    if (!checked) return std::nullopt;
    return VerifiedForcedActionV3(std::move(checked->first),checked->second);
}
} // namespace ecx
