// Test-only pre-migration custody policy. Keep native behavioral evidence independent
// of the new orchestration; pure subrules retain their previously qualified bindings.
#ifndef ELEMENTS_TEST_CUSTODY_POLICY_REFERENCE_H
#define ELEMENTS_TEST_CUSTODY_POLICY_REFERENCE_H
namespace custody_policy_reference {
using ecx::CustodyProjection;
using ecx::ExchangeConsensus;
void Number(std::vector<unsigned char>& out, uint64_t value)
{
    const auto offset=out.size(); out.resize(offset+8); WriteBE64(out.data()+offset,value);
}
uint256 ScriptHash(const CScript& script)
{
    auto hash=HashWriter{};
    hash.write(AsBytes(Span{script.data(),script.size()}));
    return hash.GetSHA256();
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
bool CheckCustodyReservedSpendPolicy(const CTransaction& tx,const CBlockIndex* previous,
    std::string& error,const ExchangeConsensus& consensus,
    const std::function<CTransactionRef(const Txid&)>& unconfirmed_parent)
{
    if (!consensus.custody_successor.activation_enabled || !previous ||
        static_cast<int64_t>(previous->nHeight)+1<consensus.activation_height) return true;
    const CustodyProjection* prior=previous->ecxCustodyProjection ? &*previous->ecxCustodyProjection : nullptr;
    if (!prior && static_cast<int64_t>(previous->nHeight)+1==consensus.activation_height &&
        consensus.custody_successor.genesis_projection) prior=&*consensus.custody_successor.genesis_projection;
    if (!prior) {error="custody reserved-pair policy lacks authenticated predecessor";return false;}
    const COutPoint vault{prior->state_outpoint.hash,1};
    const auto reserved=std::count_if(tx.vin.begin(),tx.vin.end(),[&](const auto& input) {
        return input.prevout==prior->state_outpoint || input.prevout==vault;
    });
    const bool pair=reserved==2 && tx.vin.size()>=2 && tx.vin[0].prevout==prior->state_outpoint && tx.vin[1].prevout==vault;
    const bool recreated=tx.vout.size()>=2 && ExplicitCoin(tx.vout[1],prior->vault_asset,prior->controlled_ecx_atoms) &&
        ScriptHash(tx.vout[1].scriptPubKey)==prior->vault_script;
    // The consensus transition leaves its new pair unspent through the block.
    // Inspect actual unconfirmed parents rather than matching reusable scripts.
    const bool descendant=unconfirmed_parent && std::any_of(tx.vin.begin(),tx.vin.end(),[&](const auto& input) {
        if (input.prevout.n>1) return false;
        const auto parent=unconfirmed_parent(input.prevout.hash);
        return parent && parent->GetHash()==input.prevout.hash && parent->vin.size()>=2 &&
            parent->vin[0].prevout==prior->state_outpoint && parent->vin[1].prevout==vault;
    });
    const std::array<unsigned char,4> facts{static_cast<unsigned char>(reserved!=0),static_cast<unsigned char>(pair),
        static_cast<unsigned char>(recreated),static_cast<unsigned char>(descendant)};
    if (!drivechain::haskell::ExchangeCustodyCheck(7,{},facts)) {
        error="custody reserved singleton/vault spend must preserve the coupled pair";return false;
    }
    return true;
}

bool CustodySourceAppendBudget(const CBlockIndex& previous,uint64_t parent,uint64_t& budget)
{
    std::vector<unsigned char> bytes(previous.swapForcedState.begin(),previous.swapForcedState.end());
    Number(bytes,parent); Number(bytes,0);
    if (!drivechain::haskell::ExchangeCustodyCheck(6,{},bytes)) return false;
    uint64_t low=0,high=64;
    while (low<high) {
        const auto middle=low+(high-low+1)/2;
        WriteBE64(bytes.data()+153,middle);
        if (drivechain::haskell::ExchangeCustodyCheck(6,{},bytes)) low=middle; else high=middle-1;
    }
    budget=low;return true;
}
} // namespace custody_policy_reference
#endif

