// Test-only pre-migration identity/decoding workflow for behavioral comparisons.
#ifndef ELEMENTS_TEST_CUSTODY_IDENTITY_REFERENCE_H
#define ELEMENTS_TEST_CUSTODY_IDENTITY_REFERENCE_H
namespace custody_identity_reference {
using ecx::CustodyProjection;
using ecx::ExchangeConsensus;
using ecx::BigEndianUint128;
uint256 ReadHash(std::span<const unsigned char> bytes, size_t offset)
{
    uint256 out;
    std::copy_n(bytes.data()+offset,32,out.begin());
    return out;
}
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
bool Identity(const CustodyProjection&,const uint256&,const ExchangeConsensus&);

bool Available(const ExchangeConsensus& consensus)
{
    const auto& p=consensus.custody_successor;
    if (!p.identities_frozen) return false;
    for (const auto* h : {&p.program_id,&p.composition_policy,&p.ecx_configuration,&p.clearing_policy,
            &p.source_configuration,&p.custodian_registry,&p.vault_asset,&p.vault_script,
            &p.transition_cmr,&p.state_node_domain_sha256,&p.forced_source_domain}) if (h->IsNull()) return false;
    return p.program_id!=consensus.swap_successor.program_id &&
        p.program_id!=consensus.bond_v2.incremental_successor_program_id &&
        p.transition_cmr!=consensus.swap_successor.transition_cmr &&
        p.transition_cmr!=consensus.bond_v2.incremental_successor_transition_cmr &&
        Tagged("ECX/linear-ecx-settlement-configuration/mainchain-v2",p.canonical_economics)==p.ecx_configuration &&
        std::equal(p.vault_asset.begin(),p.vault_asset.end(),p.canonical_economics.begin()+50);
}

bool Genesis(const ExchangeConsensus& consensus)
{
    const auto& p=consensus.custody_successor;
    if (!Available(consensus) || !p.genesis_projection || consensus.bond_v2.activation_enabled) return false;
    const auto& initial=*p.genesis_projection;
    auto context=PriorContext(initial);
    context.insert(context.end(),p.genesis_forced_state.begin(),p.genesis_forced_state.end());
    std::vector<unsigned char> domain;
    HashBytes(domain,p.forced_source_domain); HashBytes(domain,p.ecx_configuration);
    return Identity(initial,consensus.genesis_state_root,consensus) &&
        initial.state_outpoint==consensus.genesis_state_outpoint && initial.sequence==0 && initial.profit_lock_insolvent==0 &&
        initial.forced_count==BigEndianUint128{0} && initial.forced_cursor==BigEndianUint128{0} &&
        initial.forced_head==Tagged("ECX/exact-forced-genesis/v3-u128",domain) &&
        std::equal(p.ecx_configuration.begin(),p.ecx_configuration.end(),p.genesis_forced_state.begin()+1) &&
        std::equal(initial.forced_head.begin(),initial.forced_head.end(),p.genesis_forced_state.begin()+33) &&
        std::equal(initial.forced_count.bytes.begin(),initial.forced_count.bytes.end(),p.genesis_forced_state.begin()+65) &&
        drivechain::haskell::ExchangeCustodyCheck(3,{},context);
}

bool Identity(const CustodyProjection& s, const uint256& root, const ExchangeConsensus& consensus)
{
    const auto& p=consensus.custody_successor;
    return Available(consensus) && s.version==CustodyProjection::VERSION &&
        !root.IsNull() && s.exchange_state_root==root && !s.state_outpoint.hash.IsNull() && s.state_outpoint.n==0 && !s.outer_state_root.IsNull() &&
        !s.custody_history_root.IsNull() && s.program_id==p.program_id && s.transition_cmr==p.transition_cmr &&
        s.composition_policy==p.composition_policy && s.ecx_configuration==p.ecx_configuration &&
        s.clearing_policy==p.clearing_policy && s.source_configuration==p.source_configuration &&
        s.custodian_registry==p.custodian_registry && s.vault_asset==p.vault_asset && s.vault_script==p.vault_script &&
        !s.forced_head.IsNull() && !s.forced_processed_root.IsNull() && s.forced_cursor<=s.forced_count &&
        (s.forced_cursor!=s.forced_count || s.forced_processed_root==s.forced_head) && s.profit_lock_insolvent<=1;
}

bool Decode(const std::vector<unsigned char>& annex, const uint256& root,
    CustodyProjection& result, std::string& error, const ExchangeConsensus& consensus)
{
    if (!Available(consensus) || root.IsNull()) {
        error="exact custody profile has no qualified deployment identity"; return false;
    }
    std::array<unsigned char,32> program{},digest{};
    std::array<unsigned char,ECX_SP1_CUSTODY_SUCCESSOR_PUBLIC_VALUES_LEN> v{};
    if (!simplicity_elements_parse_sp1_groth16_v8_custody_successor_annex(annex.data(),annex.size(),program.data(),digest.data(),v.data())) {
        error="exact custody requires canonical annex8/PublicValues25"; return false;
    }
    const auto& p=consensus.custody_successor;
    std::vector<unsigned char> expected(program.begin(),program.end());
    for (const auto* h : {&p.program_id,&p.composition_policy,&p.ecx_configuration,&p.clearing_policy,
            &p.source_configuration,&p.custodian_registry,&p.vault_asset,&p.vault_script}) HashBytes(expected,*h);
    if (!drivechain::haskell::ExchangeCustodyCheck(1,v,expected)) {
        error="custody statement does not match its independent deployment pins"; return false;
    }
    CustodyProjection s;
    s.exchange_state_root=root; s.state_outpoint=COutPoint{Txid::FromUint256(ReadHash(v,100)),0}; s.program_id=p.program_id; s.transition_cmr=p.transition_cmr;
    s.composition_policy=ReadHash(v,4); s.outer_state_root=ReadHash(v,68); s.custody_history_root=ReadHash(v,228);
    s.ecx_configuration=ReadHash(v,260); s.clearing_policy=ReadHash(v,292); s.source_configuration=ReadHash(v,324);
    s.custodian_registry=ReadHash(v,420); s.vault_asset=ReadHash(v,484); s.vault_script=ReadHash(v,516);
    s.forced_head=ReadHash(v,580); s.forced_processed_root=ReadHash(v,612);
    std::copy_n(v.begin()+748,16,s.forced_count.bytes.begin()); std::copy_n(v.begin()+764,16,s.forced_cursor.bytes.begin());
    s.sequence=ReadBE64(v.data()+740); s.controlled_ecx_atoms=ReadBE64(v.data()+700); s.profit_lock_insolvent=v[782];
    if (!Identity(s,root,consensus)) { error="invalid exact custody projection"; return false; }
    result=std::move(s); return true;
}

} // namespace custody_identity_reference
#endif

