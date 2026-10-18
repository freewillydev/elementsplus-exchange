// Preserved native decoder orchestration for differential tests only. Nested
// profile codecs are shared with Haskell; this checks ordering, publication and
// error propagation, not an independent implementation of those nested codecs.
static constexpr std::array<unsigned char,16> REFERENCE_FROZEN_MARKET{'E','C','X','-','U','S','D','D','-','P','E','R','P',0,0,0};
static uint256 ReferenceFrozenHash(const drivechain::haskell::CustodyHash& effect, uint32_t kind, const std::vector<unsigned char>& bytes)
{
    const auto hash=effect(kind,bytes);
    uint256 result;
    std::copy(hash.begin(),hash.end(),result.begin());
    return result;
}
static bool ReferenceFrozenKey(const drivechain::haskell::CustodyHash& effect,const uint256& key)
{
    return effect(3,{key.begin(),32})[0]==1;
}
struct ReferenceFrozenConfiguration
{
    bool direct_price{false};
    uint256 chain_id;
    uint256 ecx_asset_id;
    uint256 usdd_asset_id;
    uint256 policy_asset_id;
    uint256 state_authority_asset_id;
    uint256 availability_scheme_hash;
    uint256 availability_registry_hash;
    uint256 truthcoin_program_id;
    uint256 matcher_genesis_receipt_hash;
    uint256 forced_action_domain;
    uint256 deposit_inbox_domain;
    uint256 collateral_vault_script_sha256;
    uint256 collateral_vault_covenant_cmr;
    uint256 bond_asset_id;
    uint256 deployment_commitment;
    uint256 inventory_script_sha256;
    uint256 queue_script_sha256;
    uint256 staging_template_commitment;
    uint256 staging_renderer_domain;
    uint256 staging_internal_key;
    uint8_t staging_tapleaf_version{0};
    uint256 staging_process_cmr;
    uint256 staging_refund_cmr;
    uint32_t refund_minimum_parent_blocks{0};
    uint256 insurance_script_sha256;
    uint256 insurance_reserve_covenant_cmr;
    uint256 burn_script_sha256;
    uint256 bond_inbox_domain;
    uint256 custody_receipt_codec_hash;
    uint32_t inbox_inclusion_blocks{0};
    uint32_t inbox_max_bundle_bytes{0};
    uint32_t inbox_max_entries_per_block{0};
    uint32_t inbox_max_unique_witness_bytes_per_block{0};
    uint32_t inbox_max_unique_transaction_bytes_per_block{0};
    uint32_t inbox_max_pending_per_transition{0};
    uint32_t inbox_max_consumed_per_transition{0};
    uint32_t redemption_max_queue_entries{0};
    uint32_t matcher_execution_inclusion_parent_blocks{0};
    uint256 ecx_btc_program_id;
    uint256 usdd_usd_program_id;
    uint256 ecx_btc_redemption_covenant;
    uint256 ecx_btc_source_checkpoint;
    uint256 usdd_usd_redemption_covenant;
    uint256 usdd_usd_source_checkpoint;
    uint64_t maximum_conversion_age_seconds{0};
    uint32_t maximum_conversion_proof_bytes{0};
    uint32_t recursive_proof_marker_bytes{0};
    uint64_t fixed_supply_atoms{0};
    uint64_t redemption_delay_parent_blocks{0};
};

class ReferenceFrozenCursor
{
private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_offset{0};

public:
    explicit ReferenceFrozenCursor(const std::vector<unsigned char>& bytes) : m_bytes(bytes) {}

    bool Bytes(unsigned char* output, size_t count)
    {
        if (count > m_bytes.size() - std::min(m_offset, m_bytes.size())) return false;
        std::copy(m_bytes.begin() + m_offset, m_bytes.begin() + m_offset + count, output);
        m_offset += count;
        return true;
    }

    bool Finished() const { return m_offset == m_bytes.size(); }
};

static bool ReferenceDecodeFrozenConfigurationV18(
    const std::vector<unsigned char>& bytes,
    ReferenceFrozenConfiguration& decoded,
    std::string& error, const drivechain::haskell::CustodyHash& effect)
{
    error.clear();
    if (bytes.size() != 1977) {
        error = "canonical FrozenConfigurationV2/V18 must be exactly 1977 bytes";
        return false;
    }
    ReferenceFrozenCursor cursor(bytes);
    uint256 truth_chain, truth_branch, truth_template, truth_lmsr;
    uint32_t truth_min_confirmations{0};

    const auto fail = [&](const char* reason) {
        error = std::string("noncanonical FrozenConfigurationV2/V18: ") + reason;
        return false;
    };

    const auto nonzero=[](const auto& profile,size_t offset) {
        return std::any_of(profile.begin()+offset,profile.begin()+offset+32,[](auto byte) { return byte!=0; });
    };
    std::array<unsigned char,178> base_profile;
    if (!cursor.Bytes(base_profile.data(),base_profile.size()) ||
        (base_profile[0]!=5 && base_profile[0]!=6) || base_profile[1]!=3 ||
        !std::equal(REFERENCE_FROZEN_MARKET.begin(),REFERENCE_FROZEN_MARKET.end(),base_profile.begin()+34) ||
        !nonzero(base_profile,2) || !nonzero(base_profile,50) || !nonzero(base_profile,82) ||
        !nonzero(base_profile,114) || !nonzero(base_profile,146)) return fail("outer/base identity");
    const uint8_t outer_version=base_profile[0];
    const std::array<uint256*,5> base_hashes{&decoded.chain_id,&decoded.ecx_asset_id,&decoded.usdd_asset_id,
        &decoded.policy_asset_id,&decoded.state_authority_asset_id};
    for (size_t i=0;i<base_hashes.size();++i) std::copy_n(base_profile.data()+(i==0 ? 2 : 18+i*32),32,base_hashes[i]->begin());

    std::array<unsigned char,73> checkpoint_profile;
    std::array<unsigned char,64> checkpoint_identities;
    if (!cursor.Bytes(checkpoint_profile.data(),checkpoint_profile.size()) ||
        !drivechain::haskell::ExchangeCheckpointProfile(false,checkpoint_profile,
            std::span<const unsigned char,32>{decoded.policy_asset_id.begin(),32},checkpoint_identities))
        return fail("USDD checkpoint profile");

    std::vector<unsigned char> risk(41);
    if (!cursor.Bytes(risk.data(),risk.size()) || risk != drivechain::haskell::ExchangeGenesisState(
        drivechain::haskell::GenesisCodec::RISK_PROFILE,0,0,{})) return fail("risk profile");

    /* FrozenConfigurationV1 permits a generic nonzero availability identity,
     * but the V2 proof relation accepts only the concrete threshold codec.
     * Reject it here during activation decoding instead of admitting a
     * configuration that can never produce an accepted V2 successor. */
    std::array<unsigned char,71> availability_profile;
    const auto scheme=ReferenceFrozenHash(effect,0,drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::AVAILABILITY_SCHEME,0,0,{}));
    if (!cursor.Bytes(availability_profile.data(),availability_profile.size()) ||
        availability_profile[0]!=1 || !nonzero(availability_profile,1) || !nonzero(availability_profile,33) ||
        !std::equal(scheme.begin(),scheme.end(),availability_profile.begin()+1) ||
        availability_profile[65]!=3 || availability_profile[66]!=5 || ReadBE32(availability_profile.data()+67)!=16777216)
        return fail("availability profile");
    std::copy_n(availability_profile.data()+1,32,decoded.availability_scheme_hash.begin());
    std::copy_n(availability_profile.data()+33,32,decoded.availability_registry_hash.begin());

    std::array<unsigned char,390> truth_profile;
    std::array<unsigned char,164> truth_fields;
    if (!cursor.Bytes(truth_profile.data(),truth_profile.size()) ||
        !drivechain::haskell::ExchangeTruthcoinProfile(truth_profile,truth_fields))
        return fail("Truthcoin authentication profile");
    std::array<uint256*,5> truth_hashes{&truth_chain,&truth_branch,&truth_template,&truth_lmsr,&decoded.truthcoin_program_id};
    for (size_t i=0;i<truth_hashes.size();++i) std::copy_n(truth_fields.data()+i*32,32,truth_hashes[i]->begin());
    truth_min_confirmations=ReadBE32(truth_fields.data()+160);

    if (!cursor.Bytes(checkpoint_profile.data(),checkpoint_profile.size()) ||
        !drivechain::haskell::ExchangeCheckpointProfile(true,checkpoint_profile,
            std::span<const unsigned char,32>{decoded.policy_asset_id.begin(),32},checkpoint_identities))
        return fail("Truthcoin anchor deployment");

    std::array<unsigned char,221> oracle_profile;
    std::array<uint64_t,2> prices;
    if (!cursor.Bytes(oracle_profile.data(),oracle_profile.size()) ||
        !drivechain::haskell::ExchangeOracleProfile(truth_min_confirmations,oracle_profile,
            std::array<const unsigned char*,4>{truth_chain.begin(),truth_branch.begin(),truth_template.begin(),truth_lmsr.begin()},prices))
        return fail("hybrid oracle profile");
    const bool direct_price{outer_version == 6};
    decoded.direct_price = direct_price;
    if (direct_price && (decoded.policy_asset_id != decoded.ecx_asset_id ||
        prices[0] != UINT64_C(100000000) || prices[1] != UINT64_C(100000000)))
        return fail("direct native price lane");

    /* The generic V1 matcher type permits 1..144 blocks.  The transition
     * relation and live source-inbox lane both freeze the V2 profile to six,
     * so the activation decoder mirrors that reachable relation exactly. */
    static_assert(ecx::FORCED_INCLUSION_BLOCKS==6);
    std::array<unsigned char,85> matcher_profile;
    if (!cursor.Bytes(matcher_profile.data(),matcher_profile.size())) return fail("central matcher profile");
    const bool signer_valid=effect(3,{matcher_profile.data()+9,32})[0]==1;
    if (matcher_profile[0]!=1 || !signer_valid || ReadBE64(matcher_profile.data()+41)==UINT64_MAX ||
        !nonzero(matcher_profile,49) || ReadBE32(matcher_profile.data()+81)!=6)
        return fail("central matcher profile");
    std::copy_n(matcher_profile.data()+49,32,decoded.matcher_genesis_receipt_hash.begin());

    std::array<unsigned char,100> accumulator_profile;
    if (!cursor.Bytes(accumulator_profile.data(),accumulator_profile.size()) ||
        !nonzero(accumulator_profile,0) || !nonzero(accumulator_profile,32) || !nonzero(accumulator_profile,64) ||
        std::equal(accumulator_profile.begin(),accumulator_profile.begin()+32,accumulator_profile.begin()+32) ||
        ReadBE32(accumulator_profile.data()+96)==0 || ReadBE32(accumulator_profile.data()+96)>64)
        return fail("base accumulator profile");
    const std::array<uint256*,3> accumulator_hashes{&decoded.forced_action_domain,&decoded.deposit_inbox_domain,&decoded.collateral_vault_script_sha256};
    for (size_t i=0;i<accumulator_hashes.size();++i) std::copy_n(accumulator_profile.data()+i*32,32,accumulator_hashes[i]->begin());

    if (!drivechain::haskell::ExchangeConfigurationIdentities(false,bytes,error)) return false;

    std::array<unsigned char,485> bond_profile;
    const auto custody_codec=ReferenceFrozenHash(effect,1,drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::CUSTODY_RECEIPT,0,0,{}));
    if (!cursor.Bytes(bond_profile.data(),bond_profile.size()) ||
        !drivechain::haskell::ExchangeBondProfile(bond_profile,std::span<const unsigned char,32>{custody_codec.begin(),32}))
        return fail("bond/covenant identities");
    const std::array<uint256*,15> bond_hashes{&decoded.collateral_vault_covenant_cmr,
        &decoded.bond_asset_id,&decoded.deployment_commitment,&decoded.inventory_script_sha256,
        &decoded.queue_script_sha256,&decoded.staging_template_commitment,&decoded.staging_renderer_domain,
        &decoded.staging_internal_key,&decoded.staging_process_cmr,&decoded.staging_refund_cmr,
        &decoded.insurance_script_sha256,&decoded.insurance_reserve_covenant_cmr,&decoded.burn_script_sha256,
        &decoded.bond_inbox_domain,&decoded.custody_receipt_codec_hash};
    for (size_t i=0;i<bond_hashes.size();++i)
        std::copy_n(bond_profile.data()+i*32+(i>=8 ? 1 : 0)+(i>=10 ? 4 : 0),32,bond_hashes[i]->begin());
    decoded.staging_tapleaf_version=bond_profile[256];
    decoded.refund_minimum_parent_blocks=ReadBE32(bond_profile.data()+321);

    const auto descriptor = drivechain::haskell::ExchangeInboxEntry(
        drivechain::haskell::InboxCodec::STAGING_DESCRIPTOR, {decoded.staging_tapleaf_version},
        {decoded.staging_renderer_domain.begin(), decoded.staging_internal_key.begin(),
         decoded.staging_process_cmr.begin(), decoded.staging_refund_cmr.begin()});
    if (ReferenceFrozenHash(effect,2,descriptor) !=
            decoded.staging_template_commitment ||
        !ReferenceFrozenKey(effect,decoded.staging_internal_key))
        return fail("staging descriptor commitment");

    std::array<unsigned char,260> tail;
    if (!cursor.Bytes(tail.data(),tail.size())) return fail("bond inbox/matcher limits");
    if (!drivechain::haskell::ExchangeFrozenTail(direct_price,tail,error)) return false;
    if (!cursor.Finished())
        return fail("recursive proof/bond constants or trailing bytes");
    const std::array<uint32_t*,9> limits{&decoded.inbox_inclusion_blocks,&decoded.inbox_max_bundle_bytes,
        &decoded.inbox_max_entries_per_block,&decoded.inbox_max_unique_witness_bytes_per_block,
        &decoded.inbox_max_unique_transaction_bytes_per_block,&decoded.inbox_max_pending_per_transition,
        &decoded.inbox_max_consumed_per_transition,&decoded.redemption_max_queue_entries,&decoded.matcher_execution_inclusion_parent_blocks};
    for (size_t i=0;i<limits.size();++i) *limits[i]=ReadBE32(tail.data()+i*4);
    const std::array<uint256*,6> conversions{&decoded.ecx_btc_program_id,&decoded.usdd_usd_program_id,
        &decoded.ecx_btc_redemption_covenant,&decoded.ecx_btc_source_checkpoint,
        &decoded.usdd_usd_redemption_covenant,&decoded.usdd_usd_source_checkpoint};
    for (size_t i=0;i<conversions.size();++i) std::copy_n(tail.data()+36+i*32,32,conversions[i]->begin());
    decoded.maximum_conversion_age_seconds=ReadBE64(tail.data()+228);
    decoded.maximum_conversion_proof_bytes=ReadBE32(tail.data()+236);
    decoded.recursive_proof_marker_bytes=ReadBE32(tail.data()+240);
    decoded.fixed_supply_atoms=ReadBE64(tail.data()+244);
    decoded.redemption_delay_parent_blocks=ReadBE64(tail.data()+252);

    return drivechain::haskell::ExchangeConfigurationIdentities(true,bytes,error);
}

static std::array<std::vector<unsigned char>,8> ReferenceFrozenGroups(const ReferenceFrozenConfiguration& d)
{
    using Bytes=std::vector<unsigned char>;
    std::array<Bytes,8> groups;
    const auto hashes=[](std::initializer_list<const uint256*> values) {
        Bytes result;
        for (const auto* value : values) result.insert(result.end(),value->begin(),value->end());
        return result;
    };
    groups[0]=hashes({&d.chain_id,&d.ecx_asset_id,&d.usdd_asset_id,&d.policy_asset_id,&d.state_authority_asset_id});
    groups[1]=hashes({&d.availability_scheme_hash,&d.availability_registry_hash});
    groups[2]=hashes({&d.truthcoin_program_id});
    groups[3]={static_cast<unsigned char>(d.direct_price)};
    groups[4]=hashes({&d.matcher_genesis_receipt_hash});
    groups[5]=hashes({&d.forced_action_domain,&d.deposit_inbox_domain,&d.collateral_vault_script_sha256});
    groups[6]=hashes({&d.collateral_vault_covenant_cmr,&d.bond_asset_id,&d.deployment_commitment,&d.inventory_script_sha256,
        &d.queue_script_sha256,&d.staging_template_commitment,&d.staging_renderer_domain,&d.staging_internal_key,
        &d.staging_process_cmr,&d.staging_refund_cmr,&d.insurance_script_sha256,&d.insurance_reserve_covenant_cmr,
        &d.burn_script_sha256,&d.bond_inbox_domain,&d.custody_receipt_codec_hash});
    groups[6].push_back(d.staging_tapleaf_version);
    TestPushU32Be(groups[6],d.refund_minimum_parent_blocks);
    for (auto value : {d.inbox_inclusion_blocks,d.inbox_max_bundle_bytes,d.inbox_max_entries_per_block,
        d.inbox_max_unique_witness_bytes_per_block,d.inbox_max_unique_transaction_bytes_per_block,d.inbox_max_pending_per_transition,
        d.inbox_max_consumed_per_transition,d.redemption_max_queue_entries,d.matcher_execution_inclusion_parent_blocks})
        TestPushU32Be(groups[7],value);
    const auto conversions=hashes({&d.ecx_btc_program_id,&d.usdd_usd_program_id,&d.ecx_btc_redemption_covenant,
        &d.ecx_btc_source_checkpoint,&d.usdd_usd_redemption_covenant,&d.usdd_usd_source_checkpoint});
    groups[7].insert(groups[7].end(),conversions.begin(),conversions.end());
    TestPushU64Be(groups[7],d.maximum_conversion_age_seconds);
    TestPushU32Be(groups[7],d.maximum_conversion_proof_bytes);
    TestPushU32Be(groups[7],d.recursive_proof_marker_bytes);
    TestPushU64Be(groups[7],d.fixed_supply_atoms);
    TestPushU64Be(groups[7],d.redemption_delay_parent_blocks);
    return groups;
}
