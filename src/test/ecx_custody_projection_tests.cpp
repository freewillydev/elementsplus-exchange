// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <ecx_exchange_state.h>
#include <ecx_forced_v3_block.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <node/blockstorage.h>
#include <kernel/cs_main.h>
#include <util/signalinterrupt.h>
#include <map>
#include <haskell/bridge.h>
extern "C" {
#include <simplicity/elements/env.h>
}
#include <streams.h>
#include <test/data/ecx_forced_v3_vectors.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <util/strencodings.h>
#include <boost/test/unit_test.hpp>
#include <test/util/custody_policy_reference.h>
#include <test/util/custody_identity_reference.h>

namespace {
struct Setup : BasicTestingSetup {
    const bool old_mode{g_con_ecx_swap_v3};
    Setup() : BasicTestingSetup(ChainTypeMetaFrom("elementsregtest")) { g_con_ecx_swap_v3=true; }
    ~Setup() { g_con_ecx_swap_v3=old_mode; }
};
uint256 H(unsigned char value) { uint256 out; std::fill_n(out.begin(),32,value); return out; }
void Put(std::vector<unsigned char>& out,size_t at,const uint256& h) { std::copy(h.begin(),h.end(),out.begin()+at); }
uint256 Tag(const char* domain,std::span<const unsigned char> bytes) {
    auto hash=::TaggedHash(domain);hash.write(AsBytes(Span{bytes.data(),bytes.size()}));return hash.GetSHA256();
}
struct Fixture {
    ecx::ExchangeConsensus config;
    CTxOut state_coin,vault_coin;
    CBlock genesis;
    Fixture() {
        config.activation_height=1;
        config.genesis_state_outpoint=COutPoint{Txid::FromUint256(H(77)),0};
        config.chain_id.fill(3);config.forced_action_domain.fill(4);config.deposit_inbox_domain.fill(5);
        auto& p=config.custody_successor;p.activation_enabled=true;p.identities_frozen=true;
        p.program_id=H(1);p.composition_policy=H(2);p.clearing_policy=H(3);p.source_configuration=H(4);
        p.custodian_registry=H(5);p.forced_source_domain=H(6);p.transition_cmr=H(7);p.state_node_domain_sha256=H(8);
        const auto economics=ParseHex(ecx_forced_v3_test::economics);
        std::copy(economics.begin(),economics.end(),p.canonical_economics.begin());
        p.ecx_configuration=Tag("ECX/linear-ecx-settlement-configuration/mainchain-v2",economics);
        std::copy_n(economics.begin()+50,32,p.vault_asset.begin());
        const auto key=ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        std::copy(key.begin(),key.end(),p.keyless_internal_key.begin());
        const CScript vault_script=CScript()<<OP_TRUE;
        CSHA256().Write(vault_script.data(),vault_script.size()).Finalize(p.vault_script.begin());
        config.collateral_vault_script=vault_script;config.collateral_vault_script_hash=p.vault_script;
        ecx::CustodyProjection initial;
        initial.state_outpoint=config.genesis_state_outpoint;initial.outer_state_root=H(10);initial.custody_history_root=H(11);
        initial.program_id=p.program_id;initial.transition_cmr=p.transition_cmr;initial.composition_policy=p.composition_policy;
        initial.ecx_configuration=p.ecx_configuration;initial.clearing_policy=p.clearing_policy;initial.source_configuration=p.source_configuration;
        initial.custodian_registry=p.custodian_registry;initial.vault_asset=p.vault_asset;initial.vault_script=p.vault_script;
        std::vector<unsigned char> domain(p.forced_source_domain.begin(),p.forced_source_domain.end());
        domain.insert(domain.end(),p.ecx_configuration.begin(),p.ecx_configuration.end());
        initial.forced_head=initial.forced_processed_root=Tag("ECX/exact-forced-genesis/v3-u128",domain);
        initial.controlled_ecx_atoms=1000;
        p.genesis_forced_state[0]=3;
        std::copy(p.ecx_configuration.begin(),p.ecx_configuration.end(),p.genesis_forced_state.begin()+1);
        std::copy(initial.forced_head.begin(),initial.forced_head.end(),p.genesis_forced_state.begin()+33);
        std::copy(initial.forced_head.begin(),initial.forced_head.end(),p.genesis_forced_state.begin()+81);
        CScript state_script;
        BOOST_REQUIRE(ecx::ComputeCustodySuccessorScript(config,initial.outer_state_root,state_script));
        state_coin=CTxOut{CAsset{H(20)},1,state_script};vault_coin=CTxOut{CAsset{p.vault_asset},1000,vault_script};
        config.genesis_state_root=initial.exchange_state_root=ecx::ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,initial.state_outpoint,state_coin);
        p.genesis_projection=initial;
        genesis.nVersion=4|CBlockHeader::EXCHANGE_STATE_HF_MASK|CBlockHeader::FORCED_INBOX_HF_MASK|
            CBlockHeader::DEPOSIT_INBOX_HF_MASK|CBlockHeader::INBOX_CURSOR_HF_MASK|CBlockHeader::SWAP_FORCED_STATE_HF_MASK;
        genesis.ecxParentHeight=100;genesis.hashExchangeStateRoot=config.genesis_state_root;
        genesis.hashForcedInboxRoot=ecx::ComputeForcedInboxGenesis(config);genesis.hashDepositInboxRoot=ecx::ComputeDepositInboxGenesis(config);
        genesis.swapForcedState=p.genesis_forced_state;
    }
    std::vector<unsigned char> Annex() const {
        const auto& p=config.custody_successor;const auto& prior=*p.genesis_projection;
        std::vector<unsigned char> v(791);WriteBE32(v.data(),25);
        for(size_t n=0;n<21;++n)Put(v,4+32*n,H(n+1));
        Put(v,4,p.composition_policy);Put(v,36,prior.outer_state_root);Put(v,196,prior.custody_history_root);
        Put(v,260,p.ecx_configuration);Put(v,292,p.clearing_policy);Put(v,324,p.source_configuration);
        Put(v,420,p.custodian_registry);Put(v,484,p.vault_asset);Put(v,516,p.vault_script);
        Put(v,580,prior.forced_head);Put(v,612,prior.forced_head);
        for(const auto offset:{676,684,692,708,716,724,732,740})WriteBE64(v.data()+offset,1);
        WriteBE64(v.data()+700,prior.controlled_ecx_atoms);
        std::vector<unsigned char> annex{'E','C','X','S','P','1',0,8,2,1,0};
        annex.insert(annex.end(),p.program_id.begin(),p.program_id.end());
        uint256 digest;CSHA256().Write(v.data(),v.size()).Finalize(digest.begin());
        annex.insert(annex.end(),digest.begin(),digest.end());
        const size_t size=annex.size();annex.resize(size+4);WriteBE32(annex.data()+size,356);
        annex.resize(435,0);annex.insert(annex.end(),v.begin(),v.end());return annex;
    }
};
} // namespace
BOOST_FIXTURE_TEST_SUITE(ecx_custody_projection_tests,Setup)
BOOST_AUTO_TEST_CASE(pinned_genesis_requires_actual_backing_and_independent_profile)
{
    Fixture f;std::string error;
    BOOST_REQUIRE(ecx::CustodyGenesisConfigured(f.config));
    BOOST_CHECK(ecx::CheckForcedV3DeploymentMode(error,&f.config));
    CCoinsView empty;CCoinsViewCache view{&empty};ecx::CustodyProjection result;
    BOOST_CHECK(!ecx::InitializeCustodyProjection(f.genesis,view,1,result,error,f.config));
    view.AddCoin(f.config.genesis_state_outpoint,Coin{f.state_coin,0,false},false);
    view.AddCoin(COutPoint{f.config.genesis_state_outpoint.hash,1},Coin{f.vault_coin,0,false},false);
    BOOST_REQUIRE_MESSAGE(ecx::InitializeCustodyProjection(f.genesis,view,1,result,error,f.config),error);
    auto changed=f.config;changed.custody_successor.ecx_configuration=H(90);
    BOOST_CHECK(!ecx::CustodyGenesisConfigured(changed));
    changed=f.config;changed.custody_successor.genesis_forced_state[81]^=1;
    BOOST_CHECK(!ecx::CustodyGenesisConfigured(changed));
    changed=f.config;changed.bond_v2.activation_enabled=true;
    BOOST_CHECK(!ecx::CustodyGenesisConfigured(changed));
    changed=f.config;changed.custody_successor.genesis_projection.reset();
    BOOST_CHECK(!ecx::CheckForcedV3DeploymentMode(error,&changed));
    BOOST_CHECK(!ecx::CheckForcedV3DeploymentMode(error));
}
BOOST_AUTO_TEST_CASE(carry_preserves_projection_and_rejects_independent_reserved_spend)
{
    Fixture f;CBlockIndex previous{f.genesis};previous.nHeight=1;previous.ecxCustodyProjection=f.config.custody_successor.genesis_projection;
    CBlock block=f.genesis;ecx::CustodyProjection result;std::string error;CBlockUndo undo;
    BOOST_REQUIRE_MESSAGE(ecx::DeriveCustodyProjectionAfterScripts(block,&previous,undo,2,H(30),100,1000,result,error,f.config),error);
    BOOST_CHECK(result.outer_state_root==previous.ecxCustodyProjection->outer_state_root);
    for(uint32_t index:{0,1}) {
        CMutableTransaction spend;spend.vin.emplace_back(COutPoint{f.config.genesis_state_outpoint.hash,index});
        block.vtx={MakeTransactionRef(spend)};
        BOOST_CHECK(!ecx::DeriveCustodyProjectionAfterScripts(block,&previous,undo,2,H(30),100,1000,result,error,f.config));
    }
    block=f.genesis;block.swapForcedState[1]^=1;
    BOOST_CHECK(!ecx::DeriveCustodyProjectionAfterScripts(block,&previous,undo,2,H(30),100,1000,result,error,f.config));
}
BOOST_AUTO_TEST_CASE(reserved_pair_policy_filters_independent_spends_before_template_selection)
{
    Fixture f;CBlockIndex previous{f.genesis};previous.nHeight=1;previous.ecxCustodyProjection=f.config.custody_successor.genesis_projection;
    CMutableTransaction spend;spend.vin.emplace_back(COutPoint{f.config.genesis_state_outpoint.hash,1});
    spend.vout.push_back(f.vault_coin);std::string error;
    BOOST_CHECK(!ecx::CheckCustodyReservedSpendPolicy(CTransaction{spend},&previous,error,f.config));
    bool added=false;uint64_t selected=0;
    BOOST_CHECK(!drivechain::haskell::ExchangeSourcePackage(true,1,[&](uint32_t step,uint64_t)->uint64_t {
        if(step==0)return ecx::CheckCustodyReservedSpendPolicy(CTransaction{spend},&previous,error,f.config);
        if(step==4)return 64;
        if(step==5)added=true;
        return 0;
    },selected,false));
    BOOST_CHECK(!added);BOOST_CHECK_EQUAL(selected,0);
    spend.vin.insert(spend.vin.begin(),CTxIn{f.config.genesis_state_outpoint});
    spend.vout.insert(spend.vout.begin(),f.state_coin);
    BOOST_CHECK(ecx::CheckCustodyReservedSpendPolicy(CTransaction{spend},&previous,error,f.config));
    spend.vout[1].nValue.SetToAmount(999);
    BOOST_CHECK(!ecx::CheckCustodyReservedSpendPolicy(CTransaction{spend},&previous,error,f.config));
    auto legacy=f.config;legacy.custody_successor.activation_enabled=false;
    BOOST_CHECK(ecx::CheckCustodyReservedSpendPolicy(CTransaction{spend},&previous,error,legacy));
    spend.vin={CTxIn{COutPoint{Txid::FromUint256(H(99)),0}}};
    BOOST_CHECK(ecx::CheckCustodyReservedSpendPolicy(CTransaction{spend},&previous,error,f.config));
}
BOOST_AUTO_TEST_CASE(reserved_pair_descendants_cannot_poison_a_transition_package)
{
    Fixture f;CBlockIndex previous{f.genesis};previous.nHeight=1;previous.ecxCustodyProjection=f.config.custody_successor.genesis_projection;
    CMutableTransaction next;next.vin.emplace_back(f.config.genesis_state_outpoint);
    next.vin.emplace_back(COutPoint{f.config.genesis_state_outpoint.hash,1});
    next.vout={f.state_coin,f.vault_coin,f.state_coin};
    const auto transition=MakeTransactionRef(next);std::string error;
    const auto lookup=[&](const Txid& hash) {return hash==transition->GetHash() ? transition : CTransactionRef{};};
    BOOST_REQUIRE(ecx::CheckCustodyReservedSpendPolicy(*transition,&previous,error,f.config,lookup));
    for(uint32_t index:{0,1}) {
        CMutableTransaction child;child.vin.emplace_back(COutPoint{transition->GetHash(),index});child.vout.push_back(f.state_coin);
        BOOST_CHECK(!ecx::CheckCustodyReservedSpendPolicy(CTransaction{child},&previous,error,f.config,lookup));
        const std::array<CTransactionRef,2> package{transition,MakeTransactionRef(child)};
        bool added=false;uint64_t selected=0;
        BOOST_CHECK(!drivechain::haskell::ExchangeSourcePackage(true,package.size(),[&](uint32_t step,uint64_t at)->uint64_t {
            if(step==0)return ecx::CheckCustodyReservedSpendPolicy(*package[at],&previous,error,f.config,lookup);
            if(step==4)return 64;
            if(step==5)added=true;
            return 0;
        },selected,false));
        BOOST_CHECK(!added);
    }
    CMutableTransaction paired;paired.vin.emplace_back(COutPoint{transition->GetHash(),0});
    paired.vin.emplace_back(COutPoint{transition->GetHash(),1});paired.vout={f.state_coin,f.vault_coin};
    BOOST_CHECK(!ecx::CheckCustodyReservedSpendPolicy(CTransaction{paired},&previous,error,f.config,lookup));
    paired.vin={CTxIn{COutPoint{transition->GetHash(),2}}};
    BOOST_CHECK(ecx::CheckCustodyReservedSpendPolicy(CTransaction{paired},&previous,error,f.config,lookup));
    next.vin[0].prevout=COutPoint{Txid::FromUint256(H(98)),0};const auto unrelated=MakeTransactionRef(next);
    paired.vin={CTxIn{COutPoint{unrelated->GetHash(),1}}};
    BOOST_CHECK(ecx::CheckCustodyReservedSpendPolicy(CTransaction{paired},&previous,error,f.config,
        [&](const Txid& hash){return hash==unrelated->GetHash()?unrelated:CTransactionRef{};}));
}
BOOST_AUTO_TEST_CASE(existing_index_namespace_reopens_full_custody_projection)
{
    Fixture f;f.genesis.proof=Params().GenesisBlock().proof;f.genesis.block_height=1;
    CBlockIndex index{f.genesis};index.nHeight=1;
    const uint256 hash=f.genesis.GetHash();index.phashBlock=&hash;
    index.ecxCustodyProjection=f.config.custody_successor.genesis_projection;
    index.ecxCustodyProjection->forced_count.bytes.fill(0xf0);
    index.ecxCustodyProjection->forced_cursor.bytes.fill(0x80);
    index.ecxCustodyProjection->profit_lock_insolvent=1;
    const auto path=m_args.GetDataDirBase()/"custody-format6-reopen";
    {
        node::BlockTreeDB db({.path=path,.cache_bytes=1<<20,.memory_only=false,.wipe_data=false,.obfuscate=false});
        BOOST_REQUIRE(db.WriteBatchSync({},0,{&index}));
    }
    node::BlockTreeDB reopened({.path=path,.cache_bytes=1<<20,.memory_only=false,.wipe_data=false,.obfuscate=false});
    std::map<uint256,std::unique_ptr<CBlockIndex>> loaded;util::SignalInterrupt interrupt;
    LOCK(cs_main);
    BOOST_REQUIRE(reopened.LoadBlockIndexGuts(Params().GetConsensus(),[&](const uint256& id)->CBlockIndex* {
        if(id.IsNull())return nullptr;
        auto [it,inserted]=loaded.try_emplace(id,nullptr);
        if(inserted){it->second=std::make_unique<CBlockIndex>();it->second->phashBlock=&it->first;}
        return it->second.get();
    },interrupt,0));
    const auto& restored=*loaded.at(hash);
    BOOST_REQUIRE(restored.ecxCustodyProjection);BOOST_CHECK(!restored.ecxBondV2Capital);
    BOOST_CHECK(restored.swapForcedState==index.swapForcedState);
    DataStream before,after;before<<*index.ecxCustodyProjection;after<<*restored.ecxCustodyProjection;
    BOOST_CHECK(before.str()==after.str());
    // Rewriting without either projection erases the shared projection key.
    index.ecxCustodyProjection.reset();BOOST_REQUIRE(reopened.WriteBatchSync({},0,{&index}));
    BOOST_CHECK(!reopened.Exists(std::make_pair(uint8_t{'E'},hash)));
}
BOOST_AUTO_TEST_CASE(canonical_projection_is_not_a_proof_and_roundtrips_full_width)
{
    Fixture f;auto annex=f.Annex();ecx::CustodyProjection result;std::string error;
    BOOST_REQUIRE_MESSAGE(ecx::DecodeCustodyProjection(annex,H(70),result,error,f.config),error);
    BOOST_CHECK(result.custody_history_root==H(8));
    for(size_t n=0;n<annex.size();++n) {
        std::vector<unsigned char> truncated(annex.begin(),annex.begin()+n);
        BOOST_CHECK(!ecx::DecodeCustodyProjection(truncated,H(70),result,error,f.config));
    }
    auto changed=f.config;changed.custody_successor.clearing_policy=H(88);
    BOOST_CHECK(!ecx::DecodeCustodyProjection(annex,H(70),result,error,changed));
    // Zero proof bytes only exercise the transport; no proof backend is supplied.
    BOOST_CHECK(!simplicity_elements_verify_sp1_groth16_v8_custody_successor_annex_sha256(
        annex.data(),annex.size(),f.config.custody_successor.program_id.begin(),annex.data()+43,nullptr,nullptr));
    result.forced_count.bytes.fill(0xf0);result.forced_cursor.bytes.fill(0x80);
    DataStream bytes;bytes<<result;ecx::CustodyProjection restored;bytes>>restored;
    BOOST_CHECK(bytes.empty());BOOST_CHECK(restored.forced_count==result.forced_count);
    BOOST_CHECK(restored.forced_cursor==result.forced_cursor);BOOST_CHECK(restored.state_outpoint==result.state_outpoint);
    BOOST_CHECK(restored.custody_history_root==result.custody_history_root);
}
BOOST_AUTO_TEST_CASE(actual_signed_source_mempool_template_and_deadline)
{
    Fixture f;std::string error;
    const auto script=ParseHex(ecx_forced_v3_test::script);
    CMutableTransaction marker;marker.vout.emplace_back(CAsset{f.config.custody_successor.vault_asset},0,CScript(script.begin(),script.end()));
    const CTransaction tx{marker};
    BOOST_REQUIRE_MESSAGE(ecx::CheckSourceTransactionPolicy(tx,2,error,f.config,100),error);
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(tx,2,error,f.config,112));
    BOOST_CHECK(!ecx::CheckSourceTransactionPolicy(tx,2,error,f.config));
    uint64_t forced=0,deposits=0;
    BOOST_REQUIRE(ecx::CountSourceTransactionMarkers(tx,forced,deposits,error,f.config,100));
    BOOST_CHECK_EQUAL(forced,1);BOOST_CHECK_EQUAL(deposits,0);
    CBlockIndex previous{f.genesis};previous.nHeight=1;previous.ecxCustodyProjection=f.config.custody_successor.genesis_projection;
    uint64_t budget=0;BOOST_REQUIRE(ecx::CustodySourceAppendBudget(previous,100,budget));BOOST_CHECK_EQUAL(budget,64);
    CBlock candidate=f.genesis;candidate.vtx={MakeTransactionRef(marker)};
    BOOST_REQUIRE_MESSAGE(ecx::PrepareCustodyHeader(candidate,&previous,2,100,error,f.config),error);
    BOOST_CHECK_EQUAL(candidate.sourceBacklogOldestParentHeight,100);
    BOOST_CHECK_EQUAL(candidate.swapForcedState[80],1);
    ecx::CustodyProjection result;CBlockUndo undo;
    BOOST_REQUIRE_MESSAGE(ecx::DeriveCustodyProjectionAfterScripts(candidate,&previous,undo,2,H(30),100,1000,result,error,f.config),error);
    CBlockIndex queued{candidate};queued.nHeight=2;queued.ecxCustodyProjection=result;
    BOOST_REQUIRE(ecx::CustodySourceAppendBudget(queued,100,budget));BOOST_CHECK_EQUAL(budget,63);
    candidate.vtx.clear();candidate.ecxParentHeight=106;
    BOOST_CHECK(!ecx::PrepareCustodyHeader(candidate,&queued,3,106,error,f.config));
    candidate.sourceBacklogOldestParentHeight=0;
    BOOST_CHECK(!ecx::DeriveCustodyProjectionAfterScripts(candidate,&queued,undo,3,H(30),106,1000,result,error,f.config));
}
BOOST_AUTO_TEST_CASE(existing_tracker_namespace_connect_and_activation_undo)
{
    Fixture f;CCoinsView base;CCoinsViewCache view{&base};std::string error;
    view.AddCoin(f.config.genesis_state_outpoint,Coin{f.state_coin,0,false},false);
    view.AddCoin(COutPoint{f.config.genesis_state_outpoint.hash,1},Coin{f.vault_coin,0,false},false);
    BOOST_REQUIRE_MESSAGE(ecx::ConnectExchangeState(f.genesis,nullptr,view,1,error,f.config,100),error);
    CBlockIndex tip{f.genesis};tip.nHeight=1;tip.ecxCustodyProjection=f.config.custody_successor.genesis_projection;
    ecx::ExchangeConsensusSnapshot snapshot;
    BOOST_REQUIRE_MESSAGE(ecx::GetExchangeConsensusSnapshot(view,&tip,snapshot,error),error);
    BOOST_CHECK(snapshot.exchange_state_root==f.config.genesis_state_root);
    BOOST_REQUIRE_MESSAGE(ecx::DisconnectExchangeState(f.genesis,nullptr,view,1,error,f.config,100),error);
    BOOST_CHECK(!ecx::HasPersistedExchangeConsensusState(view));
    BOOST_CHECK(view.HaveCoin(f.config.genesis_state_outpoint));
    BOOST_CHECK(view.HaveCoin(COutPoint{f.config.genesis_state_outpoint.hash,1}));
}
BOOST_AUTO_TEST_CASE(runtime_fingerprint_binds_every_fresh_deployment_field)
{
    Fixture f;const auto fingerprint=[](const auto& c) {
        return ecx::ComputeRuntimeConsensusFingerprint(c,"elementsregtest",H(40),H(41),H(42),false,0);
    };
    const auto original=fingerprint(f.config);
    auto changed=f.config;changed.custody_successor.program_id=H(91);BOOST_CHECK(fingerprint(changed)!=original);
    changed=f.config;changed.custody_successor.genesis_projection->custody_history_root=H(91);BOOST_CHECK(fingerprint(changed)!=original);
    changed=f.config;changed.custody_successor.genesis_forced_state[120]^=1;BOOST_CHECK(fingerprint(changed)!=original);
    changed=f.config;changed.custody_successor.canonical_economics[258]^=1;BOOST_CHECK(fingerprint(changed)!=original);
    changed=f.config;changed.custody_successor.activation_enabled=false;BOOST_CHECK(fingerprint(changed)!=original);
}
BOOST_AUTO_TEST_CASE(custody_policy_matches_prior_cpp_and_lookup_order)
{
    Fixture f;CBlockIndex previous{f.genesis};previous.nHeight=1;
    previous.ecxCustodyProjection=f.config.custody_successor.genesis_projection;
    const auto state=f.config.genesis_state_outpoint;
    const COutPoint vault{state.hash,1},unrelated{Txid::FromUint256(H(99)),0};
    CMutableTransaction parent;parent.vin={CTxIn{state},CTxIn{vault}};
    const auto good_parent=MakeTransactionRef(parent);
    parent.vin.pop_back();const auto short_parent=MakeTransactionRef(parent);
    parent.vin={CTxIn{vault},CTxIn{state}};const auto reversed_parent=MakeTransactionRef(parent);
    const std::vector<COutPoint> inputs{state,vault,unrelated,{good_parent->GetHash(),0},
        {good_parent->GetHash(),1},{good_parent->GetHash(),2},{short_parent->GetHash(),0},{reversed_parent->GetHash(),0}};
    for(int profile=0;profile<7;++profile) for(int output=0;output<10;++output) for(size_t combination=0;combination<73;++combination) {
        auto config=f.config;CBlockIndex prev{f.genesis};prev.nHeight=previous.nHeight;
        prev.ecxCustodyProjection=previous.ecxCustodyProjection;
        if(profile==1) config.custody_successor.activation_enabled=false;
        if(profile==2) config.activation_height=3;
        if(profile==3) prev.ecxCustodyProjection.reset();
        if(profile==4) {prev.ecxCustodyProjection.reset();config.activation_height=2;}
        if(profile==5) {prev.ecxCustodyProjection.reset();config.activation_height=2;config.custody_successor.genesis_projection.reset();}
        const auto* tip=profile==6 ? nullptr : &prev;
        CMutableTransaction tx;
        if(combination) tx.vin.emplace_back(inputs[(combination-1)%inputs.size()]);
        if(combination>inputs.size()) tx.vin.emplace_back(inputs[(combination-9)/inputs.size()]);
        tx.vout={f.state_coin,f.vault_coin};
        switch(output) {
        case 1:tx.vout.clear();break;
        case 2:tx.vout.pop_back();break;
        case 3:tx.vout[1].nAsset.SetToAsset(CAsset{H(91)});break;
        case 4:tx.vout[1].nValue.SetToAmount(-1);break;
        case 5:tx.vout[1].nValue.SetToAmount(999);break;
        case 6:tx.vout[1].nNonce.vchCommitment={2};break;
        case 7:tx.vout[1].scriptPubKey=CScript()<<OP_FALSE;break;
        case 8:tx.vout[1].nAsset.vchCommitment=std::vector<unsigned char>(33,10);break;
        case 9:tx.vout[1].nValue.vchCommitment=std::vector<unsigned char>(33,8);break;
        }
        const CTransaction transaction{tx};
        for(int lookup=0;lookup<3;++lookup) {
            std::vector<Txid> old_calls,new_calls;
            const auto callback=[&](std::vector<Txid>& calls) -> std::function<CTransactionRef(const Txid&)> {
                if(lookup==0) return {};
                return [&,trace=&calls](const Txid& hash)->CTransactionRef {
                    trace->push_back(hash);
                    if(lookup==2) return good_parent; // Deliberately wrong for unrelated hashes.
                    for(const auto& candidate:{good_parent,short_parent,reversed_parent}) if(candidate->GetHash()==hash) return candidate;
                    return {};
                };
            };
            std::string old_error="sentinel",new_error="sentinel";
            const auto expected=custody_policy_reference::CheckCustodyReservedSpendPolicy(transaction,tip,old_error,config,callback(old_calls));
            const auto actual=ecx::CheckCustodyReservedSpendPolicy(transaction,tip,new_error,config,callback(new_calls));
            BOOST_CHECK_EQUAL(actual,expected);BOOST_CHECK_EQUAL(new_error,old_error);
            BOOST_CHECK(old_calls==new_calls);
        }
    }
}
BOOST_AUTO_TEST_CASE(custody_budget_matches_prior_cpp_without_search_reentries)
{
    Fixture f;CBlockIndex previous{f.genesis};previous.nHeight=1;
    const auto compare=[&](const CBlockIndex& prev,uint64_t parent) {
        uint64_t old_budget=777,new_budget=777;
        const auto expected=custody_policy_reference::CustodySourceAppendBudget(prev,parent,old_budget);
        BOOST_CHECK_EQUAL(ecx::CustodySourceAppendBudget(prev,parent,new_budget),expected);
        BOOST_CHECK_EQUAL(new_budget,old_budget);
    };
    for(uint64_t count:{0,1,63,64,65,447,448,449}) for(uint64_t cursor:{uint64_t{0},count})
        for(uint32_t used:{0,1,63,64,65}) for(uint64_t parent:{0,99,100,101}) {
            CBlockIndex changed{f.genesis};
            WriteBE64(changed.swapForcedState.data()+73,count);
            WriteBE64(changed.swapForcedState.data()+121,cursor);
            WriteBE64(changed.swapForcedState.data()+129,100);
            WriteBE32(changed.swapForcedState.data()+137,used);
            compare(changed,parent);
        }
    for(size_t i=0;i<previous.swapForcedState.size();++i) for(unsigned char mask:{1,128,255}) {
        CBlockIndex changed{f.genesis};changed.swapForcedState[i]^=mask;compare(changed,100);
    }
    compare(previous,std::numeric_limits<uint64_t>::max());
}
BOOST_AUTO_TEST_CASE(custody_identity_matches_prior_cpp)
{
    Fixture f;
    const auto compare=[&](const ecx::ExchangeConsensus& config,const ecx::CustodyProjection& projection,const uint256& root) {
        BOOST_CHECK_EQUAL(ecx::CustodySuccessorAvailable(config),custody_identity_reference::Available(config));
        BOOST_CHECK_EQUAL(ecx::CustodyGenesisConfigured(config),custody_identity_reference::Genesis(config));
        BOOST_CHECK_EQUAL(ecx::CheckCustodyProjectionIdentity(projection,root,config),
            custody_identity_reference::Identity(projection,root,config));
    };
    const auto initial=*f.config.custody_successor.genesis_projection;
    const auto root=f.config.genesis_state_root;
    compare(f.config,initial,root);
    using Profile=std::remove_reference_t<decltype(f.config.custody_successor)>;
    const std::array<uint256 Profile::*,11> pins{&Profile::program_id,&Profile::composition_policy,
        &Profile::ecx_configuration,&Profile::clearing_policy,&Profile::source_configuration,
        &Profile::custodian_registry,&Profile::vault_asset,&Profile::vault_script,&Profile::transition_cmr,
        &Profile::state_node_domain_sha256,&Profile::forced_source_domain};
    for(auto pin:pins) {
        auto changed=f.config;changed.custody_successor.*pin=uint256{};compare(changed,initial,root);
        for(size_t i=0;i<32;++i) {
            changed=f.config;(changed.custody_successor.*pin).begin()[i]^=128;compare(changed,initial,root);
        }
    }
    for(size_t i=0;i<259;++i) {
        auto changed=f.config;changed.custody_successor.canonical_economics[i]^=1;compare(changed,initial,root);
    }
    for(unsigned variant=0;variant<9;++variant) {
        auto c=f.config;
        switch(variant) {
        case 0:c.custody_successor.identities_frozen=false;break;
        case 1:c.custody_successor.genesis_projection.reset();break;
        case 2:c.bond_v2.activation_enabled=true;break;
        case 3:c.swap_successor.program_id=c.custody_successor.program_id;break;
        case 4:c.bond_v2.incremental_successor_program_id=c.custody_successor.program_id;break;
        case 5:c.swap_successor.transition_cmr=c.custody_successor.transition_cmr;break;
        case 6:c.bond_v2.incremental_successor_transition_cmr=c.custody_successor.transition_cmr;break;
        case 7:c.genesis_state_outpoint.n=1;break;
        case 8:c.genesis_state_root.SetNull();break;
        }
        compare(c,initial,root);
    }
    for(size_t i=0;i<145;++i) for(unsigned char mask:{1,128,255}) {
        auto c=f.config;c.custody_successor.genesis_forced_state[i]^=mask;compare(c,initial,root);
    }
    using Projection=ecx::CustodyProjection;
    const std::array<uint256 Projection::*,14> hashes{&Projection::exchange_state_root,&Projection::outer_state_root,
        &Projection::custody_history_root,&Projection::program_id,&Projection::transition_cmr,
        &Projection::composition_policy,&Projection::ecx_configuration,&Projection::clearing_policy,
        &Projection::source_configuration,&Projection::custodian_registry,&Projection::vault_asset,
        &Projection::vault_script,&Projection::forced_head,&Projection::forced_processed_root};
    const auto changedProjection=[&](const Projection& s) {
        auto config=f.config;config.custody_successor.genesis_projection=s;compare(config,s,root);
    };
    for(auto member:hashes) {
        auto s=initial;s.*member=uint256{};changedProjection(s);
        for(size_t i=0;i<32;++i) for(unsigned char mask:{1,128,255}) {
            s=initial;(s.*member).begin()[i]^=mask;changedProjection(s);
        }
    }
    for(unsigned value:{0,1,5,6,7,255,65535}) {
        auto s=initial;s.version=value;changedProjection(s);
        s=initial;s.profit_lock_insolvent=value;changedProjection(s);
        s=initial;s.state_outpoint.n=value;changedProjection(s);
    }
    for(uint64_t value:{uint64_t{0},uint64_t{1},uint64_t{1}<<63,std::numeric_limits<uint64_t>::max()}) {
        auto s=initial;s.sequence=value;changedProjection(s);
        s=initial;s.controlled_ecx_atoms=value;changedProjection(s);
    }
    for(size_t i=0;i<32;++i) {
        auto s=initial;auto hash=uint256{s.state_outpoint.hash};hash.begin()[i]^=128;
        s.state_outpoint.hash=Txid::FromUint256(hash);changedProjection(s);
    }
    for(size_t i=0;i<16;++i) for(unsigned char value:{1,128,255}) {
        auto s=initial;s.forced_count.bytes[i]=value;changedProjection(s);
        s.forced_cursor.bytes[i]=value;changedProjection(s);
        s.forced_processed_root=H(89);changedProjection(s);
        s=initial;s.forced_cursor.bytes[i]=value;changedProjection(s);
    }
    compare(f.config,initial,uint256{});
}

BOOST_AUTO_TEST_CASE(custody_annex_decode_matches_prior_cpp_and_atomic_publication)
{
    Fixture f;const auto annex=f.Annex();
    const auto compare=[&](const std::vector<unsigned char>& bytes,const uint256& root,const ecx::ExchangeConsensus& config) {
        auto prior=*f.config.custody_successor.genesis_projection;
        prior.sequence=987;prior.controlled_ecx_atoms=123;prior.outer_state_root=H(99);
        auto actual=prior,expected=prior;
        std::string actual_error="unchanged",expected_error=actual_error;
        const bool accepted=custody_identity_reference::Decode(bytes,root,expected,expected_error,config);
        BOOST_CHECK_EQUAL(ecx::DecodeCustodyProjection(bytes,root,actual,actual_error,config),accepted);
        BOOST_CHECK_EQUAL(actual_error,expected_error);
        DataStream old_bytes,new_bytes;old_bytes<<expected;new_bytes<<actual;
        BOOST_CHECK(old_bytes.str()==new_bytes.str());
        if(!accepted) {DataStream sentinel;sentinel<<prior;BOOST_CHECK(new_bytes.str()==sentinel.str());}
    };
    compare(annex,f.config.genesis_state_root,f.config);
    compare(annex,uint256{},f.config);
    auto unqualified=f.config;unqualified.custody_successor.identities_frozen=false;
    compare(annex,f.config.genesis_state_root,unqualified);
    for(size_t length=0;length<annex.size();++length)
        compare({annex.begin(),annex.begin()+length},f.config.genesis_state_root,f.config);
    auto extended=annex;extended.push_back(0);compare(extended,f.config.genesis_state_root,f.config);
    for(size_t i=0;i<annex.size();++i) for(unsigned char mask:{1,128,255}) {
        auto changed=annex;changed[i]^=mask;compare(changed,f.config.genesis_state_root,f.config);
        if(i>=435) {
            CSHA256().Write(changed.data()+435,791).Finalize(changed.data()+43);
            compare(changed,f.config.genesis_state_root,f.config);
        }
    }
    for(unsigned char fill:{0,1,128,255}) {
        auto changed=annex;
        for(size_t at:{size_t{700},size_t{740}}) std::fill_n(changed.begin()+435+at,8,fill);
        std::fill_n(changed.begin()+435+748,32,fill);
        CSHA256().Write(changed.data()+435,791).Finalize(changed.data()+43);
        compare(changed,f.config.genesis_state_root,f.config);
    }
}

BOOST_AUTO_TEST_SUITE_END()
