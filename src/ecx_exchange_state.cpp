// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <ecx_exchange_state.h>
#include <addresstype.h>
#include <haskell/bridge.h>

#include <chain.h>
#include <chainparams.h>
#include <blind.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <crypto/common.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <hash.h>
#include <issuance.h>
#include <policy/policy.h>
#include <protocol.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/ecx_activation_annex.h>
#include <streams.h>
#include <undo.h>
#include <util/strencodings.h>
#include <common/args.h>
extern "C" {
#include <simplicity/elements/env.h>
}

#include <algorithm>
#include <array>
#include <bitset>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace ecx {

// Haskell-owned constants are generated at build time, without runtime FFI.
#include <haskell/exchange_constants.h>

static bool HasOnlyOrdinaryInputs(const CTransaction& transaction)
{
    return drivechain::haskell::ParentReplayEach(transaction.vin, [](const CTxIn& input) {
        return drivechain::haskell::ParentReplayAll<2>({[&] { return !input.m_is_pegin; },
            [&] { return input.assetIssuance.IsNull(); }});
    });
}

bool VerifyPublicBondDeployment(const CTransaction& tx, uint32_t issuance_index,
    uint32_t inventory_index, uint32_t burn_index)
{
    const auto issuance=[&]() -> const auto& { return tx.vin[issuance_index].assetIssuance; };
    const auto inventory=[&]() -> const auto& { return tx.vout[inventory_index]; };
    const auto burn=[&]() -> const auto& { return tx.vout[burn_index]; };
    CAsset asset,token,output_asset;
    size_t index=0;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::PUBLIC_BOND_ISSUANCE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return issuance_index < tx.vin.size();
            case 2: return inventory_index < tx.vout.size();
            case 3: return burn_index < tx.vout.size();
            case 4: return inventory_index != burn_index;
            case 5: return Consensus::HasOnlyExplicitCreations(tx);
            case 6: return drivechain::haskell::ParentReplayEach(tx.vin, [](const CTxIn& in) { return !in.m_is_pegin; });
            case 7: return drivechain::haskell::CountMatches(tx.vin.size(), [&](uint64_t i) { return !tx.vin[i].assetIssuance.IsNull(); })==1;
            case 8: return issuance().assetBlindingNonce.IsNull();
            case 9: return issuance().nAmount.IsExplicit();
            case 10: return issuance().nAmount.GetAmount()==ECX_BOND_FIXED_SUPPLY;
            case 11: return issuance().nInflationKeys.IsExplicit();
            case 12: return issuance().nInflationKeys.GetAmount()==1;
            case 13: {
                uint256 entropy; GenerateAssetEntropy(entropy,tx.vin[issuance_index].prevout,issuance().assetEntropy);
                CalculateAsset(asset,entropy); CalculateReissuanceToken(token,entropy,false); return 1;
            }
            case 14: return !asset.IsNull();
            case 15: return !token.IsNull();
            case 16: return asset!=token;
            case 17: return inventory().nAsset.GetAsset()==asset;
            case 18: return inventory().nValue.GetAmount()==ECX_BOND_FIXED_SUPPLY;
            case 19: return !inventory().scriptPubKey.empty();
            case 20: return !inventory().scriptPubKey.IsUnspendable();
            case 21: return burn().nAsset.GetAsset()==token;
            case 22: return burn().nValue.GetAmount()==1;
            case 23: return burn().scriptPubKey.IsUnspendable();
            case 24: return index < tx.vout.size();
            case 25: output_asset=tx.vout[index].nAsset.GetAsset(); return output_asset!=asset;
            case 26: return output_asset!=token;
            case 27: ++index; return 1;
            case 28: return index==inventory_index;
            case 29: return index==burn_index;
            default: throw std::logic_error("invalid public bond issuance action");
            }
        })==0;
}

// Verify the fixed supply opening and its issuance rangeproof together. The
// issuance generator is unblinded; the inventory generator need not be.
bool VerifyBondIssuance(const CTransaction& tx, uint32_t index, const uint256& vbf)
{
    const auto issuance=[&]() -> const auto& { return tx.vin[index].assetIssuance; };
    const auto witness=[&]() -> const auto& { return tx.witness.vtxinwit[index]; };
    CAsset asset;
    secp256k1_generator generator;
    secp256k1_pedersen_commitment commitment;
    uint64_t minimum{},maximum{};
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BOND_ISSUANCE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return index < tx.vin.size();
            case 2: return index < tx.witness.vtxinwit.size();
            case 3: return !vbf.IsNull();
            case 4: return !issuance().IsNull();
            case 5: return issuance().assetBlindingNonce.IsNull();
            case 6: return issuance().nAmount.IsCommitment();
            case 7: return issuance().nInflationKeys.IsExplicit();
            case 8: return issuance().nInflationKeys.GetAmount()==1;
            case 9: return !witness().vchIssuanceAmountRangeproof.empty();
            case 10: return witness().vchInflationKeysRangeproof.empty();
            case 11: {
                uint256 entropy; GenerateAssetEntropy(entropy,tx.vin[index].prevout,issuance().assetEntropy);
                CalculateAsset(asset,entropy); return 1;
            }
            case 12: return VerifyConfidentialPair(issuance().nAmount,CConfidentialAsset(asset),ECX_BOND_FIXED_SUPPLY,asset,vbf,uint256{});
            case 13: return secp256k1_generator_generate(secp256k1_blind_context,&generator,asset.begin())!=0;
            case 14: return secp256k1_pedersen_commitment_parse(secp256k1_blind_context,&commitment,issuance().nAmount.vchCommitment.data())!=0;
            case 15: return secp256k1_rangeproof_verify(secp256k1_blind_context,&minimum,&maximum,&commitment,
                witness().vchIssuanceAmountRangeproof.data(),witness().vchIssuanceAmountRangeproof.size(),nullptr,0,&generator)==1;
            case 16: return minimum<=uint64_t{ECX_BOND_FIXED_SUPPLY};
            default: return maximum>=uint64_t{ECX_BOND_FIXED_SUPPLY};
            }
        })==0;
}

void ApplyFrozenProfile(ArgsManager& args, bool matching_network, const char* release_hash,
    std::span<const std::pair<const char*, const char*>> profile)
{
    auto current = profile.begin();
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::FROZEN_PROFILE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return matching_network;
            case 2: return drivechain::haskell::ParentReplayAll<2>({
                [&] { return std::string_view{release_hash}.size() == 64; },
                [&] { return IsHex(release_hash); },
            });
            case 3: throw std::runtime_error("source-frozen ECX production release-record hash is noncanonical");
            case 4: return current != profile.end();
            case 5: return args.IsArgSet(current->first);
            case 6: return args.GetArg(current->first, "") == current->second;
            case 7: throw std::runtime_error(
                std::string("operator override conflicts with the source-frozen ECX production profile: ") + current->first);
            case 8: args.ForceSetArg(current->first, current->second); ++current; return true;
            default: throw std::logic_error("invalid frozen profile action");
            }
        });
}

namespace {
bool VerifyConfiguredBondIssuance(const CTransaction& tx,
    const ExchangeConsensus::BondV2FrozenConsensus& frozen, bool public_deployment)
{
    return drivechain::haskell::ParentReplayChoose({
        [&] { return public_deployment; },
        [&] { return VerifyPublicBondDeployment(tx, frozen.issuance_input_index,
            frozen.inventory_output_index, frozen.reissuance_token_burn_output_index); },
        [&] { return VerifyBondIssuance(tx, frozen.issuance_input_index, frozen.issuance_value_blinding_factor); }});
}

uint256 Sha256(Span<const unsigned char> bytes);
uint256 TaggedHash(const std::string& tag, std::span<const unsigned char> payload);
uint256 ParseRawHash32Arg(const std::string& name, bool allow_zero = false);
void ConfigureBondV2FromArgs(ExchangeConsensus& consensus);

#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
#define ECX_PRODUCTION_NETWORK(value) \
    constexpr const char* ECX_PRODUCTION_NETWORK_ID{value};
#define ECX_PRODUCTION_RELEASE_RECORD_SHA256(value) \
    constexpr const char* ECX_PRODUCTION_RELEASE_RECORD_HASH_HEX{value};
#define ECX_PRODUCTION_ARG(name, value)
#include "ecxProductionActivationProfile.inc"
#undef ECX_PRODUCTION_ARG
#undef ECX_PRODUCTION_RELEASE_RECORD_SHA256
#undef ECX_PRODUCTION_NETWORK

const std::vector<std::pair<const char*, const char*>> ECX_PRODUCTION_ACTIVATION_ARGS{
#define ECX_PRODUCTION_NETWORK(value)
#define ECX_PRODUCTION_RELEASE_RECORD_SHA256(value)
#define ECX_PRODUCTION_ARG(name, value) {name, value},
#include "ecxProductionActivationProfile.inc"
#undef ECX_PRODUCTION_ARG
#undef ECX_PRODUCTION_RELEASE_RECORD_SHA256
#undef ECX_PRODUCTION_NETWORK
};

void ApplyFrozenEcxProductionProfile()
{
    ApplyFrozenProfile(gArgs, Params().NetworkIDString() == ECX_PRODUCTION_NETWORK_ID,
        ECX_PRODUCTION_RELEASE_RECORD_HASH_HEX, ECX_PRODUCTION_ACTIVATION_ARGS);
}
#else
void ApplyFrozenEcxProductionProfile() {}
#endif

bool IsEcxRuntimeTestNetwork()
{
    const std::string& network = Params().NetworkIDString();
    return drivechain::haskell::ParentReplayAll<2>({
        [&] { return Params().GetConsensus().elements_mode; },
        [&] { return network == "elementsregtest"; },
    });
}

ExchangeConsensus LoadExchangeConsensus()
{
    ApplyFrozenEcxProductionProfile();
    ExchangeConsensus result;
    bool has_bond_v2{false};
    if (!drivechain::haskell::ExchangeActivationSettings([&](uint32_t step) {
        static constexpr const char* names[]{
            "-ecxactivationheight", "-ecxgenesisstateoutpoint", "-ecxgenesisstateroot",
            "-ecxchainid", "-ecxforcedactiondomain", "-ecxdepositinboxdomain",
            "-ecxcollateralvaultscript", "-ecxcollateralvaultscripthash", "-ecxbondv2"};
        if (step < std::size(names)) {
            const bool present = gArgs.IsArgSet(names[step]);
            if (step == 8) has_bond_v2 = present;
            return present;
        }
        if (step != 9) throw std::logic_error("invalid exchange activation setting step");
        const bool frozen_production_network{
#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
            Params().NetworkIDString() == ECX_PRODUCTION_NETWORK_ID
#else
            false
#endif
        };
        return !drivechain::haskell::ParentReplayAll<2>({
            [&] { return !IsEcxRuntimeTestNetwork(); },
            [&] { return !frozen_production_network; },
        });
    })) return result;

    const int64_t height = gArgs.GetIntArg("-ecxactivationheight", -1);
    if (!drivechain::haskell::ExchangeFrozenBounds(std::array<uint64_t,2>{
            static_cast<uint64_t>(height), std::numeric_limits<int>::max()})) {
        throw std::runtime_error("invalid -ecxactivationheight");
    }

    using drivechain::haskell::ConfigurationField;
    using drivechain::haskell::ParseConfigurationField;
    const auto outpoint = ParseConfigurationField(ConfigurationField::OUTPOINT,
        gArgs.GetArg("-ecxgenesisstateoutpoint", ""),
        "invalid -ecxgenesisstateoutpoint; expected txid:vout", "ECX genesis state txid must be nonzero");
    uint256 txid;
    std::copy_n(outpoint.begin(),32,txid.begin());
    const auto root_bytes = ParseConfigurationField(ConfigurationField::DISPLAY_HASH,
        gArgs.GetArg("-ecxgenesisstateroot", ""),
        "invalid -ecxgenesisstateroot", "ECX genesis state root must be nonzero");
    uint256 root;
    std::copy(root_bytes.begin(),root_bytes.end(),root.begin());

    result.activation_height = static_cast<int>(height);
    result.genesis_state_outpoint = COutPoint{Txid::FromUint256(txid), ReadBE32(outpoint.data()+32)};
    result.genesis_state_root = root;

    const auto parse_hash32 = [](const std::string& name) {
        const uint256 value = ParseRawHash32Arg(name);
        std::array<unsigned char, 32> result{};
        std::copy(value.begin(), value.end(), result.begin());
        return result;
    };
    result.chain_id = parse_hash32("-ecxchainid");
    result.forced_action_domain = parse_hash32("-ecxforcedactiondomain");
    result.deposit_inbox_domain = parse_hash32("-ecxdepositinboxdomain");
    if (!drivechain::haskell::ExchangeDistinct(std::array<const unsigned char*,2>{
            result.deposit_inbox_domain.data(), result.forced_action_domain.data()})) {
        throw std::runtime_error("ECX forced-action and deposit inbox domains must differ");
    }
    static_assert(MAX_SCRIPT_SIZE==10000);
    const auto vault_bytes = ParseConfigurationField(ConfigurationField::SPENDABLE_SCRIPT,
        gArgs.GetArg("-ecxcollateralvaultscript", ""), "invalid -ecxcollateralvaultscript",
        "ECX collateral vault script must be nonempty and spendable");
    result.collateral_vault_script = CScript(vault_bytes.begin(), vault_bytes.end());
    const auto vault_hash_bytes = ParseConfigurationField(ConfigurationField::RAW_HASH,
        gArgs.GetArg("-ecxcollateralvaultscripthash", ""), "invalid -ecxcollateralvaultscripthash", "");
    std::copy(
        vault_hash_bytes.begin(),
        vault_hash_bytes.end(),
        result.collateral_vault_script_hash.begin());
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::REQUIRED_PAIR,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return !result.collateral_vault_script_hash.IsNull();
            case 2: return result.collateral_vault_script_hash == Sha256(result.collateral_vault_script);
            default: throw std::runtime_error(
                "-ecxcollateralvaultscripthash does not match the frozen raw script bytes");
            }
        });
    drivechain::haskell::ParentReplayChoose({[&] { return has_bond_v2; },
        [&] { ConfigureBondV2FromArgs(result); return true; }, [] { return true; }});
    return result;
}

uint256 Sha256(Span<const unsigned char> bytes)
{
    uint256 result;
    CSHA256 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(result.begin());
    return result;
}

uint256 TaggedHash(const std::string& tag, std::span<const unsigned char> payload)
{
    auto writer = ::TaggedHash(tag);
    writer.write(AsBytes(Span{payload.data(), payload.size()}));
    return writer.GetSHA256();
}

std::vector<unsigned char> EncodeExchangeFingerprint(uint32_t profile, std::span<const uint64_t> numbers,
    std::span<const std::span<const unsigned char>> blobs)
{
    return drivechain::haskell::BmmFingerprint(
        [&](uint32_t group, uint32_t index, uint64_t& value, const unsigned char*& bytes) {
            if (group==0 && index<numbers.size()) { value=numbers[index]; return true; }
            if (group!=1 || index>=blobs.size()) return false;
            value=blobs[index].size(); bytes=blobs[index].data(); return true;
        },profile);
}

bool IsEcxNumsInternalKey(const unsigned char* bytes)
{
    return std::equal(
        ECX_BIP341_NUMS_XONLY.begin(), ECX_BIP341_NUMS_XONLY.end(), bytes);
}

bool IsEcxStagingRendererDomainV18(const unsigned char* bytes)
{
    return std::equal(
        ECX_BOND_STAGING_RENDERER_DOMAIN_V18.begin(),
        ECX_BOND_STAGING_RENDERER_DOMAIN_V18.end(), bytes);
}

uint256 EcxTapLeafHash(const uint256& cmr, uint8_t version = TAPROOT_LEAF_TAPSIMPLICITY)
{
    return TaggedHash("TapLeaf/elements", drivechain::haskell::ExchangeGenesisState(
        drivechain::haskell::GenesisCodec::TAP_LEAF, version, 0, {cmr.begin()}));
}

uint256 EcxTapBranchHash(const uint256& left, const uint256& right)
{
    return TaggedHash("TapBranch/elements", drivechain::haskell::ExchangeGenesisState(
        drivechain::haskell::GenesisCodec::TAP_BRANCH, 0, 0, {left.begin(), right.begin()}));
}

uint256 EcxStateNodeHash(const uint256& domain, const uint256& state)
{
    return (HashWriter{} << domain << state).GetSHA256();
}

// Destinations: first leaf, optional second leaf, lower branch, root.
void BuildBondTree(const uint256& first, const uint256* second, const uint256& hidden,
    const std::array<uint256*,4>& out, uint8_t version=TAPROOT_LEAF_TAPSIMPLICITY)
{
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::BOND_TREE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: *out[0]=EcxTapLeafHash(first,version); break;
            case 2: return second!=nullptr;
            case 3: *out[1]=EcxTapLeafHash(*second,version); break;
            case 4: *out[2]=EcxTapBranchHash(*out[1],hidden); break;
            case 5: *out[3]=EcxTapBranchHash(*out[0],*out[2]); break;
            case 6: *out[3]=EcxTapBranchHash(*out[0],hidden); break;
            default: throw std::logic_error("invalid bond tree action");
            }
            return 1;
        });
}

uint256 ParseRawHash32Arg(const std::string& name, bool allow_zero)
{
    using drivechain::haskell::ConfigurationField;
    const auto bytes = drivechain::haskell::ParseConfigurationField(
        allow_zero ? ConfigurationField::RAW_HASH : ConfigurationField::NONZERO_HASH,
        gArgs.GetArg(name, ""), "invalid " + name + "; expected 32 raw hex bytes", name + " must be nonzero");
    uint256 result;
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

[[maybe_unused]] uint32_t ParseU32Arg(const std::string& name)
{
    const int64_t value{gArgs.GetIntArg(name, -1)};
    if (!drivechain::haskell::FitsU32(std::array{static_cast<uint64_t>(value)})) {
        throw std::runtime_error("invalid " + name);
    }
    return static_cast<uint32_t>(value);
}

struct DecodedFrozenConfigurationV18
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


struct ParsedBondInboxMarker
{
    uint8_t kind{0};
    uint256 signer;
    uint256 action_id;
    uint256 staging_intent_id;
    uint32_t staging_vout{0};
    uint256 refund_script_sha256;
    uint64_t refund_not_before_parent_height{0};
    uint256 payload_commitment;
    uint256 availability_bundle_root;
    uint256 availability_context;
    uint256 availability_receipt_root;
    uint32_t availability_bundle_len{0};
    uint8_t availability_receipt_bitmap{0};
    uint256 source_authorization_commitment;
};

bool ParseCanonicalBondInboxMarker(
    const CScript& script,
    ParsedBondInboxMarker& marker,
    std::string& error,
    const ExchangeConsensus& consensus,
    bool require_wrapper_signature,
    bool successor)
{
    error.clear();
    std::vector<unsigned char> payload;
    if (!drivechain::haskell::ExchangeMarkerFrame(successor,script,payload)) {
        error = "not an exact minimal-PUSHDATA2 ECX bond-inbox marker";
        return false;
    }
    const auto raw_hash = [&](size_t offset) {
        uint256 value;
        std::copy_n(payload.data() + offset, 32, value.begin());
        return value;
    };
    marker.kind = payload[5];
    marker.signer = raw_hash(70);
    marker.action_id = raw_hash(102);
    marker.staging_intent_id = raw_hash(134);
    marker.staging_vout = ReadBE32(payload.data() + 166);
    marker.refund_script_sha256 = raw_hash(170);
    marker.refund_not_before_parent_height = ReadBE64(payload.data() + 202);
    marker.payload_commitment = raw_hash(210);
    marker.availability_bundle_root = raw_hash(306);
    marker.availability_context = raw_hash(338);
    marker.availability_receipt_root = raw_hash(370);
    marker.availability_bundle_len = ReadBE32(payload.data() + 402);
    marker.availability_receipt_bitmap = payload[406];
    marker.source_authorization_commitment = raw_hash(407);

    if (!drivechain::haskell::ExchangeBondMarker(consensus.bond_v2.bond_inbox_max_bundle_bytes, payload,
            {consensus.chain_id.data(), consensus.bond_v2.configuration_hash.begin(),
             consensus.bond_v2.availability_scheme_hash.begin(), consensus.bond_v2.availability_custodian_registry_hash.begin()}, error)) return false;

    const auto context = drivechain::haskell::ExchangeInboxEntry(
        drivechain::haskell::InboxCodec::MARKER_CONTEXT, {}, {}, payload);
    uint256 digest;
    std::optional<XOnlyPubKey> signer;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::MARKER_AUTHENTICATION,
        [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return TaggedHash(ECX_BOND_CONTEXT_TAGS[successor], context) == marker.availability_context;
        case 2: error = "ECX bond-inbox marker availability context is invalid"; return false;
        case 3: return require_wrapper_signature;
        case 4:
            digest = TaggedHash(ECX_BOND_SIGNATURE_TAGS[successor], std::span{payload}.subspan(4, 435));
            signer.emplace(Span<const unsigned char>(marker.signer.begin(), 32));
            return signer->IsFullyValid();
        case 5: return signer->VerifySchnorr(digest, Span<const unsigned char>(payload.data() + 439, 64));
        case 6: error = "ECX bond-inbox marker wrapper signature is invalid"; return false;
        default: throw std::logic_error("invalid bond marker authentication action");
        }
    }) != 0;
}

[[maybe_unused]] uint256 OrderedBondInboxCustodyReceiptRoot(
    const ParsedBondInboxMarker& marker,
    std::span<const unsigned char> receipts,
    const ExchangeConsensus& consensus,
    bool successor)
{
    const auto& tags = ECX_BOND_CUSTODY_TAGS[successor];
    const auto root = drivechain::haskell::ExchangeCustodyRoot(marker.availability_bundle_len,
        {consensus.bond_v2.availability_scheme_hash.begin(),consensus.bond_v2.availability_custodian_registry_hash.begin(),
         marker.availability_context.begin(),marker.availability_bundle_root.begin(),marker.payload_commitment.begin(),
         marker.source_authorization_commitment.begin()},receipts,[&](uint32_t kind,std::span<const unsigned char> bytes) {
            const uint256 digest = TaggedHash(tags.at(kind),bytes);
            std::array<unsigned char,32> result;
            std::copy(digest.begin(),digest.end(),result.begin());
            return result;
        });
    uint256 result;
    std::copy(root.begin(),root.end(),result.begin());
    return result;
}

bool VerifyBondInboxMarkerSourceWitness(
    const CTransaction& transaction,
    const ParsedBondInboxMarker& marker,
    std::string& error,
    const ExchangeConsensus& consensus,
    bool successor)
{
#ifndef ECX_ENABLE_SP1_GROTH16_VERIFIER
    error = "ECX bond-inbox custody verifier is not compiled in";
    return false;
#else
    /* The encrypted bundle cannot be an executed witness-stack element: it
     * may be 64 KiB while script elements are consensus-limited to 520
     * bytes.  Freeze one uniquely placed Taproot key-path annex instead.
     *
     *   input 0 script witness = [64-byte SIGHASH_DEFAULT signature, annex]
     *   annex = 0x50 | "ECXBIN2\0" | version=1 | bundle_len:u32be |
     *           receipt_count:u8 | bundle |
     *           repeated(receipt_len:u16be=138 | exact_receipt)
     *
     * The decoder consumes EOF and every other input is forbidden from
     * carrying an annex. The ordinary script interpreter authenticates the
     * designated key-path spend; wtxid commits the exact annex bytes. */
    const auto& witnesses = transaction.witness.vtxinwit;
    if (!drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::CUSTODY_WITNESS,
        [&](uint32_t step) {
            if (step == 0) return !transaction.vin.empty();
            if (step == 1) return !witnesses.empty();
            if (step == 2) return transaction.vin[0].scriptSig.empty();
            const auto& designated = witnesses[0];
            if (step == 3) return designated.vchIssuanceAmountRangeproof.empty();
            if (step == 4) return designated.vchInflationKeysRangeproof.empty();
            if (step == 5) return designated.m_pegin_witness.stack.empty();
            if (step == 6) return designated.scriptWitness.stack.size() == 2;
            if (step == 7) return designated.scriptWitness.stack[0].size() == 64;
            return drivechain::haskell::ParentReplayEach(witnesses | std::views::drop(1),[](const auto& witness) {
                const auto& stack = witness.scriptWitness.stack;
                return !drivechain::haskell::ParentReplayAll<3>({
                    [&] { return !stack.empty(); },
                    [&] { return !stack.back().empty(); },
                    [&] { return stack.back()[0] == 0x50; },
                });
            });
        },error)) return false;
    const auto& annex = witnesses[0].scriptWitness.stack[1];
    uint32_t bundle_len{};
    uint8_t receipt_count{};
    if (!drivechain::haskell::ExchangeAnnexHeader(annex,marker.availability_bundle_len,
            consensus.bond_v2.bond_inbox_max_bundle_bytes,bundle_len,receipt_count,error)) return false;
    const unsigned char* const bundle{annex.data() + 15};
    const size_t cursor{15 + size_t{bundle_len}};
    auto bundle_commitment=::TaggedHash(ECX_BOND_BUNDLE_TAGS[successor]);
    ser_writedata32be(bundle_commitment,bundle_len);
    bundle_commitment.write(AsBytes(Span{bundle,size_t{bundle_len}}));
    if (!drivechain::haskell::ParentReplayChoose({
        [&] { return bundle_commitment.GetSHA256()==marker.availability_bundle_root; },
        [] { return true; },
        [&] { error="ECX bond-inbox source annex bundle commitment mismatched"; return false; }})) return false;
    const auto registry = drivechain::haskell::ExchangeRegistryEncoding(
        consensus.bond_v2.custodian_encryption_keys,consensus.bond_v2.custodian_attestation_keys);
    std::vector<unsigned char> concatenated_receipts;
    uint8_t bitmap{0};
    if (!drivechain::haskell::ExchangeCustodyReceipts(receipt_count,
            std::span{annex}.subspan(cursor),concatenated_receipts,bitmap,error)) return false;
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::REQUIRED_QUAD,[&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return receipt_count==std::bitset<8>(marker.availability_receipt_bitmap).count();
        case 2: return bitmap==marker.availability_receipt_bitmap;
        case 3: return OrderedBondInboxCustodyReceiptRoot(marker,concatenated_receipts,consensus,successor)==marker.availability_receipt_root;
        case 4: return hs::VerifyCustody(ecx_witness_availability_verify_custody_receipts_v1,
            std::span{bundle,size_t{bundle_len}},registry,concatenated_receipts,receipt_count);
        default: error="ECX bond-inbox source annex receipt evidence is invalid"; return true;
        }
    });
#endif
}

bool DecodeFrozenConfigurationV18(
    const std::vector<unsigned char>& bytes,
    DecodedFrozenConfigurationV18& decoded,
    std::string& error)
{
    static_assert(FORCED_INCLUSION_BLOCKS==6);
    return drivechain::haskell::ExchangeFrozenConfiguration(bytes,ECX_USDD_MARKET,
        [&](uint32_t kind,std::span<const unsigned char> input) {
            std::array<unsigned char,32> result{};
            if (kind<3) {
                static constexpr const char* tags[]{"ECX/witness-availability-scheme/v1",
                    "ECX/witness-custody-receipt-codec/v1","ECX/bond-inbox-redemption-staging-template/v3-no-history"};
                const auto digest=TaggedHash(tags[kind],input);
                std::copy(digest.begin(),digest.end(),result.begin());
            } else if (kind==3) {
                result[0]=XOnlyPubKey(Span<const unsigned char>(input.data(),input.size())).IsFullyValid();
            } else {
                const auto hashes=[&](std::initializer_list<uint256*> fields,size_t offset=0) {
                    for (auto* field : fields) { std::copy_n(input.data()+offset,32,field->begin()); offset+=32; }
                };
                switch (kind) {
                case 4: hashes({&decoded.chain_id,&decoded.ecx_asset_id,&decoded.usdd_asset_id,
                    &decoded.policy_asset_id,&decoded.state_authority_asset_id}); break;
                case 5: hashes({&decoded.availability_scheme_hash,&decoded.availability_registry_hash}); break;
                case 6: hashes({&decoded.truthcoin_program_id}); break;
                case 7: decoded.direct_price=input[0]!=0; break;
                case 8: hashes({&decoded.matcher_genesis_receipt_hash}); break;
                case 9: hashes({&decoded.forced_action_domain,&decoded.deposit_inbox_domain,&decoded.collateral_vault_script_sha256}); break;
                case 10:
                    hashes({&decoded.collateral_vault_covenant_cmr,&decoded.bond_asset_id,&decoded.deployment_commitment,
                        &decoded.inventory_script_sha256,&decoded.queue_script_sha256,&decoded.staging_template_commitment,
                        &decoded.staging_renderer_domain,&decoded.staging_internal_key,&decoded.staging_process_cmr,&decoded.staging_refund_cmr,
                        &decoded.insurance_script_sha256,&decoded.insurance_reserve_covenant_cmr,&decoded.burn_script_sha256,
                        &decoded.bond_inbox_domain,&decoded.custody_receipt_codec_hash});
                    decoded.staging_tapleaf_version=input[480];
                    decoded.refund_minimum_parent_blocks=ReadBE32(input.data()+481);
                    break;
                case 11: {
                    const std::array<uint32_t*,9> limits{&decoded.inbox_inclusion_blocks,&decoded.inbox_max_bundle_bytes,
                        &decoded.inbox_max_entries_per_block,&decoded.inbox_max_unique_witness_bytes_per_block,
                        &decoded.inbox_max_unique_transaction_bytes_per_block,&decoded.inbox_max_pending_per_transition,
                        &decoded.inbox_max_consumed_per_transition,&decoded.redemption_max_queue_entries,&decoded.matcher_execution_inclusion_parent_blocks};
                    for (size_t i=0;i<limits.size();++i) *limits[i]=ReadBE32(input.data()+i*4);
                    hashes({&decoded.ecx_btc_program_id,&decoded.usdd_usd_program_id,&decoded.ecx_btc_redemption_covenant,
                        &decoded.ecx_btc_source_checkpoint,&decoded.usdd_usd_redemption_covenant,&decoded.usdd_usd_source_checkpoint},36);
                    decoded.maximum_conversion_age_seconds=ReadBE64(input.data()+228);
                    decoded.maximum_conversion_proof_bytes=ReadBE32(input.data()+236);
                    decoded.recursive_proof_marker_bytes=ReadBE32(input.data()+240);
                    decoded.fixed_supply_atoms=ReadBE64(input.data()+244);
                    decoded.redemption_delay_parent_blocks=ReadBE64(input.data()+252);
                    break;
                }
                default: throw std::logic_error("invalid frozen configuration publication");
                }
            }
            return result;
        },error);
}

void ConfigureBondV2FromArgs(ExchangeConsensus& consensus)
{
#ifndef ECX_SIMPLICITY_CATALOGUE_FROZEN
    throw std::runtime_error(
        "ECX bond V2 activation is disabled: the reviewed annex-v4/PublicValuesV5 "
        "Simplicity catalogue and its genuine CMR artifact are not compiled in");
#endif
    // Compile the parser in unfrozen builds too, so interface drift is caught.
    // The unconditional throw above still prevents activation without a freeze.
    const auto settings = drivechain::haskell::ExchangeBondSettings([&](uint32_t step) {
        if (step == 0) return gArgs.GetBoolArg("-ecxbondv2", false);
        if (step > std::size(ECX_BOND_ARGUMENTS)) throw std::logic_error("invalid bond setting step");
        return gArgs.IsArgSet(ECX_BOND_ARGUMENTS[step-1]);
    });
    if (settings == 1) throw std::runtime_error("-ecxbondv2 must be explicitly set to 1");
    if (settings >= 2 && settings <= 37)
        throw std::runtime_error(std::string("ECX bond V2 activation requires ") + ECX_BOND_ARGUMENTS[settings-2]);
    if (settings == 38) {
        throw std::runtime_error(
            "ECX bond V2 activation requires USDD, keyless-key, and genesis-mark inputs");
    }

    auto& frozen{consensus.bond_v2};
    CMutableTransaction deployment,genesis_transaction;
    std::string transaction_hex;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CONFIGURATION_TRANSACTIONS,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: transaction_hex=gArgs.GetArg("-ecxbondv2deploymenttx", ""); return !transaction_hex.empty();
            case 2: return DecodeHexTx(deployment,transaction_hex,true,true);
            case 3: frozen.deployment_transaction=MakeTransactionRef(std::move(deployment)); return 1;
            // Explicit selection: pricing mode must never select confidentiality.
            case 4: frozen.deployment_version=ParseU32Arg("-ecxbondv2deploymentversion"); return frozen.deployment_version;
            case 5: transaction_hex=gArgs.GetArg("-ecxbondv2genesistx", ""); return !transaction_hex.empty();
            case 6: return DecodeHexTx(genesis_transaction,transaction_hex,true,true);
            case 7: frozen.genesis_transaction=MakeTransactionRef(std::move(genesis_transaction)); return 1;
            case 8: return frozen.deployment_version==3;
            case 9: return Consensus::HasOnlyExplicitCreations(*frozen.genesis_transaction);
            case 10: throw std::runtime_error("invalid -ecxbondv2deploymenttx");
            case 11: throw std::runtime_error("unsupported ECX deployment version");
            case 12: throw std::runtime_error("invalid -ecxbondv2genesistx");
            case 13: throw std::runtime_error("public ECX genesis contains confidential creations or proofs");
            default: throw std::logic_error("invalid configuration transaction action");
            }
        });
    const CTransaction& transaction{*frozen.deployment_transaction};
    const CTransaction& genesis{*frozen.genesis_transaction};
    const bool public_deployment{frozen.deployment_version==3};
    frozen.issuance_input_index = ParseU32Arg("-ecxbondv2issuanceinput");
    frozen.inventory_output_index = ParseU32Arg("-ecxbondv2inventoryoutput");
    frozen.reissuance_token_burn_output_index =
        ParseU32Arg("-ecxbondv2burnoutput");
    frozen.state_authority_source_output_index =
        ParseU32Arg("-ecxbondv2stateauthoritysourceoutput");
    frozen.inventory_asset_blinding_factor =
        ParseRawHash32Arg("-ecxbondv2inventoryassetblinder", public_deployment);
    frozen.inventory_value_blinding_factor =
        ParseRawHash32Arg("-ecxbondv2inventoryvalueblinder", public_deployment);
    frozen.issuance_value_blinding_factor =
        ParseRawHash32Arg("-ecxbondv2issuancevalueblinder", public_deployment);
    drivechain::haskell::ExchangeDeploymentBlinders(public_deployment,
        std::array<const unsigned char*,3>{frozen.issuance_value_blinding_factor.begin(),
            frozen.inventory_asset_blinding_factor.begin(),frozen.inventory_value_blinding_factor.begin()});
    frozen.transition_program_id =
        ParseRawHash32Arg("-ecxbondv2transitionprogramid");
    const uint256 authorized_configuration_hash{
        ParseRawHash32Arg("-ecxbondv2configurationhash")};
    frozen.canonical_configuration_bytes = drivechain::haskell::ParseConfigurationField(
        drivechain::haskell::ConfigurationField::CONFIGURATION_HEX,
        gArgs.GetArg("-ecxbondv2configurationbytes", ""),
        "invalid -ecxbondv2configurationbytes; expected bounded canonical hex", "");
    DecodedFrozenConfigurationV18 decoded_configuration;
    std::string configuration_error;
    if (!DecodeFrozenConfigurationV18(
            frozen.canonical_configuration_bytes,
            decoded_configuration,
            configuration_error)) {
        throw std::runtime_error(configuration_error);
    }
    frozen.configuration_hash = TaggedHash(
        "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
        frozen.canonical_configuration_bytes);
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CONFIGURATION_BINDING,[&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return frozen.configuration_hash==authorized_configuration_hash;
        case 2: return std::equal(decoded_configuration.chain_id.begin(),decoded_configuration.chain_id.end(),consensus.chain_id.begin());
        case 3: return decoded_configuration.ecx_asset_id==Params().GetConsensus().pegged_asset.id;
        case 4: return decoded_configuration.usdd_asset_id==ParseRawHash32Arg("-ecxbondv2usddasset");
        case 5: return decoded_configuration.policy_asset_id==::policyAsset.id;
        case 6: return std::equal(decoded_configuration.forced_action_domain.begin(),decoded_configuration.forced_action_domain.end(),consensus.forced_action_domain.begin());
        case 7: return std::equal(decoded_configuration.deposit_inbox_domain.begin(),decoded_configuration.deposit_inbox_domain.end(),consensus.deposit_inbox_domain.begin());
        case 8: return decoded_configuration.collateral_vault_script_sha256==consensus.collateral_vault_script_hash;
        case 9: throw std::runtime_error("-ecxbondv2configurationhash does not match the canonical bytes");
        case 10: throw std::runtime_error("FrozenConfigurationV2/V18 base identities do not match the active Elements deployment");
        default: throw std::logic_error("invalid configuration binding action");
        }
    });
    frozen.collateral_vault_covenant_cmr =
        decoded_configuration.collateral_vault_covenant_cmr;
    const std::array hash_fields{
        &frozen.public_state_domain_sha256, &frozen.state_node_domain_sha256,
        &frozen.transition_journal_domain_sha256, &frozen.transition_cmr,
        &frozen.incremental_activation_program_id, &frozen.incremental_activation_configuration_hash,
        &frozen.incremental_activation_cmr, &frozen.incremental_successor_program_id,
        &frozen.incremental_successor_configuration_hash, &frozen.incremental_successor_transition_cmr,
        &frozen.incremental_successor_state_node_domain_sha256, &frozen.inventory_cmr,
        &frozen.redemption_queue_cmr, &frozen.ecx_btc_conversion_program_id,
        &frozen.ecx_btc_redemption_covenant_commitment, &frozen.ecx_btc_source_checkpoint_commitment,
        &frozen.usdd_usd_conversion_program_id, &frozen.usdd_usd_redemption_covenant_commitment,
        &frozen.usdd_usd_source_checkpoint_commitment, &frozen.matcher_genesis_receipt_hash,
        &frozen.order_receipts_genesis_root, &frozen.genesis_availability_root};
    static_assert(std::tuple_size_v<decltype(hash_fields)> == ECX_BOND_HASH_ARGUMENTS.size());
    if (const auto failure=drivechain::haskell::ParseHashArguments(decoded_configuration.direct_price,
        [&](uint32_t index) { return gArgs.GetArg(ECX_BOND_HASH_ARGUMENTS.at(index), ""); },
        [&](uint32_t index,std::span<const unsigned char,32> bytes) {
            std::copy(bytes.begin(),bytes.end(),hash_fields.at(index)->begin());
        })) {
        const std::string name{ECX_BOND_HASH_ARGUMENTS.at(failure->first)};
        throw std::runtime_error(failure->second ? name+" must be nonzero" : "invalid "+name+"; expected 32 raw hex bytes");
    }
    frozen.usdd_asset_id = CAsset(ParseRawHash32Arg("-ecxbondv2usddasset"));
    const auto registry_bytes=drivechain::haskell::ParseConfigurationField(
        drivechain::haskell::ConfigurationField::CUSTODIAN_REGISTRY,gArgs.GetArg("-ecxbondv2custodianregistry", ""),
        "invalid -ecxbondv2custodianregistry; expected five exact index|X25519|Ed25519 records (325 bytes)", "");
    drivechain::haskell::ExchangeRegistryDecoding(registry_bytes,
        frozen.custodian_encryption_keys,frozen.custodian_attestation_keys);
    frozen.availability_scheme_hash = decoded_configuration.availability_scheme_hash;
    frozen.availability_custodian_registry_hash =
        decoded_configuration.availability_registry_hash;
    drivechain::haskell::ParentReplayChoose({
        [&] { return TaggedHash("ECX/witness-custodian-registry/v1", registry_bytes)==frozen.availability_custodian_registry_hash; },
        [] { return true; }, []() -> bool { throw std::runtime_error(
            "-ecxbondv2custodianregistry does not match FrozenConfigurationV2/V18"); }});
    frozen.redemption_queue_script_sha256 = decoded_configuration.queue_script_sha256;
    frozen.insurance_reserve_script_sha256 = decoded_configuration.insurance_script_sha256;
    frozen.insurance_reserve_covenant_cmr =
        decoded_configuration.insurance_reserve_covenant_cmr;
    frozen.bond_inbox_redemption_staging_template_commitment =
        decoded_configuration.staging_template_commitment;
    frozen.bond_inbox_redemption_staging_renderer_domain =
        decoded_configuration.staging_renderer_domain;
    frozen.bond_inbox_redemption_staging_internal_key =
        decoded_configuration.staging_internal_key;
    frozen.bond_inbox_redemption_staging_tapleaf_version =
        decoded_configuration.staging_tapleaf_version;
    frozen.bond_inbox_redemption_staging_process_cmr =
        decoded_configuration.staging_process_cmr;
    frozen.bond_inbox_redemption_staging_refund_cmr =
        decoded_configuration.staging_refund_cmr;
    frozen.bond_inbox_refund_minimum_parent_blocks =
        decoded_configuration.refund_minimum_parent_blocks;
    frozen.bond_inbox_domain = decoded_configuration.bond_inbox_domain;
    frozen.bond_inbox_custody_receipt_codec_hash =
        decoded_configuration.custody_receipt_codec_hash;
    frozen.bond_inbox_inclusion_blocks = decoded_configuration.inbox_inclusion_blocks;
    frozen.bond_inbox_max_bundle_bytes = decoded_configuration.inbox_max_bundle_bytes;
    frozen.bond_inbox_max_entries_per_sidechain_block =
        decoded_configuration.inbox_max_entries_per_block;
    frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block =
        decoded_configuration.inbox_max_unique_witness_bytes_per_block;
    frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block =
        decoded_configuration.inbox_max_unique_transaction_bytes_per_block;
    frozen.bond_inbox_max_pending_entries_per_transition =
        decoded_configuration.inbox_max_pending_per_transition;
    frozen.bond_inbox_max_consumed_entries_per_transition =
        decoded_configuration.inbox_max_consumed_per_transition;
    frozen.bond_redemption_max_queue_entries =
        decoded_configuration.redemption_max_queue_entries;
    frozen.matcher_execution_inclusion_parent_blocks =
        decoded_configuration.matcher_execution_inclusion_parent_blocks;
    frozen.maximum_conversion_age_seconds =
        decoded_configuration.maximum_conversion_age_seconds;
    frozen.maximum_conversion_proof_bytes =
        decoded_configuration.maximum_conversion_proof_bytes;
    frozen.recursive_proof_marker_bytes =
        decoded_configuration.recursive_proof_marker_bytes;
    frozen.fixed_supply_atoms = decoded_configuration.fixed_supply_atoms;
    frozen.redemption_delay_parent_blocks =
        decoded_configuration.redemption_delay_parent_blocks;

    drivechain::haskell::ExchangeRuntimeIdentities(std::array<const unsigned char*,16>{
        frozen.transition_program_id.begin(),decoded_configuration.truthcoin_program_id.begin(),
        frozen.ecx_btc_conversion_program_id.begin(),decoded_configuration.ecx_btc_program_id.begin(),
        frozen.usdd_usd_conversion_program_id.begin(),decoded_configuration.usdd_usd_program_id.begin(),
        frozen.ecx_btc_redemption_covenant_commitment.begin(),decoded_configuration.ecx_btc_redemption_covenant.begin(),
        frozen.ecx_btc_source_checkpoint_commitment.begin(),decoded_configuration.ecx_btc_source_checkpoint.begin(),
        frozen.usdd_usd_redemption_covenant_commitment.begin(),decoded_configuration.usdd_usd_redemption_covenant.begin(),
        frozen.usdd_usd_source_checkpoint_commitment.begin(),decoded_configuration.usdd_usd_source_checkpoint.begin(),
        frozen.matcher_genesis_receipt_hash.begin(),decoded_configuration.matcher_genesis_receipt_hash.begin()});
    const std::array<const unsigned char*,22> deployment_identities{frozen.configuration_hash.begin(),
        frozen.incremental_activation_configuration_hash.begin(), frozen.incremental_successor_configuration_hash.begin(),
        frozen.transition_program_id.begin(),
        frozen.incremental_activation_program_id.begin(), frozen.incremental_successor_program_id.begin(),
        frozen.ecx_btc_conversion_program_id.begin(), frozen.usdd_usd_conversion_program_id.begin(),
        frozen.transition_cmr.begin(),
        frozen.incremental_activation_cmr.begin(), frozen.incremental_successor_transition_cmr.begin(),
        frozen.collateral_vault_covenant_cmr.begin(), frozen.insurance_reserve_covenant_cmr.begin(),
        frozen.inventory_cmr.begin(), frozen.redemption_queue_cmr.begin(),
        frozen.bond_inbox_redemption_staging_process_cmr.begin(), frozen.bond_inbox_redemption_staging_refund_cmr.begin(),
        frozen.incremental_successor_state_node_domain_sha256.begin(),
        frozen.state_node_domain_sha256.begin(), frozen.public_state_domain_sha256.begin(),
        frozen.transition_journal_domain_sha256.begin(), frozen.bond_inbox_redemption_staging_renderer_domain.begin()};
    drivechain::haskell::ExchangeDeploymentIdentities(decoded_configuration.direct_price,deployment_identities);
    const std::array<const uint256*,4> cmrs{&frozen.inventory_cmr,&frozen.redemption_queue_cmr,
        &frozen.collateral_vault_covenant_cmr,&frozen.insurance_reserve_covenant_cmr};
    std::array<uint256,4> derived_scripts;
    const auto& [derived_inventory_script_hash,derived_queue_script_hash,
        derived_collateral_vault_script_hash,derived_insurance_script_hash]=derived_scripts;
    std::optional<std::pair<XOnlyPubKey,bool>> tweaked;
    int64_t mark_price=0,initialization_height=0,initialization_mtp=0;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CONFIGURATION_COVENANTS,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: {
                const uint256 keyless{ParseRawHash32Arg("-ecxbondv2keylessinternalkey")};
                std::copy(keyless.begin(),keyless.end(),frozen.keyless_internal_key.begin()); return 1;
            }
            case 2: return IsEcxNumsInternalKey(frozen.keyless_internal_key.data());
            case 3: return XOnlyPubKey(Span<const unsigned char>(frozen.keyless_internal_key.data(),32)).IsFullyValid();
            case 4: case 6: case 8: case 10: {
                const uint256 leaf{EcxTapLeafHash(*cmrs[(step-4)/2])};
                tweaked=XOnlyPubKey(Span<const unsigned char>(frozen.keyless_internal_key.data(),32)).CreateTapTweak(&leaf);
                return tweaked.has_value();
            }
            case 5: case 7: case 9: case 11: {
                const CScript script{GetScriptForDestination(WitnessV1Taproot(tweaked->first))};
                derived_scripts[(step-5)/2]=Sha256(script); return 1;
            }
            case 12: mark_price=gArgs.GetIntArg("-ecxbondv2genesismarkprice",0);
                return drivechain::haskell::ExchangeFrozenBounds(std::array<uint64_t,1>{static_cast<uint64_t>(mark_price)});
            case 13: frozen.genesis_mark_price=static_cast<uint64_t>(mark_price); return 1;
            case 14: initialization_height=gArgs.GetIntArg("-ecxbondv2initializationheight",0); return 1;
            case 15: initialization_mtp=gArgs.GetIntArg("-ecxbondv2initializationmtp",0); return 1;
            case 16: return drivechain::haskell::ExchangeFrozenBounds(std::array<uint64_t,3>{static_cast<uint64_t>(initialization_height),
                static_cast<uint64_t>(consensus.activation_height),static_cast<uint64_t>(initialization_mtp)});
            case 17:
                frozen.genesis_initialization_version=2;
                frozen.genesis_initialization_height=static_cast<uint32_t>(initialization_height);
                frozen.genesis_initialization_parent_mtp=static_cast<uint64_t>(initialization_mtp); return 1;
            case 18: frozen.genesis_initialization_block_hash=ParseRawHash32Arg("-ecxbondv2initializationblock"); return 1;
            case 19: throw std::runtime_error("invalid -ecxbondv2keylessinternalkey; every ECX V2 covenant requires the exact BIP341 NUMS H x-coordinate");
            case 20: throw std::runtime_error("ECX bond V2 single-leaf covenant descriptor is invalid");
            case 21: throw std::runtime_error("invalid -ecxbondv2genesismarkprice");
            case 22: throw std::runtime_error("ECX checkpoint genesis requires valid initialization height and parent MTP");
            default: throw std::logic_error("invalid configuration covenant action");
            }
        });

    if (!drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::DEPLOYMENT_ARGUMENTS,
        [&](uint32_t step) {
            switch (step) {
            case 0: return !transaction.vin.empty();
            case 1: return !transaction.vout.empty();
            case 2: return frozen.issuance_input_index < transaction.vin.size();
            case 3: return frozen.inventory_output_index < transaction.vout.size();
            case 4: return frozen.reissuance_token_burn_output_index < transaction.vout.size();
            case 5: return frozen.state_authority_source_output_index < transaction.vout.size();
            case 6: return frozen.inventory_output_index != frozen.reissuance_token_burn_output_index;
            case 7: return frozen.inventory_output_index != frozen.state_authority_source_output_index;
            case 8: return frozen.reissuance_token_burn_output_index != frozen.state_authority_source_output_index;
            case 9: return drivechain::haskell::ParentReplayEach(transaction.vin, [](const CTxIn& input) { return !input.m_is_pegin; });
            case 10: return drivechain::haskell::CountMatches(transaction.vin.size(), [&](uint64_t i) { return !transaction.vin[i].assetIssuance.IsNull(); })==1;
            default: throw std::logic_error("invalid deployment argument action");
            }
        },configuration_error)) throw std::runtime_error(configuration_error);
    const CTxIn& issuance{transaction.vin[frozen.issuance_input_index]};
    uint256 entropy;
    CAsset bond_asset;
    CAsset reissuance_token;
    const CTxOut& inventory{transaction.vout[frozen.inventory_output_index]};
    const CTxOut& burn{
        transaction.vout[frozen.reissuance_token_burn_output_index]};
    const CTxOut& authority_source{
        transaction.vout[frozen.state_authority_source_output_index]};
    Txid deployment_txid, genesis_txid;
    const auto outputs_valid=[&](const CTransaction& tx,uint64_t skipped,std::optional<uint64_t> token_burn) {
        return drivechain::haskell::ExchangeDeploymentOutputs(skipped,tx.vout.size(),[&](uint64_t index) {
            const auto& output=tx.vout[index];
            const bool asset=output.nAsset.IsExplicit(), value=output.nValue.IsExplicit();
            // DeploymentOutputs fact bits; explicit-only getters must stay guarded.
            return uint64_t(asset) | (uint64_t(value)<<1) | (uint64_t(output.nNonce.IsNull())<<2) |
                (uint64_t(asset && output.nAsset.GetAsset()==bond_asset)<<3) |
                (uint64_t(asset && output.nAsset.GetAsset()==reissuance_token)<<4) |
                (uint64_t(asset && output.nAsset.GetAsset()==frozen.usdd_asset_id)<<5) |
                (uint64_t(value && output.nValue.GetAmount()!=0)<<6) | (uint64_t(token_burn==index)<<7);
        });
    };
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::STARTUP_DEPLOYMENT,[&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return !issuance.assetIssuance.IsNull();
        case 2: return issuance.assetIssuance.assetBlindingNonce.IsNull();
        case 3: return VerifyConfiguredBondIssuance(transaction, frozen, public_deployment);
        case 4: return issuance.assetIssuance.nInflationKeys.IsExplicit();
        case 5: return issuance.assetIssuance.nInflationKeys.GetAmount()==1;
        case 6:
            GenerateAssetEntropy(entropy,issuance.prevout,issuance.assetIssuance.assetEntropy);
            CalculateAsset(bond_asset,entropy); CalculateReissuanceToken(reissuance_token,entropy,!public_deployment); return 1;
        case 7: return !bond_asset.IsNull();
        case 8: return !reissuance_token.IsNull();
        case 9: return bond_asset!=reissuance_token;
        case 10: frozen.bond_asset_id=bond_asset.id; return 1;
        case 11: return public_deployment;
        case 12: return inventory.nAsset.IsCommitment();
        case 13: return inventory.nValue.IsCommitment();
        case 14: return inventory.nNonce.IsCommitment();
        case 15: return !inventory.scriptPubKey.empty();
        case 16: return !inventory.scriptPubKey.IsUnspendable();
        case 17: return VerifyConfidentialPair(inventory.nValue,inventory.nAsset,ECX_BOND_FIXED_SUPPLY,bond_asset,
            frozen.inventory_value_blinding_factor,frozen.inventory_asset_blinding_factor);
        case 18: return burn.nAsset.IsExplicit();
        case 19: return burn.nAsset.GetAsset()==reissuance_token;
        case 20: return burn.nValue.IsExplicit();
        case 21: return burn.nValue.GetAmount()==1;
        case 22: return burn.nNonce.IsNull();
        case 23: return burn.scriptPubKey.IsUnspendable();
        case 24:
            frozen.inventory_covenant_script_sha256=Sha256(inventory.scriptPubKey);
            frozen.reissuance_token_burn_script_sha256=Sha256(burn.scriptPubKey); return 1;
        case 25: return authority_source.nAsset.IsExplicit();
        case 26: return authority_source.nValue.IsExplicit();
        case 27: return authority_source.nValue.GetAmount()==1;
        case 28: return authority_source.nNonce.IsNull();
        case 29: return !authority_source.scriptPubKey.empty();
        case 30: return !authority_source.scriptPubKey.IsUnspendable();
        case 31: frozen.state_authority_asset_id=authority_source.nAsset.GetAsset().id; return 1;
        case 32: return !frozen.state_authority_asset_id.IsNull();
        case 33: return frozen.state_authority_asset_id==decoded_configuration.state_authority_asset_id;
        case 34: return frozen.state_authority_asset_id!=frozen.bond_asset_id;
        case 35: return frozen.state_authority_asset_id!=reissuance_token.id;
        case 36: return frozen.state_authority_asset_id!=frozen.usdd_asset_id.id;
        case 37: return outputs_valid(transaction,frozen.inventory_output_index,frozen.reissuance_token_burn_output_index);
        case 38: deployment_txid=transaction.GetHash(); genesis_txid=genesis.GetHash(); return 1;
        case 39: return deployment_txid!=genesis_txid;
        case 40: return consensus.genesis_state_outpoint.hash==genesis_txid;
        case 41: return consensus.genesis_state_outpoint.n<genesis.vout.size();
        case 42: return !genesis.vin.empty();
        case 43: return genesis.vin[0].prevout==COutPoint{deployment_txid,frozen.state_authority_source_output_index};
        case 44: return HasOnlyOrdinaryInputs(genesis);
        case 45: return genesis.vout[consensus.genesis_state_outpoint.n].nAsset.IsExplicit();
        case 46: return genesis.vout[consensus.genesis_state_outpoint.n].nValue.IsExplicit();
        case 47: return genesis.vout[consensus.genesis_state_outpoint.n].nAsset.GetAsset().id==frozen.state_authority_asset_id;
        case 48: return genesis.vout[consensus.genesis_state_outpoint.n].nValue.GetAmount()==1;
        case 49: return genesis.vout[consensus.genesis_state_outpoint.n].nNonce.IsNull();
        case 50: return genesis.vout[consensus.genesis_state_outpoint.n].scriptPubKey.size()==34;
        case 51: return genesis.vout[consensus.genesis_state_outpoint.n].scriptPubKey[0]==OP_1;
        case 52: return genesis.vout[consensus.genesis_state_outpoint.n].scriptPubKey[1]==32;
        case 53: return outputs_valid(genesis,consensus.genesis_state_outpoint.n,std::nullopt);
        default: {
            static constexpr const char* errors[]{"ECX bond V2 issuance is not the exact fixed supply",
                "ECX bond V2 derived asset identities are invalid","ECX bond V2 inventory opening is invalid",
                "ECX bond V2 reissuance token is not destroyed","ECX bond V2 state-authority source is not one explicit spendable unit",
                "ECX bond V2 state-authority source asset is not independent","ECX bond V2 deployment has an unclassified or prefunded output",
                "ECX bond V2 deployment and genesis must be separate transactions",
                "ECX bond V2 genesis is not the preauthorized spend of its deployment authority",
                "ECX bond V2 state authority output is invalid","ECX bond V2 genesis has an unclassified or prefunded output"};
            if (step<54 || step>64) throw std::logic_error("invalid startup deployment action");
            throw std::runtime_error(errors[step-54]);
        }
        }
    });

    frozen.bond_deployment_commitment = BondDeploymentCommitment(frozen.deployment_version,
        {deployment_txid.ToUint256(), issuance.prevout.hash.ToUint256(), issuance.prevout.n,
         bond_asset.id, reissuance_token.id, frozen.inventory_output_index,
         frozen.reissuance_token_burn_output_index, frozen.inventory_covenant_script_sha256,
         frozen.reissuance_token_burn_script_sha256});

    /* Activation is an exact physical/configuration join.  A valid V18 hash
     * for different Tx1/Tx2 assets or scripts must never activate this
     * singleton. */
    drivechain::haskell::ExchangeActivationFacts(std::array<const unsigned char*,40>{
        decoded_configuration.bond_asset_id.begin(),frozen.bond_asset_id.begin(),
        decoded_configuration.deployment_commitment.begin(),frozen.bond_deployment_commitment.begin(),
        decoded_configuration.inventory_script_sha256.begin(),frozen.inventory_covenant_script_sha256.begin(),
        derived_inventory_script_hash.begin(),decoded_configuration.burn_script_sha256.begin(),
        frozen.reissuance_token_burn_script_sha256.begin(),decoded_configuration.queue_script_sha256.begin(),
        derived_queue_script_hash.begin(),decoded_configuration.staging_template_commitment.begin(),
        frozen.bond_inbox_redemption_staging_template_commitment.begin(),decoded_configuration.staging_renderer_domain.begin(),
        frozen.bond_inbox_redemption_staging_renderer_domain.begin(),decoded_configuration.staging_internal_key.begin(),
        frozen.bond_inbox_redemption_staging_internal_key.begin(),decoded_configuration.staging_process_cmr.begin(),
        frozen.bond_inbox_redemption_staging_process_cmr.begin(),decoded_configuration.staging_refund_cmr.begin(),
        frozen.bond_inbox_redemption_staging_refund_cmr.begin(),decoded_configuration.collateral_vault_covenant_cmr.begin(),
        frozen.collateral_vault_covenant_cmr.begin(),frozen.transition_cmr.begin(),
        frozen.insurance_reserve_covenant_cmr.begin(),decoded_configuration.collateral_vault_script_sha256.begin(),
        derived_collateral_vault_script_hash.begin(),consensus.collateral_vault_script_hash.begin(),
        decoded_configuration.insurance_reserve_covenant_cmr.begin(),decoded_configuration.insurance_script_sha256.begin(),
        derived_insurance_script_hash.begin(),frozen.inventory_cmr.begin(),
        frozen.redemption_queue_cmr.begin(),frozen.incremental_activation_program_id.begin(),
        frozen.incremental_activation_configuration_hash.begin(),frozen.incremental_activation_cmr.begin(),
        frozen.incremental_successor_program_id.begin(),frozen.incremental_successor_configuration_hash.begin(),
        frozen.incremental_successor_transition_cmr.begin(),frozen.incremental_successor_state_node_domain_sha256.begin()
    });

    DataStream transaction_bytes;
    transaction_bytes << TX_WITH_WITNESS(transaction);
    DataStream genesis_bytes;
    genesis_bytes << TX_WITH_WITNESS(genesis);
    const uint64_t numbers[]{frozen.issuance_input_index,frozen.inventory_output_index,
        frozen.reissuance_token_burn_output_index,frozen.state_authority_source_output_index,
        frozen.genesis_mark_price,frozen.genesis_initialization_version,frozen.genesis_initialization_height,
        frozen.genesis_initialization_parent_mtp};
    std::vector<std::span<const unsigned char>> blobs{
        {UCharCast(transaction_bytes.data()),transaction_bytes.size()},
        {UCharCast(genesis_bytes.data()),genesis_bytes.size()},frozen.canonical_configuration_bytes};
    for (const uint256* value : {
             &frozen.inventory_asset_blinding_factor,
             &frozen.inventory_value_blinding_factor,
             &frozen.issuance_value_blinding_factor,
             &frozen.transition_program_id,
             &frozen.configuration_hash,
             &frozen.bond_asset_id,
             &frozen.bond_deployment_commitment,
             &frozen.inventory_covenant_script_sha256,
             &frozen.reissuance_token_burn_script_sha256,
             &frozen.collateral_vault_covenant_cmr,
             &frozen.insurance_reserve_script_sha256,
             &frozen.insurance_reserve_covenant_cmr,
             &frozen.redemption_queue_script_sha256,
             &frozen.bond_inbox_redemption_staging_template_commitment,
             &frozen.bond_inbox_redemption_staging_renderer_domain,
             &frozen.bond_inbox_redemption_staging_internal_key,
             &frozen.bond_inbox_redemption_staging_process_cmr,
             &frozen.bond_inbox_redemption_staging_refund_cmr,
             &frozen.state_authority_asset_id,
             &frozen.public_state_domain_sha256,
             &frozen.state_node_domain_sha256,
             &frozen.transition_journal_domain_sha256,
             &frozen.transition_cmr,
             &frozen.incremental_activation_program_id,
             &frozen.incremental_activation_configuration_hash,
             &frozen.incremental_activation_cmr,
             &frozen.incremental_successor_program_id,
             &frozen.incremental_successor_configuration_hash,
             &frozen.incremental_successor_transition_cmr,
             &frozen.incremental_successor_state_node_domain_sha256,
             &frozen.inventory_cmr,
             &frozen.redemption_queue_cmr,
             &frozen.ecx_btc_conversion_program_id,
             &frozen.ecx_btc_redemption_covenant_commitment,
             &frozen.ecx_btc_source_checkpoint_commitment,
             &frozen.usdd_usd_conversion_program_id,
             &frozen.usdd_usd_redemption_covenant_commitment,
             &frozen.usdd_usd_source_checkpoint_commitment,
             &frozen.matcher_genesis_receipt_hash,
             &frozen.order_receipts_genesis_root,
             &frozen.genesis_availability_root,
             &frozen.usdd_asset_id.id}) {
        blobs.emplace_back(value->begin(),32);
    }
    blobs.emplace_back(frozen.keyless_internal_key);
    blobs.emplace_back(frozen.genesis_initialization_block_hash.begin(),32);
    frozen.identity_derivation_record_sha256 =
        TaggedHash("ECX/bond-v2-activation-identity/v5", EncodeExchangeFingerprint(2,numbers,blobs));
    frozen.activation_enabled = true;
    static_assert(BOND_V2_PARTITIONED_INCREMENTAL_RECOVERY_BOUND_PROVEN,
                  "partitioned incremental recovery theorem must be source frozen");
    frozen.identities_frozen = true;
}

uint256 EmptyBondV2QueueRoot()
{
    return TaggedHash("ECX/redemption-queue/v2/empty", {});
}

uint256 ComputeBondInboxGenesisRoot(const ExchangeConsensus& consensus)
{
    return (::TaggedHash("ECX/bond-inbox-genesis/v2") << consensus.bond_v2.bond_inbox_domain
        << consensus.chain_id << consensus.bond_v2.configuration_hash).GetSHA256();
}

uint256 ComputeBondInboxOutcomeGenesisRoot(const ExchangeConsensus& consensus)
{
    return (::TaggedHash("ECX/bond-inbox-outcomes-genesis/v4-expired-unavailable-v2")
        << consensus.bond_v2.bond_inbox_domain << consensus.chain_id << consensus.bond_v2.configuration_hash).GetSHA256();
}

uint256 EmptyMatcherExecutionReceiptBatchRoot()
{
    return TaggedHash(
        "ECX/central-matcher-execution-receipt-batch/v2/empty", {});
}

std::array<uint256,4> ComputeBondV2GenesisRoots(const ExchangeConsensus& consensus, uint64_t height, uint64_t mtp,
    std::array<uint256*,4> published = {})
{
    const auto& frozen=consensus.bond_v2;
    const auto encoded=drivechain::haskell::ExchangeGenesisRoots(height,mtp,frozen.genesis_mark_price,
        {frozen.bond_asset_id.begin(),frozen.bond_deployment_commitment.begin(),frozen.inventory_covenant_script_sha256.begin(),
         consensus.chain_id.data(),frozen.matcher_genesis_receipt_hash.begin(),frozen.order_receipts_genesis_root.begin(),
         consensus.forced_action_domain.data(),consensus.deposit_inbox_domain.data(),frozen.bond_inbox_domain.begin(),
         frozen.configuration_hash.begin(),frozen.public_state_domain_sha256.begin(),frozen.genesis_availability_root.begin()},
        [&](uint32_t kind,std::span<const unsigned char> bytes) {
            static constexpr const char* tags[]{"ECX/redemption-queue/v2/empty","ECX/bond-public-state/v2",
                "ECX/funding-state/v2","ECX/merkle-empty/v1","ECX/forced-inbox-genesis/v1","ECX/deposit-inbox-genesis/v1",
                "ECX/bond-inbox-genesis/v2","ECX/bond-inbox-outcomes-genesis/v4-expired-unavailable-v2",
                "ECX/exchange-state/v9-expired-unavailable-v2"};
            const uint256 digest=kind==9 ? Sha256({bytes.data(),bytes.size()}) : TaggedHash(tags[kind],bytes);
            const int index=kind==1 ? 1 : kind==2 ? 2 : kind==8 ? 0 : kind==9 ? 3 : -1;
            if (index>=0 && published[index]) *published[index]=digest;
            std::array<unsigned char,32> result;
            std::copy(digest.begin(),digest.end(),result.begin());
            return result;
        });
    std::array<uint256,4> roots;
    for (size_t i=0;i<roots.size();++i) std::copy_n(encoded.begin()+32*i,32,roots[i].begin());
    return roots;
}

uint256 ComputeBondV2GenesisStateNode(
    const ExchangeConsensus& consensus,
    const uint256& covenant_state_hash)
{
    return EcxStateNodeHash(consensus.bond_v2.state_node_domain_sha256, covenant_state_hash);
}

uint256 ComputeBondV2GenesisTaprootRoot(
    const ExchangeConsensus& consensus,
    const uint256& state_node)
{
    std::array<uint256,4> hashes;
    BuildBondTree(consensus.bond_v2.transition_cmr,&consensus.bond_v2.incremental_activation_cmr,
        state_node,{&hashes[0],&hashes[1],&hashes[2],&hashes[3]});
    return hashes[3];
}

bool ComputeBondV2GenesisScript(
    const ExchangeConsensus& consensus,
    const uint256& covenant_state_hash,
    CScript& script)
{
    const uint256 state_node{
        ComputeBondV2GenesisStateNode(consensus, covenant_state_hash)};
    const uint256 root{ComputeBondV2GenesisTaprootRoot(consensus, state_node)};
    const XOnlyPubKey internal{Span<const unsigned char>(
        consensus.bond_v2.keyless_internal_key.data(), 32)};
    const auto tweaked{internal.CreateTapTweak(&root)};
    if (!tweaked) return false;
    script = GetScriptForDestination(WitnessV1Taproot(tweaked->first));
    return true;
}

bool IsZero(const std::array<unsigned char, 32>& value)
{
    return drivechain::haskell::ExchangeAbsent(std::array{value.data()});
}

uint256 RawHash32(const unsigned char* bytes)
{
    uint256 result;
    std::copy(bytes, bytes + 32, result.begin());
    return result;
}

bool FrozenBondV2IdentityAvailable(
    const ExchangeConsensus::BondV2FrozenConsensus& frozen,
    std::string& error)
{
    const bool public_deployment=frozen.deployment_version==3;
    bool direct_price=false;
    DecodedFrozenConfigurationV18 decoded;
    const std::array<std::pair<const char*, const uint256*>, 45> identities{{
        {"transition program", &frozen.transition_program_id},
        {"configuration", &frozen.configuration_hash},
        {"collateral vault covenant CMR", &frozen.collateral_vault_covenant_cmr},
        {"bond asset", &frozen.bond_asset_id},
        {"deployment", &frozen.bond_deployment_commitment},
        {"inventory covenant script", &frozen.inventory_covenant_script_sha256},
        {"token burn script", &frozen.reissuance_token_burn_script_sha256},
        {"redemption queue script", &frozen.redemption_queue_script_sha256},
        {"insurance reserve script", &frozen.insurance_reserve_script_sha256},
        {"insurance reserve CMR", &frozen.insurance_reserve_covenant_cmr},
        {"redemption staging descriptor", &frozen.bond_inbox_redemption_staging_template_commitment},
        {"redemption staging renderer domain", &frozen.bond_inbox_redemption_staging_renderer_domain},
        {"redemption staging internal key", &frozen.bond_inbox_redemption_staging_internal_key},
        {"redemption staging process CMR", &frozen.bond_inbox_redemption_staging_process_cmr},
        {"redemption staging refund CMR", &frozen.bond_inbox_redemption_staging_refund_cmr},
        {"bond inbox domain", &frozen.bond_inbox_domain},
        {"custody receipt codec", &frozen.bond_inbox_custody_receipt_codec_hash},
        {"availability scheme", &frozen.availability_scheme_hash},
        {"availability registry", &frozen.availability_custodian_registry_hash},
        {"state authority asset", &frozen.state_authority_asset_id},
        {"public state domain", &frozen.public_state_domain_sha256},
        {"state node domain", &frozen.state_node_domain_sha256},
        {"journal domain", &frozen.transition_journal_domain_sha256},
        {"transition CMR", &frozen.transition_cmr},
        {"incremental activation program", &frozen.incremental_activation_program_id},
        {"incremental activation configuration", &frozen.incremental_activation_configuration_hash},
        {"incremental activation CMR", &frozen.incremental_activation_cmr},
        {"incremental successor program", &frozen.incremental_successor_program_id},
        {"incremental successor configuration", &frozen.incremental_successor_configuration_hash},
        {"incremental successor transition CMR", &frozen.incremental_successor_transition_cmr},
        {"incremental successor state-node domain", &frozen.incremental_successor_state_node_domain_sha256},
        {"inventory CMR", &frozen.inventory_cmr},
        {"redemption queue CMR", &frozen.redemption_queue_cmr},
        {"ECX/BTC conversion program", &frozen.ecx_btc_conversion_program_id},
        {"ECX/BTC redemption covenant", &frozen.ecx_btc_redemption_covenant_commitment},
        {"ECX/BTC source checkpoint", &frozen.ecx_btc_source_checkpoint_commitment},
        {"USDD/USD conversion program", &frozen.usdd_usd_conversion_program_id},
        {"USDD/USD redemption covenant", &frozen.usdd_usd_redemption_covenant_commitment},
        {"USDD/USD source checkpoint", &frozen.usdd_usd_source_checkpoint_commitment},
        {"identity derivation record", &frozen.identity_derivation_record_sha256},
        {"matcher genesis receipt", &frozen.matcher_genesis_receipt_hash},
        {"order receipts genesis", &frozen.order_receipts_genesis_root},
        {"genesis availability", &frozen.genesis_availability_root},
        {"USDD asset", &frozen.usdd_asset_id.id},
        {"inventory asset blinder", &frozen.inventory_asset_blinding_factor},
    }};
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::FROZEN_ADMISSION,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return drivechain::haskell::ExchangeDeployment(frozen.deployment_version, [&](uint32_t step) {
                switch (step) {
                case 0: return frozen.inventory_asset_blinding_factor.IsNull();
                case 1: return frozen.inventory_value_blinding_factor.IsNull();
                case 2: return frozen.issuance_value_blinding_factor.IsNull();
                case 3: return frozen.activation_enabled;
                default: return frozen.identities_frozen;
                }
            }, error);
            case 2: return drivechain::haskell::ParentReplayAll<2>({
                [&] { return !frozen.canonical_configuration_bytes.empty(); },
                [&] { return frozen.canonical_configuration_bytes.front() == 6; },
            });
            case 3: return DecodeFrozenConfigurationV18(frozen.canonical_configuration_bytes,decoded,error);
            case 4: return TaggedHash("ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
                frozen.canonical_configuration_bytes)==frozen.configuration_hash;
            case 5: direct_price=decoded.direct_price; return direct_price;
            case 6: {
                std::array<const unsigned char*,6> conversions;
                for (size_t i=0;i<conversions.size();++i) conversions[i]=identities[33+i].second->begin();
                return drivechain::haskell::ExchangeAbsent(conversions);
            }
            case 7: {
                const int missing = drivechain::haskell::ExchangeRequiredIdentity(public_deployment, direct_price,
                    [&](uint32_t index) { return !identities[index].second->IsNull(); });
                if (missing) error = std::string("missing frozen ECX bond V2 ") + identities[missing-1].first;
                return missing==0;
            }
            case 8: return drivechain::haskell::ExchangePhysicalInputs(public_deployment, [&](uint32_t step) {
                switch (step) {
                case 0: return bool(frozen.deployment_transaction);
                case 1: return bool(frozen.genesis_transaction);
                case 2: return !frozen.canonical_configuration_bytes.empty();
                case 3: return frozen.genesis_mark_price != 0;
                case 4: return !frozen.inventory_value_blinding_factor.IsNull();
                case 5: return !frozen.issuance_value_blinding_factor.IsNull();
                case 6: return frozen.issuance_value_blinding_factor != frozen.inventory_value_blinding_factor;
                case 7: return frozen.issuance_value_blinding_factor != frozen.inventory_asset_blinding_factor;
                case 8: return frozen.inventory_asset_blinding_factor != frozen.inventory_value_blinding_factor;
                case 9: return !IsZero(frozen.keyless_internal_key);
                case 10: return IsEcxNumsInternalKey(frozen.keyless_internal_key.data());
                case 11: return IsEcxStagingRendererDomainV18(frozen.bond_inbox_redemption_staging_renderer_domain.begin());
                default: return IsEcxNumsInternalKey(frozen.bond_inbox_redemption_staging_internal_key.begin());
                }
            });
            case 9: return drivechain::haskell::ExchangeFrozenBounds(std::array<uint64_t, 16>{
                frozen.bond_inbox_redemption_staging_tapleaf_version, frozen.bond_inbox_refund_minimum_parent_blocks,
                frozen.bond_inbox_inclusion_blocks, frozen.bond_inbox_max_bundle_bytes,
                frozen.bond_inbox_max_entries_per_sidechain_block, frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block,
                frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block, frozen.bond_inbox_max_pending_entries_per_transition,
                frozen.bond_inbox_max_consumed_entries_per_transition, frozen.bond_redemption_max_queue_entries,
                frozen.matcher_execution_inclusion_parent_blocks, frozen.maximum_conversion_age_seconds,
                frozen.maximum_conversion_proof_bytes, frozen.recursive_proof_marker_bytes,
                frozen.fixed_supply_atoms, frozen.redemption_delay_parent_blocks});
            case 10: return drivechain::haskell::ExchangeRegistry(frozen.custodian_encryption_keys,frozen.custodian_attestation_keys,error);
            case 11: {
                // Configuration, proof, covenant and isolated-domain roles reuse the required identity table.
                static constexpr std::array<size_t,22> roles{1,25,28,0,24,27,33,36,23,26,29,2,9,31,32,13,14,30,21,20,22,11};
                std::array<const unsigned char*,22> hashes;
                std::transform(roles.begin(),roles.end(),hashes.begin(),[&](size_t index) { return identities[index].second->begin(); });
                return drivechain::haskell::ExchangeFrozenIdentities(direct_price,hashes,error);
            }
            case 12: error="direct-price configuration hash mismatch"; return 1;
            case 13: error="direct-price configuration requires absent oracle conversion identities"; return 1;
            case 14: error="incomplete frozen ECX bond V2 physical activation inputs"; return 1;
            case 15: error="invalid frozen ECX bond V2 bounds or timing parameters"; return 1;
            default: throw std::logic_error("invalid frozen admission action");
            }
        })==0;
}

uint256 TxOutHash(const CTxOut& output)
{
    HashWriter stream;
    return (stream << output).GetSHA256();
}

struct ForcedActionPayload
{
    uint8_t kind{0};
    std::vector<unsigned char> body;
};

struct DepositPayload
{
    uint32_t deposit_vout{0};
    std::array<unsigned char, 32> trader{};
};

bool ScriptContainsMagic(
    const CScript& script,
    const std::array<unsigned char, 4>& magic)
{
    return drivechain::haskell::ReturnMarker(magic, script);
}

bool IsNullOutputWitness(const CTransaction& tx, size_t output_index)
{
    return !drivechain::haskell::ParentReplayAll<2>({
        [&] { return output_index < tx.witness.vtxoutwit.size(); },
        [&] { return !tx.witness.vtxoutwit[output_index].IsNull(); },
    });
}

bool VerifySignedBody(
    const std::string& tag,
    const std::vector<unsigned char>& body,
    size_t unsigned_size,
    size_t trader_offset,
    std::string& error)
{
    const XOnlyPubKey trader{
        Span<const unsigned char>(body.data() + trader_offset, 32)};
    return drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::FORCED_SIGNATURE,
        [&](uint32_t step) {
        switch (step) {
        case 0: return trader.IsFullyValid();
        case 1: {
            return trader.VerifySchnorr(TaggedHash(tag,std::span{body}.first(unsigned_size)),
                Span<const unsigned char>(body.data()+unsigned_size,64));
        }
        default: throw std::logic_error("invalid forced signature read");
        }
    },error);
}

bool ValidateForcedBody(
    uint8_t kind,
    const std::vector<unsigned char>& body,
    const ExchangeConsensus& consensus,
    std::string& error)
{
    static_assert(FORCED_CANCEL_BODY_SIZE == 201 && FORCED_LIMIT_BODY_SIZE == 208 &&
        FORCED_WITHDRAW_BODY_SIZE == 193 && DEPOSIT_PAYLOAD_SIZE == 73);
    const int code = drivechain::haskell::ExchangeForcedBody(kind, body, consensus.chain_id, ECX_USDD_MARKET);
    static constexpr const char* errors[]{
        "ECX forced action kind, version, or fixed body length is invalid",
        "ECX forced action chain id does not match this deployment",
        "ECX forced cancellation body is non-canonical",
        "ECX forced reduce-only IOC body is non-canonical",
        "ECX forced withdrawal body is non-canonical"};
    if (code) { error = errors[code-1]; return false; }
    static constexpr const char* tags[]{"ECX/cancel-order/v1", "ECX/limit-order/v1", "ECX/withdrawal-request/v1"};
    return VerifySignedBody(tags[kind], body, body.size()-64, kind == 2 ? 33 : 49, error);
}

bool CheckMarkerOutput(const CTransaction& tx, size_t index)
{
    const CTxOut& output = tx.vout[index];
    return drivechain::haskell::ExchangeProfile(false, [&](uint32_t step) {
        switch (step) {
        case 0: return output.nAsset.IsExplicit();
        case 1: return output.nAsset.GetAsset() == ::policyAsset;
        case 2: return output.nValue.IsExplicit();
        case 3: return output.nValue.GetAmount() == 0;
        case 4: return output.nNonce.IsNull();
        case 5: return IsNullOutputWitness(tx, index);
        default: throw std::logic_error("invalid marker output read");
        }
    });
}

bool CheckMarkerEnvelope(const CTransaction& tx, size_t index, const std::vector<unsigned char>& payload,
    const ExchangeConsensus& consensus, bool forced, std::string& error)
{
    namespace hs = drivechain::haskell;
    return hs::ExchangeTransactionShape(forced ? hs::TransactionShape::FORCED_ENVELOPE : hs::TransactionShape::DEPOSIT_ENVELOPE,
        [&](uint32_t step) {
        switch (step) {
        case 0: return payload[4] == 1;
        case 1: return forced ? ReadBE16(payload.data()+6) == payload.size()-8 :
            std::equal(consensus.chain_id.begin(),consensus.chain_id.end(),payload.begin()+5);
        case 2: return CheckMarkerOutput(tx,index);
        default: throw std::logic_error("invalid marker envelope read");
        }
    },error);
}

template <typename Payload, typename Parse>
bool ParseMarkerOutput(const CTransaction& tx, size_t output_index,
    const ExchangeConsensus& consensus, bool forced, std::optional<Payload>& result,
    std::string& error, Parse&& parse)
{
    result.reset();
    const auto& script = tx.vout[output_index].scriptPubKey;
    std::vector<unsigned char> payload;
    Payload parsed;
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::LEGACY_MARKER, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return ScriptContainsMagic(script, forced ? FORCED_MAGIC : DEPOSIT_MAGIC);
        case 2: return hs::ExchangeLegacyMarkerFrame(forced, script, payload);
        case 3:
            error = forced ? "ECX forced action output is not one exact minimal OP_RETURN push"
                : "ECX deposit marker is not one exact minimal OP_RETURN push";
            return 0;
        case 4: return CheckMarkerEnvelope(tx, output_index, payload, consensus, forced, error);
        case 5: return parse(payload, parsed);
        case 6: result = std::move(parsed); return 1;
        default: throw std::logic_error("invalid legacy marker action");
        }
    });
}

bool ParseForcedOutput(
    const CTransaction& tx,
    size_t output_index,
    const ExchangeConsensus& consensus,
    std::optional<ForcedActionPayload>& result,
    std::string& error)
{
    return ParseMarkerOutput(tx, output_index, consensus, true, result, error,
        [&](const auto& payload, ForcedActionPayload& parsed) {
            parsed.kind = payload[5];
            parsed.body.assign(payload.begin() + 8, payload.end());
            return ValidateForcedBody(parsed.kind, parsed.body, consensus, error);
        });
}

bool ParseDepositOutput(
    const CTransaction& tx,
    size_t output_index,
    const ExchangeConsensus& consensus,
    std::optional<DepositPayload>& result,
    std::string& error)
{
    return ParseMarkerOutput(tx, output_index, consensus, false, result, error,
        [&](const auto& payload, DepositPayload& parsed) {
            parsed.deposit_vout = ReadBE32(payload.data() + 37);
            std::copy(payload.begin() + 41, payload.end(), parsed.trader.begin());
            const XOnlyPubKey trader{Span<const unsigned char>(parsed.trader.data(), 32)};
            const CTxOut* deposit{nullptr};
            return drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::DEPOSIT_REFERENCE,
                [&](uint32_t step) {
                switch (step) {
                case 0: return trader.IsFullyValid();
                case 1: return parsed.deposit_vout < tx.vout.size();
                case 2: return parsed.deposit_vout != output_index;
                case 3:
                    deposit = &tx.vout[parsed.deposit_vout];
                    return deposit->scriptPubKey == consensus.collateral_vault_script;
                case 4: return deposit->nAsset.IsCommitment();
                case 5: return deposit->nValue.IsCommitment();
                case 6: return deposit->nNonce.IsCommitment();
                case 7: return parsed.deposit_vout < tx.witness.vtxoutwit.size();
                case 8: return !tx.witness.vtxoutwit[parsed.deposit_vout].vchRangeproof.empty();
                case 9: return !tx.witness.vtxoutwit[parsed.deposit_vout].vchSurjectionproof.empty();
                default: throw std::logic_error("invalid collateral output read");
                }
            },error);
        });
}

bool ConsensusConfigured(const ExchangeConsensus& consensus, std::string& error)
{
    using drivechain::haskell::ParentReplayAll;
    const bool enabled = consensus.activation_height != std::numeric_limits<int>::max();
    const bool external = ParentReplayAll<2>({[&] { return enabled; },
        [&] { return !IsExchangeStateInternalOutpoint(consensus.genesis_state_outpoint); }});
    // Identity initialization enters Haskell; never run it inside an admission callback.
    const bool not_bmm = ParentReplayAll<2>({[&] { return external; },
        [&] { return !drivechain::IsBmmStateInternalOutpoint(consensus.genesis_state_outpoint); }});
    return drivechain::haskell::ExchangeConfiguration([&](uint32_t step) {
        switch (step) {
        case 0: return enabled;
        case 1: return external;
        case 2: return not_bmm;
        case 3: return !drivechain::IsCtipStateInternalOutpoint(consensus.genesis_state_outpoint);
        case 4: return consensus.activation_height > 0;
        case 5: return !consensus.genesis_state_outpoint.IsNull();
        case 6: return !consensus.genesis_state_root.IsNull();
        case 7: return !IsZero(consensus.chain_id);
        case 8: return !IsZero(consensus.forced_action_domain);
        case 9: return !IsZero(consensus.deposit_inbox_domain);
        case 10: return consensus.forced_action_domain != consensus.deposit_inbox_domain;
        case 11: return !consensus.collateral_vault_script.empty();
        case 12: return !consensus.collateral_vault_script_hash.IsNull();
        case 13: return Sha256(consensus.collateral_vault_script) == consensus.collateral_vault_script_hash;
        default: throw std::logic_error("invalid exchange configuration read");
        }
    }, error);
}

bool DecodeCursorPayload(
    const CScript& script,
    bool& is_cursor_marker,
    uint64_t& forced_cursor,
    uint64_t& deposit_cursor,
    std::string& error)
{
    is_cursor_marker = false;
    CScript::const_iterator cursor = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> payload;
    using drivechain::haskell::ParentReplayAll;
    if (!ParentReplayAll<4>({
        [&] { return script.GetOp(cursor, opcode); },
        [&] { return opcode == OP_RETURN; },
        [&] { return ParentReplayAll<2>({
            [&] { return script.GetOp(cursor, opcode, payload); },
            [&] { return opcode <= OP_PUSHDATA4; },
        }); },
        [&] { return cursor == script.end(); },
    })) {
        return true;
    }
    return drivechain::haskell::ExchangeCursorPayload(payload,is_cursor_marker,forced_cursor,deposit_cursor,error);
}

bool DeriveProcessedCursors(
    const CBlock& block,
    const ExchangeStateTracker& previous_state,
    const ExchangeStateTracker& next_state,
    uint64_t previous_forced_cursor,
    uint64_t previous_deposit_cursor,
    uint64_t& next_forced_cursor,
    uint64_t& next_deposit_cursor,
    std::string& error,
    bool empty_incremental_activation = false)
{
    uint256 marker_transaction;
    const uint32_t flags = (next_state.outpoint != previous_state.outpoint) |
        (uint32_t{empty_incremental_activation} << 1);
    return drivechain::haskell::ExchangeDeriveCursors(block.vtx.size(),flags,
        previous_forced_cursor,previous_deposit_cursor,
        [&](uint32_t step, uint64_t tx, uint64_t index, uint64_t* fields) -> int32_t {
        if (step == 4) return marker_transaction == next_state.outpoint.hash;
        const auto& transaction = *block.vtx.at(tx);
        switch (step) {
        case 1: fields[0] = transaction.vout.size(); return 1;
        case 2: {
            bool is_marker{false};
            if (!DecodeCursorPayload(transaction.vout.at(index).scriptPubKey,
                    is_marker,fields[0],fields[1],error)) return 0;
            return is_marker ? 2 : 1;
        }
        case 3: marker_transaction = transaction.GetHash(); return 1;
        default: throw std::logic_error("invalid cursor derivation action");
        }
    },next_forced_cursor,next_deposit_cursor,error);
}

bool ValidateInboxLiveness(
    const InboxTracker& previous_forced,
    const InboxTracker& previous_deposits,
    const InboxTracker& next_forced,
    const InboxTracker& next_deposits,
    uint64_t previous_forced_cursor,
    uint64_t previous_deposit_cursor,
    uint64_t next_forced_cursor,
    uint64_t next_deposit_cursor,
    uint64_t forced_appends,
    uint64_t deposit_appends,
    uint64_t previous_oldest_parent_height,
    uint64_t current_parent_height,
    uint64_t& next_oldest_parent_height,
    std::string& error)
{
    static_assert(MAX_COMBINED_UNCONSUMED == 64 && MAX_COMBINED_SAME_PARENT_APPENDS == 64 &&
        MAX_COMBINED_PENDING_WITNESS_ENTRIES == 448 && FORCED_INCLUSION_BLOCKS == 6);
    const std::array<uint64_t, 12> fields{previous_forced.count, previous_forced_cursor,
        previous_deposits.count, previous_deposit_cursor, next_forced.count, next_forced_cursor,
        next_deposits.count, next_deposit_cursor, forced_appends, deposit_appends,
        previous_oldest_parent_height, current_parent_height};
    return drivechain::haskell::ExchangeInbox(fields, next_oldest_parent_height, error);
}

bool ActiveAt(int height, const ExchangeConsensus& consensus)
{
    return drivechain::haskell::BmmActivation(3, 0, height, consensus.activation_height) == 1;
}

template <typename Tracker>
CScript EncodeTrackerRecord(const std::vector<unsigned char>& marker, const Tracker& tracker)
{
    DataStream stream;
    stream << marker << tracker;
    return CScript()
        << std::span<const std::byte>{stream.data(), stream.size()}
        << OP_DROP
        << OP_FALSE;
}

template <typename Tracker, typename Valid>
bool GetTrackerRecord(const CCoinsViewCache& view, const COutPoint& outpoint,
    const std::vector<unsigned char>& expected_marker,
    Tracker& tracker, std::string& error, const char* name, Valid valid)
{
    namespace hs = drivechain::haskell;
    const Coin& coin = view.AccessCoin(outpoint);
    if (const auto status = hs::ExchangeTracker(hs::TrackerPhase::ENCODING, [&](uint32_t step) {
        switch (step) {
        case 0: return !coin.IsSpent();
        case 1: return coin.out.nAsset.IsExplicit();
        case 2: return coin.out.nAsset.GetAsset() == Params().GetConsensus().pegged_asset;
        case 3: return coin.out.nValue.IsExplicit();
        case 4: return coin.out.nValue.GetAmount() == 0;
        default: throw std::logic_error("invalid tracker encoding read");
        }
    })) {
        error = std::string{name} + (status == 2 ? " is missing" : " has invalid asset or value encoding");
        return false;
    }
    CScript::const_iterator cursor = coin.out.scriptPubKey.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (hs::ExchangeTracker(hs::TrackerPhase::SCRIPT, [&](uint32_t step) {
        switch (step) {
        case 0: return coin.out.scriptPubKey.GetOp(cursor, opcode, data);
        case 1: return opcode <= OP_PUSHDATA4;
        case 2: case 4: return coin.out.scriptPubKey.GetOp(cursor, opcode);
        case 3: return opcode == OP_DROP;
        case 5: return opcode == OP_FALSE;
        case 6: return cursor == coin.out.scriptPubKey.end();
        default: throw std::logic_error("invalid tracker script read");
        }
    })) {
        error = std::string{name} + " script is malformed";
        return false;
    }
    try {
        DataStream stream{data};
        std::vector<unsigned char> marker;
        stream >> marker >> tracker;
        if (hs::ExchangeTracker(hs::TrackerPhase::PAYLOAD, [&](uint32_t step) {
            switch (step) {
            case 0: return stream.empty();
            case 1: return marker == expected_marker;
            case 2: return valid(tracker);
            default: throw std::logic_error("invalid tracker payload read");
            }
        })) {
            error = std::string{name} + " payload is invalid";
            return false;
        }
    } catch (...) {
        error = std::string{name} + " cannot be decoded";
        return false;
    }
    return true;
}

bool GetInboxTracker(const CCoinsViewCache& view, const COutPoint& outpoint,
    const std::vector<unsigned char>& marker, InboxTracker& tracker, std::string& error)
{
    return GetTrackerRecord(view,outpoint,marker,tracker,error,"persisted ECX inbox tracker",
        [](const InboxTracker& value) { return !value.root.IsNull(); });
}

template <typename Tracker>
void SetTrackerRecord(
    CCoinsViewCache& view,
    const COutPoint& outpoint,
    const std::vector<unsigned char>& marker,
    const Tracker& tracker,
    int height)
{
    view.SpendCoin(outpoint);
    CTxOut output(
        Params().GetConsensus().pegged_asset,
        0,
        EncodeTrackerRecord(marker, tracker));
    view.AddCoin(
        outpoint,
        Coin(std::move(output), drivechain::haskell::ExchangeTrackerHeight(false, height), false),
        true);
}

bool GetTracker(const CCoinsViewCache& view, ExchangeStateTracker& tracker, std::string& error)
{
    return GetTrackerRecord(view,EXCHANGE_TRACKER_OUTPOINT,EXCHANGE_TRACKER_MARKER,tracker,error,"persisted ECX tracker",
        [](const ExchangeStateTracker& value) {
            return drivechain::haskell::ParentReplayAll<2>({
                [&] { return !value.outpoint.IsNull(); },
                [&] { return !value.root.IsNull(); },
            });
        });
}

void SetTracker(CCoinsViewCache& view, const ExchangeStateTracker& tracker, int height)
{
    SetTrackerRecord(view, EXCHANGE_TRACKER_OUTPOINT, EXCHANGE_TRACKER_MARKER, tracker, height);
}

bool CheckAuthority(const CTxOut& output, const CTxOut* previous, std::string& error)
{
    const int code = drivechain::haskell::ExchangeAuthority(previous != nullptr, [&](uint32_t step) {
        switch (step) {
        case 0: return output.nAsset.IsExplicit();
        case 1: return output.nValue.IsExplicit();
        case 2: return output.nNonce.IsNull();
        case 3: return output.nAsset.GetAsset() == previous->nAsset.GetAsset();
        case 4: return output.nValue.GetAmount() == previous->nValue.GetAmount();
        case 5: return output.scriptPubKey.size() == 34;
        case 6: return output.scriptPubKey[0] == OP_1;
        case 7: return output.scriptPubKey[1] == 0x20;
        default: throw std::logic_error("invalid exchange authority read");
        }
    });
    if (code == 1) error = previous ? "ECX successor authority must use an explicit asset/value and null nonce"
                                   : "ECX state authority must use an explicit asset/value and null nonce";
    if (code == 2) error = "ECX transition changed the state authority asset";
    if (code == 3) error = "ECX transition changed the state authority value";
    if (code == 4) error = previous ? "ECX successor state authority must be a P2TR output"
                                   : "ECX state authority must be a P2TR output";
    return code == 0;
}

bool VerifyTrackedCoin(
    const CCoinsViewCache& view,
    const ExchangeStateTracker& tracker,
    CTxOut& output,
    std::string& error)
{
    const Coin& coin = view.AccessCoin(tracker.outpoint);
    return drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::TRACKED_COIN,
        [&](uint32_t step) {
        switch (step) {
        case 0: return !coin.IsSpent();
        case 1: output = coin.out; return CheckAuthority(output,nullptr,error);
        case 2: return ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,tracker.outpoint,output) == tracker.root;
        default: throw std::logic_error("invalid tracked coin read");
        }
    },error);
}

bool DeriveNext(
    const CBlock& block,
    const ExchangeStateTracker& previous,
    const CTxOut& previous_output,
    ExchangeStateTracker& next,
    std::string& error)
{
    return drivechain::haskell::ExchangeTransition(block.vtx.size(),[&](uint32_t step, uint64_t index) -> uint64_t {
        if (step == 2) { next = previous; return 1; }
        const auto& transaction = *block.vtx.at(index);
        if (step == 1 || step == 8) {
            const auto& outpoint = step == 1 ? previous.outpoint : next.outpoint;
            return drivechain::haskell::CountMatches(transaction.vin.size(),
                [&](uint64_t i) { return transaction.vin[i].prevout == outpoint; });
        }
        switch (step) {
        case 3: return !transaction.vin.empty();
        case 4: return transaction.vin.at(0).prevout == previous.outpoint;
        case 5: return !transaction.vout.empty();
        case 6: return CheckAuthority(transaction.vout.at(0),&previous_output,error);
        case 7:
            next.outpoint = COutPoint{transaction.GetHash(),0};
            next.root = ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,next.outpoint,transaction.vout.at(0));
            return 1;
        default: throw std::logic_error("invalid state transition action");
        }
    },error);
}

bool ResolveAuthenticatedParentHeight(
    const CCoinsViewCache& view,
    std::optional<uint64_t> supplied,
    uint64_t& parent_height,
    std::string& error)
{
    drivechain::BmmL1State bmm_state;
    std::string bmm_error;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::AUTHENTICATED_HEIGHT,
        [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return supplied.has_value();
        case 2: return *supplied != 0;
        case 3: error="ECX inbox event parent height must be nonzero"; return 1;
        case 4: parent_height=*supplied; return 1;
        case 5: return drivechain::GetBmmState(view,bmm_state,&bmm_error);
        case 6: return bmm_error.empty();
        case 7: error="ECX inbox event requires the authenticated BMM parent height"; return 1;
        case 8: error=bmm_error; return 1;
        case 9: parent_height=bmm_state.height; return 1;
        case 10: return parent_height != 0;
        default: throw std::logic_error("invalid authenticated parent height action");
        }
    })!=0;
}

uint256 AppendInboxHash(InboxTracker& tracker, const uint256& event_hash, const char* domain)
{
    const auto step = drivechain::haskell::ExchangeInboxEntry(drivechain::haskell::InboxCodec::STEP,
        {tracker.count}, {tracker.root.begin(), event_hash.begin()});
    tracker.root = TaggedHash(domain, step);
    ++tracker.count;
    return event_hash;
}

uint256 AppendForcedEntry(
    const ForcedActionPayload& action,
    const uint256& source_txid,
    uint32_t source_vout,
    uint64_t sidechain_height,
    uint64_t parent_height,
    const ExchangeConsensus& consensus,
    InboxTracker& tracker)
{
    const auto entry = drivechain::haskell::ExchangeInboxEntry(drivechain::haskell::InboxCodec::FORCED,
        {tracker.count, sidechain_height, parent_height, source_vout, action.kind},
        {consensus.chain_id.data(), tracker.root.begin(), source_txid.begin()}, action.body);
    return AppendInboxHash(tracker,TaggedHash("ECX/forced-action-entry/v1", entry),"ECX/forced-inbox-step/v1");
}

uint256 AppendDepositEntry(
    const DepositPayload& deposit,
    const CTransaction& transaction,
    uint32_t marker_vout,
    uint64_t sidechain_height,
    uint64_t parent_height,
    const ExchangeConsensus& consensus,
    InboxTracker& tracker)
{
    const uint256 source_txid{transaction.GetHash()};
    const uint256 output_hash{TxOutHash(transaction.vout[deposit.deposit_vout])};
    const auto event = drivechain::haskell::ExchangeInboxEntry(drivechain::haskell::InboxCodec::DEPOSIT,
        {tracker.count, sidechain_height, parent_height, deposit.deposit_vout, marker_vout},
        {consensus.chain_id.data(), tracker.root.begin(), source_txid.begin(), output_hash.begin(), deposit.trader.data()});
    return AppendInboxHash(tracker,TaggedHash("ECX/deposit-event/v1", event),"ECX/deposit-inbox-step/v1");
}

bool DeriveInboxNext(
    const CBlock& block,
    const CCoinsViewCache& view,
    int height,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> supplied_parent_height,
    const InboxTracker& previous_forced,
    const InboxTracker& previous_deposits,
    InboxTracker& next_forced,
    InboxTracker& next_deposits,
    uint64_t* forced_appends,
    uint64_t* deposit_appends,
    std::string& error)
{
    next_forced = previous_forced;
    next_deposits = previous_deposits;
    uint64_t resolved_parent_height{0};
    std::optional<std::pair<uint32_t, ForcedActionPayload>> forced;
    std::optional<std::pair<uint32_t, DepositPayload>> deposit;
    std::optional<ForcedActionPayload> parsed_forced;
    std::optional<DepositPayload> parsed_deposit;
    return drivechain::haskell::ExchangeDeriveInbox(block.vtx.size(),next_forced.count,next_deposits.count,
        [&](uint32_t step, uint64_t tx_index, uint64_t output_index) -> int64_t {
        if (step == 10) {
            if (forced_appends) *forced_appends = tx_index;
            if (deposit_appends) *deposit_appends = output_index;
            return 1;
        }
        const CTransaction& transaction = *block.vtx.at(tx_index);
        switch (step) {
        case 1:
            forced.reset(); deposit.reset(); parsed_forced.reset(); parsed_deposit.reset();
            if (transaction.vout.size() > INT64_MAX) throw std::length_error("inbox output count exceeds adapter range");
            return transaction.vout.size();
        case 2:
            parsed_forced.reset();
            if (!ParseForcedOutput(transaction,output_index,consensus,parsed_forced,error)) return 0;
            return parsed_forced ? 2 : 1;
        case 3:
            forced.emplace(static_cast<uint32_t>(output_index),std::move(parsed_forced.value()));
            return 1;
        case 4:
            parsed_deposit.reset();
            if (!ParseDepositOutput(transaction,output_index,consensus,parsed_deposit,error)) return 0;
            return parsed_deposit ? 2 : 1;
        case 5:
            deposit.emplace(static_cast<uint32_t>(output_index),parsed_deposit.value());
            return 1;
        case 6: return ResolveAuthenticatedParentHeight(view,supplied_parent_height,resolved_parent_height,error);
        case 7:
            error.clear(); // Preserve the tranche check's diagnostic reset.
            return forced.value().second.kind;
        case 8:
            AppendForcedEntry(forced.value().second,transaction.GetHash(),forced.value().first,
                static_cast<uint64_t>(height),resolved_parent_height,consensus,next_forced);
            return 1;
        case 9:
            AppendDepositEntry(deposit.value().second,transaction,deposit.value().first,
                static_cast<uint64_t>(height),resolved_parent_height,consensus,next_deposits);
            return 1;
        default: throw std::logic_error("invalid inbox derivation action");
        }
    },error);
}

bool ExpectedForBlock(
    const CBlock& block,
    const CBlockIndex* previous_index,
    const CCoinsViewCache& view,
    int height,
    ExchangeStateTracker& next,
    InboxTracker& next_forced,
    InboxTracker& next_deposits,
    uint64_t& next_forced_cursor,
    uint64_t& next_deposit_cursor,
    uint64_t& next_oldest_parent_height,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> authenticated_parent_height)
{
    const bool activation = height == consensus.activation_height;
    ExchangeStateTracker previous;
    InboxTracker previous_forced;
    InboxTracker previous_deposits;
    bool empty_incremental_activation{false};
    {
        CTxOut previous_output;
        ExchangeStateTracker derived;
        namespace hs = drivechain::haskell;
        if (!hs::ParentReplayStore(hs::ReplayStoreFlow::EXPECTED_CONTEXT,[&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return activation;
            case 2: previous={consensus.genesis_state_outpoint,consensus.genesis_state_root}; return true;
            case 3: case 14: return VerifyTrackedCoin(view,previous,previous_output,error);
            case 4: return DeriveNext(block,previous,previous_output,derived,error);
            case 5: return derived.outpoint==previous.outpoint;
            case 6: return derived.root==previous.root;
            case 7:
                next=previous;
                previous_forced={ComputeForcedInboxGenesis(consensus),0};
                previous_deposits={ComputeDepositInboxGenesis(consensus),0};
                return true;
            case 9: error="ECX activation block must carry the frozen genesis state"; return true;
            case 10: return GetTracker(view,previous,error);
            case 11: return previous_index!=nullptr;
            case 12: return (static_cast<uint32_t>(previous_index->nVersion)&CBlockHeader::EXCHANGE_STATE_HF_MASK)!=0;
            case 13: return previous_index->hashExchangeStateRoot==previous.root;
            case 15: return DeriveNext(block,previous,previous_output,next,error);
            case 16: return GetInboxTracker(view,FORCED_INBOX_TRACKER_OUTPOINT,FORCED_INBOX_TRACKER_MARKER,previous_forced,error);
            case 17: return GetInboxTracker(view,DEPOSIT_INBOX_TRACKER_OUTPOINT,DEPOSIT_INBOX_TRACKER_MARKER,previous_deposits,error);
            case 18: return (static_cast<uint32_t>(previous_index->nVersion)&CBlockHeader::FORCED_INBOX_HF_MASK)!=0;
            case 19: return (static_cast<uint32_t>(previous_index->nVersion)&CBlockHeader::DEPOSIT_INBOX_HF_MASK)!=0;
            case 20: return (static_cast<uint32_t>(previous_index->nVersion)&CBlockHeader::INBOX_CURSOR_HF_MASK)!=0;
            case 21: return previous_index->hashForcedInboxRoot==previous_forced.root;
            case 22: return previous_index->hashDepositInboxRoot==previous_deposits.root;
            case 23: return !previous_forced.root.IsNull();
            case 24: return !previous_deposits.root.IsNull();
            case 28: error="ECX inbox genesis commitment is invalid"; return true;
            case 29: error="persisted ECX inbox trackers disagree with the prior header roots"; return true;
            case 30: error="persisted ECX tracker disagrees with the prior header root"; return true;
            default: throw std::logic_error("invalid expected-state context action");
            }
        })) return false;
    }
    {
        size_t index{0};
        std::array<unsigned char,32> program{};
        namespace hs = drivechain::haskell;
        hs::ParentReplayStore(hs::ReplayStoreFlow::INCREMENTAL_SCAN,[&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return !activation;
            case 2: return consensus.bond_v2.activation_enabled;
            case 3: return consensus.bond_v2.identities_frozen;
            case 4: return previous_index->ecxBondV2Capital.has_value();
            case 5: return previous_index->ecxBondV2Capital->proof_profile==0;
            case 6: return previous.outpoint==consensus.genesis_state_outpoint;
            case 7: return previous_forced.count==0;
            case 8: return previous_deposits.count==0;
            case 9: return index<block.vtx.size();
            case 10: return !block.vtx.at(index)->vin.empty();
            case 11: return block.vtx.at(index)->vin[0].prevout==previous.outpoint;
            case 12: return block.vtx.at(index)->GetHash()==next.outpoint.hash;
            case 13: return !block.vtx.at(index)->witness.vtxinwit.empty();
            case 14: {
                program.fill(0);
                std::array<unsigned char,364> values{};
                return ParseActivationAnnex(block.vtx.at(index)->witness.vtxinwit[0].scriptWitness.stack,program,values);
            }
            case 15: return std::equal(program.begin(),program.end(),consensus.bond_v2.incremental_activation_program_id.begin());
            case 16: {
                const auto& cmr=block.vtx.at(index)->witness.vtxinwit[0].scriptWitness.stack[2];
                return std::equal(cmr.begin(),cmr.end(),consensus.bond_v2.incremental_activation_cmr.begin());
            }
            case 18: empty_incremental_activation=false; return true;
            case 19: empty_incremental_activation=true; return true;
            case 20: ++index; return true;
            default: throw std::logic_error("invalid incremental activation scan action");
            }
        });
    }
    uint64_t forced_appends{0};
    uint64_t deposit_appends{0};
    uint64_t previous_forced_cursor{0},previous_deposit_cursor{0};
    const auto prior_value=[&](uint64_t CBlockIndex::* field) {
        uint64_t value=0;
        drivechain::haskell::ParentReplayChoose({[&] { return activation; }, [] { return true; },
            [&] { value=previous_index->*field; return true; }});
        return value;
    };
    return drivechain::haskell::ParentReplayEach(std::views::iota(0,4),[&](int stage) {
        switch (stage) {
        case 0: return DeriveInboxNext(block,view,height,consensus,authenticated_parent_height,
            previous_forced,previous_deposits,next_forced,next_deposits,&forced_appends,&deposit_appends,error);
        case 1: {
            uint64_t ignored{0};
            return drivechain::haskell::ExchangeInbox(
                std::array<uint64_t,3>{activation,forced_appends,deposit_appends},ignored,error);
        }
        case 2:
            previous_forced_cursor=prior_value(&CBlockIndex::forcedProcessedCursor);
            previous_deposit_cursor=prior_value(&CBlockIndex::depositProcessedCursor);
            return DeriveProcessedCursors(block,previous,next,previous_forced_cursor,previous_deposit_cursor,
                next_forced_cursor,next_deposit_cursor,error,
                drivechain::haskell::ParentReplayAll<3>({[&] { return empty_incremental_activation; },
                    [&] { return forced_appends==0; }, [&] { return deposit_appends==0; }}));
        case 3: return ValidateInboxLiveness(previous_forced,previous_deposits,next_forced,next_deposits,
            previous_forced_cursor,previous_deposit_cursor,next_forced_cursor,next_deposit_cursor,
            forced_appends,deposit_appends,prior_value(&CBlockIndex::sourceBacklogOldestParentHeight),
            authenticated_parent_height.value_or(0),next_oldest_parent_height,error);
        default: throw std::logic_error("invalid expected-state inbox stage");
        }
    });
}

} // namespace

bool IsStateAuthorityOutput(const CTxOut& output)
{
    std::string error;
    return CheckAuthority(output, nullptr, error);
}

std::vector<unsigned char> EncodeBondDeploymentCommitment(
    uint32_t version, const BondDeploymentCommitmentFields& fields)
{
    if (drivechain::haskell::ParentReplayAll<2>({[&] { return version!=2; }, [&] { return version!=3; }}))
        throw std::invalid_argument("unsupported bond deployment version");
    return drivechain::haskell::ExchangeInboxEntry(drivechain::haskell::InboxCodec::BOND_DEPLOYMENT,
        {version,fields.previous_output_index,fields.inventory_output_index,fields.burn_output_index},
        {fields.transaction_id.begin(),fields.previous_transaction_id.begin(),fields.bond_asset.begin(),
         fields.token_asset.begin(),fields.inventory_script_hash.begin(),fields.burn_script_hash.begin()});
}

uint256 BondDeploymentCommitment(uint32_t version, const BondDeploymentCommitmentFields& fields)
{
    const auto bytes = EncodeBondDeploymentCommitment(version, fields);
    return TaggedHash(version == 3 ? "ECX/frozen-bond-deployment/v3" : "ECX/frozen-bond-deployment/v2", bytes);
}

bool ComputeBondV2FiniteStateScript(
    const ExchangeConsensus& consensus,
    const uint256& covenant_state_hash,
    CScript& script)
{
    return ComputeBondV2GenesisScript(consensus, covenant_state_hash, script);
}

bool ComputeBondV2EmptyGenesisRoots(
    const ExchangeConsensus& consensus,
    uint64_t initialization_height,
    uint64_t initialization_parent_mtp,
    uint256& private_state_root,
    uint256& bond_state_root,
    uint256& funding_state_root,
    uint256& covenant_state_hash)
{
    private_state_root.SetNull();
    bond_state_root.SetNull();
    funding_state_root.SetNull();
    covenant_state_hash.SetNull();
    if (!drivechain::haskell::ParentReplayAll<3>({
        [&] { return initialization_height != 0; },
        [&] { return initialization_parent_mtp != 0; },
        [&] { return consensus.bond_v2.genesis_mark_price != 0; },
    })) return false;
    ComputeBondV2GenesisRoots(consensus,initialization_height,initialization_parent_mtp,
        {&private_state_root,&bond_state_root,&funding_state_root,&covenant_state_hash});
    return drivechain::haskell::ParentReplayAll<2>({
        [&] { return !private_state_root.IsNull(); },
        [&] { return !covenant_state_hash.IsNull(); },
    });
}

bool ComputeBondV2IncrementalSuccessorScript(
    const ExchangeConsensus& consensus,
    const uint256& successor_state_root,
    CScript& script)
{
    const auto& frozen{consensus.bond_v2};
    if (!drivechain::haskell::ParentReplayAll<3>({
        [&] { return !successor_state_root.IsNull(); },
        [&] { return !frozen.incremental_successor_transition_cmr.IsNull(); },
        [&] { return !frozen.incremental_successor_state_node_domain_sha256.IsNull(); },
    })) return false;
    const uint256 state_node{EcxStateNodeHash(frozen.incremental_successor_state_node_domain_sha256, successor_state_root)};
    std::array<uint256,4> hashes;
    BuildBondTree(frozen.incremental_successor_transition_cmr,nullptr,state_node,
        {&hashes[0],&hashes[1],&hashes[2],&hashes[3]});
    const XOnlyPubKey internal{Span<const unsigned char>(
        frozen.keyless_internal_key.data(), frozen.keyless_internal_key.size())};
    const auto tweaked{internal.CreateTapTweak(&hashes[3])};
    if (!tweaked) return false;
    script = GetScriptForDestination(WitnessV1Taproot(tweaked->first));
    return true;
}

bool ValidateBondV2FrozenConfigurationV18(
    const std::vector<unsigned char>& canonical_bytes,
    uint256& configuration_hash,
    std::string& error)
{
    DecodedFrozenConfigurationV18 decoded;
    if (!DecodeFrozenConfigurationV18(canonical_bytes, decoded, error)) {
        configuration_hash.SetNull();
        return false;
    }
    configuration_hash = TaggedHash(
        "ECX/frozen-configuration/v18-no-history-keyless-staging-renderer-v2",
        canonical_bytes);
    return true;
}

bool ComputeForcedTrancheOrderWork(
    const std::vector<uint8_t>& kinds,
    uint32_t& order_work,
    std::string& error)
{
    static_assert(MAX_FORCED_TRANCHE_ORDER_WORK == 64);
    return drivechain::haskell::ExchangeTranche(kinds, order_work, error);
}

uint256 BondInboxGenesisHead(const ExchangeConsensus& consensus)
{
    return ComputeBondInboxGenesisRoot(consensus);
}

uint256 IncrementalSuccessorBondInboxGenesisHead(
    const ExchangeConsensus& consensus)
{
    return (::TaggedHash("ECX/successor-bond-inbox-genesis/v2-u128") << consensus.bond_v2.bond_inbox_domain
        << consensus.chain_id << consensus.bond_v2.configuration_hash).GetSHA256();
}

bool RenderBondInboxStagingV18(
    const uint256& marker_signer,
    const uint256& stable_intent_id,
    uint32_t staging_vout,
    const uint256& refund_script_sha256,
    uint64_t refund_not_before_parent_height,
    BondInboxStagingRenderV18& rendered,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    rendered = {};
    const auto& frozen{consensus.bond_v2};
    if (!drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::STAGING_RENDERER,
        [&](uint32_t step) {
            switch (step) {
            case 0: return !frozen.configuration_hash.IsNull();
            case 1: return !frozen.bond_inbox_redemption_staging_template_commitment.IsNull();
            case 2: return !frozen.bond_inbox_redemption_staging_renderer_domain.IsNull();
            case 3: return IsEcxStagingRendererDomainV18(frozen.bond_inbox_redemption_staging_renderer_domain.begin());
            case 4: return IsEcxNumsInternalKey(frozen.bond_inbox_redemption_staging_internal_key.begin());
            case 5: return frozen.bond_inbox_redemption_staging_tapleaf_version == TAPROOT_LEAF_TAPSIMPLICITY;
            case 6: return !frozen.bond_inbox_redemption_staging_process_cmr.IsNull();
            case 7: return !frozen.bond_inbox_redemption_staging_refund_cmr.IsNull();
            case 8: return frozen.bond_inbox_redemption_staging_process_cmr != frozen.bond_inbox_redemption_staging_refund_cmr;
            case 9: return !marker_signer.IsNull();
            case 10: return XOnlyPubKey(Span<const unsigned char>(marker_signer.begin(),32)).IsFullyValid();
            case 11: return !stable_intent_id.IsNull();
            case 12: return staging_vout != UINT32_MAX;
            case 13: return !refund_script_sha256.IsNull();
            case 14: return refund_not_before_parent_height != 0;
            default: return !IsZero(consensus.chain_id);
            }
        }, error)) return false;

    const auto hidden_preimage = drivechain::haskell::ExchangeInboxEntry(
        drivechain::haskell::InboxCodec::STAGING_HIDDEN, {staging_vout, refund_not_before_parent_height},
        {frozen.bond_inbox_redemption_staging_renderer_domain.begin(), consensus.chain_id.begin(),
         frozen.configuration_hash.begin(), marker_signer.begin(), stable_intent_id.begin(),
         refund_script_sha256.begin()});
    rendered.hidden_node_hash = TaggedHash(
        "ECX/bond-inbox-redemption-staging-hidden-node/v3-no-history",
        hidden_preimage);

    BuildBondTree(frozen.bond_inbox_redemption_staging_process_cmr,&frozen.bond_inbox_redemption_staging_refund_cmr,
        rendered.hidden_node_hash,{&rendered.process_leaf_hash,&rendered.refund_leaf_hash,
            &rendered.lower_branch_hash,&rendered.top_branch_hash},frozen.bond_inbox_redemption_staging_tapleaf_version);

    const XOnlyPubKey internal{Span<const unsigned char>(
        frozen.bond_inbox_redemption_staging_internal_key.begin(), 32)};
    const auto tweaked{internal.CreateTapTweak(&rendered.top_branch_hash)};
    if (!tweaked) {
        error = "ECX V18 staging descriptor cannot be rendered";
        rendered = {};
        return false;
    }
    rendered.script_pubkey = GetScriptForDestination(WitnessV1Taproot(tweaked->first));
    return true;
}

static bool IsCanonicalBondInboxSourceTransactionForProfile(
    const CTransaction& transaction,
    std::string& error,
    const ExchangeConsensus& consensus,
    bool successor)
{
    error.clear();
    const auto& frozen{consensus.bond_v2};
    if (!drivechain::haskell::ExchangeSourceAdmission([&](uint64_t step) -> uint64_t {
        switch (step) {
        case 0: return frozen.activation_enabled;
        case 1: return frozen.identities_frozen;
        case 2: return !frozen.configuration_hash.IsNull();
        case 3: return !frozen.availability_scheme_hash.IsNull();
        case 4: return !frozen.availability_custodian_registry_hash.IsNull();
        case 5: return frozen.bond_inbox_max_bundle_bytes;
        case 6: return frozen.bond_inbox_max_entries_per_sidechain_block;
        case 7: return frozen.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block;
        case 8: return frozen.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block;
        case 9: return !transaction.IsCoinBase();
        case 10: return !transaction.vin.empty();
        case 11: return !transaction.vout.empty();
        case 12: return transaction.HasWitness();
        case 13: return HasOnlyOrdinaryInputs(transaction);
        case 14: { DataStream bytes; bytes << TX_WITH_WITNESS(transaction); return bytes.size(); }
        case 15: { DataStream bytes; bytes << transaction.witness; return bytes.size(); }
        default: throw std::runtime_error("invalid source admission field");
        }
    },error)) return false;

    std::vector<uint256> action_ids;
    size_t output_index{0};
    ParsedBondInboxMarker marker;
    uint256 expected_source_authorization;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXCHANGE_SOURCE_TRANSACTION,
      [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return output_index < transaction.vout.size();
        case 2: {
            const auto& script = transaction.vout[output_index].scriptPubKey;
            return drivechain::haskell::ParentReplayAll<2>({[&] { return !script.empty(); },
                [&] { return script[0] == OP_RETURN; }});
        }
        case 3:
            marker = {};
            return ParseCanonicalBondInboxMarker(transaction.vout[output_index].scriptPubKey,
                marker, error, consensus, true, successor);
        case 4:
        if (!CheckMarkerOutput(transaction, output_index)) {
            error = "ECX bond-inbox marker output envelope is noncanonical";
            return false;
        }
        return true;
        case 5:
        if (!drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::MARKER_UNIQUENESS,
            [&](uint32_t step) {
                return step == 0 ? action_ids.size() < frozen.bond_inbox_max_entries_per_sidechain_block :
                    drivechain::haskell::ParentReplayEach(action_ids,
                        [&](const uint256& id) { return id != marker.action_id; });
            },error)) return false;
        action_ids.push_back(marker.action_id);
        return true;
        case 6: return marker.kind == 1;
        case 7: {
            if (!drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::STAGING_INDEX,
                [&](uint32_t step) { return step == 0 ? marker.staging_vout < transaction.vout.size() : marker.staging_vout != output_index; },error)) return false;
            const CTxOut& staging{transaction.vout[marker.staging_vout]};
            BondInboxStagingRenderV18 rendered;
            if (!RenderBondInboxStagingV18(
                    marker.signer,
                    marker.staging_intent_id,
                    marker.staging_vout,
                    marker.refund_script_sha256,
                    marker.refund_not_before_parent_height,
                    rendered,
                    error,
                    consensus)) {
                return false;
            }
            if (!drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::STAGING_OUTPUT,
                [&](uint32_t step) {
                    switch (step) {
                    case 0: return staging.scriptPubKey == rendered.script_pubkey;
                    case 1: return !staging.scriptPubKey.IsUnspendable();
                    case 2: return staging.nAsset.IsCommitment();
                    case 3: return staging.nValue.IsCommitment();
                    case 4: return staging.nNonce.IsCommitment();
                    case 5: return marker.staging_vout < transaction.witness.vtxoutwit.size();
                    case 6: return !transaction.witness.vtxoutwit[marker.staging_vout].vchSurjectionproof.empty();
                    case 7: return !transaction.witness.vtxoutwit[marker.staging_vout].vchRangeproof.empty();
                    default: throw std::logic_error("invalid staging output read");
                    }
                },error)) return false;
            DataStream staging_stream;
            staging_stream << staging;
            if (!drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::STAGING_BYTES,
                [&](uint32_t step) { return step == 0 ? staging_stream.size() != 0 : staging_stream.size() <= frozen.bond_inbox_max_bundle_bytes; },error)) return false;
            const auto authorization = drivechain::haskell::ExchangeInboxEntry(drivechain::haskell::InboxCodec::STAGING_AUTH,
                {marker.refund_not_before_parent_height},{marker.staging_intent_id.begin(),marker.refund_script_sha256.begin()},
                {UCharCast(staging_stream.data()),staging_stream.size()});
            expected_source_authorization = TaggedHash(
                ECX_BOND_STAGING_AUTH_TAGS[successor],
                authorization);
            return true;
        }
        case 8: {
            const auto authorization = drivechain::haskell::ExchangeInboxEntry(drivechain::haskell::InboxCodec::NO_STAGING_AUTH,
                {output_index},{consensus.chain_id.data(),frozen.configuration_hash.begin(),marker.signer.begin(),marker.action_id.begin()});
            expected_source_authorization = TaggedHash(
                ECX_BOND_NO_STAGING_AUTH_TAGS[successor],
                authorization);
            return true;
        }
        case 9: return drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::SOURCE_AUTHORIZATION,
            [&](uint32_t) { return expected_source_authorization == marker.source_authorization_commitment; },error);
        case 10: return VerifyBondInboxMarkerSourceWitness(transaction, marker, error, consensus, successor);
        case 11: ++output_index; return true;
        case 12: return drivechain::haskell::ExchangeTransactionShape(drivechain::haskell::TransactionShape::SOURCE_SINGLETON,
            [&](uint32_t) { return action_ids.size() == 1; },error);
        default: throw std::logic_error("invalid source transaction action");
        }
      }) == 1;
}

bool IsCanonicalBondInboxSourceTransaction(
    const CTransaction& transaction,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    return IsCanonicalBondInboxSourceTransactionForProfile(
        transaction, error, consensus, false);
}

static bool AppendBondInboxSourcesForProfile(
    bool successor,
    const CBlock& block,
    uint64_t sidechain_height,
    uint64_t observed_parent_height,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::vector<BondInboxSourceExport>* exported_entries)
{
    error.clear();
    const std::string label = successor ? "ECX successor bond-inbox" : "ECX bond-inbox";
    if (!drivechain::haskell::ExchangeSourcePredecessor(successor, snapshot.proof_profile,
            sidechain_height, observed_parent_height,
            std::span<const unsigned char,32>{snapshot.node_bond_inbox_head_root.begin(),32},
            snapshot.node_bond_inbox_entry_count.bytes, snapshot.bond_inbox_entry_count.bytes, error)) return false;
    const std::array<unsigned char, 4> magic{{'E', 'C', 'X', 'B'}};
    uint32_t marker_count{0};
    std::vector<unsigned char> source_tracker(8, 0);
    uint256 head{snapshot.node_bond_inbox_head_root};
    uint64_t count{0};
    BigEndianUint128 wide_count{snapshot.node_bond_inbox_entry_count};
    if (!successor) snapshot.node_bond_inbox_entry_count.ToU64(count);
    const uint256 block_hash{block.GetHash()};

    size_t transaction_index{0}, output_index{0};
    DataStream transaction_stream, witness_stream;
    uint32_t transaction_len{0}, witness_len{0};
    uint256 txid, wtxid, witness_sha256;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::EXCHANGE_BLOCK_SOURCES,
      [&](uint32_t action) -> uint32_t {
        if (action==1) return transaction_index < block.vtx.size();
        if (action==10) { ++transaction_index; output_index=0; return 1; }
        if (action==11) {
            snapshot.node_bond_inbox_head_root = head;
            snapshot.node_bond_inbox_entry_count = successor ? wide_count : BigEndianUint128{count};
            return 1;
        }
        const CTransaction& transaction{*block.vtx[transaction_index]};
        switch (action) {
        case 2: return !drivechain::haskell::ParentReplayEach(transaction.vout,
            [&](const CTxOut& output) {
                return !ScriptContainsMagic(output.scriptPubKey, magic);
            });
        case 3:
        if (!IsCanonicalBondInboxSourceTransactionForProfile(
                transaction, error, consensus, successor)) {
            error = "invalid " + label + " source transaction: " + error;
            return false;
        }
        return true;
        case 4:
        transaction_stream.clear();
        witness_stream.clear();
        transaction_stream << TX_WITH_WITNESS(transaction);
        witness_stream << transaction.witness;
        if (!drivechain::haskell::FitsU32(std::array<uint64_t,2>{transaction_stream.size(), witness_stream.size()})) {
            error = label + " source serialization length overflows u32";
            return false;
        }
        transaction_len = static_cast<uint32_t>(transaction_stream.size());
        witness_len = static_cast<uint32_t>(witness_stream.size());
        txid = transaction.GetHash();
        wtxid = transaction.GetWitnessHash();
        witness_sha256 = Sha256({
            UCharCast(witness_stream.data()),
            UCharCast(witness_stream.data()) + witness_stream.size()});
        return true;
        case 5: return drivechain::haskell::ExchangeTrackSource(successor,
                {witness_len, transaction_len,
                consensus.bond_v2.bond_inbox_max_unique_source_witness_bytes_per_sidechain_block,
                consensus.bond_v2.bond_inbox_max_unique_source_transaction_bytes_per_sidechain_block},
                {wtxid.begin(), txid.begin(), witness_sha256.begin()}, source_tracker, error);
        case 6: return output_index < transaction.vout.size();
        case 7: return ScriptContainsMagic(transaction.vout[output_index].scriptPubKey, magic);
        case 8: {
            const CScript& script{transaction.vout[output_index].scriptPubKey};
            ParsedBondInboxMarker marker;
            if (!ParseCanonicalBondInboxMarker(
                    script, marker, error, consensus, true, successor)) return false;
            std::array<unsigned char, 48> next_state{};
            if (!drivechain::haskell::ExchangeAppendMarker({successor ? 1U : 0U, observed_parent_height,
                    consensus.bond_v2.bond_inbox_inclusion_blocks, marker.kind,
                    consensus.bond_v2.bond_inbox_refund_minimum_parent_blocks, marker.refund_not_before_parent_height,
                    marker_count, consensus.bond_v2.bond_inbox_max_entries_per_sidechain_block,
                    count, transaction_index, output_index, sidechain_height, transaction_len, witness_len},
                {head.begin(), block_hash.begin(), txid.begin(), wtxid.begin(), witness_sha256.begin()},
                wide_count.bytes, script,
                [&](uint32_t action, std::span<const unsigned char> bytes, std::span<unsigned char, 32> digest) {
                if (action != 0) {
                    const auto value = TaggedHash(action == 1
                        ? ECX_BOND_ENTRY_TAGS[successor] : ECX_BOND_STEP_TAGS[successor],
                        bytes);
                    std::copy(value.begin(), value.end(), digest.begin());
                    return;
                }
                if (exported_entries == nullptr) return;
                BondInboxSourceExport exported;
                exported.proof_profile = successor ? 1 : 0;
                exported.entry_index = count;
                exported.entry_index_u128 = successor ? wide_count : BigEndianUint128{count};
                if (successor) wide_count.ToU64(exported.entry_index);
                exported.sidechain_height = sidechain_height;
                exported.observed_parent_height = observed_parent_height;
                exported.process_deadline_parent_height = ReadBE64(bytes.data());
                exported.refund_not_before_parent_height = marker.kind == 1
                    ? marker.refund_not_before_parent_height
                    : 0;
                exported.marker_kind = marker.kind;
                exported.action_id = marker.action_id;
                exported.source_transaction_index =
                    static_cast<uint32_t>(transaction_index);
                exported.marker_vout = static_cast<uint32_t>(output_index);
                exported.source_txid = txid;
                exported.source_wtxid = wtxid;
                exported.canonical_entry.assign(bytes.begin()+8, bytes.end());
                exported.source_transaction.assign(
                    UCharCast(transaction_stream.data()),
                    UCharCast(transaction_stream.data()) +
                        transaction_stream.size());
                exported_entries->push_back(std::move(exported));
                }, next_state, error)) return false;
            ++marker_count;
            std::copy_n(next_state.begin(), 32, head.begin());
            std::copy_n(next_state.begin()+32, 16, wide_count.bytes.begin());
            if (!successor) count = ReadBE64(next_state.data()+40);
            return true;
        }
        case 9: ++output_index; return true;
        default: throw std::logic_error("invalid block source action");
        }
      }) == 1;
}

bool AppendBondInboxSourcesForBlock(
    const CBlock& block,
    uint64_t sidechain_height,
    uint64_t observed_parent_height,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::vector<BondInboxSourceExport>* exported_entries)
{
    return AppendBondInboxSourcesForProfile(false, block, sidechain_height, observed_parent_height,
        snapshot, error, consensus, exported_entries);
}

bool AppendIncrementalSuccessorBondInboxSourcesForBlock(
    const CBlock& block,
    uint64_t sidechain_height,
    uint64_t observed_parent_height,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::vector<BondInboxSourceExport>* exported_entries)
{
    return AppendBondInboxSourcesForProfile(true, block, sidechain_height, observed_parent_height,
        snapshot, error, consensus, exported_entries);
}

uint256 ComputeForcedInboxGenesis(const ExchangeConsensus& consensus)
{
    return (::TaggedHash("ECX/forced-inbox-genesis/v1") << consensus.forced_action_domain << consensus.chain_id).GetSHA256();
}

uint256 ComputeDepositInboxGenesis(const ExchangeConsensus& consensus)
{
    return (::TaggedHash("ECX/deposit-inbox-genesis/v1") << consensus.deposit_inbox_domain << consensus.chain_id).GetSHA256();
}

uint256 ComputeRuntimeConsensusFingerprint(
    const ExchangeConsensus& consensus,
    const std::string& network_id,
    const uint256& genesis_hash,
    const uint256& policy_asset,
    const uint256& bmm_consensus_fingerprint,
    const bool private_bmm_enabled,
    const uint32_t private_bmm_activation_height)
{
    const uint64_t numbers[]{
        9, ECX_CONSENSUS_RULESET_REVISION, EXCHANGE_STATE_INTERFACE_VERSION,
        EXCHANGE_SCRIPT_CACHE_REVISION, CBlockHeader::BMM_PROOF_HF_MASK,
        CBlockHeader::EXCHANGE_STATE_HF_MASK, CBlockHeader::FORCED_INBOX_HF_MASK,
        CBlockHeader::DEPOSIT_INBOX_HF_MASK, CBlockHeader::INBOX_CURSOR_HF_MASK,
        FORCED_INCLUSION_BLOCKS, MAX_COMBINED_UNCONSUMED,
        MAX_COMBINED_SAME_PARENT_APPENDS, MAX_COMBINED_PENDING_WITNESS_ENTRIES,
        MAX_FORCED_TRANCHE_ORDER_WORK, 1, MAX_FORCED_TRANCHE_ORDER_WORK, 0,
        FORCED_CANCEL_BODY_SIZE, FORCED_LIMIT_BODY_SIZE, FORCED_WITHDRAW_BODY_SIZE,
        DEPOSIT_PAYLOAD_SIZE, EXCHANGE_TRACKER_OUTPOINT.n,
        FORCED_INBOX_TRACKER_OUTPOINT.n, DEPOSIT_INBOX_TRACKER_OUTPOINT.n,
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        1,
#else
        0,
#endif
#ifdef ECX_SIMPLICITY_CATALOGUE_FROZEN
        1,
#else
        0,
#endif
#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
        1,
#else
        0,
#endif
        static_cast<uint32_t>(consensus.activation_height), consensus.genesis_state_outpoint.n,
        consensus.bond_v2.activation_enabled, consensus.bond_v2.identities_frozen,
        consensus.bond_v2.deployment_version, consensus.bond_v2.issuance_input_index,
        consensus.bond_v2.inventory_output_index, consensus.bond_v2.reissuance_token_burn_output_index,
        consensus.bond_v2.state_authority_source_output_index, consensus.bond_v2.genesis_mark_price,
        private_bmm_enabled, private_bmm_activation_height};
#ifdef ECX_PRODUCTION_ACTIVATION_PROFILE_FROZEN
    const auto release_record_hash = ParseHex(ECX_PRODUCTION_RELEASE_RECORD_HASH_HEX);
#else
    const std::vector<unsigned char> release_record_hash(32, 0);
#endif
    DataStream deployment, genesis;
    if (consensus.bond_v2.deployment_transaction) deployment << TX_WITH_WITNESS(*consensus.bond_v2.deployment_transaction);
    if (consensus.bond_v2.genesis_transaction) genesis << TX_WITH_WITNESS(*consensus.bond_v2.genesis_transaction);
    const auto hash_bytes = [](const uint256& hash) { return std::span<const unsigned char>{hash.begin(), hash.size()}; };
    const auto& bond = consensus.bond_v2;
    std::vector<std::span<const unsigned char>> blobs{
        hash_bytes(EXCHANGE_TRACKER_OUTPOINT.hash.ToUint256()),
        hash_bytes(FORCED_INBOX_TRACKER_OUTPOINT.hash.ToUint256()),
        hash_bytes(DEPOSIT_INBOX_TRACKER_OUTPOINT.hash.ToUint256()),
        EXCHANGE_TRACKER_MARKER, FORCED_INBOX_TRACKER_MARKER, DEPOSIT_INBOX_TRACKER_MARKER,
        FORCED_MAGIC, DEPOSIT_MAGIC, ECX_USDD_MARKET, release_record_hash,
        {reinterpret_cast<const unsigned char*>(network_id.data()), network_id.size()},
        hash_bytes(genesis_hash), hash_bytes(policy_asset), hash_bytes(bmm_consensus_fingerprint),
        hash_bytes(consensus.genesis_state_outpoint.hash.ToUint256()),
        hash_bytes(consensus.genesis_state_root), consensus.chain_id,
        consensus.forced_action_domain, consensus.deposit_inbox_domain,
        consensus.collateral_vault_script, hash_bytes(consensus.collateral_vault_script_hash),
        {UCharCast(deployment.data()), deployment.size()}, {UCharCast(genesis.data()), genesis.size()},
        bond.canonical_configuration_bytes};
    for (const uint256* identity : {
             &consensus.bond_v2.inventory_asset_blinding_factor,
             &consensus.bond_v2.inventory_value_blinding_factor,
             &consensus.bond_v2.issuance_value_blinding_factor,
             &consensus.bond_v2.transition_program_id,
             &consensus.bond_v2.configuration_hash,
             &consensus.bond_v2.bond_asset_id,
             &consensus.bond_v2.bond_deployment_commitment,
             &consensus.bond_v2.collateral_vault_covenant_cmr,
             &consensus.bond_v2.inventory_covenant_script_sha256,
             &consensus.bond_v2.reissuance_token_burn_script_sha256,
             &consensus.bond_v2.redemption_queue_script_sha256,
             &consensus.bond_v2.insurance_reserve_script_sha256,
             &consensus.bond_v2.insurance_reserve_covenant_cmr,
             &consensus.bond_v2.state_authority_asset_id,
             &consensus.bond_v2.public_state_domain_sha256,
             &consensus.bond_v2.state_node_domain_sha256,
              &consensus.bond_v2.transition_journal_domain_sha256,
              &consensus.bond_v2.transition_cmr,
              &consensus.bond_v2.incremental_activation_program_id,
              &consensus.bond_v2.incremental_activation_configuration_hash,
              &consensus.bond_v2.incremental_activation_cmr,
              &consensus.bond_v2.incremental_successor_program_id,
              &consensus.bond_v2.incremental_successor_configuration_hash,
              &consensus.bond_v2.incremental_successor_transition_cmr,
              &consensus.bond_v2.incremental_successor_state_node_domain_sha256,
              &consensus.bond_v2.inventory_cmr,
             &consensus.bond_v2.redemption_queue_cmr,
             &consensus.bond_v2.ecx_btc_conversion_program_id,
             &consensus.bond_v2.ecx_btc_redemption_covenant_commitment,
             &consensus.bond_v2.ecx_btc_source_checkpoint_commitment,
             &consensus.bond_v2.usdd_usd_conversion_program_id,
             &consensus.bond_v2.usdd_usd_redemption_covenant_commitment,
             &consensus.bond_v2.usdd_usd_source_checkpoint_commitment,
             &consensus.bond_v2.matcher_genesis_receipt_hash,
             &consensus.bond_v2.order_receipts_genesis_root,
             &consensus.bond_v2.genesis_availability_root,
             &consensus.bond_v2.usdd_asset_id.id,
             &consensus.bond_v2.identity_derivation_record_sha256}) {
        blobs.push_back(hash_bytes(*identity));
    }
    blobs.emplace_back(bond.keyless_internal_key);
    const auto payload = EncodeExchangeFingerprint(1,numbers,blobs);
    return TaggedHash("ECX/runtime-consensus-configuration/v9", payload);
}

bool GetRuntimeConsensusFingerprint(
    uint256& fingerprint,
    bool& runtime_configured,
    int& first_activation_height,
    std::string& error)
{
    error.clear();
    runtime_configured = false;
    first_activation_height = std::numeric_limits<int>::max();
    try {
        const ExchangeConsensus& consensus{LayerTwoLabsExchangeConsensus()};
        if (drivechain::haskell::ParentReplayAll<2>({
            [&] { return consensus.activation_height != std::numeric_limits<int>::max(); },
            [&] { return !ConsensusConfigured(consensus, error); },
        })) {
            return false;
        }
        const bool private_checkpoint{
            gArgs.GetBoolArg("-ecxprivatebmmcheckpoint", false)};
        const bool private_activation_set{
            gArgs.IsArgSet("-ecxprivatebmmactivationheight")};
        uint32_t private_activation{0};
        if (!drivechain::haskell::ExchangeTransactionShape(
                drivechain::haskell::TransactionShape::RUNTIME_SETTINGS,
                [&](uint32_t step) {
                    switch (step) {
                    case 0: return private_checkpoint;
                    case 1: return private_activation_set;
                    case 2:
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
                        return true;
#else
                        return false;
#endif
                    case 3: return IsEcxRuntimeTestNetwork();
                    case 4: {
                        const auto value = gArgs.GetIntArg("-ecxprivatebmmactivationheight", -1);
                        if (!drivechain::haskell::ExchangeFrozenBounds(std::array<uint64_t,2>{
                            static_cast<uint64_t>(value), std::numeric_limits<int>::max()})) return false;
                        private_activation = static_cast<uint32_t>(value);
                        return true;
                    }
                    default: throw std::logic_error("invalid exchange runtime setting step");
                    }
                }, error)) return false;
        fingerprint = ComputeRuntimeConsensusFingerprint(
            consensus,
            Params().NetworkIDString(),
            Params().GetConsensus().hashGenesisBlock,
            policyAsset.id,
            drivechain::RuntimeBmmConsensusFingerprint(),
            private_checkpoint,
            private_activation);
        const auto activation = drivechain::haskell::ExchangeRuntimeActivation(consensus.activation_height,
            private_checkpoint ? std::optional<int32_t>{private_activation} : std::nullopt);
        runtime_configured = activation.first;
        first_activation_height = activation.second;
        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool HasPersistedExchangeConsensusState(const CCoinsView& view)
{
    return !drivechain::haskell::ParentReplayEach(std::array{EXCHANGE_TRACKER_OUTPOINT,
        FORCED_INBOX_TRACKER_OUTPOINT, DEPOSIT_INBOX_TRACKER_OUTPOINT}, [&](const COutPoint& outpoint) {
        const auto coin = view.GetCoin(outpoint);
        return !drivechain::haskell::ParentReplayAll<2>({
            [&] { return coin.has_value(); },
            [&] { return !coin->IsSpent(); },
        });
    });
}

const ExchangeConsensus& LayerTwoLabsExchangeConsensus()
{
    // Mainnet/signet remain fail-closed until reviewed constants replace the
    // defaults. Regtest can inject a frozen checkpoint at process start for
    // activation, reorg and reindex functional testing.
    static const ExchangeConsensus consensus{LoadExchangeConsensus()};
    return consensus;
}

bool IsCanonicalForcedActionOutput(
    const CTransaction& transaction,
    const size_t output_index,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    std::optional<ForcedActionPayload> action;
    namespace hs = drivechain::haskell;
    return hs::ExchangeTransactionShape(hs::TransactionShape::CANONICAL_FORCED, [&](uint32_t step) {
        switch (step) {
        case 0: return output_index < transaction.vout.size();
        case 1: return ParseForcedOutput(transaction,output_index,consensus,action,error);
        case 2: return action.has_value();
        default: throw std::logic_error("invalid forced-action admission step");
        }
    },error);
}

static std::optional<uint32_t> AdmitSourceMarkers(const CTransaction& transaction, int next_height,
    const ExchangeConsensus& consensus, std::string& error)
{
    namespace hs = drivechain::haskell;
    error.clear();
    uint32_t seen{0};
    if (!hs::ParentReplayEach(std::views::iota(size_t{0}, transaction.vout.size()), [&](size_t index) {
        std::optional<ForcedActionPayload> forced;
        std::optional<DepositPayload> deposit;
        return hs::ParentReplayAll<4>({
            [&] { return ParseForcedOutput(transaction,index,consensus,forced,error); },
            [&] { return hs::ExchangeSourceMarker(seen,hs::SourceMarker::FORCED,forced.has_value(),error); },
            [&] { return ParseDepositOutput(transaction,index,consensus,deposit,error); },
            [&] { return hs::ExchangeSourceMarker(seen,hs::SourceMarker::DEPOSIT,deposit.has_value(),error); },
        });
    })) return std::nullopt;
    if (!hs::ExchangeSourceMarker(seen,hs::SourceMarker::ACTIVATION,
        ActiveAt(next_height,consensus),error)) return std::nullopt;
    return seen;
}

bool CheckSourceTransactionPolicy(
    const CTransaction& transaction,
    const int next_height,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    return AdmitSourceMarkers(transaction,next_height,consensus,error).has_value();
}

bool CountSourceTransactionMarkers(
    const CTransaction& transaction,
    uint64_t& forced_count,
    uint64_t& deposit_count,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    forced_count = 0;
    deposit_count = 0;
    const auto admitted=AdmitSourceMarkers(transaction,consensus.activation_height,consensus,error);
    if (!admitted) return false;
    forced_count=*admitted & 1U;
    deposit_count=(*admitted >> 1) & 1U;
    return true;
}

bool ComputeSourceAppendBudget(
    const ExchangeConsensusSnapshot& snapshot,
    uint64_t& budget,
    std::string& error)
{
    const std::array<uint64_t, 4> fields{snapshot.forced_entry_count, snapshot.forced_processed_cursor,
        snapshot.deposit_entry_count, snapshot.deposit_processed_cursor};
    return drivechain::haskell::ExchangeInbox(fields, budget, error);
}

bool IsExchangeStateInternalOutpoint(const COutPoint& outpoint)
{
    return !drivechain::haskell::ParentReplayEach(std::array{EXCHANGE_TRACKER_OUTPOINT,
        FORCED_INBOX_TRACKER_OUTPOINT, DEPOSIT_INBOX_TRACKER_OUTPOINT},
        [&](const COutPoint& reserved) { return outpoint!=reserved; });
}

uint256 ComputeStateUtxoRoot(
    const uint256& child_genesis,
    const COutPoint& outpoint,
    const CTxOut& output)
{
    return (::TaggedHash("ECX/header-state/v1") << child_genesis << outpoint << TxOutHash(output)).GetSHA256();
}

bool CheckExchangeStateHeader(
    const CBlockHeader& block,
    const int height,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    namespace hs = drivechain::haskell;
    error.clear();
    const std::array<bool, 4> signals{block.HasExchangeState(), block.HasForcedInbox(), block.HasDepositInbox(),
        (static_cast<uint32_t>(block.nVersion) & CBlockHeader::INBOX_CURSOR_HF_MASK) != 0};
    const auto check = [&](hs::HeaderPhase phase) {
        return hs::ExchangeHeader(phase, [&](uint32_t step) {
            if (phase == hs::HeaderPhase::GENESIS) {
                switch (step) {
                case 0: return block.hashExchangeStateRoot == consensus.genesis_state_root;
                case 1: return block.hashForcedInboxRoot == ComputeForcedInboxGenesis(consensus);
                case 2: return block.hashDepositInboxRoot == ComputeDepositInboxGenesis(consensus);
                case 3: return block.forcedProcessedCursor == 0;
                case 4: return block.depositProcessedCursor == 0;
                case 5: return block.sourceBacklogOldestParentHeight == 0;
                default: throw std::logic_error("invalid genesis header read");
                }
            }
            const bool inactive = phase == hs::HeaderPhase::BEFORE_ACTIVATION;
            if (step < signals.size()) return signals[step] != inactive;
            switch (step) {
            case 4: return block.hashExchangeStateRoot.IsNull() == inactive;
            case 5: return block.hashForcedInboxRoot.IsNull() == inactive;
            case 6: return block.hashDepositInboxRoot.IsNull() == inactive;
            case 7: return (block.ecxParentHeight == 0) == inactive;
            case 8: return block.forcedProcessedCursor == 0;
            case 9: return block.depositProcessedCursor == 0;
            case 10: return block.sourceBacklogOldestParentHeight == 0;
            default: throw std::logic_error("invalid exchange header read");
            }
        }, error);
    };
    return hs::ParentReplayStore(hs::ReplayStoreFlow::HEADER_CHECK,[&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return ActiveAt(height,consensus);
        case 2: return check(hs::HeaderPhase::BEFORE_ACTIVATION);
        case 3: return ConsensusConfigured(consensus,error);
        case 4: return check(hs::HeaderPhase::ACTIVE);
        case 5: return height==consensus.activation_height;
        case 6: return check(hs::HeaderPhase::GENESIS);
        default: throw std::logic_error("invalid header validation stage");
        }
    });
}

bool CheckExchangeStateIndexHeader(
    const CBlockIndex& index,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    // Header trimming removes only block-signing/dynafed material. Rebuild the
    // fixed ECX commitment view directly from CBlockIndex so startup auditing
    // remains safe with -trim_headers enabled and never needs to mutate the
    // in-memory index merely to revalidate it.
    CBlockHeader header;
    header.nVersion = index.nVersion;
    header.hashExchangeStateRoot = index.hashExchangeStateRoot;
    header.hashForcedInboxRoot = index.hashForcedInboxRoot;
    header.hashDepositInboxRoot = index.hashDepositInboxRoot;
    header.ecxParentHeight = index.ecxParentHeight;
    header.forcedProcessedCursor = index.forcedProcessedCursor;
    header.depositProcessedCursor = index.depositProcessedCursor;
    header.sourceBacklogOldestParentHeight =
        index.sourceBacklogOldestParentHeight;
    return CheckExchangeStateHeader(header, index.nHeight, error, consensus);
}

bool PrepareExchangeStateHeader(
    CBlock& block,
    const CBlockIndex* previous,
    const CCoinsViewCache& view,
    const int height,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> authenticated_parent_height)
{
    error.clear();
    ExchangeStateTracker next;
    InboxTracker next_forced;
    InboxTracker next_deposits;
    uint64_t next_forced_cursor{0};
    uint64_t next_deposit_cursor{0};
    uint64_t next_oldest_parent_height{0};
    constexpr uint32_t mask=CBlockHeader::EXCHANGE_STATE_HF_MASK | CBlockHeader::FORCED_INBOX_HF_MASK |
        CBlockHeader::DEPOSIT_INBOX_HF_MASK | CBlockHeader::INBOX_CURSOR_HF_MASK;
    namespace hs = drivechain::haskell;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::HEADER_PREPARE,[&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return ActiveAt(height,consensus);
        case 2:
            block.nVersion=static_cast<int32_t>(static_cast<uint32_t>(block.nVersion)&~mask);
            block.hashExchangeStateRoot.SetNull();
            block.hashForcedInboxRoot.SetNull();
            block.hashDepositInboxRoot.SetNull();
            block.ecxParentHeight=0;
            block.forcedProcessedCursor=0;
            block.depositProcessedCursor=0;
            block.sourceBacklogOldestParentHeight=0;
            return true;
        case 3: return ConsensusConfigured(consensus,error);
        case 4: return hs::ExchangeParentTarget(authenticated_parent_height,[&](uint32_t fact) -> uint64_t {
            if (fact==0) return IsEcxRuntimeTestNetwork();
            if (fact==1) return previous ? previous->ecxParentHeight : 0;
            throw std::logic_error("invalid parent target read");
        },error);
        case 5: return ExpectedForBlock(block,previous,view,height,next,next_forced,next_deposits,
            next_forced_cursor,next_deposit_cursor,next_oldest_parent_height,error,consensus,authenticated_parent_height);
        case 6:
            block.nVersion=static_cast<int32_t>(static_cast<uint32_t>(block.nVersion)|mask);
            block.hashExchangeStateRoot=next.root;
            block.hashForcedInboxRoot=next_forced.root;
            block.hashDepositInboxRoot=next_deposits.root;
            block.ecxParentHeight=static_cast<uint32_t>(*authenticated_parent_height);
            block.forcedProcessedCursor=next_forced_cursor;
            block.depositProcessedCursor=next_deposit_cursor;
            block.sourceBacklogOldestParentHeight=next_oldest_parent_height;
            return true;
        default: throw std::logic_error("invalid header preparation stage");
        }
    });
}

bool ConnectExchangeState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> authenticated_parent_height,
    const bool allow_incomplete_candidate)
{
    {
        std::optional<drivechain::BmmL1State> bmm_state;
        std::string bmm_error;
        const auto status=drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CONNECTION_PREFLIGHT,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return CheckExchangeStateHeader(block,height,error,consensus);
                case 2: return ActiveAt(height,consensus);
                case 3: return authenticated_parent_height.has_value();
                case 4: return authenticated_parent_height.value()==block.ecxParentHeight;
                case 5: error="ECX supplied parent height disagrees with the committed header height"; return true;
                case 6: return drivechain::GetBmmState(view,bmm_state.emplace(),&bmm_error);
                case 7: return bmm_state->height==block.ecxParentHeight;
                case 8: return allow_incomplete_candidate;
                case 9: return block.HasBmmProof();
                case 10: return block.hashBmmProof.IsNull();
                case 11: return block.m_bmm_proof.empty();
                case 12: error="ECX committed parent height disagrees with authenticated BMM state"; return true;
                case 13: return IsEcxRuntimeTestNetwork();
                case 14: return bmm_error.empty();
                case 15: error="ECX committed parent height has no authenticated BMM state"; return true;
                case 16: error=bmm_error; return true;
                default: authenticated_parent_height=block.ecxParentHeight; return true;
                }
            });
        if (status<2) return status==1;
    }
    ExchangeStateTracker next;
    InboxTracker next_forced;
    InboxTracker next_deposits;
    uint64_t next_forced_cursor{0};
    uint64_t next_deposit_cursor{0};
    uint64_t next_oldest_parent_height{0};
    namespace hs = drivechain::haskell;
    return hs::ParentReplayEach(std::views::iota(0,5), [&](int stage) {
        switch (stage) {
        case 0: return ExpectedForBlock(block,previous,view,height,next,next_forced,next_deposits,
            next_forced_cursor,next_deposit_cursor,next_oldest_parent_height,error,consensus,authenticated_parent_height);
        case 1: return hs::ExchangeConnection(height == consensus.activation_height, [&](uint32_t step) {
            switch (step) {
            case 0: return block.hashExchangeStateRoot == next.root;
            case 1: return block.hashForcedInboxRoot == next_forced.root;
            case 2: return block.hashDepositInboxRoot == next_deposits.root;
            case 3: return block.forcedProcessedCursor == next_forced_cursor;
            case 4: return block.depositProcessedCursor == next_deposit_cursor;
            case 5: return block.sourceBacklogOldestParentHeight == next_oldest_parent_height;
            case 6: return view.AccessCoin(EXCHANGE_TRACKER_OUTPOINT).IsSpent();
            case 7: return view.AccessCoin(FORCED_INBOX_TRACKER_OUTPOINT).IsSpent();
            case 8: return view.AccessCoin(DEPOSIT_INBOX_TRACKER_OUTPOINT).IsSpent();
            default: throw std::logic_error("invalid exchange connection read");
            }
        },error);
        case 2: SetTracker(view,next,height); break;
        case 3: SetTrackerRecord(view,FORCED_INBOX_TRACKER_OUTPOINT,FORCED_INBOX_TRACKER_MARKER,next_forced,height); break;
        case 4: SetTrackerRecord(view,DEPOSIT_INBOX_TRACKER_OUTPOINT,DEPOSIT_INBOX_TRACKER_MARKER,next_deposits,height); break;
        default: throw std::logic_error("invalid exchange connection stage");
        }
        return true;
    });
}

bool DisconnectExchangeState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    std::string& error,
    const ExchangeConsensus& consensus,
    std::optional<uint64_t> authenticated_parent_height)
{
    error.clear();
    ExchangeStateTracker current;
    InboxTracker current_forced;
    InboxTracker current_deposits;
    const auto status=drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::DISCONNECT_PREFLIGHT,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return ActiveAt(height,consensus);
            case 2: return block.ecxParentHeight!=0;
            case 3: return authenticated_parent_height.has_value();
            case 4: return authenticated_parent_height.value()==block.ecxParentHeight;
            case 5: error="ECX disconnected block has an inconsistent parent height"; return true;
            case 6: authenticated_parent_height=block.ecxParentHeight; return true;
            case 7: return GetTracker(view,current,error);
            case 8: return current.root==block.hashExchangeStateRoot;
            case 9: error="persisted ECX tracker disagrees with disconnected header"; return true;
            case 10: return GetInboxTracker(view,FORCED_INBOX_TRACKER_OUTPOINT,FORCED_INBOX_TRACKER_MARKER,current_forced,error);
            case 11: return GetInboxTracker(view,DEPOSIT_INBOX_TRACKER_OUTPOINT,DEPOSIT_INBOX_TRACKER_MARKER,current_deposits,error);
            case 12: return current_forced.root==block.hashForcedInboxRoot;
            case 13: return current_deposits.root==block.hashDepositInboxRoot;
            case 14: error="persisted ECX inbox trackers disagree with disconnected header"; return true;
            case 15: return height==consensus.activation_height;
            case 16:
                return drivechain::haskell::ExchangeDisconnect(drivechain::haskell::DisconnectPhase::REMOVE, [&](uint32_t slot) {
                    switch (slot) {
                    case 0: return view.SpendCoin(EXCHANGE_TRACKER_OUTPOINT);
                    case 1: return view.SpendCoin(FORCED_INBOX_TRACKER_OUTPOINT);
                    case 2: return view.SpendCoin(DEPOSIT_INBOX_TRACKER_OUTPOINT);
                    default: throw std::logic_error("invalid activation removal");
                    }
                }, error);
            default: throw std::logic_error("invalid disconnect preflight step");
            }
        });
    if (status<2) return status==1;
    if (!drivechain::haskell::ExchangeDisconnect(drivechain::haskell::DisconnectPhase::PRIOR_HEADER, [&](uint32_t step) {
        switch (step) {
        case 0: return previous != nullptr;
        case 1: return (static_cast<uint32_t>(previous->nVersion) & CBlockHeader::EXCHANGE_STATE_HF_MASK) != 0;
        case 2: return !previous->hashExchangeStateRoot.IsNull();
        case 3: return (static_cast<uint32_t>(previous->nVersion) & CBlockHeader::FORCED_INBOX_HF_MASK) != 0;
        case 4: return (static_cast<uint32_t>(previous->nVersion) & CBlockHeader::DEPOSIT_INBOX_HF_MASK) != 0;
        case 5: return !previous->hashForcedInboxRoot.IsNull();
        case 6: return !previous->hashDepositInboxRoot.IsNull();
        default: throw std::logic_error("invalid disconnect header read");
        }
    }, error)) return false;

    InboxTracker restored_forced;
    InboxTracker restored_deposits;
    InboxTracker rederived_forced;
    InboxTracker rederived_deposits;
    uint64_t forced_appends{0};
    uint64_t deposit_appends{0};
    namespace hs = drivechain::haskell;
    if (!hs::ParentReplayEach(std::views::iota(0,4), [&](int stage) {
        switch (stage) {
        case 0: {
            InboxTracker ignored_forced;
            InboxTracker ignored_deposits;
            return DeriveInboxNext(block,view,height,consensus,authenticated_parent_height,
                {previous->hashForcedInboxRoot,0},{previous->hashDepositInboxRoot,0},
                ignored_forced,ignored_deposits,&forced_appends,&deposit_appends,error);
        }
        case 1:
            return hs::ExchangeDisconnect(hs::DisconnectPhase::COUNTS, [&](uint32_t step) {
                if (step == 0) return forced_appends <= current_forced.count;
                if (step == 1) return deposit_appends <= current_deposits.count;
                throw std::logic_error("invalid disconnect count read");
            }, error);
        case 2: {
            const auto counts=hs::ExchangePending({current_forced.count,forced_appends,current_deposits.count,deposit_appends});
            restored_forced={previous->hashForcedInboxRoot,counts[0]};
            restored_deposits={previous->hashDepositInboxRoot,counts[1]};
            return DeriveInboxNext(block,view,height,consensus,authenticated_parent_height,
                restored_forced,restored_deposits,rederived_forced,rederived_deposits,nullptr,nullptr,error);
        }
        case 3:
            return hs::ExchangeDisconnect(hs::DisconnectPhase::UNDO, [&](uint32_t step) {
                switch (step) {
                case 0: return rederived_forced.root == current_forced.root;
                case 1: return rederived_forced.count == current_forced.count;
                case 2: return rederived_deposits.root == current_deposits.root;
                case 3: return rederived_deposits.count == current_deposits.count;
                default: throw std::logic_error("invalid disconnect undo read");
                }
            }, error);
        default: throw std::logic_error("invalid inbox restoration stage");
        }
    })) return false;

    COutPoint prior_outpoint = current.outpoint;
    const Coin* prior_coin{nullptr};
    std::optional<ExchangeStateTracker> restored;
    size_t index{0};
    if (!hs::ParentReplayStore(hs::ReplayStoreFlow::SINGLETON_RECOVERY, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return index<block.vtx.size();
            case 2: return current.outpoint.n==0;
            case 3: return block.vtx.at(index)->GetHash()==current.outpoint.hash;
            case 4: return !block.vtx.at(index)->vin.empty();
            case 5: prior_outpoint=block.vtx.at(index)->vin[0].prevout; return true;
            case 6: ++index; return true;
            case 7: prior_coin=&view.AccessCoin(prior_outpoint); return !prior_coin->IsSpent();
            case 8:
                restored=ExchangeStateTracker{prior_outpoint,ComputeStateUtxoRoot(
                    Params().GetConsensus().hashGenesisBlock,prior_outpoint,prior_coin->out)};
                return restored->root==previous->hashExchangeStateRoot;
            case 9: error="ECX transition cannot recover its prior singleton"; return true;
            case 10: error="prior ECX singleton was not restored by transaction undo"; return true;
            default: error="restored ECX singleton disagrees with prior header root"; return true;
            }
        })) return false;
    const int restored_height=hs::ExchangeTrackerHeight(true,height);
    return hs::ParentReplayEach(std::views::iota(0,3), [&](int stage) {
        switch (stage) {
        case 0: SetTracker(view,*restored,restored_height); break;
        case 1: SetTrackerRecord(view,FORCED_INBOX_TRACKER_OUTPOINT,FORCED_INBOX_TRACKER_MARKER,restored_forced,restored_height); break;
        case 2: SetTrackerRecord(view,DEPOSIT_INBOX_TRACKER_OUTPOINT,DEPOSIT_INBOX_TRACKER_MARKER,restored_deposits,restored_height); break;
        default: throw std::logic_error("invalid exchange restoration stage");
        }
        return true;
    });
}

static bool GetPriorRoot(const CBlockIndex* previous, uint256& root, std::string& error,
    uint32_t mask, uint256 CBlockIndex::* member, const char* unavailable)
{
    error.clear();
    root.SetNull();
    if (!drivechain::haskell::ExchangeAvailable(drivechain::haskell::Availability::ROOT, [&](uint32_t step) {
        if (step == 0) return previous != nullptr;
        if (step == 1) return (static_cast<uint32_t>(previous->nVersion) & mask) != 0;
        if (step == 2) return !(previous->*member).IsNull();
        throw std::logic_error("invalid prior root read");
    })) {
        error = unavailable;
        return false;
    }
    root = previous->*member;
    return true;
}

bool GetPriorActiveExchangeStateRoot(const CBlockIndex* previous, uint256& root, std::string& error)
{
    return GetPriorRoot(previous, root, error, CBlockHeader::EXCHANGE_STATE_HF_MASK,
        &CBlockIndex::hashExchangeStateRoot, "prior-active ECX state root is unavailable");
}

bool GetPriorActiveForcedInboxRoot(const CBlockIndex* previous, uint256& root, std::string& error)
{
    return GetPriorRoot(previous, root, error, CBlockHeader::FORCED_INBOX_HF_MASK,
        &CBlockIndex::hashForcedInboxRoot, "prior-active ECX forced inbox root is unavailable");
}

bool GetPriorActiveDepositInboxRoot(const CBlockIndex* previous, uint256& root, std::string& error)
{
    return GetPriorRoot(previous, root, error, CBlockHeader::DEPOSIT_INBOX_HF_MASK,
        &CBlockIndex::hashDepositInboxRoot, "prior-active ECX deposit inbox root is unavailable");
}

bool GetPriorActiveInboxCursors(
    const CBlockIndex* previous,
    uint64_t& forced_cursor,
    uint64_t& deposit_cursor,
    std::string& error)
{
    error.clear();
    forced_cursor = 0;
    deposit_cursor = 0;
    if (!drivechain::haskell::ExchangeAvailable(drivechain::haskell::Availability::CURSORS, [&](uint32_t step) {
        if (step == 0) return previous != nullptr;
        if (step == 1) return (static_cast<uint32_t>(previous->nVersion) & CBlockHeader::INBOX_CURSOR_HF_MASK) != 0;
        throw std::logic_error("invalid prior cursor read");
    })) {
        error = "prior active block has no ECX processed-cursor commitment";
        return false;
    }
    forced_cursor = previous->forcedProcessedCursor;
    deposit_cursor = previous->depositProcessedCursor;
    return true;
}

bool GetExchangeConsensusSnapshot(
    const CCoinsViewCache& view,
    const CBlockIndex* tip,
    ExchangeConsensusSnapshot& snapshot,
    std::string& error)
{
    error.clear();
    snapshot = {};
    ExchangeStateTracker exchange;
    InboxTracker forced, deposits;
    CTxOut exchange_output;
    if (!drivechain::haskell::ExchangeSnapshot([&](uint32_t step) {
        switch (step) {
        case 0: return tip != nullptr;
        case 1: return (static_cast<uint32_t>(tip->nVersion) & CBlockHeader::EXCHANGE_STATE_HF_MASK) != 0;
        case 2: return (static_cast<uint32_t>(tip->nVersion) & CBlockHeader::FORCED_INBOX_HF_MASK) != 0;
        case 3: return (static_cast<uint32_t>(tip->nVersion) & CBlockHeader::DEPOSIT_INBOX_HF_MASK) != 0;
        case 4: return GetTracker(view,exchange,error);
        case 5: return GetInboxTracker(view,FORCED_INBOX_TRACKER_OUTPOINT,FORCED_INBOX_TRACKER_MARKER,forced,error);
        case 6: return GetInboxTracker(view,DEPOSIT_INBOX_TRACKER_OUTPOINT,DEPOSIT_INBOX_TRACKER_MARKER,deposits,error);
        case 7: return exchange.root == tip->hashExchangeStateRoot;
        case 8: return forced.root == tip->hashForcedInboxRoot;
        case 9: return deposits.root == tip->hashDepositInboxRoot;
        case 10: return (static_cast<uint32_t>(tip->nVersion) & CBlockHeader::INBOX_CURSOR_HF_MASK) != 0;
        case 11: return tip->forcedProcessedCursor <= forced.count;
        case 12: return tip->depositProcessedCursor <= deposits.count;
        case 13: return VerifyTrackedCoin(view,exchange,exchange_output,error);
        default: throw std::logic_error("invalid snapshot context read");
        }
    },error)) return false;

    snapshot.exchange_state_root = exchange.root;
    snapshot.forced_inbox_root = forced.root;
    snapshot.forced_entry_count = forced.count;
    snapshot.forced_processed_cursor = tip->forcedProcessedCursor;
    snapshot.deposit_inbox_root = deposits.root;
    snapshot.deposit_entry_count = deposits.count;
    snapshot.deposit_processed_cursor = tip->depositProcessedCursor;
    snapshot.source_backlog_oldest_parent_height =
        tip->sourceBacklogOldestParentHeight;
    return true;
}

CScript BuildWithdrawalBundleEnvelopeScript(const WithdrawalBundleEnvelopeV1& envelope)
{
    return CScript() << OP_RETURN << drivechain::haskell::ExchangeEnvelopePayload(
        envelope.checkpoint_height,envelope.checkpoint_block_hash.begin(),envelope.m6_no_witness);
}

bool CheckWithdrawalBundleEnvelope(
    const CBlock& block,
    const CBlockIndex* previous,
    int height,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    WithdrawalBundleEnvelopeV1 envelope, parsed;
    std::vector<CTxOut>::const_iterator output;
    CScript::const_iterator cursor;
    opcodetype opcode;
    std::vector<unsigned char> payload;
    const CBlockIndex* checkpoint{nullptr};
    std::array<unsigned char,64> commitments{};
    return drivechain::haskell::ExchangeEnvelopeScan([&](uint32_t step) -> int32_t {
        switch (step) {
        case 0: return height < consensus.activation_height;
        case 1: return !block.vtx.empty();
        case 2: return block.vtx[0]->IsCoinBase();
        case 3: output = block.vtx[0]->vout.begin(); return 1;
        case 4: return output != block.vtx[0]->vout.end();
        case 5:
            payload.clear();
            cursor = output->scriptPubKey.begin();
            return drivechain::haskell::ParentReplayAll<2>({
                [&] { return output->scriptPubKey.GetOp(cursor,opcode); }, [&] { return opcode == OP_RETURN; }});
        case 6: return output->scriptPubKey.GetOp(cursor,opcode,payload);
        case 7: return cursor == output->scriptPubKey.end();
        case 8: return payload.size() >= 5;
        case 9: return std::equal(payload.begin(),payload.begin()+4,"ECXM");
        case 10: return drivechain::haskell::ExchangeEnvelopeHeader(payload,error);
        case 11:
            parsed.checkpoint_height = ReadLE32(payload.data() + 5);
            std::copy(payload.begin() + 9, payload.begin() + 41, parsed.checkpoint_block_hash.begin());
            parsed.m6_no_witness.assign(payload.begin() + 45, payload.end());
            return output->scriptPubKey == BuildWithdrawalBundleEnvelopeScript(parsed);
        case 12: envelope = std::move(parsed); return 1;
        case 13: ++output; return 1;
        case 14: {
            const uint256 previous_bundle = previous == nullptr ? uint256::ZERO : previous->hashWithdrawalBundle;
            const bool changed = block.hashWithdrawalBundle != previous_bundle;
            const bool prior_active = drivechain::haskell::ParentReplayAll<3>({[&] { return previous != nullptr; },
                [&] { return previous->nHeight >= consensus.activation_height; },
                [&] { return (static_cast<uint32_t>(previous->nVersion) & CBlockHeader::EXCHANGE_STATE_HF_MASK) != 0; }});
            return unsigned(!block.hashWithdrawalBundle.IsNull()) | (unsigned(changed) << 1) | (unsigned(prior_active) << 2);
        }
        case 15: return drivechain::haskell::ExchangeCheckpoint([&](uint32_t check) {
            switch (check) {
            case 0: return Hash(envelope.m6_no_witness) == block.hashWithdrawalBundle;
            case 1: return previous != nullptr;
            case 2: return envelope.checkpoint_height < static_cast<uint32_t>(height);
            case 3: checkpoint = previous->GetAncestor(envelope.checkpoint_height); return checkpoint != nullptr;
            case 4: return checkpoint->GetBlockHash() == envelope.checkpoint_block_hash;
            case 5: return checkpoint->pprev != nullptr;
            case 6: return (static_cast<uint32_t>(checkpoint->nVersion) & CBlockHeader::EXCHANGE_STATE_HF_MASK) != 0;
            default: return !checkpoint->hashExchangeStateRoot.IsNull();
            }
        },error);
        case 16: return drivechain::haskell::ExchangeM6Preimage(envelope.m6_no_witness,commitments,error);
        case 17: {
            const uint256 child_genesis = Params().GetConsensus().hashGenesisBlock;
            const uint256 previous_hash = checkpoint->pprev->GetBlockHash();
            const auto anchor_payload = drivechain::haskell::WithdrawalAnchorPayload(envelope.checkpoint_height,
                {child_genesis.begin(), previous_hash.begin(), commitments.data(), checkpoint->hashExchangeStateRoot.begin()});
            const uint256 expected_anchor = TaggedHash("ECX/perps-m6-state/v1", anchor_payload);
            return std::equal(commitments.begin()+32,commitments.end(),expected_anchor.begin());
        }
        default: throw std::logic_error("invalid M6 envelope workflow step");
        }
    },error);
}

static BondV2CapitalSnapshot DecodeCapitalSnapshot(std::span<const unsigned char> encoded)
{
    DataStream stream{Span{encoded.data(),encoded.size()}};
    BondV2CapitalSnapshot snapshot;
    stream >> snapshot;
    if (!stream.empty()) throw std::logic_error("Haskell capital snapshot has trailing bytes");
    return snapshot;
}

static BondV2CapitalSnapshot ProjectActivationCapitalSnapshot(std::span<const unsigned char> values,
    const uint256& active_root, const ExchangeConsensus& consensus, uint64_t height, uint64_t mtp)
{
    static_assert(BOND_V2_CAPITAL_SNAPSHOT_VERSION==4);
    const auto& frozen=consensus.bond_v2;
    const auto queue=(::TaggedHash("ECX/successor-redemption-queue/v2-u128") << uint32_t{0}).GetSHA256();
    const auto inbox=IncrementalSuccessorBondInboxGenesisHead(consensus);
    const auto outcome=(::TaggedHash("ECX/successor-bond-inbox-outcomes-genesis/v2-u128")
        << frozen.bond_inbox_domain << consensus.chain_id << frozen.configuration_hash).GetSHA256();
    const auto encoded=drivechain::haskell::ExchangeGenesisState(drivechain::haskell::GenesisCodec::ACTIVATION_SNAPSHOT,height,mtp,
        {active_root.begin(),frozen.incremental_successor_configuration_hash.begin(),frozen.bond_asset_id.begin(),
         frozen.bond_deployment_commitment.begin(),frozen.incremental_successor_program_id.begin(),
         frozen.incremental_successor_transition_cmr.begin(),
         frozen.inventory_covenant_script_sha256.begin(),queue.begin(),inbox.begin(),outcome.begin()},values);
    return DecodeCapitalSnapshot(encoded);
}

template <bool Incremental>
static bool DecodeCapitalProjection(
    const std::vector<unsigned char>& stripped_annex,
    const uint256& active_exchange_state_root,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    const auto& frozen = consensus.bond_v2;
    std::array<unsigned char, 32> program_id{};
    std::array<unsigned char, 32> public_values_sha256{};
    std::array<unsigned char, Incremental ? ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN : ECX_SP1_PUBLIC_VALUES_V5_LEN> values{};
    std::array<unsigned char,914> encoded{};
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CAPITAL_DECODE,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return FrozenBondV2IdentityAvailable(frozen,error);
            case 2: return !active_exchange_state_root.IsNull();
            case 3: error = Incremental ? "ECX incremental successor projection has no active exchange root" :
                "ECX bond V2 capital projection has no active exchange root"; return true;
            case 4:
                return (Incremental ? simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex :
                    simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex)(stripped_annex.data(),
                    stripped_annex.size(),program_id.data(),public_values_sha256.data(),values.data());
            case 5: error = Incremental ? "ECX incremental successor lacks one canonical version-6/PublicValuesV23 annex" :
                "ECX bond V2 transition lacks one canonical version-4/PublicValuesV5 annex"; return true;
            case 6:
                if constexpr (Incremental) {
                    return drivechain::haskell::ExchangeCapitalIdentity(true,program_id,values,{
                        frozen.incremental_successor_program_id.begin(),frozen.incremental_successor_configuration_hash.begin(),
                        frozen.configuration_hash.begin(),consensus.chain_id.data(),frozen.bond_asset_id.begin(),
                        frozen.bond_deployment_commitment.begin(),frozen.inventory_covenant_script_sha256.begin()}, {},
                        {active_exchange_state_root.begin(),frozen.incremental_successor_transition_cmr.begin(),
                         frozen.inventory_covenant_script_sha256.begin()},encoded);
                } else {
                    return drivechain::haskell::ExchangeCapitalIdentity(false,program_id,values,{
                        frozen.transition_program_id.begin(),frozen.transition_journal_domain_sha256.begin(),
                        frozen.configuration_hash.begin(),frozen.bond_asset_id.begin(),frozen.bond_deployment_commitment.begin()}, {},
                        {active_exchange_state_root.begin(),frozen.transition_cmr.begin(),
                         frozen.inventory_covenant_script_sha256.begin()},encoded);
                }
            case 7: error = Incremental ? "ECX incremental successor annex does not match frozen program/configuration/deployment identities" :
                "ECX bond V2 annex does not match the source-frozen deployment identities"; return true;
            default: snapshot=DecodeCapitalSnapshot(encoded); return true;
            }
        }) != 0;
}

bool DecodeBondV2CapitalProjection(const std::vector<unsigned char>& annex, const uint256& root,
    BondV2CapitalSnapshot& snapshot, std::string& error, const ExchangeConsensus& consensus)
{
    return DecodeCapitalProjection<false>(annex,root,snapshot,error,consensus);
}

bool DecodeBondV2IncrementalSuccessorCapitalProjection(
    const std::vector<unsigned char>& stripped_annex,
    const uint256& active_exchange_state_root,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    return DecodeCapitalProjection<true>(stripped_annex,active_exchange_state_root,snapshot,error,consensus);
}

bool ResolveBondV2GenesisInitialization(
    const CBlockIndex* previous,
    uint32_t state_creation_height,
    uint64_t activation_parent_mtp,
    uint64_t& initialization_height,
    uint64_t& initialization_parent_mtp,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    initialization_height = 0;
    initialization_parent_mtp = 0;
    error.clear();
    const auto& frozen{consensus.bond_v2};
    const auto version = frozen.genesis_initialization_version;
    const CBlockIndex* anchor{nullptr};
    return drivechain::haskell::ExchangeGenesisInitialization(version, [&](uint32_t step) {
        switch (step) {
        case 0: return activation_parent_mtp != 0;
        case 1: return state_creation_height != 0;
        case 2: return frozen.genesis_initialization_height == 0;
        case 3: return frozen.genesis_initialization_block_hash.IsNull();
        case 4: return frozen.genesis_initialization_parent_mtp == 0;
        case 5: return previous != nullptr;
        case 6: return previous->nHeight >= 0;
        case 7: return state_creation_height <= static_cast<uint32_t>(previous->nHeight);
        case 8: return frozen.genesis_initialization_height != 0;
        case 9: return frozen.genesis_initialization_height < state_creation_height;
        case 10: return frozen.genesis_initialization_height <= static_cast<uint32_t>(previous->nHeight);
        case 11: return !frozen.genesis_initialization_block_hash.IsNull();
        case 12: return frozen.genesis_initialization_parent_mtp != 0;
        case 13: return frozen.genesis_initialization_parent_mtp <= activation_parent_mtp;
        case 14: anchor = previous->GetAncestor(frozen.genesis_initialization_height); return anchor != nullptr;
        case 15: return anchor->GetBlockHash() == frozen.genesis_initialization_block_hash;
        case 16: return anchor->m_drivechain_anchor.has_value();
        case 17: return anchor->m_drivechain_anchor->IsSane();
        case 18: return anchor->m_drivechain_anchor->parent_median_time_past == frozen.genesis_initialization_parent_mtp;
        case 19:
            initialization_height = state_creation_height;
            initialization_parent_mtp = activation_parent_mtp;
            return true;
        case 20:
            initialization_height = frozen.genesis_initialization_height;
            initialization_parent_mtp = frozen.genesis_initialization_parent_mtp;
            return true;
        default: throw std::logic_error("invalid genesis initialization action");
        }
    }, error);
}

bool VerifyBondV2DeploymentAndGenesis(
    const CCoinsViewCache& view,
    const uint64_t prior_parent_mtp,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus,
    const CBlockIndex* previous)
{
    error.clear();
    const auto& frozen=consensus.bond_v2;
    Txid deployment_txid, genesis_txid;
    CAsset bond_asset, token_asset;
    const Coin* deployment_inventory=nullptr;
    const Coin* state_coin=nullptr;
    uint64_t initialization_height=0, initialization_mtp=0;
    std::array<uint256,4> roots;
    const auto& [private_state_root,bond_state_root,funding_state_root,covenant_state_hash]=roots;
    CScript expected_script;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::GENESIS_ADMISSION,
        [&](uint32_t step) -> uint32_t {
            if (step==1) return FrozenBondV2IdentityAvailable(frozen,error);
            if (step==2) return prior_parent_mtp!=0;
            const CTransaction& deployment=*frozen.deployment_transaction;
            const CTransaction& genesis=*frozen.genesis_transaction;
            const bool public_deployment=frozen.deployment_version==3;
            switch (step) {
            case 3: deployment_txid=deployment.GetHash(); return public_deployment;
            case 4: return Consensus::HasOnlyExplicitCreations(genesis);
            case 5: genesis_txid=genesis.GetHash(); return 1;
            case 6: return deployment_txid != genesis_txid;
            case 7: return consensus.genesis_state_outpoint.hash == genesis_txid;
            case 8: return frozen.issuance_input_index < deployment.vin.size();
            case 9: return frozen.inventory_output_index < deployment.vout.size();
            case 10: return frozen.reissuance_token_burn_output_index < deployment.vout.size();
            case 11: return frozen.state_authority_source_output_index < deployment.vout.size();
            case 12: return consensus.genesis_state_outpoint.n < genesis.vout.size();
            case 13: return !genesis.vin.empty();
            case 14: return genesis.vin[0].prevout == COutPoint{deployment_txid, frozen.state_authority_source_output_index};
            case 15: return !deployment.vin[frozen.issuance_input_index].assetIssuance.IsNull();
            case 16: return deployment.vin[frozen.issuance_input_index].assetIssuance.assetBlindingNonce.IsNull();
            case 17: return VerifyConfiguredBondIssuance(deployment, frozen, public_deployment);
            case 18: return deployment.vin[frozen.issuance_input_index].assetIssuance.nInflationKeys.IsExplicit();
            case 19: return deployment.vin[frozen.issuance_input_index].assetIssuance.nInflationKeys.GetAmount() == 1;
            case 20: return drivechain::haskell::CountMatches(deployment.vin.size(),
                [&](uint64_t i) { return !deployment.vin[i].assetIssuance.IsNull(); }) == 1;
            case 21: return drivechain::haskell::ParentReplayEach(deployment.vin,
                [](const CTxIn& input) { return !input.m_is_pegin; });
            case 22: return HasOnlyOrdinaryInputs(genesis);
            case 23: {
                const auto& issuance=deployment.vin[frozen.issuance_input_index];
                uint256 entropy;
                GenerateAssetEntropy(entropy,issuance.prevout,issuance.assetIssuance.assetEntropy);
                CalculateAsset(bond_asset,entropy);
                CalculateReissuanceToken(token_asset,entropy,!public_deployment);
                return drivechain::haskell::ParentReplayAll<2>({[&] { return bond_asset.id==frozen.bond_asset_id; },
                    [&] { return bond_asset!=token_asset; }});
            }
            case 24: return public_deployment;
            case 25: return VerifyConfidentialPair(deployment.vout[frozen.inventory_output_index].nValue, deployment.vout[frozen.inventory_output_index].nAsset, ECX_BOND_FIXED_SUPPLY, bond_asset,
                frozen.inventory_value_blinding_factor, frozen.inventory_asset_blinding_factor);
            case 26: return Sha256(deployment.vout[frozen.inventory_output_index].scriptPubKey) == frozen.inventory_covenant_script_sha256;
            case 27: return deployment.vout[frozen.reissuance_token_burn_output_index].nAsset.IsExplicit();
            case 28: return deployment.vout[frozen.reissuance_token_burn_output_index].nAsset.GetAsset() == token_asset;
            case 29: return deployment.vout[frozen.reissuance_token_burn_output_index].nValue.IsExplicit();
            case 30: return deployment.vout[frozen.reissuance_token_burn_output_index].nValue.GetAmount() == 1;
            case 31: return deployment.vout[frozen.reissuance_token_burn_output_index].nNonce.IsNull();
            case 32: return deployment.vout[frozen.reissuance_token_burn_output_index].scriptPubKey.IsUnspendable();
            case 33: return Sha256(deployment.vout[frozen.reissuance_token_burn_output_index].scriptPubKey) == frozen.reissuance_token_burn_script_sha256;
            case 34: return deployment.vout[frozen.state_authority_source_output_index].nAsset.IsExplicit();
            case 35: return deployment.vout[frozen.state_authority_source_output_index].nAsset.GetAsset().id == frozen.state_authority_asset_id;
            case 36: return deployment.vout[frozen.state_authority_source_output_index].nValue.IsExplicit();
            case 37: return deployment.vout[frozen.state_authority_source_output_index].nValue.GetAmount() == 1;
            case 38: return deployment.vout[frozen.state_authority_source_output_index].nNonce.IsNull();
            case 39: return !deployment.vout[frozen.state_authority_source_output_index].scriptPubKey.empty();
            case 40: return !deployment.vout[frozen.state_authority_source_output_index].scriptPubKey.IsUnspendable();
            case 41: return BondDeploymentCommitment(frozen.deployment_version,
                {deployment_txid.ToUint256(),deployment.vin[frozen.issuance_input_index].prevout.hash.ToUint256(),
                 deployment.vin[frozen.issuance_input_index].prevout.n,bond_asset.id,token_asset.id,frozen.inventory_output_index,
                 frozen.reissuance_token_burn_output_index,frozen.inventory_covenant_script_sha256,
                 frozen.reissuance_token_burn_script_sha256})==frozen.bond_deployment_commitment;
            case 42:
                deployment_inventory=&view.AccessCoin(COutPoint{deployment_txid,frozen.inventory_output_index});
                state_coin=&view.AccessCoin(consensus.genesis_state_outpoint);
                return 1;
            case 43: return !deployment_inventory->IsSpent();
            case 44: return !state_coin->IsSpent();
            case 45: return deployment_inventory->out == deployment.vout[frozen.inventory_output_index];
            case 46: return state_coin->out == genesis.vout[consensus.genesis_state_outpoint.n];
            case 47: return deployment_inventory->nHeight != 0;
            case 48: return state_coin->nHeight != 0;
            case 49: return deployment_inventory->nHeight != UINT32_C(0x7fffffff);
            case 50: return state_coin->nHeight != UINT32_C(0x7fffffff);
            case 51: return state_coin->nHeight >= deployment_inventory->nHeight;
            case 52: return deployment_inventory->nHeight < static_cast<uint32_t>(consensus.activation_height);
            case 53: return state_coin->nHeight < static_cast<uint32_t>(consensus.activation_height);
            case 54: return ResolveBondV2GenesisInitialization(previous,state_coin->nHeight,prior_parent_mtp,
                initialization_height,initialization_mtp,error,consensus);
            case 55:
                roots=ComputeBondV2GenesisRoots(consensus,initialization_height,initialization_mtp);
                return !private_state_root.IsNull();
            case 56: return ComputeBondV2GenesisScript(consensus,covenant_state_hash,expected_script);
            case 57: return state_coin->out.scriptPubKey == expected_script;
            case 58: return state_coin->out.nAsset.IsExplicit();
            case 59: return state_coin->out.nAsset.GetAsset().id == frozen.state_authority_asset_id;
            case 60: return state_coin->out.nValue.IsExplicit();
            case 61: return state_coin->out.nValue.GetAmount() == 1;
            case 62: return state_coin->out.nNonce.IsNull();
            case 63: return ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,
                consensus.genesis_state_outpoint, state_coin->out) == consensus.genesis_state_root;
            case 64: {
                std::array<unsigned char,8> price;
                WriteBE64(price.data(),frozen.genesis_mark_price);
                const auto queue=EmptyBondV2QueueRoot(), inbox=ComputeBondInboxGenesisRoot(consensus),
                    outcome=ComputeBondInboxOutcomeGenesisRoot(consensus), receipt=EmptyMatcherExecutionReceiptBatchRoot();
                snapshot=DecodeCapitalSnapshot(drivechain::haskell::ExchangeGenesisState(
                    drivechain::haskell::GenesisCodec::GENESIS_SNAPSHOT,initialization_height,initialization_mtp,
                    {consensus.genesis_state_root.begin(),frozen.configuration_hash.begin(),frozen.bond_asset_id.begin(),
                     frozen.bond_deployment_commitment.begin(),frozen.transition_program_id.begin(),frozen.transition_cmr.begin(),
                     covenant_state_hash.begin(),bond_state_root.begin(),funding_state_root.begin(),frozen.inventory_covenant_script_sha256.begin(),
                     queue.begin(),frozen.genesis_availability_root.begin(),inbox.begin(),outcome.begin(),receipt.begin()},price));
                return 1;
            }
            case 65: error="ECX bond V2 genesis has no authenticated parent MTP"; return 1;
            case 66: error="public ECX genesis contains confidential creations or proofs"; return 1;
            case 67: error="ECX bond V2 physical deployment/genesis linkage changed"; return 1;
            case 68: error="ECX bond V2 deployment/genesis issuance shape changed"; return 1;
            case 69: error="ECX bond V2 physical issuance derives a substituted asset"; return 1;
            case 70: error="ECX bond V2 deployment outputs differ from the authorized facts"; return 1;
            case 71: error="ECX bond V2 deployment commitment was substituted"; return 1;
            case 72: error="ECX bond V2 activation requires confirmed ordered deployment and genesis UTXOs"; return 1;
            case 73: error="ECX bond V2 canonical genesis encoding failed"; return 1;
            case 74: error="ECX bond V2 genesis singleton is not the exact derived empty state"; return 1;
            default: throw std::logic_error("invalid genesis admission action");
            }
        })==0;
}

bool CheckBondV2ActivationPredecessorCoin(
    const CTransaction& transition,
    const Coin& predecessor_coin,
    const uint256& previous_exchange_root,
    const BondV2CapitalSnapshot& prior_capital,
    std::string& error,
    const ExchangeConsensus& consensus)
{
    error.clear();
    CScript expected_script;
    const auto status=drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::ACTIVATION_PREDECESSOR,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return !transition.vin.empty();
            case 2: return !transition.vin[0].m_is_pegin;
            case 3: return !predecessor_coin.IsSpent();
            case 4: return !previous_exchange_root.IsNull();
            case 5: return prior_capital.proof_profile==0;
            case 6: return prior_capital.exchange_state_root==previous_exchange_root;
            case 7: return !prior_capital.covenant_state_hash.IsNull();
            case 8: return ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,
                transition.vin[0].prevout,predecessor_coin.out)==previous_exchange_root;
            case 9: return ComputeBondV2FiniteStateScript(consensus,prior_capital.covenant_state_hash,expected_script);
            default: return predecessor_coin.out.scriptPubKey==expected_script;
            }
        });
    if (status) error=status==1 ? "ECX incremental activation predecessor coin is not previous-root bound" :
        "ECX incremental activation predecessor script is not covenant-state bound";
    // The successfully executed activation leaf binds its private-state root
    // to this exact public-state covenant script. The two roots are distinct.
    return status==0;
}

bool DeriveBondV2CapitalProjectionAfterScripts(
    const CBlock& block,
    const CBlockIndex* previous,
    const CCoinsViewCache& view,
    const int height,
    const uint256& prior_parent_block_hash,
    const uint64_t prior_parent_height,
    const uint64_t prior_parent_mtp,
    BondV2CapitalSnapshot& snapshot,
    std::string& error,
    const ExchangeConsensus& consensus,
    const CBlockUndo* block_undo,
    std::optional<uint256> activation_execution_hash,
    std::optional<uint64_t> activation_execution_mtp)
{
    error.clear();
    const CTransaction* transition=nullptr;
    size_t transition_index=0,candidate_index=0;
    std::vector<unsigned char> stripped_annex;
    const auto annex_version=[&](unsigned char version) {
        return drivechain::haskell::ParentReplayAll<2>({[&] { return stripped_annex.size()>7; },
            [&] { return stripped_annex[7]==version; }});
    };
    const auto prior=[&]() -> const BondV2CapitalSnapshot& { return *previous->ecxBondV2Capital; };
    const auto witness=[&]() -> const auto& { return transition->witness.vtxinwit[0].scriptWitness.stack; };
    const uint256* execution_hash=&prior_parent_block_hash;
    uint64_t execution_mtp=prior_parent_mtp;
    std::array<unsigned char,32> activation_program{}, activation_digest{};
    std::array<unsigned char,ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN> activation_values{};
    CScript activation_script;
    bool incremental=false;
    const auto scan_successor=[&] {
        const auto scan=drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::SUCCESSOR_SCAN,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return candidate_index<block.vtx.size();
                case 2: return !block.vtx[candidate_index]->vin.empty();
                case 3: return !block.vtx[candidate_index]->vout.empty();
                case 4: return ComputeStateUtxoRoot(Params().GetConsensus().hashGenesisBlock,
                    COutPoint{block.vtx[candidate_index]->GetHash(),0},block.vtx[candidate_index]->vout[0])==block.hashExchangeStateRoot;
                case 5: return transition!=nullptr;
                case 6: ++candidate_index; return 1;
                case 7: return transition!=nullptr;
                case 8: transition=block.vtx[candidate_index].get(); transition_index=candidate_index; return 1;
                case 9: return !transition->witness.vtxinwit.empty();
                case 10: return witness().size()>=2;
                case 11: return !witness().back().empty();
                default: return witness().back()[0]==0x50;
                }
            });
        if (scan) {
            static constexpr const char* errors[]{"ECX bond V2 block contains more than one successor-root transaction",
                "ECX bond V2 state change lacks its transition input/witness","ECX bond V2 transition input zero lacks a Taproot annex"};
            error=errors[scan-1];
            return false;
        }

        const auto& stack=witness();
        stripped_annex.assign(stack.back().begin()+1,stack.back().end());
        return true;
    };
    const auto bind_context=[&] {
        std::array<unsigned char, 32> program_id{};
        std::array<unsigned char, 32> public_values_sha256{};
        std::array<unsigned char, std::max(ECX_SP1_PUBLIC_VALUES_V5_LEN, ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN)> values{};
        CScript expected_successor_script;
        const auto bind_values=[&](bool profile,size_t size) {
            return drivechain::haskell::ExchangeSuccessorBinding(profile,std::span{values}.first(size),
                std::array<const unsigned char*,4>{prior().covenant_state_hash.begin(),transition->GetHash().ToUint256().begin(),
                    previous->hashExchangeStateRoot.begin(),prior_parent_block_hash.begin()},
                std::array<uint64_t,3>{prior_parent_height,prior_parent_mtp,static_cast<uint64_t>(height)});
        };
        const auto status=drivechain::haskell::ParentReplayStore(incremental ?
            drivechain::haskell::ReplayStoreFlow::INCREMENTAL_CONTEXT : drivechain::haskell::ReplayStoreFlow::FINITE_CONTEXT,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return prior().proof_profile==0;
                case 7: return prior().proof_profile==1;
                case 2: return DecodeBondV2CapitalProjection(stripped_annex,block.hashExchangeStateRoot,snapshot,error,consensus);
                case 8: return DecodeBondV2IncrementalSuccessorCapitalProjection(stripped_annex,block.hashExchangeStateRoot,snapshot,error,consensus);
                case 3: return simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(stripped_annex.data(),stripped_annex.size(),
                        program_id.data(),public_values_sha256.data(),values.data());
                case 9: return simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(stripped_annex.data(),stripped_annex.size(),
                        program_id.data(),public_values_sha256.data(),values.data());
                case 4: return ComputeBondV2FiniteStateScript(consensus,snapshot.covenant_state_hash,expected_successor_script);
                case 10: return ComputeBondV2IncrementalSuccessorScript(consensus,snapshot.covenant_state_hash,expected_successor_script);
                case 5:
                case 11: return transition->vout[0].scriptPubKey==expected_successor_script;
                case 6: return bind_values(false,ECX_SP1_PUBLIC_VALUES_V5_LEN);
                case 12: return bind_values(true,ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN);
                case 13: return snapshot.bond_inbox_head_root==prior().node_bond_inbox_head_root;
                case 14: return snapshot.bond_inbox_entry_count==prior().node_bond_inbox_entry_count;
                case 15: return snapshot.bond_inbox_processed_cursor>=prior().bond_inbox_processed_cursor;
                case 16: return snapshot.matcher_execution_sequence>=prior().matcher_execution_sequence;
                default: return snapshot.previous_matcher_execution_sequence==prior().matcher_execution_sequence;
                }
            });
        if (status) {
            if (status==1 && error.empty()) error=incremental ? "ECX incremental successor cannot follow a finite predecessor" :
                "finite V18 annex cannot follow an incremental successor";
            if (status==2) error=incremental ? "ECX incremental successor annex changed between decode and context binding" :
                "ECX finite V18 annex changed between decode and context binding";
            if (status==3) error=incremental ? "ECX incremental successor does not bind the transition/header/BMM/cursor context" :
                "ECX finite V18 public values do not bind the transition/header/BMM context";
            return false;
        }

        return true;
    };
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::CAPITAL_PROJECTION,
        [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return FrozenBondV2IdentityAvailable(consensus.bond_v2,error);
            case 2: return height>=consensus.activation_height;
            case 3: return height==consensus.activation_height;
            case 4: return block.hashExchangeStateRoot==consensus.genesis_state_root;
            case 5: return VerifyBondV2DeploymentAndGenesis(view,prior_parent_mtp,snapshot,error,consensus,previous);
            case 6: return AppendBondInboxSourcesForBlock(block,height,prior_parent_height,snapshot,error,consensus);
            case 7: return drivechain::haskell::ParentReplayAll<2>({[&] { return previous!=nullptr; },
                [&] { return previous->ecxBondV2Capital.has_value(); }});
            case 8: return block.hashExchangeStateRoot==previous->hashExchangeStateRoot;
            case 9: snapshot=prior(); return 1;
            case 10: return drivechain::haskell::ExchangeCarryIdentity(snapshot.proof_profile,std::array<const unsigned char*,15>{
                snapshot.configuration_hash.begin(),snapshot.transition_program_id.begin(),snapshot.transition_cmr.begin(),
                snapshot.exchange_state_root.begin(),snapshot.bond_asset_id.begin(),snapshot.bond_deployment_commitment.begin(),
                consensus.bond_v2.configuration_hash.begin(),consensus.bond_v2.transition_program_id.begin(),consensus.bond_v2.transition_cmr.begin(),
                consensus.bond_v2.incremental_successor_configuration_hash.begin(),consensus.bond_v2.incremental_successor_program_id.begin(),
                consensus.bond_v2.incremental_successor_transition_cmr.begin(),block.hashExchangeStateRoot.begin(),
                consensus.bond_v2.bond_asset_id.begin(),consensus.bond_v2.bond_deployment_commitment.begin()});
            case 11: return AppendBondInboxSourcesForProfile(snapshot.proof_profile==1,
                block,height,prior_parent_height,snapshot,error,consensus,nullptr);
            case 12: return !prior_parent_block_hash.IsNull();
            case 13: return prior_parent_height!=0;
            case 14: return prior_parent_mtp!=0;
            case 15: return scan_successor();
            case 16: return annex_version(5);
            case 17: return activation_execution_hash.has_value()==activation_execution_mtp.has_value();
            case 18:
                execution_hash=activation_execution_hash ? &*activation_execution_hash : &prior_parent_block_hash;
                execution_mtp=activation_execution_mtp.value_or(prior_parent_mtp);
                return block_undo!=nullptr;
            case 19: return transition_index!=0;
            case 20: return block_undo->vtxundo.size()==block.vtx.size()-1;
            case 21: return block_undo->vtxundo[transition_index-1].vprevout.size()==transition->vin.size();
            case 22: return CheckBondV2ActivationPredecessorCoin(*transition,
                block_undo->vtxundo[transition_index-1].vprevout[0],previous->hashExchangeStateRoot,prior(),error,consensus);
            case 23: return prior().proof_profile==0;
            case 24: return simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
                stripped_annex.data(),stripped_annex.size(),activation_program.data(),activation_digest.data(),activation_values.data());
            case 25: return drivechain::haskell::ExchangeCapitalIdentity(2,activation_program,activation_values,{
                consensus.bond_v2.incremental_activation_program_id.begin(),
                consensus.bond_v2.incremental_activation_configuration_hash.begin(),consensus.bond_v2.configuration_hash.begin(),
                consensus.bond_v2.incremental_successor_configuration_hash.begin(),transition->GetHash().ToUint256().begin(),
                execution_hash->begin(),consensus.chain_id.data()},{static_cast<uint64_t>(height),execution_mtp});
            case 26: return ComputeBondV2IncrementalSuccessorScript(consensus,RawHash32(activation_values.data()+132),activation_script);
            case 27: return transition->vout[0].scriptPubKey==activation_script;
            case 28: snapshot=ProjectActivationCapitalSnapshot(activation_values,block.hashExchangeStateRoot,consensus,static_cast<uint64_t>(height),execution_mtp); return 1;
            case 29: return AppendIncrementalSuccessorBondInboxSourcesForBlock(block,height,prior_parent_height,snapshot,error,consensus);
            case 30: incremental=annex_version(6); return incremental;
            case 31:
            case 32: return bind_context();
            case 33: snapshot.previous_matcher_execution_sequence=prior().matcher_execution_sequence; return 1;
            case 34: snapshot.last_transition_sidechain_height=static_cast<uint64_t>(height); return 1;
            case 35: return AppendBondInboxSourcesForProfile(incremental,block,height,prior_parent_height,snapshot,error,consensus,nullptr);
            case 36: error="ECX bond V2 capital projection requested before activation"; return 1;
            case 37: error="ECX bond V2 activation header does not commit exact genesis"; return 1;
            case 38: error="ECX bond V2 predecessor lacks a verified block-index capital projection"; return 1;
            case 39: error="ECX bond V2 carry-forward projection is not root/frozen-identity bound"; return 1;
            case 40: error="ECX bond V2 transition has no authenticated prior BMM context"; return 1;
            case 41: error="ECX activation execution context is partial"; return 1;
            case 42: error="ECX incremental activation lacks exact consumed-coin undo context"; return 1;
            case 43: error="ECX incremental activation is not a canonical finite-state one-shot annex"; return 1;
            case 44: error="ECX incremental activation does not bind the frozen predecessor/transaction/BMM context"; return 1;
            case 45: error="ECX incremental activation output does not commit the proven successor state"; return 1;
            default: throw std::logic_error("invalid capital projection action");
            }
        })==0;
}

} // namespace ecx
