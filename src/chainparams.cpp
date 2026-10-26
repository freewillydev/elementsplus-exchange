// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chainparams.h>

#include <chainparamsbase.h>
#include <haskell/bridge.h>
#include <common/args.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <deploymentinfo.h>
#include <issuance.h>
#include <primitives/transaction.h>
#include <logging.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>
#include <bitcoin-build-config.h> // IWYU pragma: keep

using util::SplitString;

void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    if (!args.GetArgs("-signetseednode").empty()) {
        options.seeds.emplace(args.GetArgs("-signetseednode"));
    }
    if (!args.GetArgs("-signetchallenge").empty()) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }
        const auto val{TryParseHex<uint8_t>(signet_challenge[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", signet_challenge[0]));
        }
        options.challenge.emplace(*val);
    }
}

void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    if (auto value = args.GetBoolArg("-fastprune")) options.fastprune = *value;
    if (HasTestOption(args, "bip94")) options.enforce_bip94 = true;

    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }

        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }

        const auto deployment_name{arg.substr(0, found)};
        if (const auto buried_deployment = GetBuriedDeployment(deployment_name)) {
            options.activation_heights[*buried_deployment] = height;
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        CChainParams::VersionBitsParameters vbparams{};
        if (!ParseInt64(vDeploymentParams[1], &vbparams.start_time)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &vbparams.timeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4) {
            if (!ParseInt32(vDeploymentParams[3], &vbparams.min_activation_height)) {
                throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
            }
        } else {
            vbparams.min_activation_height = 0;
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                options.version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d\n", vDeploymentParams[0], vbparams.start_time, vbparams.timeout, vbparams.min_activation_height);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

std::vector<unsigned char> PeginConfirmationSnapshot(const CChainParams& params, int height)
{
    static_assert(ALPHA_PEGIN_ONE_CONFIRMATION_HEIGHT == 64);
    const auto& consensus = params.GetConsensus();
    std::vector<unsigned char> snapshot;
    VectorWriter writer{snapshot, 0};
    SerializeMany(writer, int64_t{height}, params.NetworkIDString(), consensus.elements_mode,
        consensus.has_parent_chain, consensus.drivechain_slot.has_value(), consensus.drivechain_slot.value_or(0),
        consensus.hashGenesisBlock, params.ParentGenesisBlockHash(), consensus.drivechain_protocol_manifest_hash,
        consensus.pegin_min_depth);
    return snapshot;
}

static uint32_t PeginConfirmationPolicy(const CChainParams& params, int height, bool alpha_only)
{
    namespace hs = drivechain::haskell;
    uint32_t depth{0};
    if (!hs::RunReplayStore(alpha_only ? hs::ReplayStoreWorkflow::ALPHA_PEGIN_IDENTITY : hs::ReplayStoreWorkflow::CONFIRMATION_DEPTH,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
            if (step == 0 && index == 0 && input.empty()) return PeginConfirmationSnapshot(params, height);
            if (step != 1 || index > UINT32_MAX || !input.empty()) throw std::logic_error("invalid confirmation depth publication");
            depth = static_cast<uint32_t>(index);
            return {};
        })) throw std::runtime_error("Haskell pegin confirmation policy failed");
    return depth;
}

bool HasAlphaPeginOneConfirmationUpgrade(const CChainParams& params)
{
    return PeginConfirmationPolicy(params, 0, true) == 1;
}

uint32_t GetDrivechainPeginConfirmationDepth(const CChainParams& params, const int child_height)
{
    return PeginConfirmationPolicy(params, child_height, false);
}

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainTypeMeta chain)
{
    drivechain::haskell::ValidateNetworkSelection(drivechain::haskell::NetworkSelection::CHAIN_NAME, chain.chain_name);
    switch (chain.chain_type) {
    case ChainType::ELEMENTS:
        return CChainParams::ElementsDrivechain();
    case ChainType::MAIN:
        return CChainParams::Main();
    case ChainType::TESTNET:
        return CChainParams::TestNet();
    case ChainType::TESTNET4:
        return CChainParams::TestNet4();
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        // CCustomParams derives from CRegTestParams, so this guard must live at
        // the exact network-selection boundary instead of in the base
        // constructor. Otherwise every custom Elements chain that explicitly
        // enables Elements mode is rejected before its parameters are applied.
        drivechain::haskell::ValidateNetworkSelection(drivechain::haskell::NetworkSelection::REGTEST_OPTION,
            "", args.GetBoolArg("-con_elementsmode", false));
        for (const std::string& deployment : args.GetArgs("-vbparams")) {
            drivechain::haskell::ValidateNetworkSelection(drivechain::haskell::NetworkSelection::REGTEST_OPTION, deployment);
        }
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::RegTest(opts);
    }
    case ChainType::LIQUID1:
        return CChainParams::LiquidV1(args);
    case ChainType::LIQUID1TEST:
        return CChainParams::LiquidV1Test(args);
    case ChainType::LIQUIDTESTNET: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::LiquidTestNet(chain, args, opts);
    }
    case ChainType::CUSTOM:
        // just log the custom chain and fallthrough to the catch-all for custom params
        LogPrintf("CreateChainParams for custom chain: %s\n", chain.chain_name);
    }

    auto opts = CChainParams::RegTestOptions{};
    ReadRegTestArgs(args, opts);
    return CChainParams::Custom(chain, args, opts);
}

void SelectParams(const ChainTypeMeta chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}

// ELEMENTS:
// keep the original ChainType constructors, which just call our new ChainTypeMeta constructors
// this helps not to have to change all the other callsites
// in general: don't use these, they're "lossy" for custom chain names
std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain) {
    return CreateChainParams(args, ChainTypeMetaFrom(chain));
}

void SelectParams(const ChainType chain) {
    SelectParams(ChainTypeMetaFrom(chain));
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    return CreateChainParams(args, ChainTypeMetaFrom(chain));
}

void SelectParams(const std::string& chain)
{
    SelectParams(ChainTypeMetaFrom(chain));
}
