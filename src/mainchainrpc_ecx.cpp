#include <mainchainrpc.h>
#include <haskell/bridge.h>
#include <haskell/network_defaults.h>

#include <chainparams.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <drivechain_treasury.h>
#include <logging.h>
#include <pegins.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/bitcoin/block.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <common/args.h>
#include <util/strencodings.h>
#include <tinyformat.h>

#include <optional>
#include <vector>

namespace {
template <typename Action>
bool CatchParentError(std::string* error, Action&& action)
{
    try { return action(); }
    catch (const std::exception& exception) {
        if (error) *error = exception.what();
        return false;
    }
}
} // namespace

bool CallAuthenticatedDrivechainJSON(
    const std::string& endpoint,
    const std::string& method,
    const UniValue& request,
    UniValue& response,
    std::string* error)
{
    namespace hs = drivechain::haskell;
    std::optional<BoundedCommandResult> result;
    return hs::ParentReplayStore(hs::ReplayStoreFlow::AUTHENTICATED_JSON, [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: case 19: response = UniValue(); return 1;
        case 2: case 5: case 15: case 20: return error != nullptr;
        case 3: error->clear(); return 1;
        case 4: return endpoint == GetDrivechainGrpcAddress(gArgs);
        case 6: *error = "enforcer endpoint differs from the configured mTLS endpoint"; return 1;
        case 7: result.emplace(RunAuthenticatedDrivechainGrpc(
            method, request.write(), std::chrono::seconds{drivechain::AUTHENTICATED_GRPC_TIMEOUT_SECONDS},
            drivechain::MAX_AUTHENTICATED_GRPC_RESPONSE_SIZE)); return 1;
        case 8: return result->started;
        case 9: return result->exited;
        case 10: return result->exit_code == 0;
        case 11: return !result->timed_out;
        case 12: return !result->cancelled;
        case 13: return !result->output_truncated;
        case 14: return result->error.empty();
        case 16: *error = "authenticated enforcer request failed, timed out, or exceeded its output limit"; return 1;
        case 22: return result->error.empty();
        case 23: *error = result->error; return 1;
        case 17: return response.read(result->output);
        case 18: return response.isObject();
        case 21: *error = "authenticated enforcer returned non-object JSON"; return 1;
        default: throw std::logic_error("invalid authenticated JSON action");
        }
    });
}
UniValue BuildDrivechainBmmRequest(int sidechain_slot, uint64_t bid_sats, int64_t parent_height,
    const uint256& critical_hash, const uint256& previous_parent_hash)
{
    using Layout = drivechain::haskell::EventLayoutKind;
    const auto object = [](Layout layout, const std::vector<UniValue>& values) {
        UniValue result(UniValue::VOBJ);
        drivechain::AppendEvent(result, layout, [&](uint32_t index) { return values.at(index); });
        return result;
    };
    // uint64 wrapper values are strings in canonical protobuf JSON.
    return object(Layout::BMM_REQUEST,{UniValue(sidechain_slot),UniValue(std::to_string(bid_sats)),
        UniValue(parent_height),object(Layout::HEX,{UniValue(critical_hash.GetHex())}),
        object(Layout::HEX,{UniValue(previous_parent_hash.GetHex())})});
}

bool SubmitDrivechainBmmBid(
    const int sidechain_slot,
    const uint64_t bid_sats,
    const uint32_t parent_height,
    const uint256& critical_hash,
    const uint256& previous_parent_hash,
    uint256& request_txid,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        namespace hs = drivechain::haskell;
        UniValue response;
        return hs::ParentReplayAll<3>({[&] {
        return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_BID_PREFLIGHT, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: return hs::ParentReplayRecord(hs::ReplayRecordKind::HEIGHT, 0, 0, static_cast<uint64_t>(sidechain_slot), 255);
            case 2: throw std::runtime_error("BMM sidechain slot is outside uint8 range");
            case 3: return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, bid_sats, 0);
            case 4: return !hs::ParentReplayRecord(hs::ReplayRecordKind::LESS, 0, 0, MAX_MONEY, bid_sats);
            case 5: throw std::runtime_error("BMM bid must be positive and within the money range");
            case 6: return hs::ParentReplayRecord(hs::ReplayRecordKind::POSITIVE, 0, 0, parent_height, 0);
            case 7: return !critical_hash.IsNull();
            case 8: return !previous_parent_hash.IsNull();
            case 9: throw std::runtime_error("BMM bid identity is incomplete");
            default: throw std::logic_error("invalid BMM bid preflight action");
            }
        });
        }, [&] {
        const UniValue request = BuildDrivechainBmmRequest(sidechain_slot,bid_sats,parent_height,critical_hash,previous_parent_hash);
        return CallAuthenticatedDrivechainJSON(
                GetDrivechainGrpcAddress(gArgs),
                "cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction",
                request,
                response,
                error);
        }, [&] {
        const UniValue* txid_value{nullptr};
        const UniValue* hex{nullptr};
        return hs::ParentReplayStore(hs::ReplayStoreFlow::BMM_BID_TXID, [&](uint32_t step) -> uint32_t {
            switch (step) {
            case 1: txid_value = &response.get_obj()["txid"]; return 1;
            case 2: return txid_value->isObject();
            case 3: throw std::runtime_error("BMM wallet response has no transaction id");
            case 4: hex = &txid_value->get_obj()["hex"]; return 1;
            case 5: return hex->isStr();
            case 6: return IsHex(hex->get_str());
            case 7: return hex->get_str().size() == drivechain::PARENT_HASH_HEX_LENGTH;
            case 8: throw std::runtime_error("BMM wallet returned a malformed transaction id");
            case 9: request_txid = uint256S(hex->get_str()); return 1;
            default: throw std::logic_error("invalid BMM bid transaction id action");
            }
        });
        }});
    });
}

static UniValue CallMainChainHexRPC(const std::string& method, const UniValue& params, const char* malformed)
{
    UniValue result = CallMainChainRPCChecked(method, params);
    if (!drivechain::IsHexField(result)) throw std::runtime_error(malformed);
    return result;
}

static UniValue CallMainChainTransactionHex(bool proof, const std::string& txid,
    const std::string& block_hash, const char* malformed)
{
    UniValue params(UniValue::VARR);
    if (proof) {
        UniValue txids(UniValue::VARR);
        txids.push_back(txid);
        params.push_back(txids);
    } else {
        params.push_back(txid);
        params.push_back(false);
    }
    params.push_back(block_hash);
    return CallMainChainHexRPC(proof ? "gettxoutproof" : "getrawtransaction",params,malformed);
}

static std::string CallMainChainBlockHash(int64_t height)
{
    UniValue params(UniValue::VARR);
    params.push_back(height);
    return CallMainChainRPCChecked("getblockhash", params).get_str();
}

static const UniValue& FindField(const UniValue& obj, const std::string& lower_camel, const std::string& snake_case)
{
    return drivechain::FindField(obj.get_obj(), lower_camel, snake_case);
}

static bool GetDrivechainGrpcJSON(
    const std::string& method,
    const UniValue& request,
    UniValue& response,
    std::string* error)
{
    return CallAuthenticatedDrivechainJSON(
        GetDrivechainGrpcAddress(gArgs),
        "cusf.mainchain.v1.ValidatorService/" + method,
        request,
        response,
        error);
}

static bool GetDrivechainTwoWayPegDataAtTip(
    const int sidechain_slot,
    const uint256& mainchain_tip,
    UniValue& response,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        UniValue request(UniValue::VOBJ), block_hash(UniValue::VOBJ);
        using Layout = drivechain::haskell::EventLayoutKind;
        drivechain::AppendEvent(block_hash, Layout::HEX, [&](uint32_t) { return UniValue(mainchain_tip.GetHex()); });
        drivechain::AppendEvent(request, Layout::TWO_WAY_PEG_REQUEST,
            [&](uint32_t index) { return index == 0 ? UniValue(sidechain_slot) : block_hash; });
        if (!GetDrivechainGrpcJSON("GetTwoWayPegData", request, response, error)) {
            return false;
        }

        size_t block_count{0};
        size_t event_count{0};
        const UniValue& blocks = FindField(response, "blocks", "blocks");
        if (blocks.isArray()) {
            block_count = blocks.size();
            for (const UniValue& block : blocks.getValues()) {
                if (!block.isObject()) continue;
                const UniValue& block_info = FindField(block, "blockInfo", "block_info");
                if (!block_info.isObject()) continue;
                const UniValue& events = FindField(block_info, "events", "events");
                if (events.isArray()) event_count += events.size();
            }
        }
        LogPrintf("GetTwoWayPegData returned %u blocks and %u raw events for sidechain %d\n", block_count, event_count, sidechain_slot);
        return true;
    });
}

bool GetDrivechainTwoWayPegData(const int sidechain_slot, UniValue& response, std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        UniValue no_params(UniValue::VARR);
        const uint256 mainchain_tip = uint256S(CallMainChainRPCChecked("getbestblockhash", no_params).get_str());
        return GetDrivechainTwoWayPegDataAtTip(sidechain_slot, mainchain_tip, response, error);
    });
}

static drivechain::DepositIdentity ConfiguredDepositIdentity()
{
    drivechain::DepositIdentity identity;
    identity.sidechain_slot = gArgs.GetIntArg("-drivechainbmmslot", drivechain::HISTORICAL_DEPOSIT_SLOT);
    identity.sidechain_network = gArgs.GetArg("-drivechainsidechainnetwork", drivechain::HISTORICAL_DEPOSIT_SIDECHAIN_NETWORK);
    identity.mainchain_network = gArgs.GetArg("-drivechainmainchainnetwork", drivechain::HISTORICAL_DEPOSIT_MAINCHAIN_NETWORK);
    identity.mainchain_signet_challenge = ToLower(gArgs.GetArg(
        "-drivechainmainchainsignetchallenge",
        drivechain::HISTORICAL_DEPOSIT_SIGNET_CHALLENGE));
    identity.enforcer_network = gArgs.GetArg("-drivechainenforcernetwork", drivechain::HISTORICAL_DEPOSIT_ENFORCER_NETWORK);
    identity.mainchain_genesis = Params().ParentGenesisBlockHash();
    identity.title = gArgs.GetArg("-drivechainsidechaintitle", drivechain::HISTORICAL_DEPOSIT_TITLE);
    identity.hash_id_1 = ToLower(gArgs.GetArg(
        "-drivechainsidechainhashid1",
        drivechain::HISTORICAL_DEPOSIT_HASH_ID_1));
    identity.hash_id_2 = ToLower(gArgs.GetArg(
        "-drivechainsidechainhashid2",
        drivechain::HISTORICAL_DEPOSIT_HASH_ID_2));
    return identity;
}

bool VerifyDrivechainDeposit(
    const CTransaction& tx,
    const size_t input_index,
    drivechain::AuthenticatedDeposit* authenticated_out,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        namespace hs = drivechain::haskell;
        CAmount value{0};
        CScript claim_script;
        uint256 mainchain_txid, mainchain_genesis, mainchain_tip;
        UniValue mainchain_info, enforcer_chain_info, enforcer_tip, sidechains, ctip, two_way_peg_data;
        std::optional<drivechain::DepositIdentity> identity;
        drivechain::AuthenticatedDeposit authenticated;
        std::string lookup_error, verify_error;
        hs::DepositVerify(input_index, tx.vin.size(), tx.witness.vtxinwit.size(), [&](uint32_t stage) {
        switch (stage) {
        case 1:
        return GetDrivechainDepositPeginData(
                tx.witness.vtxinwit[input_index].m_pegin_witness,
                tx.vin[input_index].prevout,
                value,
                claim_script,
                mainchain_txid);
        case 2: {
        UniValue no_params(UniValue::VARR);
        mainchain_info = CallMainChainRPCChecked("getblockchaininfo", no_params);
        UniValue genesis_params(UniValue::VARR);
        genesis_params.push_back(0);
        mainchain_genesis = uint256S(CallMainChainRPCChecked("getblockhash", genesis_params).get_str());
        mainchain_tip = uint256S(mainchain_info.get_obj()["bestblockhash"].get_str());
        return true;
        }
        case 3: case 4: case 5: {
        static constexpr const char* methods[]{"GetChainInfo", "GetChainTip", "GetSidechains"};
        UniValue* replies[]{&enforcer_chain_info, &enforcer_tip, &sidechains};
        return GetDrivechainGrpcJSON(methods[stage-3], UniValue(UniValue::VOBJ), *replies[stage-3], &lookup_error);
        }
        case 6: {
        identity = ConfiguredDepositIdentity();
        UniValue ctip_request(UniValue::VOBJ);
        ctip_request.pushKV("sidechainNumber", identity->sidechain_slot);
        return GetDrivechainGrpcJSON("GetCtip", ctip_request, ctip, &lookup_error);
        }
        case 7:
        return GetDrivechainTwoWayPegDataAtTip(
                identity->sidechain_slot,
                mainchain_tip,
                two_way_peg_data,
                &lookup_error);
        case 8:
        return drivechain::AuthenticateDepositEvidence(
                mainchain_info,
                mainchain_genesis,
                enforcer_chain_info,
                enforcer_tip,
                sidechains,
                two_way_peg_data,
                ctip,
                Params().NetworkIDString(),
                *identity,
                tx.vin[input_index].prevout,
                value,
                authenticated,
                verify_error);
        case 9: {
        UniValue block_params(UniValue::VARR);
        block_params.push_back(authenticated.confirmation_block.GetHex());
        block_params.push_back(true);
        const UniValue block_header = CallMainChainRPCChecked("getblockheader", block_params);
        return drivechain::VerifyDepositBlockConfirmation(block_header, authenticated, verify_error);
        }
        case 10: {
        UniValue ctip_params(UniValue::VARR);
        ctip_params.push_back(authenticated.current_ctip.hash.GetHex());
        ctip_params.push_back(static_cast<int64_t>(authenticated.current_ctip.n));
        ctip_params.push_back(false);
        const UniValue ctip_txout = CallMainChainRPCChecked("gettxout", ctip_params);
        return drivechain::VerifyCurrentCtipOutput(ctip_txout, authenticated, verify_error);
        }
        case 11:
        return drivechain::VerifyDepositTransaction(tx, input_index, authenticated, verify_error);
        case 12:
        if (authenticated_out) {
            *authenticated_out = std::move(authenticated);
        }
        return true;
        case 13: throw std::runtime_error("transaction input is not a valid drivechain deposit witness");
        case 14: throw std::runtime_error("unable to obtain enforcer chain identity: " + lookup_error);
        case 15: throw std::runtime_error("unable to obtain current CTIP state: " + lookup_error);
        case 16: throw std::runtime_error("unable to obtain confirmed two-way-peg data: " + lookup_error);
        case 17: throw std::runtime_error(verify_error);
        default: throw std::logic_error("Invalid Haskell live deposit stage");
        }
        });
        return true;
    });
}

bool BuildDrivechainDepositEvidence(
    const drivechain::AuthenticatedDeposit& authenticated,
    DrivechainDepositEvidence& evidence,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        std::optional<Sidechain::Bitcoin::CMutableTransaction> deposit_tx;
        bool fully_decoded{false};
        const uint32_t flags = unsigned{!authenticated.outpoint.hash.IsNull()} |
            (unsigned{!authenticated.confirmation_block.IsNull()} << 1);
        drivechain::haskell::DepositBuild(authenticated.sequence_number, authenticated.confirmation_height, flags, [&](uint32_t build_stage) {
        switch (build_stage) {
        case 1: {
        const UniValue raw_result = CallMainChainTransactionHex(false,
            authenticated.outpoint.hash.GetHex(),authenticated.confirmation_block.GetHex(),
            "getrawtransaction returned malformed deposit transaction hex");
        evidence.deposit_tx = ParseHex(raw_result.get_str());

        deposit_tx.emplace();
        {
            DataStream stream{evidence.deposit_tx};
            stream >> TX_WITH_WITNESS(*deposit_tx);
            fully_decoded = stream.empty();
        }
        return true;
        }
        case 5: return fully_decoded;
        case 6: return deposit_tx->GetHash() == authenticated.outpoint.hash;
        case 7: return authenticated.outpoint.n < deposit_tx->vout.size();
        case 8: throw std::runtime_error("L1 deposit transaction does not contain the authenticated outpoint");
        case 2: {
        const UniValue proof_result = CallMainChainTransactionHex(true,
            authenticated.outpoint.hash.GetHex(),authenticated.confirmation_block.GetHex(),
            "gettxoutproof returned malformed proof hex");
        evidence.txout_proof = ParseHex(proof_result.get_str());
        return true;
        }
        case 3: {
        std::optional<std::vector<unsigned char>> previous_ctip;
        std::vector<unsigned char> candidate;
        UniValue previous_result;
        Sidechain::Bitcoin::CMutableTransaction previous_tx;
        drivechain::haskell::DepositCtipSearch(deposit_tx->vin.size(), [&](uint32_t stage, uint64_t index) -> int32_t {
            if (stage < 1 || stage > 5) throw std::logic_error("Invalid Haskell CTIP search stage");
            try {
                const auto& input = deposit_tx->vin.at(index);
                switch (stage) {
                case 1: {
                UniValue previous_params(UniValue::VARR);
                previous_params.push_back(input.prevout.hash.GetHex());
                previous_params.push_back(false);
                previous_result = CallMainChainRPCChecked("getrawtransaction", previous_params);
                return drivechain::IsHexField(previous_result);
                }
                case 2: previous_ctip = candidate; return 1;
                case 3: {
                candidate = ParseHex(previous_result.get_str());
                previous_tx = {};
                DataStream stream{candidate};
                stream >> TX_WITH_WITNESS(previous_tx);
                return stream.empty();
                }
                case 4: return input.prevout.n < previous_tx.vout.size();
                // Historical ECX v2 evidence requires NOP5, not native Betanet's opcode.
                case 5: return drivechain::IsTreasuryScript(previous_tx.vout[input.prevout.n].scriptPubKey,
                    drivechain::TreasuryOpcode::NOP5, authenticated.sidechain_slot);
                }
            } catch (const std::runtime_error& exception) {
                if (drivechain::haskell::DepositMessageMatches(2, exception.what())) throw;
            } catch (...) {
            }
            return 0;
        });
        evidence.previous_ctip_tx = std::move(*previous_ctip);
        evidence.sequence_number = authenticated.sequence_number;
        evidence.previous_sequence_number = drivechain::haskell::PreviousDepositSequence(authenticated.sequence_number);
        return true;
        }
        case 4: {
        UniValue chain_info_params(UniValue::VARR);
        const UniValue chain_info = CallMainChainRPCChecked("getblockchaininfo", chain_info_params);
        const int64_t tip_height = chain_info.get_obj()["blocks"].getInt<int64_t>();
        Sidechain::Bitcoin::CBlockHeader header;
        drivechain::haskell::DepositHeaders(authenticated.confirmation_height, tip_height, [&](uint32_t stage, uint64_t height) {
            if (stage == 1) { evidence.headers.clear(); return true; }
            if (stage == 3) throw std::runtime_error("serialized L1 header contains trailing data");
            if (stage == 4) { evidence.headers.push_back(header); return true; }
            if (stage != 2) throw std::logic_error("Invalid Haskell deposit header stage");
            const std::string hash = CallMainChainBlockHash(static_cast<int64_t>(height));
            UniValue header_params(UniValue::VARR);
            header_params.push_back(hash);
            header_params.push_back(false);
            const UniValue header_result = CallMainChainHexRPC("getblockheader", header_params,
                "getblockheader returned malformed serialized header");
            const std::vector<unsigned char> header_bytes = ParseHex(header_result.get_str());
            header = {};
            DataStream stream{header_bytes};
            stream >> header;
            return stream.empty();
        });
        return true;
        }
        default: throw std::logic_error("Invalid Haskell deposit build stage");
        }
        });
        return true;
    });
}

bool BuildDrivechainBmmProof(
    const drivechain::BmmL1State& previous_state,
    const int64_t parent_height,
    const uint256& parent_hash,
    const uint256& critical_hash,
    drivechain::BmmProof& proof,
    std::string* error)
{
    return CatchParentError(error, [&]() -> bool {
        std::string verify_error;
        uint256 block_hash;
        UniValue block;
        const UniValue* transactions{nullptr};
        drivechain::haskell::BmmProofBuild(previous_state.height, parent_height, [&](uint32_t stage, uint64_t height) {
        switch (stage) {
        case 1: {
        const uint256 active_anchor{uint256S(CallMainChainBlockHash(static_cast<int64_t>(previous_state.height)))};
        return active_anchor == previous_state.block_hash;
        }
        case 6:
            throw std::runtime_error(strprintf(
                "authenticated BMM anchor %s at height %u is not on the active L1 chain",
                previous_state.block_hash.GetHex(),
                previous_state.height));
        case 2: {
        const uint256 active_parent{uint256S(CallMainChainBlockHash(parent_height))};
        return active_parent == parent_hash;
        }
        case 7:
            throw std::runtime_error("sidechain parent commitment is no longer the active L1 block");
        case 3:
        proof = drivechain::BmmProof{};
        proof.previous_state = previous_state;
        return true;
        case 4: {
            block_hash = uint256S(CallMainChainBlockHash(static_cast<int64_t>(height)));

            UniValue block_params(UniValue::VARR);
            block_params.push_back(block_hash.GetHex());
            block_params.push_back(1);
            block = CallMainChainRPCChecked("getblock", block_params);
            transactions = &block.get_obj()["tx"];
            return true;
        }
        case 9: return transactions->isArray();
        case 10: return !transactions->empty();
        case 11: return (*transactions)[0].isStr();
        case 13: throw std::runtime_error("getblock returned no parent-chain coinbase txid");
        case 12: {
            const std::string coinbase_txid = (*transactions)[0].get_str();

            const UniValue raw = CallMainChainTransactionHex(false,coinbase_txid,block_hash.GetHex(),
                "getrawtransaction returned malformed coinbase hex");

            const UniValue merkle = CallMainChainTransactionHex(true,coinbase_txid,block_hash.GetHex(),
                "gettxoutproof returned malformed coinbase proof hex");
            proof.entries.push_back({
                ParseHex(raw.get_str()),
                ParseHex(merkle.get_str())});
            return true;
        }
        case 5: {
        drivechain::BmmL1State next_state;
        return drivechain::VerifyBmmProofEntries(
                proof,
                critical_hash,
                parent_hash,
                next_state,
                verify_error,
                drivechain::LayerTwoLabsBmmConsensus());
        }
        case 8:
            throw std::runtime_error(
                "constructed BMM successor proof failed self-verification: " +
                verify_error);
        default: throw std::logic_error("Invalid Haskell BMM proof build stage");
        }
        });
        return true;
    });
}
