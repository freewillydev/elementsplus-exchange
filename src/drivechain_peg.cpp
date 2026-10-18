// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_peg.h>
#include <drivechain_treasury.h>
#include <haskell/bridge.h>
#include <haskell/bmm_constants.h>

#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <key_io.h>
#include <pegins.h>
#include <primitives/bitcoin/merkleblock.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/solver.h>
#include <streams.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace drivechain {
void AppendEvent(UniValue& event, haskell::EventLayoutKind kind,
    const std::function<UniValue(uint32_t)>& read, uint32_t status)
{
    haskell::EventFields(kind, status, [&](uint32_t index, std::string_view key, std::optional<std::string_view> literal) {
        auto value = literal ? UniValue(std::string(*literal)) : read(index);
        event.pushKV(std::string(key), std::move(value));
    });
}

namespace {

template <typename Action>
bool TranslatePegError(std::string& error, Action&& action)
{
    try {
        return action();
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

const COutPoint CTIP_STATE_OUTPOINT{
    Txid::FromUint256(uint256S(CTIP_STATE_HASH)), CTIP_STATE_INDEX};
const std::vector<unsigned char> CTIP_STATE_MARKER{
    std::begin(CTIP_MARKER_BYTES), std::end(CTIP_MARKER_BYTES)};

// Historical ECX CTIP bootstraps are immutable checkpoints below. Native
// Elements deposits use authenticated parent replay and its frozen bootstrap.

// Readers run between interpreter calls and may invoke nested schema validation.
template <typename Reader>
void CheckLiveEvidence(haskell::LiveEvidencePhase phase, Reader&& read)
{
    struct Context { Reader& read; std::exception_ptr failure; } context{read, {}};
    const auto adapter = +[](void* opaque, uint32_t step, int64_t* fields) -> int32_t {
        auto& context = *static_cast<Context*>(opaque);
        try {
            std::fill_n(fields, 4, 0);
            return context.read(step, fields) ? 1 : -1;
        } catch (...) { context.failure = std::current_exception(); return 0; }
    };
    std::string error;
    const bool valid = haskell::LiveEvidence(phase, adapter, &context, "upstream peg field parsing failed", error);
    // Preserve even non-std RPC exceptions, but only rethrow after leaving the FFI.
    if (context.failure) std::rethrow_exception(context.failure);
    if (!valid) throw std::runtime_error(error);
}

template <typename T>
bool DeserializeExactly(const std::vector<unsigned char>& bytes, T& value)
{
    try {
        DataStream stream{bytes};
        stream >> TX_WITH_WITNESS(value);
        return stream.empty();
    } catch (...) {
        return false;
    }
}

bool IsSlot24CtipScript(const CScript& script)
{
    // Historical v2 evidence predates Betanet. Its authenticated transactions
    // must retain their original opcode even in a Betanet-capable binary.
    return IsTreasuryScript(script, TreasuryOpcode::NOP5, DRIVECHAIN_SIDECHAIN_SLOT);
}

bool ExtractDepositDestination(
    const Sidechain::Bitcoin::CMutableTransaction& deposit_tx,
    std::string& address,
    CScript& destination_script,
    std::string& error)
{
    struct Scan {
        const Sidechain::Bitcoin::CMutableTransaction& transaction;
        uint32_t index{0};
        std::vector<unsigned char> data;
        std::string address;
        CScript script;
        CScript::const_iterator cursor;
        std::string candidate;
        CTxDestination destination;
    } scan{deposit_tx, 0, {}, {}, {}, {}, {}, {}};
    const auto inspect = +[](void* opaque, uint32_t index, uint32_t action) -> int32_t {
        auto& scan = *static_cast<Scan*>(opaque);
        try {
            if (action == 0) {
                const auto& script = scan.transaction.vout.at(index).scriptPubKey;
                scan.cursor = script.begin();
                scan.index = index;
                opcodetype opcode;
                return script.GetOp(scan.cursor, opcode, scan.data) ? static_cast<int32_t>(opcode) : 256;
            }
            if (index != scan.index) return -1;
            switch (action) {
            case 1: {
                const auto& script = scan.transaction.vout.at(index).scriptPubKey;
                opcodetype opcode;
                const bool read = script.GetOp(scan.cursor, opcode, scan.data);
                return (read ? static_cast<int32_t>(opcode) : 256) |
                    ((!scan.data.empty()) << 9) | ((scan.cursor == script.end()) << 10);
            }
            case 2:
                scan.candidate.assign(scan.data.begin(), scan.data.end());
                scan.destination = DecodeDestination(scan.candidate);
                return IsValidDestination(scan.destination);
            case 3:
                scan.address = scan.candidate;
                scan.script = GetScriptForDestination(scan.destination);
                return 1;
            default: return -1;
            }
        } catch (...) { return -1; }
    };
    if (!haskell::DepositDestination(deposit_tx.vout.size(), inspect, &scan, error)) return false;
    address = std::move(scan.address);
    destination_script = std::move(scan.script);
    return true;
}

struct ParsedDeterministicDeposit
{
    AuthenticatedDeposit authenticated;
    CtipState previous_state;
    CtipState next_state;
    uint256 anchor;
};

bool ParseV2Deposit(
    const CTransaction& tx,
    size_t input_index,
    ParsedDeterministicDeposit& parsed,
    std::string& error)
{
    using Step = haskell::DepositVerifyStep;
    DrivechainDepositEvidence evidence;
    Sidechain::Bitcoin::CMutableTransaction deposit_tx;
    Sidechain::Bitcoin::CMutableTransaction previous_tx;
    Sidechain::Bitcoin::CMerkleBlock proof;
    uint256 previous_txid;
    size_t matching_inputs{0};
    uint32_t previous_vout{0};
    CAmount previous_value{0}, witness_value{0};
    bool decoded{false};
    std::string address;
    CScript destination_script;
    return haskell::RunDepositParsing([&](Step step) {
        switch (step) {
        case Step::INPUT_BOUNDS: return input_index < tx.vin.size();
        case Step::WITNESS_BOUNDS: return input_index < tx.witness.vtxinwit.size();
        case Step::REJECT_INDEX:
            error = "drivechain deposit input index is out of range";
            return false;
        case Step::READ_EVIDENCE:
            return GetDrivechainDepositEvidence(tx.witness.vtxinwit[input_index].m_pegin_witness,
                tx.vin[input_index].prevout, evidence, error);
        case Step::DECODE_DEPOSIT: return DeserializeExactly(evidence.deposit_tx, deposit_tx);
        case Step::DECODE_PREVIOUS: return DeserializeExactly(evidence.previous_ctip_tx, previous_tx);
        case Step::DECODE_PROOF: return DeserializeExactly(evidence.txout_proof, proof);
        case Step::REJECT_ENCODING:
            error = "drivechain deposit evidence contains malformed transaction or merkle proof data";
            return false;
        case Step::INCLUSION: {
            const uint256 deposit_txid = deposit_tx.GetHash();
            std::vector<uint256> proof_matches;
            std::vector<unsigned int> proof_indices;
            const bool root_matches = proof.txn.ExtractMatches(proof_matches, proof_indices) == proof.header.hashMerkleRoot;
            const uint32_t inclusion_facts =
                (deposit_txid == tx.vin[input_index].prevout.hash && tx.vin[input_index].prevout.n < deposit_tx.vout.size()) |
                (root_matches << 1) | ((!proof_matches.empty() && proof_matches[0] == deposit_txid) << 2) |
                ((evidence.headers.front().GetHash() == proof.header.GetHash()) << 3);
            const auto check_header = +[](void* opaque, uint32_t index) -> int32_t {
                try {
                    const auto& headers = static_cast<DrivechainDepositEvidence*>(opaque)->headers;
                    const auto& header = headers.at(index);
                    return CheckParentProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus()) |
                        ((index == 0 || header.hashPrevBlock == headers.at(index - 1).GetHash()) << 1);
                } catch (...) { return -1; }
            };
            return haskell::DepositInclusion(inclusion_facts, proof_matches.size(), evidence.headers.size(),
                check_header, &evidence, error);
        }
        case Step::SET_ANCHOR:
            parsed.anchor = evidence.headers.back().GetHash();
            return true;
        case Step::FIND_PREVIOUS: {
            previous_txid = previous_tx.GetHash();
            size_t index{0};
            haskell::RunCtipInputScan([&](Step scan) {
                switch (scan) {
                case Step::SCAN_BOUNDS: return index < deposit_tx.vin.size();
                case Step::SCAN_HASH: return deposit_tx.vin[index].prevout.hash == previous_txid;
                case Step::SCAN_OUTPUT_BOUNDS: return deposit_tx.vin[index].prevout.n < previous_tx.vout.size();
                case Step::SCAN_SCRIPT: return IsSlot24CtipScript(previous_tx.vout[deposit_tx.vin[index].prevout.n].scriptPubKey);
                case Step::SCAN_MATCH:
                    ++matching_inputs;
                    previous_vout = deposit_tx.vin[index].prevout.n;
                    return true;
                case Step::SCAN_ADVANCE: ++index; return true;
                case Step::SCAN_PRESENT: return matching_inputs != 0;
                case Step::SCAN_VALUE: previous_value = previous_tx.vout[previous_vout].nValue; return true;
                case Step::SCAN_EMPTY: previous_value = 0; return true;
                default: throw std::logic_error("invalid CTIP scan action");
                }
            });
            return true;
        }
        case Step::READ_WITNESS: {
            CScript claim_script;
            uint256 witness_txid;
            decoded = GetDrivechainDepositPeginData(tx.witness.vtxinwit[input_index].m_pegin_witness,
                tx.vin[input_index].prevout, witness_value, claim_script, witness_txid);
            return true;
        }
        case Step::CTIP: {
            const auto& current_output = deposit_tx.vout[tx.vin[input_index].prevout.n];
            const uint32_t ctip_facts = IsSlot24CtipScript(current_output.scriptPubKey) | (decoded << 1);
            return haskell::DepositCtip(ctip_facts, matching_inputs, current_output.nValue,
                previous_value, witness_value, error);
        }
        case Step::DESTINATION: return ExtractDepositDestination(deposit_tx, address, destination_script, error);
        case Step::PUBLISH_PARSED:
            parsed.previous_state = {COutPoint(Txid::FromUint256(previous_txid), previous_vout),
                previous_value, evidence.previous_sequence_number};
            parsed.next_state = {tx.vin[input_index].prevout,
                deposit_tx.vout[tx.vin[input_index].prevout.n].nValue, evidence.sequence_number};
            parsed.authenticated.sidechain_slot = DRIVECHAIN_SIDECHAIN_SLOT;
            parsed.authenticated.sequence_number = evidence.sequence_number;
            parsed.authenticated.outpoint = tx.vin[input_index].prevout;
            parsed.authenticated.value = witness_value;
            parsed.authenticated.address = address;
            parsed.authenticated.destination_script = destination_script;
            parsed.authenticated.confirmation_block = proof.header.GetHash();
            parsed.authenticated.current_ctip = parsed.next_state.outpoint;
            parsed.authenticated.current_ctip_value = parsed.next_state.value;
            parsed.authenticated.current_ctip_sequence = parsed.next_state.sequence_number;
            return true;
        default: throw std::logic_error("invalid deposit parsing action");
        }
    });
}

struct LegacyCheckpoint
{
    uint256 parent_hash;
    COutPoint outpoint;
    CAmount deposit_value;
    CAmount ctip_value;
    int64_t sequence_number;
    std::string destination;
};

std::optional<LegacyCheckpoint> FindLegacyCheckpoint(const CTransaction& tx, size_t input_index)
{
    using Step = haskell::DepositVerifyStep;
    std::vector<unsigned char> record;
    std::optional<LegacyCheckpoint> checkpoint;
    haskell::RunCheckpointLookup([&](Step step) {
        switch (step) {
        case Step::LOOKUP_INPUT: return input_index < tx.vin.size();
        case Step::LOOKUP_WITNESS: return input_index < tx.witness.vtxinwit.size();
        case Step::LOOKUP_MATCH: {
            const auto& prevout = tx.vin[input_index].prevout;
            return haskell::LegacyCheckpoint(IsLegacyDrivechainDepositPeginWitness(tx.witness.vtxinwit[input_index].m_pegin_witness),
                UCharCast(tx.GetHash().begin()), UCharCast(prevout.hash.begin()), prevout.n, record);
        }
        case Step::LOOKUP_PUBLISH: {
            LegacyCheckpoint decoded;
            DataStream stream{record};
            stream >> decoded.parent_hash >> decoded.outpoint >> decoded.deposit_value >>
                decoded.ctip_value >> decoded.sequence_number >> decoded.destination;
            if (!stream.empty()) throw std::runtime_error("Haskell checkpoint record has trailing bytes");
            checkpoint = std::move(decoded);
            return true;
        }
        default: throw std::logic_error("invalid checkpoint lookup action");
        }
    });
    return checkpoint;
}

bool BuildLegacyAuthenticated(
    const CTransaction& tx,
    size_t input_index,
    const LegacyCheckpoint& checkpoint,
    AuthenticatedDeposit& authenticated,
    std::string& error)
{
    CAmount witness_value{0};
    CScript claim_script;
    uint256 witness_txid;
    bool decoded{false};
    CTxDestination destination;
    using Step = haskell::DepositVerifyStep;
    return haskell::RunLegacyClaim([&](Step step) {
        switch (step) {
        case Step::CLAIM_WITNESS:
            decoded = GetDrivechainDepositPeginData(
                tx.witness.vtxinwit[input_index].m_pegin_witness,
                tx.vin[input_index].prevout,
                witness_value,
                claim_script,
                witness_txid);
            return true;
        case Step::CLAIM_DESTINATION:
            destination = DecodeDestination(checkpoint.destination);
            return true;
        case Step::CLAIM_VERIFY:
            return haskell::LegacyClaim(decoded, IsValidDestination(destination), witness_value, checkpoint.deposit_value, error);
        case Step::CLAIM_PUBLISH:
            authenticated.sidechain_slot = DRIVECHAIN_SIDECHAIN_SLOT;
            authenticated.sequence_number = checkpoint.sequence_number;
            authenticated.outpoint = checkpoint.outpoint;
            authenticated.value = checkpoint.deposit_value;
            authenticated.address = checkpoint.destination;
            authenticated.destination_script = GetScriptForDestination(destination);
            authenticated.confirmation_block = checkpoint.parent_hash;
            authenticated.current_ctip = checkpoint.outpoint;
            authenticated.current_ctip_value = checkpoint.ctip_value;
            authenticated.current_ctip_sequence = checkpoint.sequence_number;
            return true;
        default: throw std::logic_error("invalid legacy claim action");
        }
    });
}

CScript EncodeCtipState(const CtipState& state)
{
    DataStream stream;
    CScript script;
    haskell::BmmEncodeState([&](uint32_t action, uint32_t opcode) {
        switch (action) {
        case 0: stream << CTIP_STATE_MARKER; break;
        case 1: stream << state.outpoint << state.value << state.sequence_number; break;
        case 2: script << std::vector<unsigned char>(UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()); break;
        case 3: script << static_cast<opcodetype>(opcode); break;
        default: throw std::logic_error("invalid CTIP state encoding action");
        }
    });
    return script;
}

bool DecodeCtipState(const Coin& coin, CtipState& state, std::string& error)
{
    uint32_t facts = !coin.IsSpent() | (coin.out.nAsset.IsExplicit() << 1) |
        ((coin.out.nAsset.IsExplicit() && coin.out.nAsset.GetAsset() == Params().GetConsensus().pegged_asset) << 2) |
        (coin.out.nValue.IsExplicit() << 3);
    CScript::const_iterator cursor = coin.out.scriptPubKey.begin();
    std::vector<unsigned char> data;
    const uint32_t script = haskell::CtipScript([&](uint32_t i) -> int32_t {
        opcodetype opcode;
        const bool read = i == 0 ? coin.out.scriptPubKey.GetOp(cursor, opcode, data) : coin.out.scriptPubKey.GetOp(cursor, opcode);
        return read ? static_cast<int32_t>(opcode) : 256;
    });
    facts |= (cursor == coin.out.scriptPubKey.end()) << 4;
    struct Payload { const std::vector<unsigned char>& bytes; CtipState decoded; } payload{data, {}};
    const auto decode = +[](void* opaque, int64_t* fields) -> int32_t {
        auto& payload = *static_cast<Payload*>(opaque);
        try {
            DataStream stream{payload.bytes};
            std::vector<unsigned char> marker;
            auto& decoded = payload.decoded;
            stream >> marker >> decoded.outpoint >> decoded.value >> decoded.sequence_number;
            fields[0] = decoded.value;
            fields[1] = decoded.sequence_number;
            return 8 | stream.empty() | ((marker == CTIP_STATE_MARKER) << 1) | ((!decoded.outpoint.hash.IsNull()) << 2);
        } catch (...) {
            return 0;
        }
    };
    if (!haskell::PersistedCtip(facts, coin.out.nValue.IsExplicit() ? coin.out.nValue.GetAmount() : 0,
            script, decode, &payload, error)) return false;
    state = payload.decoded;
    return true;
}

void SetCtipState(CCoinsViewCache& inputs, const CtipState& state, int height, bool restore = false)
{
    std::optional<CTxOut> output;
    haskell::BmmStoreState(height, [&](uint32_t action, uint32_t value) {
        switch (action) {
        case 0: inputs.SpendCoin(CTIP_STATE_OUTPOINT); break;
        case 1: output.emplace(Params().GetConsensus().pegged_asset, value, EncodeCtipState(state)); break;
        case 2: inputs.AddCoin(CTIP_STATE_OUTPOINT, Coin(std::move(output.value()), value, false), true); break;
        default: throw std::logic_error("invalid CTIP state storage action");
        }
    }, restore);
}

std::runtime_error FieldTypeError(const std::string& field, bool evidence, const char* type)
{
    return std::runtime_error(std::string(evidence ? "drivechain evidence field '" : "drivechain peg data field '") +
        field + "' must be " + type);
}

const UniValue& RequireTypedField(const UniValue& value, const std::string& field,
    const std::optional<std::string>& alias, UniValue::VType type, const char* name)
{
    const UniValue& result = alias ? FindField(value,field,*alias) : value[field];
    if (!haskell::PegSchema(haskell::PegSchemaKind::TYPE, 0, [&](uint32_t) { return result.getType()==type; }))
        throw FieldTypeError(field,alias.has_value(),name);
    return result;
}

const UniValue& RequireObjectField(const UniValue& value, const std::string& field,
    const std::optional<std::string>& alias = std::nullopt)
{
    return RequireTypedField(value,field,alias,UniValue::VOBJ,"an object");
}

const UniValue& RequireArrayField(const UniValue& value, const std::string& field,
    const std::optional<std::string>& alias = std::nullopt)
{
    return RequireTypedField(value,field,alias,UniValue::VARR,"an array");
}

bool ReadHexField(const UniValue& value, size_t bytes, std::string& result)
{
    if (!IsHexField(value, bytes)) return false;
    result = value.get_str();
    return true;
}

std::string RequireHexField(const UniValue& value, const std::string& field, size_t bytes = 0)
{
    std::string result;
    if (!ReadHexField(value[field], bytes, result)) {
        throw std::runtime_error("drivechain peg data field '" + field + "' must be valid hex");
    }
    return result;
}

bool ReadIntegerField(const UniValue& value, int64_t& parsed)
{
    return haskell::PegSchema(haskell::PegSchemaKind::INTEGER, 0, [&](uint32_t step) -> uint64_t {
        switch (step) {
        case 1: return value.isNum();
        case 2: parsed = value.getInt<int64_t>(); return 1;
        case 3: return value.isStr();
        case 4: return ParseInt64(value.get_str(), &parsed);
        case 5: return 1;
        default: throw std::logic_error("invalid integer field action");
        }
    });
}

int64_t RequireInt64Field(const UniValue& value, const std::string& field,
    const std::optional<std::string>& alias = std::nullopt)
{
    const UniValue& result = alias ? FindField(value,field,*alias) : value[field];
    int64_t parsed{0};
    if (ReadIntegerField(result, parsed)) return parsed;
    throw FieldTypeError(field,alias.has_value(),"an integer");
}

std::string RequireStringField(const UniValue& value, const std::string& lower_camel, const std::string& snake_case)
{
    return RequireTypedField(value,lower_camel,snake_case,UniValue::VSTR,"a string").get_str();
}

std::string RequireHexObjectField(const UniValue& value, const std::string& lower_camel, const std::string& snake_case, size_t bytes)
{
    const UniValue& object = RequireObjectField(value, lower_camel, snake_case);
    std::string hex;
    if (!ReadHexField(object["hex"], bytes, hex)) {
        throw std::runtime_error("drivechain evidence field '" + lower_camel + ".hex' must be valid hex");
    }
    return hex;
}

using Layout = haskell::EventLayoutKind;

UniValue SidechainLocation(const CBlock& block, int height)
{
    UniValue location(UniValue::VOBJ);
    AppendEvent(location, Layout::SIDECHAIN_BLOCK, [&](uint32_t index) {
        return index == 0 ? UniValue(block.GetHash().GetHex()) : UniValue(height);
    });
    return location;
}

UniValue L1Location(const UniValue& block)
{
    const UniValue* header{nullptr};
    UniValue location(UniValue::VOBJ);
    haskell::L1LocationFlow([&](uint32_t step) {
        switch (step) {
        case 1: header = &RequireObjectField(block, "blockHeaderInfo"); return true;
        case 2: AppendEvent(location, Layout::BLOCK_HASH, [&](uint32_t) { return UniValue(RequireHexField(RequireObjectField(*header, "blockHash"), "hex", 32)); }); return true;
        case 3: AppendEvent(location, Layout::HEIGHT, [&](uint32_t) { return UniValue(RequireInt64Field(*header, "height")); }); return true;
        case 4: return !(*header)["timestamp"].isNull();
        case 5: AppendEvent(location, Layout::TIMESTAMP, [&](uint32_t) { return UniValue(RequireInt64Field(*header, "timestamp")); }); return true;
        case 6: return true;
        default: throw std::logic_error("invalid L1 location action");
        }
    });
    return location;
}

int64_t WithdrawalStatusIndex(const UniValue& event)
{
    const auto& names = WITHDRAWAL_STATUSES;
    int64_t present{0}, objects{0};
    for (size_t i = 0; i < names.size(); ++i) {
        present |= int64_t(!event[names[i]].isNull()) << i;
        objects |= int64_t(event[names[i]].isObject()) << i;
    }
    return haskell::PegEvent(haskell::PegEventKind::LIFECYCLE, present, objects);
}

void VerifySidechainIdentity(
    const UniValue& sidechains,
    const DepositIdentity& expected,
    int64_t enforcer_tip_height)
{
    const UniValue *entries{nullptr}, *current{nullptr}, *match{nullptr}, *v0{nullptr};
    size_t index{0};
    CheckLiveEvidence(haskell::LiveEvidencePhase::SIDECHAIN, [&](uint32_t step, int64_t* fields) {
        switch (step) {
        case 0:
            entries = &RequireArrayField(sidechains, "sidechains", "sidechains");
            fields[0] = entries->size();
            break;
        case 1:
            if (!entries || index >= entries->size()) return false;
            current = &(*entries)[index++];
            fields[0] = current->isObject();
            haskell::ReadWhen(fields[0], [&] { fields[1] = RequireInt64Field(*current, "sidechainNumber", "sidechain_number"); });
            fields[2] = expected.sidechain_slot;
            break;
        case 2:
            if (!current) return false;
            match = current;
            break;
        case 3:
            if (!match) return false;
            fields[0] = RequireInt64Field(*match, "activationHeight", "activation_height");
            fields[1] = enforcer_tip_height;
            break;
        case 4:
            if (!match) return false;
            v0 = &RequireObjectField(RequireObjectField(*match, "declaration", "declaration"), "v0", "v0");
            fields[0] = RequireStringField(*v0, "title", "title") == expected.title;
            break;
        case 5: case 6:
            if (!v0) return false;
            fields[0] = step == 5 ? RequireHexObjectField(*v0, "hashId1", "hash_id_1", 32) == expected.hash_id_1
                                  : RequireHexObjectField(*v0, "hashId2", "hash_id_2", 20) == expected.hash_id_2;
            break;
        default: return false;
        }
        return true;
    });
}

AuthenticatedDeposit FindDeposit(
    const UniValue& two_way_peg_data,
    const DepositIdentity& expected,
    const COutPoint& expected_outpoint,
    CAmount expected_value)
{
    AuthenticatedDeposit result;
    const UniValue *blocks{nullptr}, *block{nullptr}, *events{nullptr}, *event{nullptr}, *deposit{nullptr}, *output{nullptr};
    size_t block_index{0}, event_index{0}, address_index{0};
    uint256 block_hash;
    int64_t block_height{0}, value{0}, sequence{0};
    COutPoint outpoint;
    std::string address;
    CTxDestination destination;
    CheckLiveEvidence(haskell::LiveEvidencePhase::DEPOSITS, [&](uint32_t step, int64_t* fields) {
        switch (step) {
        case 0:
            blocks = &RequireArrayField(two_way_peg_data, "blocks", "blocks");
            fields[0] = blocks->size();
            break;
        case 1:
            if (!blocks || block_index >= blocks->size()) return false;
            block = &(*blocks)[block_index++];
            fields[0] = block->isObject();
            break;
        case 2: {
            if (!block) return false;
            const auto& header = RequireObjectField(*block, "blockHeaderInfo", "block_header_info");
            block_hash = uint256S(RequireHexObjectField(header, "blockHash", "block_hash", 32));
            block_height = RequireInt64Field(header, "height", "height");
            events = &FindField(RequireObjectField(*block, "blockInfo", "block_info"), "events", "events");
            event_index = 0;
            fields[0] = events->isNull() ? 0 : events->isArray() ? 1 : 2;
            haskell::ReadWhen(events->isArray(), [&] { fields[1] = events->size(); });
            break;
        }
        case 3:
            if (!events || !events->isArray() || event_index >= events->size()) return false;
            event = &(*events)[event_index++];
            fields[0] = event->isObject();
            break;
        case 4:
            if (!event) return false;
            deposit = &FindField(*event, "deposit", "deposit");
            fields[0] = !deposit->isNull();
            fields[1] = deposit->isObject();
            break;
        case 5: {
            if (!deposit) return false;
            const auto& encoded = RequireObjectField(*deposit, "outpoint", "outpoint");
            const auto txid = uint256S(RequireHexObjectField(encoded, "txid", "txid", 32));
            fields[1] = RequireInt64Field(encoded, "vout", "vout");
            fields[0] = txid == expected_outpoint.hash && fields[1] == expected_outpoint.n;
            outpoint = COutPoint(Txid::FromUint256(txid), static_cast<uint32_t>(fields[1]));
            break;
        }
        case 6:
            if (!deposit) return false;
            output = &RequireObjectField(*deposit, "output", "output");
            value = RequireInt64Field(*output, "valueSats", "value_sats");
            sequence = RequireInt64Field(*deposit, "sequenceNumber", "sequence_number");
            fields[0] = value;
            fields[1] = expected_value;
            fields[2] = sequence;
            break;
        case 7: {
            if (!output) return false;
            const auto bytes = ParseHex(RequireHexObjectField(*output, "address", "address", 0));
            address.assign(bytes.begin(), bytes.end());
            address_index = 0;
            fields[0] = address.size();
            break;
        }
        case 9:
            if (address_index >= address.size()) return false;
            for (unsigned i = 0; i < 4 && address_index < address.size(); ++i)
                fields[i] = static_cast<unsigned char>(address[address_index++]);
            break;
        case 8:
            destination = DecodeDestination(address);
            fields[0] = IsValidDestination(destination);
            break;
        case 10:
            result.sidechain_slot = expected.sidechain_slot;
            result.sequence_number = sequence;
            result.outpoint = outpoint;
            result.value = value;
            result.address = address;
            result.destination_script = GetScriptForDestination(destination);
            result.confirmation_block = block_hash;
            result.confirmation_height = block_height;
            break;
        default: return false;
        }
        return true;
    });
    return result;
}

void VerifyCtip(const UniValue& ctip_response, AuthenticatedDeposit& authenticated)
{
    COutPoint outpoint;
    const UniValue* ctip{nullptr};
    int64_t value{0}, sequence{0};
    CheckLiveEvidence(haskell::LiveEvidencePhase::CTIP_STATE, [&](uint32_t step, int64_t* fields) {
        if (step == 0) {
            ctip = &RequireObjectField(ctip_response, "ctip", "ctip");
            const uint256 txid = uint256S(RequireHexObjectField(*ctip, "txid", "txid", 32));
            const UniValue& vout = FindField(*ctip, "vout", "vout");
            haskell::PegSchema(haskell::PegSchemaKind::NULL_DEFAULT, 0, [&](uint32_t action) -> uint64_t {
                switch (action) {
                case 1: return vout.isNull();
                case 2: fields[0] = 0; return 1;
                case 3: fields[0] = RequireInt64Field(*ctip, "vout", "vout"); return 1;
                default: throw std::logic_error("invalid CTIP default action");
                }
            });
            outpoint = COutPoint(Txid::FromUint256(txid), static_cast<uint32_t>(fields[0]));
            return true;
        }
        if (step != 1 || !ctip) return false;
        value = RequireInt64Field(*ctip, "value", "value");
        sequence = RequireInt64Field(*ctip, "sequenceNumber", "sequence_number");
        fields[0] = value;
        fields[1] = sequence;
        fields[2] = authenticated.sequence_number;
        fields[3] = outpoint == authenticated.outpoint;
        return true;
    });
    authenticated.current_ctip = outpoint;
    authenticated.current_ctip_value = value;
    authenticated.current_ctip_sequence = sequence;
}

} // namespace

bool IsHexField(const UniValue& value, size_t bytes)
{
    return haskell::PegSchema(haskell::PegSchemaKind::HEX, bytes, [&](uint32_t step) -> uint64_t {
        switch (step) {
        case 1: return value.isStr();
        case 2: return IsHex(value.get_str());
        case 3: return value.get_str().size();
        case 4: return 1;
        default: throw std::logic_error("invalid hex field action");
        }
    });
}

const UniValue& FindField(const UniValue& value, const std::string& lower_camel, const std::string& snake_case)
{
    static const UniValue null_value;
    const UniValue* result{nullptr};
    haskell::PegSchema(haskell::PegSchemaKind::FIELD, 0, [&](uint32_t step) -> uint64_t {
        switch (step) {
        case 1: return value.isObject();
        case 2: result = &null_value; return 1;
        case 3: result = &value[lower_camel]; return result->isNull();
        case 4: result = &value[snake_case]; return 1;
        case 5: return 1;
        default: throw std::logic_error("invalid field lookup action");
        }
    });
    return *result;
}

UniValue ExtractSidechainPegEvents(const CBlock& block, int height, const uint256& previous_bundle_hash)
{
    UniValue events(UniValue::VARR), event;
    const uint256 block_bundle_hash = block.hashWithdrawalBundle;
    size_t transaction_index{0}, vin{0}, vout{0};
    const CTransaction* tx{nullptr};
    std::string txid;
    CAmount value{0};
    CScript claim_script, destination_script;
    uint256 mainchain_txid, genesis_hash;
    haskell::SidechainEventFlow([&](uint32_t step) {
        switch (step) {
        case 1: return !block_bundle_hash.IsNull();
        case 2: return block_bundle_hash != previous_bundle_hash;
        case 3: {
            UniValue event(UniValue::VOBJ);
            AppendEvent(event, Layout::BUNDLE, [&](uint32_t field) -> UniValue {
                switch (field) {
                case 0: return UniValue(haskell::EventIdentity(haskell::EventIdentityKind::BUNDLE, block_bundle_hash.GetHex(), height));
                case 4: return UniValue(block_bundle_hash.GetHex());
                case 5: return SidechainLocation(block, height);
                default: throw std::logic_error("invalid bundle event field");
                }
            });
            events.push_back(event);
            return true;
        }
        case 4: return transaction_index < block.vtx.size();
        case 5:
            tx = block.vtx[transaction_index].get();
            txid = tx->GetHash().GetHex();
            vin = vout = 0;
            return true;
        case 6: return vin < tx->vin.size();
        case 7: return vin < tx->witness.vtxinwit.size();
        case 8:
            value = 0;
            claim_script.clear();
            mainchain_txid.SetNull();
            return GetDrivechainDepositPeginData(tx->witness.vtxinwit[vin].m_pegin_witness,
                tx->vin[vin].prevout, value, claim_script, mainchain_txid);
        case 9: {
            UniValue event(UniValue::VOBJ);
            AppendEvent(event, Layout::DEPOSIT, [&](uint32_t field) -> UniValue {
                switch (field) {
                case 0: return UniValue(haskell::EventIdentity(haskell::EventIdentityKind::DEPOSIT, txid, vin));
                case 4: return UniValue(txid);
                case 5: return UniValue(static_cast<uint64_t>(vin));
                case 6: return UniValue(mainchain_txid.GetHex());
                case 7: return UniValue(static_cast<uint64_t>(tx->vin[vin].prevout.n));
                case 8: return UniValue(value);
                case 9: return UniValue(Params().GetConsensus().pegged_asset.GetHex());
                case 10: return UniValue(HexStr(claim_script));
                case 11: return SidechainLocation(block, height);
                default: throw std::logic_error("invalid deposit event field");
                }
            });
            events.push_back(event);
            return true;
        }
        case 10: ++vin; return true;
        case 11: return vout < tx->vout.size();
        case 12:
            genesis_hash.SetNull();
            destination_script.clear();
            return tx->vout[vout].scriptPubKey.IsPegoutScript(genesis_hash, destination_script);
        case 13: return genesis_hash == Params().ParentGenesisBlockHash();
        case 14: return tx->vout[vout].nAsset.IsExplicit();
        case 15: return tx->vout[vout].nAsset.GetAsset() == Params().GetConsensus().pegged_asset;
        case 16: return tx->vout[vout].nValue.IsExplicit();
        case 17: {
            const auto& output = tx->vout[vout];
            event = UniValue(UniValue::VOBJ);
            AppendEvent(event, Layout::WITHDRAWAL, [&](uint32_t field) -> UniValue {
                switch (field) {
                case 0: return UniValue(haskell::EventIdentity(haskell::EventIdentityKind::WITHDRAWAL, txid, vout));
                case 4: return UniValue(txid);
                case 5: return UniValue(static_cast<uint64_t>(vout));
                case 6: return UniValue(output.nValue.GetAmount());
                case 7: return UniValue(output.nAsset.GetAsset().GetHex());
                case 8: return UniValue(genesis_hash.GetHex());
                case 9: return UniValue(HexStr(destination_script));
                default: throw std::logic_error("invalid withdrawal event field");
                }
            });
            return true;
        }
        case 18: return !block_bundle_hash.IsNull();
        case 19: AppendEvent(event, Layout::BUNDLE_ID, [&](uint32_t) { return UniValue(block_bundle_hash.GetHex()); }); return true;
        case 20:
            AppendEvent(event, Layout::SIDECHAIN, [&](uint32_t) { return SidechainLocation(block, height); });
            events.push_back(event);
            return true;
        case 25: ++vout; return true;
        case 26: ++transaction_index; return true;
        case 27: return true;
        default: throw std::logic_error("invalid sidechain event action");
        }
    });
    return events;
}

UniValue NormalizeL1PegEvents(const UniValue& two_way_peg_data, int sidechain_id)
{
    UniValue result(UniValue::VARR), location, event;
    std::map<std::string, std::string> event_payloads;
    std::map<std::string, std::string>::iterator existing;
    const UniValue *blocks{nullptr}, *raw_events{nullptr}, *details{nullptr};
    size_t block_index{0}, event_index{0};
    int64_t height{0}, status_index{0};
    std::string event_id, status, payload;
    haskell::L1NormalizationFlow([&](uint32_t step) {
        switch (step) {
        case 1: return two_way_peg_data.isObject();
        case 2: blocks = &RequireArrayField(two_way_peg_data, "blocks"); return true;
        case 3: throw std::runtime_error("GetTwoWayPegData response must be an object");
        case 4: return block_index < blocks->size();
        case 5: return (*blocks)[block_index].isObject();
        case 6: {
            const auto& block = (*blocks)[block_index];
            location = L1Location(block);
            height = location["height"].getInt<int64_t>();
            raw_events = &RequireObjectField(block, "blockInfo")["events"];
            return true;
        }
        case 7: throw std::runtime_error("GetTwoWayPegData block must be an object");
        case 8: return raw_events->isNull();
        case 9: return raw_events->isArray();
        case 10: event_index = 0; return true;
        case 11: throw std::runtime_error("drivechain peg data field 'events' must be an array");
        case 12: return event_index < raw_events->size();
        case 13: return (*raw_events)[event_index].isObject();
        case 14:
            event = UniValue(UniValue::VOBJ);
            event_id.clear();
            return (*raw_events)[event_index]["deposit"].isObject();
        case 15: throw std::runtime_error("GetTwoWayPegData event must be an object");
        case 16: {
            const auto& raw_event = (*raw_events)[event_index];
            const UniValue& deposit = raw_event["deposit"];
            const UniValue& outpoint = RequireObjectField(deposit, "outpoint");
            const std::string txid = RequireHexField(RequireObjectField(outpoint, "txid"), "hex", 32);
            const int64_t vout = RequireInt64Field(outpoint, "vout");
            const UniValue& output = RequireObjectField(deposit, "output");
            const int64_t sequence = RequireInt64Field(deposit, "sequenceNumber");
            const int64_t value_sats = RequireInt64Field(output, "valueSats");
            haskell::PegEvent(haskell::PegEventKind::DEPOSIT_NUMBERS, vout, value_sats, sequence);

            event_id = haskell::EventIdentity(haskell::EventIdentityKind::L1_DEPOSIT, txid, vout);
            AppendEvent(event, Layout::L1_DEPOSIT, [&](uint32_t field) -> UniValue {
                switch (field) {
                case 0: return UniValue(event_id);
                case 4: return UniValue(sidechain_id);
                case 5: return UniValue(sequence);
                case 6: return UniValue(txid);
                case 7: return UniValue(vout);
                case 8: return UniValue(RequireHexField(RequireObjectField(output, "address"), "hex"));
                case 9: return UniValue(value_sats);
                default: throw std::logic_error("invalid L1 deposit field");
                }
            });
            return true;
        }
        case 17: return (*raw_events)[event_index]["withdrawalBundle"].isObject();
        case 18: {
            const auto& raw_event = (*raw_events)[event_index];
            const UniValue& withdrawal = raw_event["withdrawalBundle"];
            const std::string m6id = RequireHexField(RequireObjectField(withdrawal, "m6id"), "hex", 32);
            const UniValue& lifecycle = RequireObjectField(withdrawal, "event");
            status_index = WithdrawalStatusIndex(lifecycle);
            status = WITHDRAWAL_STATUSES.at(status_index);

            event_id = haskell::EventIdentity(haskell::EventIdentityKind::L1_WITHDRAWAL, m6id, height, status_index);
            AppendEvent(event, Layout::L1_WITHDRAWAL, [&](uint32_t field) -> UniValue {
                switch (field) {
                case 0: return UniValue(event_id);
                case 4: return UniValue(sidechain_id);
                case 5: return UniValue(m6id);
                default: throw std::logic_error("invalid L1 withdrawal field");
                }
            }, status_index);
            details = &lifecycle[status];
            return true;
        }
        case 19: return !(*details)["sequenceNumber"].isNull();
        case 20: AppendEvent(event, Layout::SEQUENCE, [&](uint32_t) { return UniValue(RequireInt64Field(*details, "sequenceNumber")); }); return true;
        case 21: return !(*details)["transaction"].isNull();
        case 22:
            AppendEvent(event, Layout::TRANSACTION, [&](uint32_t) { return UniValue(RequireHexField(RequireObjectField(*details, "transaction"), "hex")); });
            return true;
        case 23:
            AppendEvent(event, Layout::ACKNOWLEDGEMENT, {}, status_index);
            return true;
        case 27: AppendEvent(event, Layout::L1, [&](uint32_t) { return location; }); return true;
        case 28: {
            payload = event.write();
            const auto [it, inserted] = event_payloads.emplace(event_id, payload);
            existing = it;
            return inserted;
        }
        case 29: result.push_back(event); return true;
        case 30: return existing->second == payload;
        case 31: ++event_index; return true;
        case 32: ++block_index; return true;
        case 33: throw std::runtime_error("conflicting drivechain peg events share event_id '" + event_id + "'");
        case 34: return true;
        default: throw std::logic_error("invalid L1 normalization action");
        }
    });
    return result;
}

std::string GetWithdrawalBundleStatus(
    const UniValue& two_way_peg_data,
    const int sidechain_id,
    const uint256& m6id)
{
    int64_t state{0};
    UniValue events;
    size_t index{0};
    std::string event_m6id_hex, result;
    haskell::WithdrawalStatusFlow([&](uint32_t step) {
        switch (step) {
        case 1: return !m6id.IsNull();
        case 2: events = NormalizeL1PegEvents(two_way_peg_data, sidechain_id); return true;
        case 3: throw std::runtime_error("withdrawal bundle id must not be null");
        case 4: return index < events.size();
        case 5: return events[index].isObject();
        case 6: return events[index]["kind"].isStr();
        case 7: return events[index]["kind"].get_str() == "withdrawal_bundle";
        case 8: return events[index]["m6id"].isStr();
        case 9:
            event_m6id_hex = events[index]["m6id"].get_str();
            return event_m6id_hex.size() == 64;
        case 10: return IsHex(event_m6id_hex);
        case 11: throw std::runtime_error("normalized withdrawal event has an invalid bundle id");
        case 12: return uint256S(event_m6id_hex) == m6id;
        case 13: return events[index]["status"].isStr();
        case 14:
            state = haskell::WithdrawalStatus(state, events[index]["status"].get_str());
            return true;
        case 15: throw std::runtime_error("normalized withdrawal event has no lifecycle status");
        case 16: ++index; return true;
        case 17:
            result = WITHDRAWAL_STATE_NAMES.at(state);
            return true;
        default: throw std::logic_error("invalid withdrawal status action");
        }
    });
    return result;
}

bool AuthenticateDepositEvidence(
    const UniValue& mainchain_info,
    const uint256& mainchain_genesis,
    const UniValue& enforcer_chain_info,
    const UniValue& enforcer_tip,
    const UniValue& sidechains,
    const UniValue& two_way_peg_data,
    const UniValue& ctip,
    const std::string& sidechain_network,
    const DepositIdentity& expected,
    const COutPoint& expected_outpoint,
    const CAmount expected_value,
    AuthenticatedDeposit& authenticated,
    std::string& error)
{
    return TranslatePegError(error, [&] {
        uint256 mainchain_tip;
        int64_t mainchain_height{0}, enforcer_tip_height{0};
        using Step = haskell::DepositVerifyStep;
        AuthenticatedDeposit candidate;
        return haskell::RunDepositAuthentication([&](Step step) {
            switch (step) {
            case Step::AUTH_NETWORK:
                CheckLiveEvidence(haskell::LiveEvidencePhase::NETWORK, [&](uint32_t step, int64_t* fields) {
                    switch (step) {
                    case 0:
                        fields[0] = expected.sidechain_slot;
                        fields[1] = sidechain_network == expected.sidechain_network;
                        fields[2] = mainchain_genesis == expected.mainchain_genesis;
                        break;
                    case 1:
                        fields[0] = mainchain_info.isObject();
                        haskell::ReadWhen(fields[0], [&] { fields[1] = RequireStringField(mainchain_info, "chain", "chain") == expected.mainchain_network; });
                        break;
                    case 2:
                        fields[0] = RequireStringField(mainchain_info, "signet_challenge", "signet_challenge") == expected.mainchain_signet_challenge;
                        break;
                    case 3: {
                        const auto& ibd = FindField(mainchain_info, "initialblockdownload", "initial_block_download");
                        fields[0] = haskell::PegSchema(haskell::PegSchemaKind::FALSE_BOOLEAN, 0,
                            [&](uint32_t action) { return action == 1 ? ibd.isBool() : ibd.get_bool(); });
                        break;
                    }
                    case 4:
                        mainchain_tip = uint256S(RequireStringField(mainchain_info, "bestblockhash", "best_block_hash"));
                        mainchain_height = RequireInt64Field(mainchain_info, "blocks", "blocks");
                        fields[0] = enforcer_chain_info.isObject();
                        haskell::ReadWhen(fields[0], [&] { fields[1] = RequireStringField(enforcer_chain_info, "network", "network") == expected.enforcer_network; });
                        break;
                    case 5: {
                        const auto& header = RequireObjectField(enforcer_tip, "blockHeaderInfo", "block_header_info");
                        const auto hash = uint256S(RequireHexObjectField(header, "blockHash", "block_hash", 32));
                        enforcer_tip_height = RequireInt64Field(header, "height", "height");
                        fields[0] = hash == mainchain_tip;
                        fields[1] = enforcer_tip_height;
                        fields[2] = mainchain_height;
                        break;
                    }
                    default: return false;
                    }
                    return true;
                });
                return true;
            case Step::AUTH_IDENTITY:
                VerifySidechainIdentity(sidechains, expected, enforcer_tip_height);
                return true;
            case Step::AUTH_DEPOSIT:
                candidate = FindDeposit(two_way_peg_data, expected, expected_outpoint, expected_value);
                return true;
            case Step::AUTH_CTIP:
                VerifyCtip(ctip, candidate);
                return true;
            case Step::AUTH_PUBLISH:
                authenticated = std::move(candidate);
                return true;
            default: throw std::logic_error("invalid deposit authentication action");
            }
        });
    });
}

bool VerifyDepositBlockConfirmation(
    const UniValue& block_header,
    const AuthenticatedDeposit& authenticated,
    std::string& error)
{
    return TranslatePegError(error, [&] {
        CheckLiveEvidence(haskell::LiveEvidencePhase::CONFIRMATION, [&](uint32_t step, int64_t* fields) {
            switch (step) {
            case 0: fields[0] = block_header.isObject(); break;
            case 1:
                fields[0] = RequireInt64Field(block_header, "confirmations", "confirmations");
                fields[1] = RequireInt64Field(block_header, "height", "height");
                fields[2] = authenticated.confirmation_height;
                break;
            case 2: {
                const auto& hash = FindField(block_header, "hash", "hash");
                std::string hex;
                fields[0] = ReadHexField(hash, 32, hex);
                haskell::ReadWhen(fields[0], [&] { fields[1] = uint256S(hex) == authenticated.confirmation_block; });
                break;
            }
            default: return false;
            }
            return true;
        });
        return true;
    });
}

bool VerifyCurrentCtipOutput(
    const UniValue& txout,
    const AuthenticatedDeposit& authenticated,
    std::string& error)
{
    return TranslatePegError(error, [&] {
        CheckLiveEvidence(haskell::LiveEvidencePhase::CTIP_OUTPUT, [&](uint32_t step, int64_t* fields) {
            switch (step) {
            case 0: fields[0] = txout.isObject(); break;
            case 1: fields[0] = RequireInt64Field(txout, "confirmations", "confirmations"); break;
            case 2: {
                const auto& value = FindField(txout, "value", "value");
                fields[0] = !value.isNull();
                haskell::ReadWhen(fields[0], [&] { fields[1] = AmountFromValue(value); });
                fields[2] = authenticated.current_ctip_value;
                break;
            }
            default: return false;
            }
            return true;
        });
        return true;
    });
}

bool VerifyDepositTransaction(
    const CTransaction& tx,
    const size_t input_index,
    const AuthenticatedDeposit& authenticated,
    std::string& error)
{
    return TranslatePegError(error, [&] {
        uint32_t facts{0};
        CAmount witness_value{0};
        std::array<unsigned char, 2> flags{};
        std::array<int64_t, 2> amounts{};
        haskell::DepositTransactionFacts([&](uint32_t step) -> uint64_t {
            switch (step) {
            case 1: return tx.vin.size();
            case 2: return input_index;
            case 3: return tx.witness.vtxinwit.size();
            case 4: {
                const auto& input = tx.vin[0];
                facts = input.m_is_pegin | ((input.prevout == authenticated.outpoint) << 1) |
                    (input.scriptSig.empty() << 2) | (input.assetIssuance.IsNull() << 3);
                return facts;
            }
            case 5: {
                CScript claim_script;
                uint256 mainchain_txid;
                const bool decoded = GetDrivechainDepositPeginData(tx.witness.vtxinwit[0].m_pegin_witness,
                    tx.vin[0].prevout, witness_value, claim_script, mainchain_txid);
                facts |= (decoded << 4) | ((mainchain_txid == authenticated.outpoint.hash) << 5) |
                    ((claim_script == (CScript() << OP_TRUE)) << 6);
                return 0;
            }
            case 7: case 9: return tx.vout.size();
            case 8: case 10: {
                const size_t i = (step - 8) / 2;
                const auto& output = tx.vout[i];
                flags[i] = (output.nAsset.IsExplicit() && output.nAsset.GetAsset() == Params().GetConsensus().pegged_asset) |
                    (output.nValue.IsExplicit() << 1) | (output.nNonce.IsNull() << 2) |
                    (output.scriptPubKey.empty() << 3) | ((output.scriptPubKey == authenticated.destination_script) << 4);
                amounts[i] = output.nValue.IsExplicit() ? output.nValue.GetAmount() : 0;
                return 0;
            }
            default: throw std::logic_error("invalid deposit fact projection action");
            }
        });
        return haskell::AuthenticatedDeposit(tx.vin.size(), input_index, tx.witness.vtxinwit.size(), facts,
            authenticated.value, witness_value, tx.vout.size(), flags, amounts, error);
    });
}

bool GetCtipState(const CCoinsViewCache& inputs, CtipState& state, std::string* error)
{
    using Step = haskell::DepositVerifyStep;
    const Coin* coin{nullptr};
    CtipState decoded;
    std::string decode_error;
    return haskell::RunCtipRead([&](Step step) {
        switch (step) {
        case Step::CTIP_READ_PRESENT:
            coin = &inputs.AccessCoin(CTIP_STATE_OUTPOINT);
            return !coin->IsSpent();
        case Step::CTIP_READ_DECODE: return DecodeCtipState(*coin, decoded, decode_error);
        case Step::CTIP_READ_ERROR_TARGET: return error != nullptr;
        case Step::CTIP_READ_ERROR: *error = decode_error; return false;
        case Step::CTIP_READ_PUBLISH: state = std::move(decoded); return true;
        default: throw std::logic_error("invalid CTIP read action");
        }
    });
}

bool IsCtipStateInternalOutpoint(const COutPoint& outpoint)
{
    return outpoint == CTIP_STATE_OUTPOINT;
}

bool VerifyDeterministicDeposit(
    const CTransaction& tx,
    const size_t input_index,
    const CCoinsViewCache& inputs,
    std::string& error)
{
    using Step = haskell::DepositVerifyStep;
    std::optional<LegacyCheckpoint> checkpoint;
    AuthenticatedDeposit authenticated;
    ParsedDeterministicDeposit parsed;
    CtipState current;
    std::string state_error;
    return haskell::RunDepositVerification([&](Step step) {
        switch (step) {
        case Step::CHECKPOINT:
            checkpoint = FindLegacyCheckpoint(tx, input_index);
            return checkpoint.has_value();
        case Step::CHECKPOINT_STATE: {
            const bool present = GetCtipState(inputs, current, &state_error);
            return haskell::DepositState(haskell::DepositStatePhase::CHECK_CHECKPOINT,
                present, false, state_error, error);
        }
        case Step::BUILD_CHECKPOINT:
            return BuildLegacyAuthenticated(tx, input_index, checkpoint.value(), authenticated, error);
        case Step::VERIFY_CHECKPOINT:
            return VerifyDepositTransaction(tx, input_index, authenticated, error);
        case Step::HAS_WITNESS: return input_index < tx.witness.vtxinwit.size();
        case Step::LEGACY_WITNESS:
            return IsLegacyDrivechainDepositPeginWitness(tx.witness.vtxinwit[input_index].m_pegin_witness);
        case Step::REJECT_LEGACY:
            error = "legacy drivechain deposit witness is not an immutable historical checkpoint";
            return false;
        case Step::PARSE: return ParseV2Deposit(tx, input_index, parsed, error);
        case Step::PRIOR_STATE: {
            const bool present = GetCtipState(inputs, current, &state_error);
            return haskell::DepositState(haskell::DepositStatePhase::CHECK_PRIOR,
                present, current == parsed.previous_state, state_error, error);
        }
        case Step::VERIFY: return VerifyDepositTransaction(tx, input_index, parsed.authenticated, error);
        default: throw std::logic_error("invalid deposit verification action");
        }
    });
}

bool VerifyDepositEvidenceAnchor(
    const CTransaction& tx,
    const size_t input_index,
    const uint256& expected_parent,
    std::string& error)
{
    using Step = haskell::DepositVerifyStep;
    std::optional<LegacyCheckpoint> checkpoint;
    ParsedDeterministicDeposit parsed;
    return haskell::RunDepositVerification([&](Step step) {
        switch (step) {
        case Step::ANCHOR_CHECKPOINT:
            checkpoint = FindLegacyCheckpoint(tx, input_index);
            return checkpoint.has_value();
        case Step::CHECKPOINT_ANCHOR:
            return haskell::DepositState(haskell::DepositStatePhase::CHECK_CHECKPOINT_ANCHOR,
                true, checkpoint.value().parent_hash == expected_parent, {}, error);
        case Step::ANCHOR_HAS_WITNESS: return input_index < tx.witness.vtxinwit.size();
        case Step::ANCHOR_LEGACY_WITNESS:
            return IsLegacyDrivechainDepositPeginWitness(tx.witness.vtxinwit[input_index].m_pegin_witness);
        case Step::REJECT_LEGACY:
            error = "legacy drivechain deposit witness is not an immutable historical checkpoint";
            return false;
        case Step::PARSE_ANCHOR: return ParseV2Deposit(tx, input_index, parsed, error);
        case Step::CHECK_ANCHOR:
            return haskell::DepositState(haskell::DepositStatePhase::CHECK_ANCHOR,
                true, parsed.anchor == expected_parent, {}, error);
        case Step::REJECT_ANCHOR:
            error = strprintf("drivechain deposit evidence anchor %s does not match sidechain block L1 parent %s",
                parsed.anchor.GetHex(), expected_parent.GetHex());
            return false;
        default: throw std::logic_error("invalid deposit anchor action");
        }
    }, true);
}

bool ConnectDepositState(
    const CTransaction& tx,
    const size_t input_index,
    CCoinsViewCache& inputs,
    const int height,
    std::string& error)
{
    using Step = haskell::DepositVerifyStep;
    std::optional<LegacyCheckpoint> checkpoint;
    AuthenticatedDeposit authenticated;
    ParsedDeterministicDeposit parsed;
    CtipState current;
    std::string state_error;
    return haskell::RunDepositLifecycle([&](Step step) {
        switch (step) {
        case Step::CONNECT_CHECKPOINT:
            checkpoint = FindLegacyCheckpoint(tx, input_index);
            return checkpoint.has_value();
        case Step::CONNECT_BUILD:
            return BuildLegacyAuthenticated(tx, input_index, checkpoint.value(), authenticated, error);
        case Step::CONNECT_VERIFY:
            return VerifyDepositTransaction(tx, input_index, authenticated, error);
        case Step::CONNECT_PUBLISH_CHECKPOINT:
            SetCtipState(inputs, {checkpoint.value().outpoint, checkpoint.value().ctip_value, checkpoint.value().sequence_number}, height);
            return true;
        case Step::CONNECT_PARSE: return ParseV2Deposit(tx, input_index, parsed, error);
        case Step::CONNECT_PRIOR: {
            const bool present = GetCtipState(inputs, current, &state_error);
            return haskell::DepositState(haskell::DepositStatePhase::CONNECT_PRIOR,
                present, current == parsed.previous_state, state_error, error);
        }
        case Step::CONNECT_PUBLISH_NEXT:
            SetCtipState(inputs, parsed.next_state, height);
            return true;
        default: throw std::logic_error("invalid deposit connect action");
        }
    }, false);
}

bool DisconnectDepositState(
    const CTransaction& tx,
    const size_t input_index,
    CCoinsViewCache& inputs,
    const int height,
    std::string& error)
{
    using Step = haskell::DepositVerifyStep;
    std::optional<LegacyCheckpoint> checkpoint;
    ParsedDeterministicDeposit parsed;
    CtipState current;
    std::string state_error;
    return haskell::RunDepositLifecycle([&](Step step) {
        switch (step) {
        case Step::DISCONNECT_PRESENT: {
            const bool present = GetCtipState(inputs, current, &state_error);
            return haskell::DepositState(haskell::DepositStatePhase::DISCONNECT_PRESENT,
                present, false, state_error, error);
        }
        case Step::DISCONNECT_CHECKPOINT:
            checkpoint = FindLegacyCheckpoint(tx, input_index);
            return checkpoint.has_value();
        case Step::DISCONNECT_CHECK: {
            const CtipState expected{checkpoint.value().outpoint, checkpoint.value().ctip_value, checkpoint.value().sequence_number};
            return haskell::DepositState(haskell::DepositStatePhase::DISCONNECT_CHECKPOINT,
                true, current == expected, {}, error);
        }
        case Step::DISCONNECT_REMOVE: {
            const bool removed = inputs.SpendCoin(CTIP_STATE_OUTPOINT);
            if (!removed) error = "historical drivechain checkpoint CTIP state could not be removed";
            return removed;
        }
        case Step::DISCONNECT_PARSE: return ParseV2Deposit(tx, input_index, parsed, error);
        case Step::DISCONNECT_CURRENT:
            return haskell::DepositState(haskell::DepositStatePhase::DISCONNECT_CURRENT,
                true, current == parsed.next_state, {}, error);
        case Step::DISCONNECT_RESTORE:
            SetCtipState(inputs, parsed.previous_state, height, true);
            return true;
        default: throw std::logic_error("invalid deposit disconnect action");
        }
    }, true);
}

} // namespace drivechain
