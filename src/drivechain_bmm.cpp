// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_bmm.h>
#include <haskell/bridge.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <hash.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/bitcoin/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>
#include <util/strencodings.h>
#include <common/args.h>

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace drivechain {
int64_t BmmConsensus::DifficultyAdjustmentInterval() const
{
    return haskell::BmmDifficultyInterval(target_timespan, target_spacing);
}

namespace {

struct BmmIdentity
{
    std::array<uint256, 2> blocks;
    COutPoint outpoint;
    std::vector<unsigned char> marker;
    std::array<unsigned char, 4> signet_header, m8_magic;
    uint32_t script_flags;
};

const BmmIdentity& Identity()
{
    static const BmmIdentity identity = [] {
        std::array<uint32_t, 2> fields{};
        std::array<unsigned char, 121> bytes{};
        haskell::BmmFixedIdentity(fields, bytes);
        // ABI: three hashes, 17-byte marker, two four-byte magic values.
        return BmmIdentity{
            {uint256{bytes.data(), 32}, uint256{bytes.data() + 32, 32}},
            {Txid::FromUint256(uint256{bytes.data() + 64, 32}), fields[0]},
            {bytes.begin() + 96, bytes.begin() + 113},
            {bytes[113], bytes[114], bytes[115], bytes[116]},
            {bytes[117], bytes[118], bytes[119], bytes[120]}, fields[1]};
    }();
    return identity;
}

BmmConsensus MakeBmmConsensus(uint32_t mode)
{
    std::array<uint64_t, 6> fields{};
    std::array<unsigned char, 32> pow_limit{};
    std::array<unsigned char, 22> challenge{};
    const auto size = haskell::BmmConsensusPreset(mode, fields, pow_limit, challenge);
    return {uint256{pow_limit.data(), pow_limit.size()}, static_cast<int64_t>(fields[0]),
        static_cast<int64_t>(fields[1]), CScript(challenge.begin(), challenge.begin() + size),
        static_cast<int>(fields[2]), fields[3], fields[4], bool(fields[5])};
}

const BmmConsensus& PublicBmmConsensus()
{
    static const auto consensus = MakeBmmConsensus(0);
    return consensus;
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
const BmmConsensus& PrivateBmmConsensus()
{
    static const auto consensus = MakeBmmConsensus(1);
    return consensus;
}

bool PrivateE2eBmmEnabled()
{
    return gArgs.GetBoolArg("-ecxprivatebmmcheckpoint", false);
}
#endif

BmmL1State MakeBmmCheckpoint(uint32_t mode)
{
    std::array<uint32_t, 16> fields{};
    std::array<unsigned char, 32> hash{};
    haskell::BmmCheckpointPreset(mode, fields, hash);
    return {uint256{hash.data(), hash.size()}, fields[0], fields[1], fields[2],
        fields[3], fields[4], {fields.begin() + 5, fields.end()}};
}

const BmmL1State& PublicBmmCheckpoint()
{
    static const auto state = MakeBmmCheckpoint(0);
    return state;
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
// Private checkpoint selection remains compile-time and runtime gated.
const BmmL1State& PrivateBmmCheckpoint()
{
    static const auto state = MakeBmmCheckpoint(1);
    return state;
}
#endif


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

template <typename T>
std::vector<unsigned char> SerializeValue(const T& value)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(value);
    return {
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size()};
}

bool ValidState(const BmmL1State& state, const BmmConsensus& consensus, std::string& error)
{
    return haskell::BmmState(!state.block_hash.IsNull(), consensus.DifficultyAdjustmentInterval(),
        state.height, state.block_time, state.n_bits, state.period_start_height, state.period_start_time,
        state.recent_times.size(), state.recent_times.empty() ? 0 : state.recent_times.back(), error);
}

bool IsPublicBmmCheckpoint(const CBlock& block, const CBlockIndex* previous)
{
    return haskell::ParentReplayAll<3>({
        [&] { return block.GetHash() == Identity().blocks[1]; },
        [&] { return previous != nullptr; },
        [&] { return previous->GetBlockHash() == Identity().blocks[0]; }});
}

uint32_t ExpectedNextBits(
    const BmmL1State& previous,
    const BmmConsensus& consensus)
{
    using Step = haskell::BmmStateStep;
    int64_t actual_timespan{0};
    uint32_t bits = previous.n_bits;
    haskell::RunBmmStateFlow(Step::RETARGET_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::RETARGET_SPAN:
            actual_timespan = haskell::BmmRetarget(previous.height,
                consensus.DifficultyAdjustmentInterval(), consensus.target_timespan,
                previous.block_time, previous.period_start_time);
            return actual_timespan != -1;
        case Step::RETARGET_SCALE: {
            uint256 next = ArithToUint256(arith_uint256{}.SetCompact(previous.n_bits));
            haskell::BmmScaleTarget(actual_timespan, consensus.target_timespan,
                std::span<unsigned char, 32>{next.begin(), 32},
                std::span<const unsigned char, 32>{consensus.pow_limit.begin(), 32});
            bits = UintToArith256(next).GetCompact();
            return 1;
        }
        default: throw std::logic_error("unexpected BMM retarget step");
        }
    });
    return bits;
}

bool CheckParentProofOfWork(
    const Sidechain::Bitcoin::CBlockHeader& header,
    const BmmConsensus& consensus,
    std::string& error)
{
    using Step = haskell::BmmStateStep;
    arith_uint256 target;
    return haskell::RunBmmStateFlow(Step::POW_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::POW_TARGET: {
            bool negative{false}, overflow{false};
            target.SetCompact(header.nBits, &negative, &overflow);
            const uint32_t facts = negative | ((target == 0) << 1) | (overflow << 2) |
                ((target > UintToArith256(consensus.pow_limit)) << 3);
            return haskell::BmmProof(haskell::BmmProofPhase::POW_TARGET, facts, 0, 0, 0, error);
        }
        case Step::POW_HASH:
            return haskell::BmmProof(haskell::BmmProofPhase::POW_HASH,
                UintToArith256(header.GetHash()) <= target, 0, 0, 0, error);
        default: throw std::logic_error("unexpected BMM PoW step");
        }
    });
}

bool FetchAndClearSignetSolution(CScript& witness_commitment, std::vector<unsigned char>& result)
{
    result.clear();
    struct Context {
        CScript& script;
        std::vector<unsigned char>& solution;
        CScript::const_iterator cursor;
        CScript replacement;
        opcodetype opcode{OP_INVALIDOPCODE};
        std::vector<unsigned char> pushdata;
        std::exception_ptr exception;
    } context{witness_commitment, result, witness_commitment.begin(), {}, OP_INVALIDOPCODE, {}, {}};
    auto step = +[](void* opaque, uint32_t action, int64_t* fields) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        try {
            switch (action) {
            case 0:
                fields[0] = ctx.script.GetOp(ctx.cursor, ctx.opcode, ctx.pushdata);
                fields[1] = ctx.cursor == ctx.script.end();
                fields[2] = ctx.pushdata.size();
                fields[3] = 0;
                for (size_t i = 0; i < std::min<size_t>(4, ctx.pushdata.size()); ++i) fields[3] |= int64_t(ctx.pushdata[i]) << (8 * i);
                break;
            case 1:
                if (ctx.pushdata.size() < 4) throw std::runtime_error("invalid signet adapter capture");
                ctx.solution.assign(ctx.pushdata.begin() + 4, ctx.pushdata.end());
                ctx.pushdata.resize(4);
                break;
            case 2: ctx.replacement << ctx.pushdata; break;
            case 3: ctx.replacement << ctx.opcode; break;
            case 4: ctx.script = ctx.replacement; break;
            default: return 0;
            }
            return 1;
        } catch (...) {
            ctx.exception = std::current_exception();
            return 0;
        }
    };
    try {
        return haskell::ExtractSignet(step, &context);
    } catch (...) {
        if (context.exception) std::rethrow_exception(context.exception);
        throw;
    }
}

} // namespace

uint256 BitcoinWitnessV0SignatureHash(
    const CScript& script_code,
    const Sidechain::Bitcoin::CTransaction& transaction,
    const unsigned int input_index,
    const int hash_type)
{
    uint256 hash_prevouts;
    uint256 hash_sequence;
    uint256 hash_outputs;
    const uint32_t plan = haskell::BmmSigHashPlan(hash_type, input_index, transaction.vout.size());
    const auto hash_items = [](const auto& items, auto field) {
        HashWriter writer;
        for (const auto& item : items) writer << field(item);
        return writer.GetHash();
    };

    haskell::BmmSignatureActions(plan, [&](uint32_t action) {
        switch (action) {
        case 0:
            hash_prevouts = hash_items(transaction.vin, [](const auto& input) -> const auto& { return input.prevout; });
            break;
        case 1:
            hash_sequence = hash_items(transaction.vin, [](const auto& input) { return input.nSequence; });
            break;
        case 2:
            hash_outputs = hash_items(transaction.vout, [](const auto& output) -> const auto& { return output; });
            break;
        case 3:
            hash_outputs = (HashWriter{} << transaction.vout[input_index]).GetHash();
            break;
        default: throw std::logic_error("invalid BMM signature hash action");
        }
    });

    HashWriter writer;
    haskell::BmmPreimage(0, [&](uint32_t field) {
        switch (field) {
        case 0: writer << transaction.version; break;
        case 1: writer << hash_prevouts; break;
        case 2: writer << hash_sequence; break;
        case 3: writer << transaction.vin[input_index].prevout; break;
        case 4: writer << script_code; break;
        case 5: writer << int64_t{0}; break;
        case 6: writer << transaction.vin[input_index].nSequence; break;
        case 7: writer << hash_outputs; break;
        case 8: writer << transaction.nLockTime; break;
        case 9: writer << hash_type; break;
        default: throw std::logic_error("invalid BMM signature field");
        }
    });
    return writer.GetHash();
}

bool BitcoinSignetSignatureChecker::CheckECDSASignature(
    const std::vector<unsigned char>& signature_with_type,
    const std::vector<unsigned char>& public_key, const CScript& script_code,
    const SigVersion sigversion, unsigned int flags) const
{
    using Step = haskell::BmmStateStep;
    ScriptError script_error{SCRIPT_ERR_OK};
    std::optional<CPubKey> pubkey;
    std::vector<unsigned char> signature;
    int hash_type{0};
    uint256 digest;
    const auto start = static_cast<Step>(haskell::BmmStateFlow(Step::SIGNATURE_MODE, static_cast<int32_t>(m_mode)));
    return haskell::RunBmmStateFlow(start, [&](Step step) -> int32_t {
        switch (step) {
        case Step::SIGNATURE_GATE:
            return haskell::BmmSignatureGate(sigversion == SigVersion::WITNESS_V0,
                signature_with_type.size(), m_input_index, m_transaction.vin.size());
        case Step::PARENT_SIGNATURE_GATE:
            return haskell::BmmSignatureGate(sigversion == SigVersion::WITNESS_V0,
                signature_with_type.size(), 0, 1);
        case Step::PARENT_SIGNATURE_ENCODING:
            return CheckSignatureEncoding(signature_with_type, flags, &script_error);
        case Step::SIGNATURE_KEY:
            pubkey.emplace(public_key);
            return pubkey->IsValid();
        case Step::SIGNATURE_SPLIT:
            signature = signature_with_type;
            hash_type = haskell::BmmSplitSignature(signature);
            return 1;
        case Step::SIGNATURE_HASH:
            digest = BitcoinWitnessV0SignatureHash(script_code, m_transaction, m_input_index, hash_type);
            return 1;
        case Step::SIGNATURE_VERIFY: return pubkey->Verify(digest, signature);
        default: throw std::logic_error("unexpected BMM signature step");
        }
    });
}

namespace {

bool CheckSignetSolution(
    const Sidechain::Bitcoin::CMutableTransaction& original_coinbase,
    Sidechain::Bitcoin::CMerkleBlock proof,
    const BmmConsensus& consensus,
    std::string& error)
{
    Sidechain::Bitcoin::CMutableTransaction modified_coinbase{original_coinbase};
    int commitment_index{-1};
    std::vector<unsigned char> signet_solution;
    Sidechain::Bitcoin::CMutableTransaction transaction_to_spend;
    Sidechain::Bitcoin::CMutableTransaction transaction_spending;
    std::vector<uint256> matches;
    std::vector<unsigned int> indices;
    uint256 modified_merkle_root;
    using Step = haskell::SignetStep;
    return haskell::RunSignetValidation(Step::START, [&](Step step) -> std::array<uint64_t,4> {
        uint64_t a{0}, b{0}, c{0}, d{0};
        switch (step) {
        case Step::WITNESS:
            commitment_index = BitcoinWitnessCommitmentIndex(modified_coinbase.vout);
            a = commitment_index >= 0;
            break;
        case Step::EXTRACT:
            a = FetchAndClearSignetSolution(modified_coinbase.vout[commitment_index].scriptPubKey, signet_solution);
            break;
        case Step::BUILD: {
            BuildBitcoinSignetTransactions(consensus.signet_challenge, transaction_to_spend, transaction_spending);
            a = !signet_solution.empty();
            break;
        }
        case Step::DECODE:
            try {
                DataStream stream{signet_solution};
                haskell::BmmSignetActions(true, [&](uint32_t action) {
                    switch (action) {
                    case 0: stream >> transaction_spending.vin[0].scriptSig; break;
                    case 1: stream >> transaction_spending.vin[0].scriptWitness.stack; break;
                    default: throw std::logic_error("invalid signet decode action");
                    }
                });
                a = !stream.empty();
            } catch (...) {
                a = 2;
            }
            break;
        case Step::MERKLE:
            modified_merkle_root = proof.txn.ExtractMatchesWithReplacement(matches, indices, 0, modified_coinbase.GetHash());
            a = !modified_merkle_root.IsNull();
            b = matches.size();
            c = indices.size();
            d = indices.empty() ? 0 : indices[0];
            break;
        case Step::COINBASE:
            a = matches[0] == original_coinbase.GetHash();
            break;
        case Step::VERIFY: {
            const auto block_data = BitcoinSignetBlockData(proof.header, modified_merkle_root);
            transaction_to_spend.vin[0].scriptSig << block_data;
            transaction_spending.vin[0].prevout = {transaction_to_spend.GetHash(), 0};
            const Sidechain::Bitcoin::CTransaction immutable_to_spend{transaction_to_spend};
            const Sidechain::Bitcoin::CTransaction immutable_spending{transaction_spending};
            const BitcoinSignetSignatureChecker checker{immutable_spending, 0};
            a = VerifyScript(immutable_spending.vin[0].scriptSig, immutable_to_spend.vout[0].scriptPubKey,
                &immutable_spending.vin[0].scriptWitness, Identity().script_flags, checker);
            break;
        }
        default: throw std::runtime_error("invalid native signet action");
        }
        return {a,b,c,d};
    },error);
}

// Only upstream script decoding and byte projection live in this adapter.
template <typename Output>
int64_t SelectCommitmentIndex(const std::vector<Output>& outputs, uint32_t kind, int slot, std::string& error, uint256* parent = nullptr)
{
    if (outputs.size() > std::numeric_limits<uint32_t>::max()) throw std::length_error("BMM output count");
    struct Context {
        const std::vector<Output>& outputs;
        CScript::const_iterator cursor{};
        std::vector<unsigned char> data;
        std::exception_ptr exception;
        uint256* parent;
    } context{outputs, {}, {}, {}, parent};
    auto inspect = +[](void* opaque, uint32_t index, uint32_t action, int64_t* fields) -> int32_t {
        auto& ctx = *static_cast<Context*>(opaque);
        try {
            const auto& script = ctx.outputs.at(index).scriptPubKey;
            std::fill_n(fields, 4, 0);
            switch (action) {
            case 0:
                fields[0] = script.size();
                for (size_t i = 0; i < std::min<size_t>(6, script.size()); ++i) fields[1] |= int64_t(script[i]) << (8 * i);
                return 1;
            case 1:
                ctx.cursor = script.begin();
                ctx.data.clear();
                [[fallthrough]];
            case 2: {
                opcodetype opcode;
                fields[0] = script.GetOp(ctx.cursor, opcode, ctx.data) ? uint32_t(opcode) : 256;
                return 1;
            }
            case 3:
                fields[0] = ctx.cursor == script.end();
                fields[1] = ctx.data.size();
                for (size_t i = 0; i < std::min<size_t>(4, ctx.data.size()); ++i) fields[2] |= int64_t(ctx.data[i]) << (8 * i);
                fields[3] = ctx.data.size() > 4 ? ctx.data[4] : 0;
                return 1;
            case 4:
                if (!ctx.parent || ctx.data.size() != 37) throw std::logic_error("invalid parent commitment publication");
                *ctx.parent = uint256(ctx.data.data()+5, uint256::size());
                return 1;
            default: throw std::logic_error("invalid BMM script action");
            }
        } catch (...) {
            ctx.exception = std::current_exception();
            return 0;
        }
    };
    try {
        return haskell::BmmCommitment(kind, slot, outputs.size(), inspect, &context, error);
    } catch (...) {
        if (context.exception) std::rethrow_exception(context.exception);
        throw;
    }
}

template <typename Output>
bool ExtractCommitment(const std::vector<Output>& outputs, uint32_t kind, int slot,
    uint256& commitment, std::string& error)
{
    using Step = haskell::BmmStateStep;
    int64_t selected{-1};
    const CScript* script{nullptr};
    CScript::const_iterator cursor{};
    opcodetype opcode;
    std::vector<unsigned char> data;
    return haskell::RunBmmStateFlow(Step::EXTRACT_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::EXTRACT_SELECT:
            selected = SelectCommitmentIndex(outputs, kind, slot, error);
            return selected >= 0;
        case Step::EXTRACT_FIRST:
            script = &outputs.at(selected).scriptPubKey;
            cursor = script->begin();
            script->GetOp(cursor, opcode, data);
            return 1;
        case Step::EXTRACT_SECOND:
            script->GetOp(cursor, opcode, data);
            return 1;
        case Step::EXTRACT_PUBLISH: {
            const auto bytes = haskell::BmmCommitmentBytes(kind, data);
            commitment = uint256{bytes.data(), bytes.size()};
            return 1;
        }
        default: throw std::logic_error("unexpected BMM extraction step");
        }
    });
}

bool ExtractM8Commitment(const Sidechain::Bitcoin::CMutableTransaction& coinbase,
    const int sidechain_slot, uint256& commitment, std::string& error)
{
    return ExtractCommitment(coinbase.vout, 0, sidechain_slot, commitment, error);
}

bool ExtractSidechainParentHash(const CBlock& block, uint256& parent_hash, std::string& error)
{
    using Step = haskell::BmmStateStep;
    return haskell::RunBmmStateFlow(Step::PARENT_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::PARENT_COINBASE:
            return haskell::BmmProof(haskell::BmmProofPhase::COINBASE_PRESENT, !block.vtx.empty(), 0, 0, 0, error);
        case Step::PARENT_EXTRACT: return ExtractCommitment(block.vtx[0]->vout, 1, 0, parent_hash, error);
        default: throw std::logic_error("unexpected BMM parent extraction step");
        }
    });
}

CScript EncodeBmmState(const BmmL1State& state)
{
    DataStream stream;
    CScript script;
    haskell::BmmEncodeState([&](uint32_t action, uint32_t opcode) {
        switch (action) {
        case 0: stream << Identity().marker; break;
        case 1: stream << state; break;
        case 2: script << std::vector<unsigned char>(UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()); break;
        case 3: script << static_cast<opcodetype>(opcode); break;
        default: throw std::logic_error("invalid BMM state encoding action");
        }
    });
    return script;
}

bool DecodeBmmState(const Coin& coin, BmmL1State& state, std::string& error)
{
    using Phase = haskell::BmmCodecPhase;
    using Step = haskell::BmmStateStep;
    const bool valid_coin = haskell::RunBmmStateFlow(Step::COIN_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::COIN_UNSPENT: return !coin.IsSpent();
        case Step::COIN_ASSET: return coin.out.nAsset.IsExplicit();
        case Step::COIN_PEGGED: return coin.out.nAsset.GetAsset() == Params().GetConsensus().pegged_asset;
        case Step::COIN_VALUE: return coin.out.nValue.IsExplicit();
        case Step::COIN_ZERO: return coin.out.nValue.GetAmount() == 0;
        default: throw std::logic_error("invalid BMM coin preflight action");
        }
    });
    if (!haskell::BmmCodec(Phase::STATE_ASSET, valid_coin ? 31 : 0, 0, 0, error)) return false;
    CScript::const_iterator cursor = coin.out.scriptPubKey.begin();
    std::vector<unsigned char> data;
    const auto read_opcode = [&](Phase phase) {
        opcodetype opcode{OP_INVALIDOPCODE};
        const bool parsed = phase == Phase::STATE_PUSH ? coin.out.scriptPubKey.GetOp(cursor, opcode, data) :
            coin.out.scriptPubKey.GetOp(cursor, opcode);
        const uint32_t facts = parsed | ((phase == Phase::STATE_END && cursor == coin.out.scriptPubKey.end()) << 1);
        return haskell::BmmCodec(phase, facts, parsed ? opcode : 0, 0, error);
    };
    std::optional<DataStream> stream;
    std::vector<unsigned char> marker;
    Step current{Step::READ_START};
    try {
        return haskell::RunBmmStateFlow(Step::READ_START, [&](Step step) {
            current = step;
            switch (step) {
            case Step::READ_PUSH: return read_opcode(Phase::STATE_PUSH);
            case Step::READ_DROP: return read_opcode(Phase::STATE_DROP);
            case Step::READ_END: return read_opcode(Phase::STATE_END);
            case Step::READ_MARKER: stream.emplace(data); *stream >> marker; return true;
            case Step::READ_STATE: *stream >> state; return true;
            case Step::READ_PAYLOAD:
                return haskell::BmmCodec(Phase::STATE_PAYLOAD, stream->empty() | ((marker == Identity().marker) << 1), 0, 0, error);
            case Step::READ_VALID: return ValidState(state, LayerTwoLabsBmmConsensus(), error);
            default: throw std::logic_error("invalid BMM state decode action");
            }
        });
    } catch (...) {
        if (current < Step::READ_MARKER) throw;
        return haskell::BmmCodec(Phase::STATE_EXCEPTION, 0, 0, 0, error);
    }
}

void SetBmmState(CCoinsViewCache& view, const BmmL1State& state, const int height, bool restore = false)
{
    std::optional<CTxOut> output;
    haskell::BmmStoreState(height, [&](uint32_t action, uint32_t value) {
        switch (action) {
        case 0: view.SpendCoin(Identity().outpoint); break;
        case 1: output.emplace(Params().GetConsensus().pegged_asset, value, EncodeBmmState(state)); break;
        case 2:
            view.AddCoin(Identity().outpoint, Coin(std::move(output.value()), value, false), true);
            break;
        default: throw std::logic_error("invalid BMM state storage action");
        }
    }, restore);
}

} // namespace

void BuildBitcoinSignetTransactions(const CScript& challenge,
    Sidechain::Bitcoin::CMutableTransaction& spend, Sidechain::Bitcoin::CMutableTransaction& sign)
{
    const auto fields = haskell::BmmSignetTemplate();
    haskell::BmmSignetActions(false, [&](uint32_t action) {
        switch (action) {
        case 0: spend.version = sign.version = fields[0]; break;
        case 1: spend.nLockTime = sign.nLockTime = fields[1]; break;
        case 2: spend.vin.emplace_back(Sidechain::Bitcoin::COutPoint(), CScript(static_cast<opcodetype>(fields[4])), fields[2]); break;
        case 3: spend.vout.emplace_back(fields[3], challenge); break;
        case 4: sign.vin.emplace_back(Sidechain::Bitcoin::COutPoint(), CScript(), fields[2]); break;
        case 5: sign.vout.emplace_back(fields[3], CScript(static_cast<opcodetype>(fields[5]))); break;
        default: throw std::logic_error("invalid signet assembly action");
        }
    });
}

std::vector<unsigned char> BitcoinSignetBlockData(const Sidechain::Bitcoin::CBlockHeader& header,
    const uint256& modified_merkle_root)
{
    std::vector<unsigned char> block_data;
    VectorWriter writer{block_data, 0};
    haskell::BmmPreimage(1, [&](uint32_t field) {
        switch (field) {
        case 0: writer << header.nVersion; break;
        case 1: writer << header.hashPrevBlock; break;
        case 2: writer << modified_merkle_root; break;
        case 3: writer << header.nTime; break;
        default: throw std::logic_error("invalid signet header field");
        }
    });
    return block_data;
}

int BitcoinWitnessCommitmentIndex(const std::vector<Sidechain::Bitcoin::CTxOut>& outputs)
{
    std::string error;
    return SelectCommitmentIndex(outputs, 2, 0, error);
}

bool ExtractTaggedParentCommitment(const std::vector<CTxOut>& outputs, uint256& parent, std::string& error)
{
    return SelectCommitmentIndex(outputs, 3, 0, error, &parent) >= 0;
}

const BmmConsensus& LayerTwoLabsBmmConsensus()
{
    using Step = haskell::BmmStateStep;
    const BmmConsensus* selected = nullptr;
    haskell::RunBmmStateFlow(Step::CONSENSUS_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::MODE_SELECT:
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
            return PrivateE2eBmmEnabled();
#else
            return 0;
#endif
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        case Step::MODE_PRIVATE: selected = &PrivateBmmConsensus(); return 1;
#endif
        case Step::MODE_PUBLIC: selected = &PublicBmmConsensus(); return 1;
        default: throw std::logic_error("unexpected BMM consensus step");
        }
    });
    if (!selected) throw std::logic_error("missing BMM consensus selection");
    return *selected;
}

const BmmL1State& LayerTwoLabsInitialBmmState()
{
    return PublicBmmCheckpoint();
}

const uint256& LayerTwoLabsPublicSidechainBlock1()
{
    return Identity().blocks[0];
}

const uint256& LayerTwoLabsPublicSidechainBlock2()
{
    return Identity().blocks[1];
}

uint256 RuntimeBmmConsensusFingerprint()
{
    const BmmConsensus& consensus{LayerTwoLabsBmmConsensus()};
    const BmmL1State* states[]{&PublicBmmCheckpoint(),
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        &PrivateBmmCheckpoint()
#else
        nullptr
#endif
    };
    const bool private_mode =
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        PrivateE2eBmmEnabled();
#else
        false;
#endif
    const std::array<uint64_t, 11> numbers{
        BMM_PROOF_SCHEMA_VERSION, CBlockHeader::BMM_PROOF_HF_MASK, private_mode,
        static_cast<uint64_t>(consensus.target_timespan), static_cast<uint64_t>(consensus.target_spacing),
        consensus.require_signet_solution, static_cast<uint32_t>(consensus.sidechain_slot),
        consensus.max_entries, consensus.max_proof_bytes, Identity().outpoint.n, Identity().script_flags};
    const std::array<std::span<const unsigned char>, 8> blobs{{
        {consensus.pow_limit.begin(), consensus.pow_limit.size()},
        {consensus.signet_challenge.data(), consensus.signet_challenge.size()},
        {Identity().blocks[0].begin(), Identity().blocks[0].size()},
        {Identity().blocks[1].begin(), Identity().blocks[1].size()},
        {Identity().outpoint.hash.ToUint256().begin(), Identity().outpoint.hash.ToUint256().size()},
        Identity().marker, Identity().signet_header, Identity().m8_magic}};
    const auto payload = haskell::BmmFingerprint(
        [&](uint32_t group, uint32_t index, uint64_t& value, const unsigned char*& bytes) {
            if (group == 0) {
                if (index >= numbers.size()) return false;
                value = numbers[index];
            } else if (group == 1) {
                if (index < blobs.size()) {
                    value = blobs[index].size();
                    bytes = blobs[index].data();
                } else {
                    if (index > 9 || !states[index - 8]) return false;
                    value = states[index - 8]->block_hash.size();
                    bytes = states[index - 8]->block_hash.begin();
                }
            } else {
                if (group > 5 || !states[(group - 2) / 2]) return false;
                const auto& state = *states[(group - 2) / 2];
                if (group & 1) {
                    if (index >= state.recent_times.size()) return false;
                    value = state.recent_times[index];
                } else {
                    const std::array<uint64_t, 6> fields{state.height, state.block_time, state.n_bits,
                        state.period_start_height, state.period_start_time, state.recent_times.size()};
                    if (index >= fields.size()) return false;
                    value = fields[index];
                }
            }
            return true;
        });
    auto writer = TaggedHash(BMM_FINGERPRINT_TAG);
    writer.write(AsBytes(Span{payload}));
    return writer.GetSHA256();
}

bool HasPersistedBmmConsensusState(const CCoinsView& view)
{
    const auto coin = view.GetCoin(Identity().outpoint);
    std::string unused;
    return haskell::BmmStateSource(4, coin && !coin->IsSpent(), {}, unused) != 0;
}

bool IsBmmStateInternalOutpoint(const COutPoint& outpoint)
{
    return outpoint == Identity().outpoint;
}

bool BmmProofRequiredAfter(const CBlockIndex* previous)
{
    using Step = haskell::BmmStateStep;
    bool required = false;
    haskell::RunBmmStateFlow(Step::ACTIVATION_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::ACTIVATION_PREFLIGHT:
            return haskell::BmmActivation(0, bool(Params().GetConsensus().drivechain_slot) |
                ((previous != nullptr) << 1));
        case Step::MODE_SELECT:
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
            return PrivateE2eBmmEnabled();
#else
            return 0;
#endif
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
        case Step::MODE_PRIVATE: {
            const bool present = gArgs.IsArgSet("-ecxprivatebmmactivationheight");
            required = haskell::BmmActivation(1, present, previous->nHeight,
                present ? gArgs.GetIntArg("-ecxprivatebmmactivationheight", -1) : -1) == 1;
            return 1;
        }
#endif
        case Step::MODE_PUBLIC:
            required = haskell::BmmActivation(2,
                (previous->GetBlockHash() == Identity().blocks[1]) |
                (((static_cast<uint32_t>(previous->nVersion) & CBlockHeader::BMM_PROOF_HF_MASK) != 0) << 1)) == 1;
            return 1;
        default: throw std::logic_error("unexpected BMM activation step");
        }
    });
    return required;
}

namespace {

bool CheckBmmHeaderCommitments(
    const int32_t version,
    const uint256& proof_commitment,
    const uint256& block_hash,
    const CBlockIndex* previous,
    std::string& error,
    const bool allow_incomplete_candidate)
{
    error.clear();
    const bool native = bool(Params().GetConsensus().drivechain_slot);
    const uint32_t facts = native | ((previous != nullptr) << 1) |
        ((!native && previous && previous->GetBlockHash() == Identity().blocks[0]) << 2) |
        ((block_hash == Identity().blocks[1]) << 3) |
        (((static_cast<uint32_t>(version) & CBlockHeader::BMM_PROOF_HF_MASK) != 0) << 4) |
        ((!proof_commitment.IsNull()) << 5) | (allow_incomplete_candidate << 7);
    const auto preflight = haskell::BmmHeader(facts, error);
    if (preflight != 6) return preflight == 0;
    return haskell::BmmHeader(facts | (BmmProofRequiredAfter(previous) << 6) | 256, error) == 0;
}

} // namespace

bool CheckBmmHeader(
    const CBlockHeader& block,
    const CBlockIndex* previous,
    std::string& error,
    const bool allow_incomplete_candidate)
{
    return CheckBmmHeaderCommitments(
        block.nVersion,
        block.hashBmmProof,
        block.GetHash(),
        previous,
        error,
        allow_incomplete_candidate);
}

bool CheckBmmIndexHeader(
    const CBlockIndex& index,
    std::string& error)
{
    return CheckBmmHeaderCommitments(
        index.nVersion,
        index.hashBmmProof,
        index.GetBlockHash(),
        index.pprev,
        error,
        /* allow_incomplete_candidate */ false);
}

bool SerializeBmmProof(
    const BmmProof& proof,
    std::vector<unsigned char>& bytes,
    std::string& error)
{
    error.clear();
    try {
        bytes = SerializeValue(proof);
        return haskell::BmmCodec(haskell::BmmCodecPhase::ENCODE_SIZE, 0, bytes.size(), MAX_BMM_PROOF_BYTES, error);
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool DeserializeBmmProof(
    const std::vector<unsigned char>& bytes,
    BmmProof& proof,
    std::string& error)
{
    error.clear();
    using Phase = haskell::BmmCodecPhase;
    using Step = haskell::BmmStateStep;
    bool decoded{false};
    return haskell::RunBmmStateFlow(Step::PROOF_START, [&](Step action) {
        switch (action) {
        case Step::PROOF_SIZE: return haskell::BmmCodec(Phase::DECODE_SIZE, 0, bytes.size(), MAX_BMM_PROOF_BYTES, error);
        case Step::PROOF_DECODE: decoded = DeserializeExactly(bytes, proof); return decoded;
        case Step::PROOF_SHAPE: {
            const bool version = decoded && proof.version == BMM_PROOF_SCHEMA_VERSION;
            return haskell::BmmCodec(Phase::DECODE_SHAPE, decoded | (version << 1),
                version ? proof.entries.size() : 0, MAX_BMM_PROOF_ENTRIES, error);
        }
        case Step::PROOF_CANONICAL: return haskell::BmmCodec(Phase::CANONICAL, SerializeValue(proof) == bytes, 0, 0, error);
        default: throw std::logic_error("invalid BMM proof decode action");
        }
    });
}

uint256 BmmProofCommitment(const std::vector<unsigned char>& bytes)
{
    return Hash(bytes);
}

bool AttachBmmProof(CBlock& block, const BmmProof& proof, std::string& error)
{
    error.clear();
    using Step = haskell::BmmStateStep;
    return haskell::RunBmmStateFlow(Step::ATTACH_START, [&](Step action) {
        switch (action) {
        case Step::ATTACH_GATE: return haskell::BmmCodec(haskell::BmmCodecPhase::ATTACH, block.HasBmmProof(), 0, 0, error);
        case Step::ATTACH_SERIALIZE: return SerializeBmmProof(proof, block.m_bmm_proof, error);
        case Step::ATTACH_PUBLISH: block.hashBmmProof = BmmProofCommitment(block.m_bmm_proof); return true;
        default: throw std::logic_error("invalid BMM attachment action");
        }
    });
}

#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
bool BuildPrivateE2eBmmProof(
    const BmmL1State& previous,
    const uint256& critical_hash,
    BmmProof& proof,
    std::string& error)
{
    error.clear();
    Sidechain::Bitcoin::CMutableTransaction coinbase;
    Sidechain::Bitcoin::CBlockHeader header;
    arith_uint256 target;
    using Step = haskell::BmmStateStep;
    std::array<uint32_t, 4> fields{};
    return haskell::RunBmmStateFlow(Step::PRIVATE_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::PRIVATE_ENABLED: {
            const bool enabled = PrivateE2eBmmEnabled();
            if (!enabled) error = "private BMM proof construction is disabled";
            return enabled;
        }
        case Step::PRIVATE_VALID:
            return ValidState(previous, PrivateBmmConsensus(), error);
        case Step::PRIVATE_COINBASE: {
            std::array<unsigned char, 37> m8{};
            haskell::BmmPrivateTemplate(previous.height, previous.block_time,
                haskell::BmmMedian(previous.recent_times), BMM_SIDECHAIN_SLOT,
                std::span<const unsigned char, 32>{critical_hash.begin(), 32}, fields, m8);
            coinbase.version = fields[0];
            coinbase.vin.resize(1);
            coinbase.vin[0].prevout.SetNull();
            coinbase.vin[0].scriptSig = CScript() << static_cast<int64_t>(fields[1]);
            coinbase.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(m8.begin(), m8.end()));

            return 1;
        }
        case Step::PRIVATE_HEADER:
            header.nVersion = fields[2];
            header.hashPrevBlock = previous.block_hash;
            header.hashMerkleRoot = coinbase.GetHash();
            header.nTime = fields[3];
            header.nBits = ExpectedNextBits(previous, PrivateBmmConsensus());
            target.SetCompact(header.nBits);
            return 1;
        case Step::PRIVATE_POW:
            return UintToArith256(header.GetHash()) <= target;
        case Step::PRIVATE_NONCE:
            ++header.nNonce;
            return 1;
        case Step::PRIVATE_ASSEMBLE: {
            Sidechain::Bitcoin::CMerkleBlock merkle;
            merkle.header = header;
            merkle.txn = Sidechain::Bitcoin::CPartialMerkleTree(
                {coinbase.GetHash()}, {true});
            proof = BmmProof{};
            proof.previous_state = previous;
            proof.entries.push_back({SerializeValue(coinbase), SerializeValue(merkle)});

            return 1;
        }
        case Step::PRIVATE_VERIFY: {
            BmmL1State next;
            return VerifyBmmProofEntries(proof, critical_hash, previous.block_hash,
                next, error, PrivateBmmConsensus());
        }
        default: throw std::logic_error("invalid private BMM construction action");
        }
    });
}
#endif

bool VerifyBmmProofEntries(
    const BmmProof& proof,
    const uint256& expected_critical_hash,
    const uint256& expected_parent_hash,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus)
{
    error.clear();
    BmmL1State state;
    Sidechain::Bitcoin::CMutableTransaction coinbase;
    Sidechain::Bitcoin::CMerkleBlock merkle_proof;
    std::vector<uint256> matches;
    std::vector<unsigned int> indices;
    uint256 mined_commitment;
    size_t index{0};
    using Step = haskell::BmmTraversalStep;
    return haskell::RunBmmTraversal(Step::START, [&](Step step) -> std::array<uint64_t,2> {
        uint64_t a{0}, b{0};
        switch (step) {
        case Step::PREFLIGHT:
            a = haskell::RunBmmStateFlow(haskell::BmmStateStep::PREFLIGHT_START, [&](auto action) {
                switch (action) {
                case haskell::BmmStateStep::PREFLIGHT_ENVELOPE:
                    return haskell::BmmProof(haskell::BmmProofPhase::ENVELOPE, proof.version == BMM_PROOF_SCHEMA_VERSION,
                        proof.entries.size(), consensus.max_entries, 0, error);
                case haskell::BmmStateStep::PREFLIGHT_STATE: return ValidState(proof.previous_state, consensus, error);
                default: throw std::logic_error("invalid BMM preflight action");
                }
            });
            break;
        case Step::INITIALIZE_ENTRIES:
            state = proof.previous_state;
            a = 1;
            break;
        case Step::ENTRY_BOUNDS: {
            const auto& entry = proof.entries.at(index);
            a = haskell::BmmProof(haskell::BmmProofPhase::BOUNDS, 0, entry.coinbase_tx.size(),
                entry.coinbase_proof.size(), MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR, error);
            break;
        }
        case Step::PREPARE_ENTRY: {
            const auto& entry = proof.entries.at(index);
            coinbase = {};
            merkle_proof = {};
            using Decode = haskell::BmmStateStep;
            uint32_t canonical{0};
            haskell::RunBmmStateFlow(Decode::ENTRY_START, [&](auto action) {
                bool accepted;
                switch (action) {
                case Decode::ENTRY_TX: accepted = DeserializeExactly(entry.coinbase_tx, coinbase); break;
                case Decode::ENTRY_PROOF: accepted = DeserializeExactly(entry.coinbase_proof, merkle_proof); break;
                case Decode::ENTRY_TX_CANONICAL: accepted = SerializeValue(coinbase) == entry.coinbase_tx; break;
                case Decode::ENTRY_PROOF_CANONICAL: accepted = SerializeValue(merkle_proof) == entry.coinbase_proof; break;
                default: throw std::logic_error("invalid BMM entry decode action");
                }
                canonical |= uint32_t{accepted} << (static_cast<uint32_t>(action) - static_cast<uint32_t>(Decode::ENTRY_TX));
                return accepted;
            });
            canonical |= (!coinbase.vin.empty() && coinbase.vin[0].prevout.IsNull()) << 4;
            a = haskell::BmmProof(haskell::BmmProofPhase::CANONICAL, canonical, coinbase.vin.size(), 0, 0, error);
            break;
        }
        case Step::MERKLE: {
            matches.clear();
            indices.clear();
            const bool root = merkle_proof.txn.ExtractMatches(matches, indices) == merkle_proof.header.hashMerkleRoot;
            a = haskell::BmmProof(haskell::BmmProofPhase::MERKLE, root, matches.size(), indices.size(),
                indices.empty() ? UINT32_MAX : indices[0], error);
            break;
        }
        case Step::COINBASE:
            a = haskell::BmmProof(haskell::BmmProofPhase::MERKLE_HASH, matches.at(0) == coinbase.GetHash(), 0, 0, 0, error);
            break;
        case Step::EXTENSION: {
            const auto& header = merkle_proof.header;
            using Extend = haskell::BmmStateStep;
            uint32_t facts{0};
            a = haskell::RunBmmStateFlow(Extend::EXTEND_START, [&](auto action) {
                bool accepted;
                switch (action) {
                case Extend::EXTEND_PARENT: accepted = header.hashPrevBlock == state.block_hash; break;
                case Extend::EXTEND_DIFFICULTY: accepted = header.nBits == ExpectedNextBits(state, consensus); break;
                case Extend::EXTEND_TIME: accepted = header.nTime > haskell::BmmMedian(state.recent_times); break;
                case Extend::EXTEND_CHECK: return haskell::BmmProof(haskell::BmmProofPhase::EXTENSION, facts, 0, 0, 0, error);
                case Extend::EXTEND_POW: return CheckParentProofOfWork(header, consensus, error);
                default: throw std::logic_error("invalid BMM extension action");
                }
                facts |= uint32_t{accepted} << (static_cast<uint32_t>(action) - static_cast<uint32_t>(Extend::EXTEND_PARENT));
                return accepted;
            });
            b = consensus.require_signet_solution;
            break;
        }
        case Step::SIGNET:
            a = CheckSignetSolution(coinbase, merkle_proof, consensus, error);
            break;
        case Step::ADVANCE: {
            const auto& header = merkle_proof.header;
            std::array<uint32_t, 16> fields{state.height, state.block_time, state.n_bits, state.period_start_height, state.period_start_time};
            if (state.recent_times.size() != 11) throw std::runtime_error("invalid native BMM history size");
            std::copy(state.recent_times.begin(), state.recent_times.end(), fields.begin() + 5);
            haskell::BmmAdvance(consensus.DifficultyAdjustmentInterval(), header.nTime, header.nBits, fields);
            state.block_hash = header.GetHash();
            state.height = fields[0]; state.block_time = fields[1]; state.n_bits = fields[2];
            state.period_start_height = fields[3]; state.period_start_time = fields[4];
            std::copy(fields.begin() + 5, fields.end(), state.recent_times.begin());
            a = index++;
            b = proof.entries.size();
            break;
        }
        case Step::PARENT:
            a = haskell::BmmProof(haskell::BmmProofPhase::PARENT,
                merkle_proof.header.hashPrevBlock == expected_parent_hash, 0, 0, 0, error);
            break;
        case Step::COMMITMENT:
            a = ExtractM8Commitment(coinbase, consensus.sidechain_slot, mined_commitment, error);
            break;
        case Step::CRITICAL:
            a = haskell::BmmProof(haskell::BmmProofPhase::CRITICAL, mined_commitment == expected_critical_hash, 0, 0, 0, error);
            break;
        case Step::PUBLISH_ENTRIES:
            next_state = std::move(state);
            break;
        default: throw std::runtime_error("invalid native BMM traversal action");
        }
        return {a,b};
    },error);
}

bool VerifyBmmProof(
    const CBlock& block,
    const BmmL1State& expected_previous,
    BmmL1State& next_state,
    std::string& error,
    const BmmConsensus& consensus)
{
    error.clear();
    BmmProof proof;
    uint256 parent_hash;
    using Step = haskell::BmmTraversalStep;
    return haskell::RunBmmTraversal(Step::BLOCK_START, [&](Step step) -> std::array<uint64_t,2> {
        bool accepted;
        switch (step) {
        case Step::BLOCK_BOUNDS:
            accepted = haskell::BmmProof(haskell::BmmProofPhase::BLOCK_BOUNDS,
                block.HasBmmProof() | ((!block.hashBmmProof.IsNull()) << 1), block.m_bmm_proof.size(), consensus.max_proof_bytes, 0, error);
            break;
        case Step::BLOCK_HASH:
            accepted = haskell::BmmProof(haskell::BmmProofPhase::BLOCK_HASH,
                BmmProofCommitment(block.m_bmm_proof) == block.hashBmmProof, 0, 0, 0, error);
            break;
        case Step::BLOCK_DECODE:
            accepted = DeserializeBmmProof(block.m_bmm_proof, proof, error);
            break;
        case Step::BLOCK_PRIOR:
            accepted = haskell::BmmProof(haskell::BmmProofPhase::PRIOR, proof.previous_state == expected_previous, 0, 0, 0, error);
            break;
        case Step::BLOCK_PARENT:
            accepted = ExtractSidechainParentHash(block, parent_hash, error);
            break;
        case Step::BLOCK_ENTRIES:
            accepted = VerifyBmmProofEntries(proof, block.GetBmmCriticalHash(), parent_hash, next_state, error, consensus);
            break;
        default: throw std::runtime_error("invalid native BMM block action");
        }
        return {accepted,0};
    },error);
}

bool GetBmmState(
    const CCoinsViewCache& view,
    BmmL1State& state,
    std::string* error)
{
    const Coin& coin = view.AccessCoin(Identity().outpoint);
    std::string decode_error;
    if (haskell::BmmStateSource(4, !coin.IsSpent(), {}, decode_error) == 0) return false;
    const bool decoded = DecodeBmmState(coin, state, decode_error);
    std::string ignored;
    return haskell::BmmStateSource(5, decoded, decode_error, error ? *error : ignored) == 0;
}

bool GetBmmParentContext(
    const BmmL1State& state,
    BmmParentContext& context,
    std::string& error)
{
    error.clear();
    context = {};
    using Step = haskell::BmmStateStep;
    int64_t median_time_past{0};
    return haskell::RunBmmStateFlow(Step::CONTEXT_START, [&](Step action) {
        switch (action) {
        case Step::CONTEXT_VALID: return ValidState(state, LayerTwoLabsBmmConsensus(), error);
        case Step::CONTEXT_MEDIAN:
            median_time_past = haskell::BmmParentMedian(state.recent_times, error);
            return median_time_past >= 0;
        case Step::CONTEXT_PUBLISH:
            context.block_hash = state.block_hash;
            context.height = state.height;
            context.median_time_past = median_time_past;
            return true;
        default: throw std::logic_error("invalid BMM parent context action");
        }
    });
}

bool GetEffectiveBmmState(
    const CCoinsViewCache& view,
    const CBlockIndex* previous,
    BmmL1State& state,
    std::string& error)
{
    std::string state_error;
    using Step = haskell::BmmStateStep;
    return haskell::RunBmmStateFlow(Step::EFFECTIVE_START, [&](Step action) -> int32_t {
        switch (action) {
        case Step::EFFECTIVE_NETWORK: return haskell::BmmStateSource(0, bool(Params().GetConsensus().drivechain_slot), {}, error);
        case Step::EFFECTIVE_LOAD: {
            const bool found = GetBmmState(view, state, &state_error);
            return haskell::BmmStateSource(1, found | ((!state_error.empty()) << 1), state_error, error);
        }
        case Step::EFFECTIVE_PUBLIC:
            return haskell::BmmStateSource(2, previous && previous->GetBlockHash() == Identity().blocks[1], {}, error);
        case Step::EFFECTIVE_PUBLISH_PUBLIC: state = PublicBmmCheckpoint(); return 1;
        case Step::EFFECTIVE_PRIVATE:
#ifdef ECX_SIMPLICITY_PRIVATE_E2E_CATALOGUE
            return haskell::BmmStateSource(3, PrivateE2eBmmEnabled(), {}, error);
        case Step::EFFECTIVE_PUBLISH_PRIVATE: state = PrivateBmmCheckpoint(); return 1;
#else
            return haskell::BmmStateSource(3, 0, {}, error);
#endif
        default: throw std::logic_error("invalid BMM effective state action");
        }
    });
}

bool ConnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    const bool allow_incomplete_candidate,
    std::string& error)
{
    using Phase = haskell::BmmLifecyclePhase;
    using Step = haskell::BmmStateStep;
    BmmL1State previous_state, next_state;
    std::string state_error;
    return haskell::RunBmmStateFlow(Step::CONNECT_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::CONNECT_KIND:
            return haskell::BmmLifecycle(Phase::CONNECT_KIND, bool(Params().GetConsensus().drivechain_slot), {}, error);
        case Step::NATIVE_HEADER:
            return CheckBmmHeader(block, previous, error, false);
        case Step::NATIVE_STATE: {
            bool has_state{false};
            return haskell::RunBmmStateFlow(Step::NATIVE_CHECK_START, [&](Step action) -> int32_t {
                switch (action) {
                case Step::NATIVE_CHECK_PROOF: has_state = !block.m_bmm_proof.empty(); return has_state;
                case Step::NATIVE_CHECK_LOOKUP: has_state = HasPersistedBmmConsensusState(view); return has_state;
                case Step::NATIVE_CHECK_RESULT: return haskell::BmmLifecycle(Phase::NATIVE_STATE, has_state, {}, error);
                default: throw std::logic_error("invalid native BMM state check");
                }
            }) ? 0 : -1;
        }
        case Step::CHECKPOINT:
            return haskell::BmmLifecycle(Phase::CONNECT_CHECKPOINT, IsPublicBmmCheckpoint(block, previous), {}, error);
        case Step::INITIALIZE: {
            const bool found = GetBmmState(view, previous_state, &state_error);
            return haskell::BmmLifecycle(Phase::INITIALIZE, found | ((!state_error.empty()) << 1), state_error, error);
        }
        case Step::STORE_INITIAL:
            SetBmmState(view, PublicBmmCheckpoint(), height);
            return 1;
        case Step::REQUIRED: {
            const bool required = BmmProofRequiredAfter(previous);
            return haskell::BmmLifecycle(Phase::REQUIRED, required | ((!required && block.HasBmmProof()) << 1), {}, error);
        }
        case Step::INCOMPLETE: {
            return haskell::BmmLifecycle(Phase::INCOMPLETE, allow_incomplete_candidate |
                (block.HasBmmProof() << 1) | (block.hashBmmProof.IsNull() << 2) |
                (block.m_bmm_proof.empty() << 3), {}, error);
        }
        case Step::EFFECTIVE:
            return GetEffectiveBmmState(view, previous, previous_state, error);
        case Step::VERIFY:
            return VerifyBmmProof(block, previous_state, next_state, error, LayerTwoLabsBmmConsensus());
        case Step::STORE_NEXT:
            SetBmmState(view, next_state, height);
            return 1;
        default: throw std::runtime_error("invalid native BMM connect action");
        }
    });
}

bool DisconnectBmmState(
    const CBlock& block,
    const CBlockIndex* previous,
    CCoinsViewCache& view,
    const int height,
    std::string& error)
{
    using Phase = haskell::BmmLifecyclePhase;
    using Step = haskell::BmmStateStep;
    BmmProof proof;
    BmmL1State current, expected_next;
    std::string state_error;
    uint256 parent_hash;
    return haskell::RunBmmStateFlow(Step::DISCONNECT_START, [&](Step step) -> int32_t {
        switch (step) {
        case Step::DISCONNECT_KIND:
            return haskell::BmmLifecycle(Phase::DISCONNECT_KIND, IsPublicBmmCheckpoint(block, previous), {}, error);
        case Step::REMOVE_CHECKPOINT: {
            const bool found = GetBmmState(view, current, &state_error);
            const bool same = found && current == PublicBmmCheckpoint();
            return haskell::BmmLifecycle(Phase::REMOVE_CHECKPOINT, found | (same << 1) |
                ((!state_error.empty()) << 2), state_error, error);
        }
        case Step::REMOVE:
            return haskell::BmmLifecycle(Phase::REMOVED, view.SpendCoin(Identity().outpoint), {}, error);
        case Step::HAS_PROOF:
            return haskell::BmmLifecycle(Phase::DISCONNECT_PROOF, block.HasBmmProof(), {}, error);
        case Step::DECODE_PROOF:
            return DeserializeBmmProof(block.m_bmm_proof, proof, error);
        case Step::LOAD_CURRENT: {
            const bool found = GetBmmState(view, current, &state_error);
            return haskell::BmmLifecycle(Phase::LOAD_CURRENT, found | ((!state_error.empty()) << 1), state_error, error);
        }
        case Step::EXTRACT_PARENT:
            return ExtractSidechainParentHash(block, parent_hash, error);
        case Step::VERIFY_ENTRIES:
            return VerifyBmmProofEntries(proof, block.GetBmmCriticalHash(), parent_hash,
                expected_next, error, LayerTwoLabsBmmConsensus());
        case Step::COMPARE_CURRENT:
            return haskell::BmmLifecycle(Phase::RESTORE, current == expected_next, {}, error);
        case Step::REJECT_PRIOR:
            return haskell::BmmLifecycle(Phase::RESTORE, false, {}, error);
        case Step::STORE_PRIOR:
            SetBmmState(view, proof.previous_state, height, true);
            return 1;
        default: throw std::runtime_error("invalid native BMM disconnect action");
        }
    });
}

} // namespace drivechain
