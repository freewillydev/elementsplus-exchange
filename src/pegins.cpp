// Copyright (c) 2017-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pegins.h>
#include <limits>
#include <span>

#include <addresstype.h>
#include <arith_uint256.h>
#include <block_proof.h>
#include <chainparams.h>
#include <crypto/hmac_sha256.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <haskell/bridge.h>
#include <haskell/resource_constants.h>
#include <merkleblock.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <primitives/bitcoin/merkleblock.h>
#include <secp256k1.h>
#include <script/interpreter.h>
#include <streams.h>
#include <util/moneystr.h>
#include <dynafed.h>

//
// ELEMENTS
//

#include <validation.h>

namespace {
static secp256k1_context* secp256k1_ctx_validation;

class Secp256k1Ctx
{
public:
    Secp256k1Ctx() {
        assert(secp256k1_ctx_validation == nullptr);
        secp256k1_ctx_validation = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
        assert(secp256k1_ctx_validation != nullptr);
    }

    ~Secp256k1Ctx() {
        assert(secp256k1_ctx_validation != nullptr);
        secp256k1_context_destroy(secp256k1_ctx_validation);
        secp256k1_ctx_validation = nullptr;
    }
};
static Secp256k1Ctx instance_of_secp256k1ctx;

static const std::vector<unsigned char> DRIVECHAIN_DEPOSIT_MARKER(
    std::begin(ElementsDrivechainIdentity::DEPOSIT_MARKER), std::end(ElementsDrivechainIdentity::DEPOSIT_MARKER));
static const std::vector<unsigned char> ECX_LEGACY_DEPOSIT_MARKER(
    std::begin(ElementsDrivechainIdentity::LEGACY_DEPOSIT_MARKER), std::end(ElementsDrivechainIdentity::LEGACY_DEPOSIT_MARKER));

template <typename T>
static bool DeserializeExactly(const std::vector<unsigned char>& bytes, T& value)
{
    try {
        DataStream stream(bytes);
        stream >> TX_WITH_WITNESS(value);
        return stream.empty();
    } catch (...) {
        return false;
    }
}

template <typename T>
static std::vector<unsigned char> SerializeEvidenceField(const T& value)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(value);
    return std::vector<unsigned char>(
        UCharCast(stream.data()),
        UCharCast(stream.data()) + stream.size());
}

static int32_t HashDepositTransaction(const unsigned char* bytes, uint32_t size, unsigned char* hash)
{
    try {
        Sidechain::Bitcoin::CMutableTransaction tx;
        DataStream stream{Span<const unsigned char>{bytes, size}};
        stream >> TX_WITH_WITNESS(tx);
        if (!stream.empty()) return 0;
        const uint256 txid = tx.GetHash();
        std::copy(txid.begin(), txid.end(), hash);
        return 1;
    } catch (...) { return 0; }
}

static bool ReadPeginWitnessPrefix(const CScriptWitness& pegin_witness, CAmount& value, CAsset& asset, uint256& genesis_hash, CScript& claim_script, std::string& err_msg)
{
    const auto& stack = pegin_witness.stack;
    if (stack.size() < 4) {
        err_msg = "Not enough stack items.";
        return false;
    }

    DataStream stream(stack[0]);
    try {
        stream >> value;
    } catch (...) {
        err_msg = "Could not deserialize value.";
        return false;
    }

    if (!MoneyRange(value)) {
        err_msg = "Value was not in valid value range.";
        return false;
    }

    if (stack[1].size() != 32) {
        err_msg = "Asset type was not 32 bytes.";
        return false;
    }
    asset = CAsset(stack[1]);

    if (stack[2].size() != 32) {
        err_msg = "Parent genesis blockhash was not 32 bytes.";
        return false;
    }
    genesis_hash = uint256(stack[2]);

    claim_script = CScript(stack[3].begin(), stack[3].end());
    if (claim_script.size() > 100) {
        err_msg = "Claim script is too large.";
        return false;
    }

    return true;
}
}

bool GetAmountFromParentChainPegin(CAmount& amount, const Sidechain::Bitcoin::CTransaction& txBTC, unsigned int nOut)
{
    amount = txBTC.vout[nOut].nValue;
    return true;
}

bool GetAmountFromParentChainPegin(CAmount& amount, const CTransaction& txBTC, unsigned int nOut)
{
    if (!txBTC.vout[nOut].nValue.IsExplicit()) {
        return false;
    }
    if (!txBTC.vout[nOut].nAsset.IsExplicit()) {
        return false;
    }
    if (txBTC.vout[nOut].nAsset.GetAsset() != Params().GetConsensus().parent_pegged_asset) {
        return false;
    }
    amount = txBTC.vout[nOut].nValue.GetAmount();
    return true;
}

// Takes federation redeem script and adds HMAC_SHA256(pubkey, scriptPubKey) as a tweak to each pubkey
CScript calculate_contract(const CScript& federation_script, const CScript& scriptPubKey) {
    CScript scriptDestination;

    bool is_liquidv1_watchman = MatchLiquidWatchman(federation_script);

    CScript::const_iterator sdpc = federation_script.begin();
    std::vector<unsigned char> vch;
    opcodetype opcodeTmp;
    bool liquid_op_else_found = false;
    while (federation_script.GetOp(sdpc, opcodeTmp, vch))
    {

        // For liquidv1 initial watchman template, don't tweak emergency keys
        if (is_liquidv1_watchman && opcodeTmp == OP_ELSE) {
            liquid_op_else_found = true;
        }

        size_t pub_len = 33;
        if (vch.size() == pub_len && !liquid_op_else_found)
        {
            unsigned char tweak[32];
            CHMAC_SHA256(vch.data(), pub_len).Write(scriptPubKey.data(), scriptPubKey.size()).Finalize(tweak);
            int ret;
            secp256k1_pubkey watchman;
            secp256k1_pubkey tweaked;
            ret = secp256k1_ec_pubkey_parse(secp256k1_ctx_validation, &watchman, vch.data(), pub_len);
            assert(ret == 1);
            ret = secp256k1_ec_pubkey_parse(secp256k1_ctx_validation, &tweaked, vch.data(), pub_len);
            assert(ret == 1);
            // If someone creates a tweak that makes this fail, they broke SHA256
            ret = secp256k1_ec_pubkey_tweak_add(secp256k1_ctx_validation, &tweaked, tweak);
            assert(ret == 1);
            unsigned char new_pub[33];
            ret = secp256k1_ec_pubkey_serialize(secp256k1_ctx_validation, new_pub, &pub_len, &tweaked, SECP256K1_EC_COMPRESSED);
            assert(ret == 1);
            assert(pub_len == 33);

            // push tweaked pubkey
            std::vector<unsigned char> pub_vec(new_pub, new_pub + pub_len);
            scriptDestination << pub_vec;

            // Sanity checks to reduce pegin risk. If the tweaked
            // value flips a bit, we may lose pegin funds irretrievably.
            // We take the tweak, derive its pubkey and check that
            // `tweaked - watchman = tweak` to check the computation
            // two different ways
            secp256k1_pubkey tweaked2;
            ret = secp256k1_ec_pubkey_create(secp256k1_ctx_validation, &tweaked2, tweak);
            assert(ret);
            ret = secp256k1_ec_pubkey_negate(secp256k1_ctx_validation, &watchman);
            assert(ret);
            secp256k1_pubkey* pubkey_combined[2];
            pubkey_combined[0] = &watchman;
            pubkey_combined[1] = &tweaked;
            secp256k1_pubkey maybe_tweaked2;
            ret = secp256k1_ec_pubkey_combine(secp256k1_ctx_validation, &maybe_tweaked2, pubkey_combined, 2);
            assert(ret);
            assert(!memcmp(&maybe_tweaked2, &tweaked2, 64));
        } else {
            // add to script untouched
            if (vch.size() > 0) {
                scriptDestination << vch;
            } else {
                scriptDestination << opcodeTmp;
            }
        }
    }

    return scriptDestination;
}

template<typename T>
static bool CheckPeginTx(const std::vector<unsigned char>& tx_data, T& pegtx, const COutPoint& prevout, const CAmount claim_amount, const CScript& claim_script, const std::vector<std::pair<CScript, CScript>>& fedpegscripts)
{
    try {
        DataStream pegtx_stream(tx_data);
        pegtx_stream >> TX_WITH_WITNESS(pegtx);
        if (!pegtx_stream.empty()) {
            return false;
        }
    } catch (std::exception&) {
        // Invalid encoding of transaction
        return false;
    }

    // Check that transaction matches txid
    if (pegtx->GetHash() != prevout.hash) {
        return false;
    }

    if (prevout.n >= pegtx->vout.size()) {
        return false;
    }
    CAmount amount = 0;
    if (!GetAmountFromParentChainPegin(amount, *pegtx, prevout.n)) {
        return false;
    }
    // Check the transaction nout/value matches
    if (claim_amount != amount) {
        return false;
    }

    // Check that the witness program matches the p2ch on the (p2sh-)p2wsh
    // transaction output. We support multiple scripts as a grace period for peg-in users
    for (const auto& scripts : fedpegscripts) {
        int fedpeg_version = 0;
        std::vector<unsigned char> fedpeg_program;
        scripts.first.IsWitnessProgram(fedpeg_version, fedpeg_program);
        // We immediately return true if any fedpegscripts are unencumbered
        // by currently-known parent chain segwit versions.
        // TODO: Refactor for future versionbits deployment of parent-segwit version
        if (fedpeg_version > 0) {
            return true;
        }
        CScript tweaked_fedpegscript = calculate_contract(scripts.second, claim_script);
        CScript expected_script(GetScriptForDestination(WitnessV0ScriptHash(tweaked_fedpegscript)));
        if (scripts.first.IsPayToScriptHash()) {
            expected_script = GetScriptForDestination(ScriptHash(expected_script));
        }
        if (pegtx->vout[prevout.n].scriptPubKey == expected_script) {
            return true;
        }
    }
    return false;
}

template<typename T>
static bool GetBlockAndTxFromMerkleBlock(uint256& block_hash, uint256& tx_hash, unsigned int& tx_index, T& merkle_block, const std::vector<unsigned char>& merkle_block_raw)
{
    try {
        std::vector<uint256> tx_hashes;
        std::vector<unsigned int> tx_indices;
        DataStream merkle_block_stream{merkle_block_raw};
        merkle_block_stream >> TX_NO_WITNESS(merkle_block);
        block_hash = merkle_block.header.GetHash();

        if (!merkle_block_stream.empty()) {
           return false;
        }
        if (merkle_block.txn.ExtractMatches(tx_hashes, tx_indices) != merkle_block.header.hashMerkleRoot || tx_hashes.size() != 1) {
            return false;
        }
        tx_hash = tx_hashes[0];
        tx_index = tx_indices[0];
    } catch (std::exception&) {
        // Invalid encoding of merkle block
        return false;
    }
    return true;
}

bool CheckParentProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.parentChainPowLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

static bool CheckFederatedPegin(const std::vector<std::vector<unsigned char>>& stack,
    const std::vector<std::pair<CScript, CScript>>& fedpegscripts, const COutPoint& prevout,
    CAmount value, const CAsset& asset, const uint256& gen_hash, const CScript& claim_script,
    std::string& err_msg, bool check_depth, bool* depth_failed)
{
    // 0) Return false if !consensus.has_parent_chain
    if (!Params().GetConsensus().has_parent_chain) {
        err_msg = "Parent chain is not enabled on this network.";
        return false;
    }

    uint256 block_hash;
    uint256 tx_hash;
    int num_txs;
    unsigned int tx_index = 0;
    // Get txout proof
    if (Params().GetConsensus().ParentChainHasPow()) {
        Sidechain::Bitcoin::CMerkleBlock merkle_block_pow;
        if (!GetBlockAndTxFromMerkleBlock(block_hash, tx_hash, tx_index, merkle_block_pow, stack[5])) {
            err_msg = "Could not extract block and tx from merkleblock.";
            return false;
        }
        if (!CheckParentProofOfWork(block_hash, merkle_block_pow.header.nBits, Params().GetConsensus())) {
            err_msg = "Parent proof of work is invalid or insufficient.";
            return false;
        }

        Sidechain::Bitcoin::CTransactionRef pegtx;
        if (!CheckPeginTx(stack[4], pegtx, prevout, value, claim_script, fedpegscripts)) {
            err_msg = "Peg-in tx is invalid.";
            return false;
        }

        num_txs = merkle_block_pow.txn.GetNumTransactions();
    } else {
        CMerkleBlock merkle_block;
        if (!GetBlockAndTxFromMerkleBlock(block_hash, tx_hash, tx_index, merkle_block, stack[5])) {
            err_msg = "Could not extract block and tx from merkleblock.";
            return false;
        }

        if (!CheckProofSignedParent(merkle_block.header, Params().GetConsensus())) {
            err_msg = "Parent signed block is invalid.";
            return false;
        }

        CTransactionRef pegtx;
        if (!CheckPeginTx(stack[4], pegtx, prevout, value, claim_script, fedpegscripts)) {
            err_msg = "Peg-in tx is invalid.";
            return false;
        }

        num_txs = merkle_block.txn.GetNumTransactions();
    }

    // Check that the merkle proof corresponds to the txid
    if (prevout.hash != tx_hash) {
        err_msg = "Merkle proof and txid mismatch.";
        return false;
    }

    // Check the genesis block corresponds to a valid peg (only one for now)
    if (gen_hash != Params().ParentGenesisBlockHash()) {
        err_msg = "Parent genesis block mismatch.";
        return false;
    }

    // Check the asset type corresponds to a valid pegged asset (only one for now)
    if (asset != Params().GetConsensus().pegged_asset) {
        return false;
    }

    // Finally, validate peg-in via rpc call
    if (check_depth && gArgs.GetBoolArg("-validatepegin", Params().GetConsensus().has_parent_chain)) {
        unsigned int required_depth = Params().GetConsensus().pegin_min_depth;
        // Don't allow coinbase output claims before coinbase maturity
        if (tx_index == 0) {
            required_depth = std::max(required_depth, (unsigned int)COINBASE_MATURITY);
        }
        if (!IsConfirmedBitcoinBlock(block_hash, required_depth, num_txs)) {
            err_msg = "Needs more confirmations.";
            if (depth_failed) {
                *depth_failed = true;
            }
            return false;
        }
    }
    return true;
}

bool IsValidPeginWitness(const CScriptWitness& pegin_witness,
                         const std::vector<std::pair<CScript, CScript>>& fedpegscripts,
                         const COutPoint& prevout,
                         std::string& err_msg,
                         bool check_depth,
                         bool* depth_failed,
                         bool* parent_unavailable,
                         const int child_height) {
    if (depth_failed) {
        *depth_failed = false;
    }
    if (parent_unavailable) {
        *parent_unavailable = false;
    }

    const auto& items = pegin_witness.stack;
    const auto routing = drivechain::haskell::SelectDepositRoute(items.size(),
        items.size() >= 5 && items[4] == ECX_LEGACY_DEPOSIT_MARKER,
        items.size() >= 5 && items[4] == DRIVECHAIN_DEPOSIT_MARKER,
        Params().GetConsensus().drivechain_slot.has_value());
    const auto route = routing.route;
    if (route == drivechain::haskell::DepositRoute::REJECT_ECX) {
        err_msg = "ECX deposit evidence is not a native Alpha CTIP witness.";
        return false;
    }

    // Format on stack is as follows:
    // 1) value - the value of the pegin output
    // 2) asset type - the asset type being pegged in
    // 3) genesis blockhash - genesis block of the parent chain
    // 4) claim script - script to be evaluated for spend authorization
    // 5) serialized transaction - serialized bitcoin transaction
    // 6) txout proof - merkle proof connecting transaction to header
    //
    // First 4 values(plus prevout) are enough to validate a peg-in without any internal knowledge
    // of Bitcoin serialization. This is useful for further abstraction by outsourcing
    // the other validity checks to RPC calls.

    const std::vector<std::vector<unsigned char> >& stack = pegin_witness.stack;
    const bool is_drivechain_deposit = route == drivechain::haskell::DepositRoute::NATIVE;
    const size_t expected_stack_size = routing.expected_stack_size;
    if (stack.size() != expected_stack_size) {
        err_msg = strprintf("Peg-in witness has %u stack items; expected %u.", stack.size(), expected_stack_size);
        return false;
    }

    CAmount value;
    CAsset asset;
    uint256 gen_hash;
    CScript claim_script;
    if (!ReadPeginWitnessPrefix(pegin_witness, value, asset, gen_hash, claim_script, err_msg)) return false;

    if (route == drivechain::haskell::DepositRoute::ECX) {
        const bool valid = IsDrivechainDepositPeginWitness(pegin_witness, prevout, nullptr, nullptr);
        if (!valid) err_msg = "Invalid drivechain deposit pegin witness.";
        return valid;
    }

    // Drivechain deposits are anchored by the bridge/two-way-peg data instead of
    // the legacy Elements parent-chain merkle proof, so recognize this marker
    // before applying the legacy parent-chain-enabled guard below.
    if (is_drivechain_deposit) {
        const auto& drivechain_slot = Params().GetConsensus().drivechain_slot;
        uint256 mainchain_block_hash;
        std::vector<unsigned char> address;
        std::string deposit_error;
        DrivechainDepositStatus deposit_status{};
        static const char* errors[]{"", "Drivechain deposits are not enabled on this network.",
            "Invalid drivechain deposit pegin witness.", "Parent genesis block mismatch.",
            "Pegin asset is not the pegged asset.", "Drivechain deposit claim script must be OP_TRUE."};
        const auto result = drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::NATIVE_DEPOSIT_ADMISSION,
            [&](uint32_t step) -> uint32_t {
                switch (step) {
                case 1: return drivechain_slot.has_value();
                case 2: return IsDrivechainDepositPeginWitness(pegin_witness, prevout, nullptr, nullptr, &mainchain_block_hash, &address);
                case 3: return gen_hash == Params().ParentGenesisBlockHash();
                case 4: return asset == Params().GetConsensus().pegged_asset;
                case 5: return claim_script == (CScript() << OP_TRUE);
                case 6:
                    deposit_status = GetConfirmedDrivechainDepositStatus(mainchain_block_hash, *drivechain_slot,
                        prevout, value, address, &deposit_error, child_height);
                    return deposit_status == DrivechainDepositStatus::VALID;
                case 7: return deposit_status == DrivechainDepositStatus::UNAVAILABLE;
                case 8: if (parent_unavailable) *parent_unavailable = true; return 0;
                case 9: case 10: case 11: case 12: case 13: err_msg = errors[step - 8]; return 0;
                case 14: err_msg = strprintf("BIP300 deposit is not confirmed on the mainchain: %s", deposit_error); return 0;
                default: throw std::runtime_error("Unknown native deposit admission step");
                }
            });
        if (result > 1) throw std::runtime_error("Invalid native deposit admission result");
        return result == 0;
    }

    // A slot-assigned Drivechain uses only native CTIP deposits. Accepting a
    // legacy federated pegin on the same network would create a second minting
    // path for the identical pegged asset, outside the BIP300 treasury delta
    // and duplicate-claim domain.
    if (route == drivechain::haskell::DepositRoute::REJECT_FEDERATED) {
        err_msg = "Legacy federated peg-ins are disabled on a Drivechain network.";
        return false;
    }

    return CheckFederatedPegin(stack, fedpegscripts, prevout, value, asset, gen_hash,
                               claim_script, err_msg, check_depth, depth_failed);
}

int32_t DepositWitnessKind(const CScriptWitness& witness, const COutPoint& prevout,
                          uint32_t mode, CAmount& value)
{
    return drivechain::haskell::DepositWitness(witness.stack, mode,
        Params().GetConsensus().pegged_asset.begin(), Params().ParentGenesisBlockHash().begin(),
        prevout.hash.ToUint256().begin(), HashDepositTransaction, value);
}

bool IsDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness,
                                     const COutPoint& prevout,
                                     CAmount* out_value,
                                     CScript* out_claim_script,
                                     uint256* out_mainchain_block_hash,
                                     std::vector<unsigned char>* out_address)
{
    const auto& stack = pegin_witness.stack;
    CAmount value;
    if (!DepositWitnessKind(pegin_witness, prevout, out_mainchain_block_hash || out_address ? 2 : 0, value)) return false;
    if (out_value != nullptr) *out_value = value;
    if (out_claim_script != nullptr) *out_claim_script = CScript(stack[3].begin(), stack[3].end());
    if (out_mainchain_block_hash != nullptr) *out_mainchain_block_hash = uint256(stack[6]);
    if (out_address != nullptr) *out_address = stack[7];
    return true;
}

namespace {
struct DepositDestinationAdapter {
    std::string_view original;
    CScript& recipient;
    CAmount& fee;
    CTxDestination destination;
    std::vector<unsigned char> operator()(uint32_t step, uint64_t index, std::span<const unsigned char> input)
    {
        switch (step) {
        case 1: recipient.clear(); fee = 0; return {};
        case 2: {
            destination = DecodeDestination(index == 1 ? std::string(original) : std::string(input.begin(),input.end()));
            std::vector<unsigned char> bytes(8);
            WriteLE64(bytes.data(),IsValidDestination(destination));
            return bytes;
        }
        case 3:
            if (input.size() != 8) throw std::logic_error("invalid deposit recipient fee frame");
            recipient = GetScriptForDestination(destination);
            fee = static_cast<int64_t>(ReadLE64(input.data()));
            return {};
        default: throw std::logic_error("invalid deposit recipient effect");
        }
    }
};

bool CheckNativeDepositOutputs(const CTransaction& tx, unsigned int index, bool canonical, std::string& error)
{
    CScript expected;
    CAmount fee{0};
    DepositDestinationAdapter destination{{},expected,fee,{}};
    return drivechain::haskell::CheckNativeDeposit(tx,index,canonical,
        Params().GetConsensus().pegged_asset.begin(),Params().ParentGenesisBlockHash().begin(),HashDepositTransaction,
        [&](uint32_t step, uint64_t item, std::span<const unsigned char> input) -> std::vector<unsigned char> {
            if (step <= 3) return destination(step,item,input);
            if (step == 10) {
                const auto& in = tx.vin.at(item);
                std::vector<unsigned char> bytes(8);
                WriteLE64(bytes.data(),in.m_is_pegin | (in.scriptSig.empty() << 1) | (in.assetIssuance.IsNull() << 2));
                return bytes;
            }
            if (step == 20) {
                const auto& out = tx.vout.at(item);
                const bool asset = out.nAsset.IsExplicit() && out.nAsset.GetAsset() == Params().GetConsensus().pegged_asset;
                const bool matches = out.scriptPubKey == expected;
                const uint64_t credit = matches | (asset << 1) | (out.nValue.IsExplicit() << 2) | (out.nNonce.IsCommitment() << 3);
                const uint64_t exact = asset | (out.nValue.IsExplicit() << 1) | (out.nNonce.IsNull() << 2) |
                    (out.scriptPubKey.empty() << 3) | (matches << 4);
                std::vector<unsigned char> bytes(16);
                WriteLE64(bytes.data(),credit | (exact << 8));
                WriteLE64(bytes.data()+8,out.nValue.IsExplicit() ? out.nValue.GetAmount() : 0);
                return bytes;
            }
            throw std::logic_error("invalid native deposit output effect");
        },error);
}
} // namespace

bool DecodeDrivechainDepositDestination(const std::string& payload, CScript& recipient, CAmount& fee)
{
    DepositDestinationAdapter native{payload,recipient,fee,{}};
    return drivechain::haskell::RunNativeRecipient(drivechain::haskell::NativeRecipient::DECODE,0,payload,std::ref(native));
}

std::string EncodeDrivechainDepositDestination(const std::string& address, CAmount fee)
{
    CScript recipient;
    CAmount unused{0};
    DepositDestinationAdapter native{address,recipient,unused,{}};
    std::string payload;
    drivechain::haskell::RunNativeRecipient(drivechain::haskell::NativeRecipient::ENCODE,fee,address,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) {
            if (step == 4) {
                payload.assign(input.begin(),input.end());
                return std::vector<unsigned char>{};
            }
            return native(step,index,input);
        });
    return payload;
}

bool CheckDrivechainDepositOutputs(const CTransaction& tx, const unsigned int pegin_index, std::string& err_msg)
{
    return CheckNativeDepositOutputs(tx,pegin_index,false,err_msg);
}

bool IsCanonicalFeeFreeDrivechainDeposit(const CTransaction& tx)
{
    std::string error;
    return CheckNativeDepositOutputs(tx,0,true,error);
}

bool GetDrivechainDepositPeginData(const CScriptWitness& pegin_witness, const COutPoint& prevout, CAmount& out_value, CScript& out_claim_script, uint256& out_mainchain_txid)
{
    CAmount value;
    if (!DepositWitnessKind(pegin_witness, prevout, 1, value)) return false;
    out_value = value;
    const auto& claim = pegin_witness.stack[3];
    out_claim_script = CScript(claim.begin(), claim.end());
    out_mainchain_txid = prevout.hash.ToUint256();
    return true;
}

bool IsEcxDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness,
                                       const COutPoint& prevout)
{
    CAmount value;
    return DepositWitnessKind(pegin_witness, prevout, 1, value) != 0;
}

bool IsLegacyDrivechainDepositPeginWitness(const CScriptWitness& pegin_witness)
{
    int64_t unused{0};
    return drivechain::haskell::DepositWitness(pegin_witness.stack,3,
        nullptr,nullptr,nullptr,nullptr,unused) != 0;
}

static int32_t DecodeDepositEvidenceFields(const std::vector<std::vector<unsigned char>>& fields,
    DrivechainDepositEvidence& value, int64_t* result)
{
    if (!DeserializeExactly(fields[8], value.sequence_number) ||
        !DeserializeExactly(fields[9], value.previous_sequence_number) ||
        !DeserializeExactly(fields[10], value.headers)) return 0;
    result[0] = value.sequence_number;
    result[1] = value.previous_sequence_number;
    result[2] = value.headers.size();
    return 1;
}

bool GetDrivechainDepositEvidence(
    const CScriptWitness& pegin_witness,
    const COutPoint& prevout,
    DrivechainDepositEvidence& evidence,
    std::string& error)
{
    const auto& stack = pegin_witness.stack;
    struct Context {
        const std::vector<std::vector<unsigned char>>& stack;
        DrivechainDepositEvidence decoded;
    } context{stack, {}};
    // Invoked only after Haskell has checked the stack shape and byte bounds.
    const auto decode = +[](void* opaque, int64_t* result) -> int32_t {
        auto& [fields, value] = *static_cast<Context*>(opaque);
        return DecodeDepositEvidenceFields(fields,value,result);
    };
    if (!drivechain::haskell::DepositEvidence(stack, prevout.hash.ToUint256().begin(),
            HashDepositTransaction, decode, &context, error)) return false;
    context.decoded.deposit_tx = stack[5];
    context.decoded.txout_proof = stack[6];
    context.decoded.previous_ctip_tx = stack[7];
    evidence = std::move(context.decoded);
    return true;
}

std::pair<uint256, COutPoint> GetPeginSpentKey(const CScriptWitness& pegin_witness, const COutPoint& prevout)
{
    if (IsDrivechainDepositPeginWitness(pegin_witness, prevout)) {
        return std::make_pair(prevout.hash, prevout);
    }
    return std::make_pair(uint256(pegin_witness.stack[2]), prevout);
}

bool MatchLiquidWatchman(const CScript& script)
{
    CScript::const_iterator it = script.begin();
    std::vector<unsigned char> data;
    opcodetype opcode;

    // Stack depth check for branch choice
    if (!script.GetOp(it, opcode, data) || opcode != OP_DEPTH) {
        return false;
    }
    // Take in value, then check equality
    if (!script.GetOp(it, opcode, data) ||
            !script.GetOp(it, opcode, data) ||
            opcode != OP_EQUAL) {
        return false;
    }
    // IF EQUAL
    if (!script.GetOp(it, opcode, data) || opcode != OP_IF) {
        return false;
    }
    // Take in value k, make sure minimally encoded number from 1 to 16
    if (!script.GetOp(it, opcode, data) ||
            opcode > OP_16 ||
            (opcode < OP_1NEGATE && !CheckMinimalPush(data, opcode))) {
        return false;
    }
    opcodetype opcode2 = opcode;
    std::vector<unsigned char> num = data;
    // Iterate through multisig stuff until ELSE is hit
    while (opcode != OP_ELSE) {
        if (!script.GetOp(it, opcode, data)) {
            return false;
        }
    }
    // Take minimally-encoded CSV push number k'
    if (!script.GetOp(it, opcode, data) ||
            opcode > OP_16 || (opcode < OP_1NEGATE && !CheckMinimalPush(data, opcode))) {
        return false;
    }
    // CSV
    if (!script.GetOp(it, opcode, data) || opcode != OP_CHECKSEQUENCEVERIFY) {
        return false;
    }
    // Drop the CSV number
    if (!script.GetOp(it, opcode, data) || opcode != OP_DROP) {
        return false;
    }
    // Take the minimally-encoded n of k-of-n multisig arg
    if (!script.GetOp(it, opcode, data) ||
            opcode > OP_16 || (opcode < OP_1NEGATE && !CheckMinimalPush(data, opcode)) ) {
        return false;
    }

    // The two multisig k-numbers must not match, otherwise ELSE branch can not be reached
    if (opcode == opcode2 && num == data) {
        return false;
    }

    // Find the ENDIF
    while (opcode != OP_ENDIF) {
        if (!script.GetOp(it, opcode, data)) {
            return false;
        }
    }
    // CHECKMULTISIG
    if (!script.GetOp(it, opcode, data) || opcode != OP_CHECKMULTISIG) {
        return false;
    }
    // No more pushes
    return (it == script.end());
}

std::vector<std::pair<CScript, CScript>> GetValidFedpegScripts(const CBlockIndex* pblockindex, const Consensus::Params& params, bool nextblock_validation)
{
    assert(pblockindex);

    std::vector<std::pair<CScript, CScript>> fedpegscripts;

    const int32_t epoch_length = (int32_t) params.dynamic_epoch_length;
    const int32_t epoch_age = pblockindex->nHeight % epoch_length;
    const int32_t epoch_start_height = pblockindex->nHeight - epoch_age;

    // In mempool and general "enforced next block" RPC we need to look ahead one block
    // to see if we're on a boundary. If so, put that epoch's fedpegscript in place
    if (nextblock_validation && epoch_age == epoch_length - 1) {
        DynaFedParamEntry next_param = ComputeNextBlockFullCurrentParameters(pblockindex, params);
        fedpegscripts.emplace_back(next_param.m_fedpeg_program, next_param.m_fedpegscript);
    }

    // Next we walk backwards up to M epoch starts
    for (int32_t i = 0; i < (int32_t) params.total_valid_epochs; i++) {
        // We are within total_valid_epochs of the genesis
        if (i * epoch_length > epoch_start_height) {
            break;
        }

        const CBlockIndex* p_epoch_start = pblockindex->GetAncestor(epoch_start_height-i*epoch_length);

        // We're done here, for whatever reason.
        if (!p_epoch_start) {
            break;
        }

        if (node::fTrimHeaders) {
            LOCK(cs_main);
            ForceUntrimHeader(p_epoch_start);
        }
        if (!p_epoch_start->dynafed_params().IsNull()) {
            fedpegscripts.emplace_back(p_epoch_start->dynafed_params().m_current.m_fedpeg_program, p_epoch_start->dynafed_params().m_current.m_fedpegscript);
        } else {
            fedpegscripts.emplace_back(GetScriptForDestination(ScriptHash(GetScriptForDestination(WitnessV0ScriptHash(params.fedpegScript)))), params.fedpegScript);
        }
    }
    // Only return up to the latest total_valid_epochs fedpegscripts, which are enforced
    fedpegscripts.resize(std::min(fedpegscripts.size(), params.total_valid_epochs));
    return fedpegscripts;
}

template<typename T_tx_ref, typename T_merkle_block>
CScriptWitness CreatePeginWitnessInner(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const T_tx_ref& tx_ref, const T_merkle_block& merkle_block)
{
    std::vector<unsigned char> value_bytes;
    VectorWriter ss_val(value_bytes, 0);
    try {
        ss_val << value;
    } catch (...) {
        throw std::ios_base::failure("Amount serialization is invalid.");
    }

    // Strip witness data for proof inclusion since only TXID-covered fields matters
    DataStream ss_tx{};
    ss_tx << TX_NO_WITNESS(tx_ref);
    const auto* ss_tx_ptr = UCharCast(ss_tx.data());
    std::vector<unsigned char> tx_data_stripped(ss_tx_ptr, ss_tx_ptr + ss_tx.size());

    // Serialize merkle block
    DataStream ss_txout_proof{};
    ss_txout_proof << TX_NO_WITNESS(merkle_block);
    const auto* ss_txout_ptr = UCharCast(ss_txout_proof.data());
    std::vector<unsigned char> txout_proof_bytes(ss_txout_ptr, ss_txout_ptr + ss_txout_proof.size());

    // Construct pegin proof
    CScriptWitness pegin_witness;
    std::vector<std::vector<unsigned char>>& stack = pegin_witness.stack;
    stack.push_back(value_bytes);
    stack.emplace_back(asset.begin(), asset.end());
    stack.emplace_back(genesis_hash.begin(), genesis_hash.end());
    stack.emplace_back(claim_script.begin(), claim_script.end());
    stack.push_back(tx_data_stripped);
    stack.push_back(txout_proof_bytes);
    return pegin_witness;
}

CScriptWitness CreatePeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const CTransactionRef& tx_ref, const CMerkleBlock& merkle_block)
{
    return CreatePeginWitnessInner(value, asset, genesis_hash, claim_script, tx_ref, merkle_block);
}
CScriptWitness CreatePeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const Sidechain::Bitcoin::CTransactionRef& tx_ref, const Sidechain::Bitcoin::CMerkleBlock& merkle_block)
{
    return CreatePeginWitnessInner(value, asset, genesis_hash, claim_script, tx_ref, merkle_block);
}

static std::vector<unsigned char> SerializeDepositValue(const CAmount& value)
{
    try {
        return SerializeEvidenceField(value);
    } catch (...) {
        throw std::ios_base::failure("Amount serialization is invalid.");
    }
}

static CScriptWitness AssembleDepositWitness(std::span<const unsigned char> layout,
    std::vector<std::vector<unsigned char>> fields)
{
    CScriptWitness witness;
    for (const auto field : layout) {
        if (field == 254) witness.stack.push_back(DRIVECHAIN_DEPOSIT_MARKER);
        else if (field == 255) witness.stack.push_back(ECX_LEGACY_DEPOSIT_MARKER);
        else witness.stack.push_back(std::move(fields.at(field)));
    }
    return witness;
}

CScriptWitness CreateDrivechainDepositPeginWitness(const CAmount& value,
                                                   const CAsset& asset,
                                                   const uint256& genesis_hash,
                                                   const CScript& claim_script,
                                                   const COutPoint& mainchain_outpoint,
                                                   const uint256& mainchain_block_hash,
                                                   const std::vector<unsigned char>& address)
{
    if (!drivechain::haskell::ParentReplayRecord(drivechain::haskell::ReplayRecordKind::NONEMPTY_BOUNDED, 0, 0, address.size(), ElementsDrivechainIdentity::DEPOSIT_ADDRESS_LIMIT)) {
        throw std::invalid_argument("Drivechain deposit address must contain 1..128 bytes.");
    }
    return AssembleDepositWitness(ElementsDrivechainIdentity::NATIVE_DEPOSIT_LAYOUT,
        {SerializeDepositValue(value), {asset.begin(),asset.end()}, {genesis_hash.begin(),genesis_hash.end()},
         {claim_script.begin(),claim_script.end()},
         {mainchain_outpoint.hash.ToUint256().begin(),mainchain_outpoint.hash.ToUint256().end()},
         {mainchain_block_hash.begin(),mainchain_block_hash.end()}, address});
}

CScriptWitness CreateDrivechainDepositPeginWitness(const CAmount& value, const CAsset& asset, const uint256& genesis_hash, const CScript& claim_script, const uint256& mainchain_txid)
{
    return AssembleDepositWitness(ElementsDrivechainIdentity::LEGACY_DEPOSIT_LAYOUT,
        {SerializeDepositValue(value), {asset.begin(),asset.end()}, {genesis_hash.begin(),genesis_hash.end()},
         {claim_script.begin(),claim_script.end()}, {mainchain_txid.begin(),mainchain_txid.end()}});
}

CScriptWitness CreateDrivechainDepositPeginWitness(
    const CAmount& value,
    const CAsset& asset,
    const uint256& genesis_hash,
    const CScript& claim_script,
    const DrivechainDepositEvidence& evidence)
{
    return AssembleDepositWitness(ElementsDrivechainIdentity::EVIDENCE_DEPOSIT_LAYOUT,
        {SerializeEvidenceField(value), {asset.begin(),asset.end()}, {genesis_hash.begin(),genesis_hash.end()},
         {claim_script.begin(),claim_script.end()}, evidence.deposit_tx, evidence.txout_proof, evidence.previous_ctip_tx,
         SerializeEvidenceField(evidence.sequence_number), SerializeEvidenceField(evidence.previous_sequence_number),
         SerializeEvidenceField(evidence.headers)});
}

CTransactionRef CreateNativeDrivechainDeposit(const DrivechainMintableDeposit& deposit)
{
    CScript recipient;
    CAmount fee{0};
    const std::string address(deposit.address.begin(),deposit.address.end());
    DepositDestinationAdapter destination{address,recipient,fee,{}};
    CMutableTransaction tx;
    const COutPoint outpoint(Txid::FromUint256(deposit.outpoint.hash),deposit.outpoint.n);
    CTransactionRef result;
    drivechain::haskell::RunNativeRecipient(drivechain::haskell::NativeRecipient::CONSTRUCT,deposit.value,address,
        [&](uint32_t step, uint64_t index, std::span<const unsigned char> input) -> std::vector<unsigned char> {
            if (step <= 3) return destination(step,index,input);
            switch (step) {
            case 5:
                tx.vin.emplace_back(outpoint);
                tx.vin[0].m_is_pegin = true;
                break;
            case 6:
            case 7:
                if (input.size() != 8) throw std::logic_error("invalid deposit output amount frame");
                tx.vout.emplace_back(Params().GetConsensus().pegged_asset,static_cast<int64_t>(ReadLE64(input.data())),
                    step == 6 ? recipient : CScript());
                break;
            case 8: {
                tx.witness.vtxinwit.resize(1);
                tx.witness.vtxoutwit.resize(tx.vout.size());
                const auto& asset = Params().GetConsensus().pegged_asset;
                const auto& genesis = Params().ParentGenesisBlockHash();
                const CScript claim = CScript() << OP_TRUE;
                tx.witness.vtxinwit[0].m_pegin_witness = AssembleDepositWitness(ElementsDrivechainIdentity::NATIVE_DEPOSIT_LAYOUT,
                    {SerializeDepositValue(deposit.value),{asset.begin(),asset.end()},{genesis.begin(),genesis.end()},
                     {claim.begin(),claim.end()},{outpoint.hash.ToUint256().begin(),outpoint.hash.ToUint256().end()},
                     {deposit.block_hash.begin(),deposit.block_hash.end()},deposit.address});
                break;
            }
            case 9: result = MakeTransactionRef(std::move(tx)); break;
            default: throw std::logic_error("invalid native deposit construction effect");
            }
            return {};
        });
    return result;
}

bool DecomposePeginWitness(const CScriptWitness& witness, CAmount& value, CAsset& asset, uint256& genesis_hash, CScript& claim_script, std::variant<std::monostate, Sidechain::Bitcoin::CTransactionRef, CTransactionRef>& tx, std::variant<std::monostate, Sidechain::Bitcoin::CMerkleBlock, CMerkleBlock>& merkle_block)
{
    const auto& stack = witness.stack;

    if (stack.size() != 6) return false;
    if (stack[1].size() != 32) return false; // asset
    if (stack[2].size() != 32) return false; // parent genesis hash

    CAmount tmp_value{0};
    CAsset tmp_asset;
    uint256 tmp_genesis_hash;
    CScript tmp_claim_script;
    std::variant<std::monostate, Sidechain::Bitcoin::CTransactionRef, CTransactionRef> tmp_tx;
    std::variant<std::monostate, Sidechain::Bitcoin::CMerkleBlock, CMerkleBlock> tmp_merkle_block;

    try {
        DataStream stream{stack[0]};
        stream >> tmp_value;

        tmp_asset = CAsset(stack[1]);
        tmp_genesis_hash = uint256(stack[2]);
        tmp_claim_script = CScript(stack[3].begin(), stack[3].end());

        DataStream ss_tx(stack[4]);
        if (Params().GetConsensus().ParentChainHasPow()) {
            Sidechain::Bitcoin::CTransactionRef btc_tx;
            ss_tx >> TX_WITH_WITNESS(btc_tx);
            tmp_tx = btc_tx;
        } else {
            CTransactionRef elem_tx;
            ss_tx >> TX_WITH_WITNESS(elem_tx);
            tmp_tx = elem_tx;
        }

        DataStream ss_proof(stack[5]);
        if (Params().GetConsensus().ParentChainHasPow()) {
            Sidechain::Bitcoin::CMerkleBlock tx_proof;
            ss_proof >> TX_WITH_WITNESS(tx_proof);
            tmp_merkle_block = tx_proof;
        } else {
            CMerkleBlock tx_proof;
            ss_proof >> TX_WITH_WITNESS(tx_proof);
            tmp_merkle_block = tx_proof;
        }
    } catch (const std::exception&) {
        // Malformed encoding. Report failure rather than propagating
        return false;
    }

    value = tmp_value;
    asset = tmp_asset;
    genesis_hash = tmp_genesis_hash;
    claim_script = tmp_claim_script;
    tx = std::move(tmp_tx);
    merkle_block = std::move(tmp_merkle_block);
    return true;
}

// Fork-specific drivechain_peg adapters.
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
    const std::vector<std::vector<unsigned char>> empty;
    const auto& stack = input_index < tx.vin.size() && input_index < tx.witness.vtxinwit.size() ?
        tx.witness.vtxinwit[input_index].m_pegin_witness.stack : empty;
    struct EvidenceContext {
        const std::vector<std::vector<unsigned char>>& stack;
        DrivechainDepositEvidence evidence;
    } context{stack, {}};
    auto& evidence = context.evidence;
    const auto decode = +[](void* opaque, int64_t* fields) -> int32_t {
        auto& context = *static_cast<EvidenceContext*>(opaque);
        return DecodeDepositEvidenceFields(context.stack,context.evidence,fields);
    };
    Sidechain::Bitcoin::CMutableTransaction deposit_tx, previous_tx;
    Sidechain::Bitcoin::CMerkleBlock proof;
    uint256 previous_txid;
    uint32_t previous_vout{0};
    CAmount previous_value{0}, witness_value{0};
    std::string address, candidate;
    CScript destination_script;
    CTxDestination destination;
    CScript::const_iterator cursor;
    uint64_t selected{0};
    std::vector<unsigned char> data;
    const auto word = [](uint64_t value) {
        std::vector<unsigned char> bytes(8);
        WriteLE64(bytes.data(),value);
        return bytes;
    };
    return haskell::ParseDeterministicDeposit(tx.vin.size(),input_index,tx.witness.vtxinwit.size(),
        stack,Params().GetConsensus().pegged_asset.begin(),Params().ParentGenesisBlockHash().begin(),
        input_index < tx.vin.size() ? tx.vin[input_index].prevout.hash.ToUint256().begin() : nullptr,
        HashDepositTransaction,decode,&context,
        [&](uint32_t step,uint64_t index,std::span<const unsigned char> input) -> std::vector<unsigned char> {
            // These two legacy adapters report faults as status values, not exceptions.
            if (step == 5) {
                try {
                    const auto& header = evidence.headers.at(index);
                    return word(CheckParentProofOfWork(header.GetHash(),header.nBits,Params().GetConsensus()) |
                        ((index == 0 || header.hashPrevBlock == evidence.headers.at(index-1).GetHash()) << 1));
                } catch (...) { return word(uint64_t(-1)); }
            }
            if (step >= 20 && step <= 23) {
                try {
                    const auto& script = deposit_tx.vout.at(index).scriptPubKey;
                    opcodetype opcode;
                    if (step == 20) {
                        cursor = script.begin();
                        selected = index;
                        return word(script.GetOp(cursor,opcode,data) ? static_cast<int32_t>(opcode) : 256);
                    }
                    if (selected != index) return word(uint64_t(-1));
                    if (step == 21) {
                        const bool read = script.GetOp(cursor,opcode,data);
                        return word((read ? static_cast<int32_t>(opcode) : 256) |
                            ((!data.empty()) << 9) | ((cursor == script.end()) << 10));
                    }
                    if (step == 22) {
                        candidate.assign(data.begin(),data.end());
                        destination = DecodeDestination(candidate);
                        return word(IsValidDestination(destination));
                    }
                    address = candidate;
                    destination_script = GetScriptForDestination(destination);
                    return word(1);
                } catch (...) { return word(uint64_t(-1)); }
            }
            switch (step) {
            case 0:
                evidence.deposit_tx = stack[5];
                evidence.txout_proof = stack[6];
                evidence.previous_ctip_tx = stack[7];
                return {};
            case 1: return word(DeserializeExactly(evidence.deposit_tx,deposit_tx));
            case 2: return word(DeserializeExactly(evidence.previous_ctip_tx,previous_tx));
            case 3: return word(DeserializeExactly(evidence.txout_proof,proof));
            case 4: {
                const uint256 txid = deposit_tx.GetHash();
                std::vector<uint256> matches;
                std::vector<unsigned int> indices;
                const bool root_matches = proof.txn.ExtractMatches(matches,indices) == proof.header.hashMerkleRoot;
                const uint32_t facts =
                    (txid == tx.vin[input_index].prevout.hash && tx.vin[input_index].prevout.n < deposit_tx.vout.size()) |
                    (root_matches << 1) | ((!matches.empty() && matches[0] == txid) << 2) |
                    ((evidence.headers.front().GetHash() == proof.header.GetHash()) << 3);
                auto row = word(facts);
                for (uint64_t value : {uint64_t(matches.size()),uint64_t(evidence.headers.size())}) {
                    const auto bytes = word(value);
                    row.insert(row.end(),bytes.begin(),bytes.end());
                }
                return row;
            }
            case 6: parsed.anchor = evidence.headers.back().GetHash(); return {};
            case 7: previous_txid = previous_tx.GetHash(); return word(deposit_tx.vin.size());
            case 8: return word(deposit_tx.vin.at(index).prevout.hash == previous_txid);
            case 9: return word(deposit_tx.vin.at(index).prevout.n < previous_tx.vout.size());
            case 10: {
                const auto& script = previous_tx.vout.at(deposit_tx.vin.at(index).prevout.n).scriptPubKey;
                return {script.begin(),script.begin()+std::min<size_t>(script.size(),5)};
            }
            case 11: previous_vout = deposit_tx.vin.at(index).prevout.n; return {};
            case 12: previous_value = previous_tx.vout.at(previous_vout).nValue; return word(previous_value);
            case 13:
                if (input.size() != 8) throw std::logic_error("invalid deposit witness value publication");
                witness_value = static_cast<int64_t>(ReadLE64(input.data()));
                return {};
            case 14: {
                const auto& script = deposit_tx.vout.at(tx.vin[input_index].prevout.n).scriptPubKey;
                return {script.begin(),script.begin()+std::min<size_t>(script.size(),5)};
            }
            case 15: return word(deposit_tx.vout.at(tx.vin[input_index].prevout.n).nValue);
            case 16: return word(deposit_tx.vout.size());
            case 24:
                parsed.previous_state = {COutPoint(Txid::FromUint256(previous_txid),previous_vout),
                    previous_value,evidence.previous_sequence_number};
                parsed.next_state = {tx.vin[input_index].prevout,
                    deposit_tx.vout[tx.vin[input_index].prevout.n].nValue,evidence.sequence_number};
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
                return {};
            default: throw std::logic_error("invalid deterministic deposit native action");
            }
        },error);
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

bool RunClaimWorkflow(haskell::DepositClaimWorkflow kind, const CTransaction& tx, size_t index,
    const haskell::NativeWorkflow& native, std::string& error)
{
    const std::vector<std::vector<unsigned char>> empty;
    const auto& stack = index < tx.vin.size() && index < tx.witness.vtxinwit.size() ?
        tx.witness.vtxinwit[index].m_pegin_witness.stack : empty;
    return haskell::RunDepositClaim(kind,tx.vin.size(),index,tx.witness.vtxinwit.size(),tx.vout.size(),
        stack,Params().GetConsensus().pegged_asset.begin(),Params().ParentGenesisBlockHash().begin(),
        index < tx.vin.size() ? tx.vin[index].prevout.hash.ToUint256().begin() : nullptr,
        HashDepositTransaction,native,error);
}

std::optional<LegacyCheckpoint> FindLegacyCheckpoint(const CTransaction& tx, size_t input_index)
{
    std::optional<LegacyCheckpoint> checkpoint;
    std::string unused;
    RunClaimWorkflow(haskell::DepositClaimWorkflow::CHECKPOINT,tx,input_index,
        [&](uint32_t step,uint64_t,std::span<const unsigned char> record) -> std::vector<unsigned char> {
            if (step == 0) {
                const auto identity = tx.GetHash();
                const auto& previous = tx.vin[input_index].prevout;
                std::vector<unsigned char> bytes(UCharCast(identity.begin()),UCharCast(identity.end()));
                bytes.insert(bytes.end(),UCharCast(previous.hash.begin()),UCharCast(previous.hash.end()));
                bytes.resize(68);
                WriteLE32(bytes.data()+64,previous.n);
                return bytes;
            }
            if (step != 1) throw std::logic_error("invalid checkpoint lookup action");
            LegacyCheckpoint decoded;
            DataStream stream{record};
            stream >> decoded.parent_hash >> decoded.outpoint >> decoded.deposit_value >>
                decoded.ctip_value >> decoded.sequence_number >> decoded.destination;
            if (!stream.empty()) throw std::runtime_error("Haskell checkpoint record has trailing bytes");
            checkpoint = std::move(decoded);
            return {};
        },unused);
    return checkpoint;
}

bool BuildLegacyAuthenticated(
    const CTransaction& tx,
    size_t input_index,
    const LegacyCheckpoint& checkpoint,
    AuthenticatedDeposit& authenticated,
    std::string& error)
{
    CTxDestination destination;
    return RunClaimWorkflow(haskell::DepositClaimWorkflow::LEGACY,tx,input_index,
        [&](uint32_t step,uint64_t,std::span<const unsigned char>) -> std::vector<unsigned char> {
            if (step == 10 || step == 11) {
                std::vector<unsigned char> bytes(8);
                if (step == 10) destination = DecodeDestination(checkpoint.destination);
                WriteLE64(bytes.data(),step == 10 ? IsValidDestination(destination) : checkpoint.deposit_value);
                return bytes;
            }
            if (step != 12) throw std::logic_error("invalid legacy claim action");
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
            return {};
        },error);
}

bool DecodeCtipState(const Coin& coin, CtipState& state, std::string& error)
{
    const uint32_t facts = !coin.IsSpent() | (coin.out.nAsset.IsExplicit() << 1) |
        ((coin.out.nAsset.IsExplicit() && coin.out.nAsset.GetAsset() == Params().GetConsensus().pegged_asset) << 2) |
        (coin.out.nValue.IsExplicit() << 3);
    CScript::const_iterator cursor = coin.out.scriptPubKey.begin();
    std::vector<unsigned char> data;
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
    if (!haskell::ReadPersistedCtip(facts, coin.out.nValue.IsExplicit() ? coin.out.nValue.GetAmount() : 0,
            [&](uint32_t i) -> int32_t {
                if (i == 3) return cursor == coin.out.scriptPubKey.end();
                opcodetype opcode;
                const bool read = i == 0 ? coin.out.scriptPubKey.GetOp(cursor,opcode,data) : coin.out.scriptPubKey.GetOp(cursor,opcode);
                return read ? static_cast<int32_t>(opcode) : 256;
            },decode,&payload,error)) return false;
    state = payload.decoded;
    return true;
}

void SetCtipState(CCoinsViewCache& inputs, const CtipState& state, int height, bool restore = false)
{
    DataStream stream;
    CScript script;
    std::optional<CTxOut> output;
    haskell::RunReplayStore(restore ? haskell::ReplayStoreWorkflow::STATE_RESTORE : haskell::ReplayStoreWorkflow::STATE_STORE,
        [&](uint32_t step, uint64_t value, std::span<const unsigned char> input) {
        if (!input.empty() || value > UINT32_MAX) throw std::logic_error("invalid CTIP state storage fields");
        std::vector<unsigned char> reply(8);
        switch (step) {
        case 0: WriteLE64(reply.data(), static_cast<uint32_t>(height)); return reply;
        case 10: inputs.SpendCoin(CTIP_STATE_OUTPOINT); break;
        case 11: stream << CTIP_STATE_MARKER; break;
        case 12: stream << state.outpoint << state.value << state.sequence_number; break;
        case 13: script << std::vector<unsigned char>(UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()); break;
        case 14:
            if (value > 255) throw std::logic_error("invalid CTIP state opcode");
            script << static_cast<opcodetype>(value); break;
        case 15: output.emplace(Params().GetConsensus().pegged_asset, value, script); break;
        case 16: inputs.AddCoin(CTIP_STATE_OUTPOINT, Coin(std::move(output.value()), value, false), true); break;
        default: throw std::logic_error("invalid CTIP state storage action");
        }
        WriteLE64(reply.data(), 1);
        return reply;
    });
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
        return RunClaimWorkflow(haskell::DepositClaimWorkflow::TRANSACTION,tx,input_index,
            [&](uint32_t step,uint64_t index,std::span<const unsigned char> data) -> std::vector<unsigned char> {
                uint64_t facts{0};
                switch (step) {
                case 20: {
                    const auto& input = tx.vin[0];
                    facts = input.m_is_pegin | ((input.prevout == authenticated.outpoint) << 1) |
                        (input.scriptSig.empty() << 2) | (input.assetIssuance.IsNull() << 3);
                    break;
                }
                case 21: {
                    if (data.size() != 1 || data[0] > 1) throw std::logic_error("invalid deposit witness projection");
                    const bool decoded = data[0] != 0;
                    const auto txid = decoded ? tx.vin[0].prevout.hash.ToUint256() : uint256{};
                    const auto& claim = tx.witness.vtxinwit[0].m_pegin_witness.stack;
                    facts = (txid == authenticated.outpoint.hash) |
                        ((decoded && claim[3] == std::vector<unsigned char>{OP_TRUE}) << 1);
                    break;
                }
                case 22: {
                    const auto& output = tx.vout.at(index);
                    facts = (output.nAsset.IsExplicit() && output.nAsset.GetAsset() == Params().GetConsensus().pegged_asset) |
                        (output.nValue.IsExplicit() << 1) | (output.nNonce.IsNull() << 2) |
                        (output.scriptPubKey.empty() << 3) | ((output.scriptPubKey == authenticated.destination_script) << 4);
                    std::vector<unsigned char> row(16);
                    WriteLE64(row.data(),facts);
                    WriteLE64(row.data()+8,output.nValue.IsExplicit() ? output.nValue.GetAmount() : 0);
                    return row;
                }
                case 23: facts = authenticated.value; break;
                default: throw std::logic_error("invalid deposit fact projection action");
                }
                std::vector<unsigned char> bytes(8);
                WriteLE64(bytes.data(),facts);
                return bytes;
            },error);
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
    return haskell::RunDepositStateWorkflow(haskell::DepositWorkflow::VERIFY, [&](Step step) -> uint32_t {
        switch (step) {
        case Step::CHECKPOINT:
            checkpoint = FindLegacyCheckpoint(tx, input_index);
            return checkpoint.has_value();
        case Step::CHECKPOINT_STATE: {
            const bool present = GetCtipState(inputs, current, &state_error);
            return haskell::DepositStateFacts(present, false, state_error);
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
            return haskell::DepositStateFacts(present, current == parsed.previous_state, state_error);
        }
        case Step::VERIFY: return VerifyDepositTransaction(tx, input_index, parsed.authenticated, error);
        default: throw std::logic_error("invalid deposit verification action");
        }
    }, state_error, error);
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
    return haskell::RunDepositStateWorkflow(haskell::DepositWorkflow::ANCHOR, [&](Step step) -> uint32_t {
        switch (step) {
        case Step::ANCHOR_CHECKPOINT:
            checkpoint = FindLegacyCheckpoint(tx, input_index);
            return checkpoint.has_value();
        case Step::CHECKPOINT_ANCHOR:
            return haskell::DepositStateFacts(true, checkpoint.value().parent_hash == expected_parent, {});
        case Step::ANCHOR_HAS_WITNESS: return input_index < tx.witness.vtxinwit.size();
        case Step::ANCHOR_LEGACY_WITNESS:
            return IsLegacyDrivechainDepositPeginWitness(tx.witness.vtxinwit[input_index].m_pegin_witness);
        case Step::REJECT_LEGACY:
            error = "legacy drivechain deposit witness is not an immutable historical checkpoint";
            return false;
        case Step::PARSE_ANCHOR: return ParseV2Deposit(tx, input_index, parsed, error);
        case Step::CHECK_ANCHOR:
            return haskell::DepositStateFacts(true, parsed.anchor == expected_parent, {});
        case Step::REJECT_ANCHOR:
            error = strprintf("drivechain deposit evidence anchor %s does not match sidechain block L1 parent %s",
                parsed.anchor.GetHex(), expected_parent.GetHex());
            return false;
        default: throw std::logic_error("invalid deposit anchor action");
        }
    }, {}, error);
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
    return haskell::RunDepositStateWorkflow(haskell::DepositWorkflow::CONNECT, [&](Step step) -> uint32_t {
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
            return haskell::DepositStateFacts(present, current == parsed.previous_state, state_error);
        }
        case Step::CONNECT_PUBLISH_NEXT:
            SetCtipState(inputs, parsed.next_state, height);
            return true;
        default: throw std::logic_error("invalid deposit connect action");
        }
    }, state_error, error);
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
    return haskell::RunDepositStateWorkflow(haskell::DepositWorkflow::DISCONNECT, [&](Step step) -> uint32_t {
        switch (step) {
        case Step::DISCONNECT_PRESENT: {
            const bool present = GetCtipState(inputs, current, &state_error);
            return haskell::DepositStateFacts(present, false, state_error);
        }
        case Step::DISCONNECT_CHECKPOINT:
            checkpoint = FindLegacyCheckpoint(tx, input_index);
            return checkpoint.has_value();
        case Step::DISCONNECT_CHECK: {
            const CtipState expected{checkpoint.value().outpoint, checkpoint.value().ctip_value, checkpoint.value().sequence_number};
            return haskell::DepositStateFacts(true, current == expected, {});
        }
        case Step::DISCONNECT_REMOVE: {
            const bool removed = inputs.SpendCoin(CTIP_STATE_OUTPOINT);
            if (!removed) error = "historical drivechain checkpoint CTIP state could not be removed";
            return removed;
        }
        case Step::DISCONNECT_PARSE: return ParseV2Deposit(tx, input_index, parsed, error);
        case Step::DISCONNECT_CURRENT:
            return haskell::DepositStateFacts(true, current == parsed.next_state, {});
        case Step::DISCONNECT_RESTORE:
            SetCtipState(inputs, parsed.previous_state, height, true);
            return true;
        default: throw std::logic_error("invalid deposit disconnect action");
        }
    }, state_error, error);
}

} // namespace drivechain
