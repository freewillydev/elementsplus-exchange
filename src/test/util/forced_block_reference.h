// Preserved pre-migration workflow for native differential tests only.
#pragma once
#include <algorithm>
#include <chain.h>
#include <crypto/common.h>
#include <ecx_forced_v3.h>
#include <ecx_exchange_state.h>
#include <ecx_forced_v3_block.h>
#include <hash.h>
#include <haskell/bridge.h>
#include <limits>
#include <primitives/block.h>
#include <set>
#include <stdexcept>

namespace forced_block_reference {
using namespace ecx;
namespace {
void Number(std::vector<unsigned char>& bytes, uint64_t n, size_t width = 8)
{
    unsigned char value[8];
    WriteBE64(value, n);
    bytes.insert(bytes.end(), value + 8 - width, value + 8);
}
uint8_t MarkerKind(std::span<const unsigned char> script)
{
    const auto result = drivechain::haskell::ExchangeForcedV3BlockBytes(2, script.first(std::min<size_t>(script.size(), 14)));
    if (!result || result->size() != 1) throw std::logic_error("forced marker classifier failed");
    return (*result)[0];
}
uint256 Hash(const char* domain, std::span<const unsigned char> bytes)
{
    auto writer = ::TaggedHash(domain);
    writer.write(AsBytes(Span{bytes.data(), bytes.size()}));
    return writer.GetSHA256();
}
bool CursorOutput(const CTransaction& tx, size_t index, const CAsset& policy_asset)
{
    const auto& out = tx.vout.at(index);
    return drivechain::haskell::ExchangeProfile(false, [&](uint32_t step) {
        switch (step) {
        case 0: return out.nAsset.IsExplicit();
        case 1: return out.nAsset.GetAsset() == policy_asset;
        case 2: return out.nValue.IsExplicit();
        case 3: return out.nValue.GetAmount() == 0;
        case 4: return out.nNonce.IsNull();
        case 5: return index >= tx.witness.vtxoutwit.size() || tx.witness.vtxoutwit[index].IsNull();
        default: throw std::logic_error("invalid cursor output read");
        }
    });
}
} // namespace

bool CheckForcedV3DeploymentMode(std::string& error, const ExchangeConsensus* consensus)
{
    // Header mode is independently selected by chain serialization settings;
    // no RPC/marker can select a deployment or supply an acceptance callback.
    if (!g_con_ecx_swap_v3) return true;
    if (consensus && consensus->custody_successor.activation_enabled && CustodyGenesisConfigured(*consensus)) return true;
    error = "ECX forced V3 native activation unavailable: requires a pinned exact-custody proof profile and fully bound genesis";
    return false;
}

bool CheckForcedV3CursorMarker(const CBlock& block, const CAsset& policy_asset,
                               const uint256& expected_transaction, std::span<const uint64_t, 3> expected_cursor, std::string& error)
{
    uint64_t count = 0;
    uint256 actual_transaction;
    std::vector<unsigned char> script;
    for (const auto& tx : block.vtx) {
        for (size_t output = 0; output < tx->vout.size(); ++output) {
            if (MarkerKind(tx->vout[output].scriptPubKey) != 2) continue;
            if (!CursorOutput(*tx, output, policy_asset)) {
                error = "ECXCv3 output profile is invalid";
                return false;
            }
            if (count < 2) ++count;
            if (count == 1) {
                actual_transaction = tx->GetHash();
                script.assign(tx->vout[output].scriptPubKey.begin(), tx->vout[output].scriptPubKey.end());
            }
        }
    }
    std::vector<unsigned char> binding(expected_transaction.begin(), expected_transaction.end());
    binding.insert(binding.end(), actual_transaction.begin(), actual_transaction.end());
    for (const auto value : expected_cursor)
        Number(binding, value);
    Number(binding, count);
    binding.insert(binding.end(), script.begin(), script.end());
    if (drivechain::haskell::ExchangeForcedV3BlockBytes(3, binding)) return true;
    error = "ECXCv3 requires one exact full-width marker in its actual transition transaction, or none on carry";
    return false;
}

namespace {
struct SourceConsumption {
    uint256 transaction,processed_root;
    std::array<unsigned char,16> cursor;
};
}
static bool DeriveSourceAppend(const CBlock& block, const CBlockIndex& previous,
                                const CAsset& policy_asset, std::span<const unsigned char, 259> economics,
                                std::span<const unsigned char, 32> economic_hash, uint64_t sidechain_height,
                                uint64_t parent, std::array<unsigned char, 145>& result, std::string& error,
                                const SourceConsumption* receipt, bool custody_only)
{
    if (!block.HasSwapForcedState() || !previous.GetBlockHeader().HasSwapForcedState() ||
        previous.nHeight < 0 || sidechain_height != uint64_t(previous.nHeight) + 1 ||
        parent == 0 || parent < previous.ecxParentHeight || parent != block.ecxParentHeight ||
        block.depositProcessedCursor != previous.depositProcessedCursor ||
        block.forcedProcessedCursor != previous.forcedProcessedCursor ||
        previous.hashExchangeStateRoot.IsNull() ||
        (!receipt && block.hashExchangeStateRoot != previous.hashExchangeStateRoot)) {
        error = "ECXFv3 carry requires exact prior header/height/parent and unchanged singleton; consumption needs a verified fresh receipt";
        return false;
    }
    const auto config_hash = Hash("ECX/linear-ecx-settlement-configuration/mainchain-v2", economics);
    if (!std::equal(config_hash.begin(), config_hash.end(), economic_hash.begin()) ||
        !std::equal(policy_asset.begin(), policy_asset.end(), economics.begin() + 50)) {
        error = "ECXFv3 carry economics or collateral asset differs from pinned configuration";
        return false;
    }
    auto next = previous.swapForcedState;
    if (!drivechain::haskell::ExchangeForcedV3State(next, economic_hash)) {
        error = "ECXFv3 previous header state is invalid";
        return false;
    }
    std::array<uint64_t,3> cursor{};
    if (receipt) {
        std::copy(receipt->processed_root.begin(),receipt->processed_root.end(),next.begin()+81);
        std::copy(receipt->cursor.begin(),receipt->cursor.end(),next.begin()+113);
        cursor={ReadBE64(receipt->cursor.data()),ReadBE64(receipt->cursor.data()+8),previous.depositProcessedCursor};
        if (!drivechain::haskell::ExchangeForcedV3State(next,economic_hash)) {
            error="verified custody cursor is outside the authenticated source state";
            return false;
        }
    }
    if (!CheckForcedV3CursorMarker(block, policy_asset, receipt ? receipt->transaction : uint256{}, cursor, error)) return false;
    std::set<std::pair<uint256, uint32_t>> locators;
    for (const auto& tx : block.vtx) {
        for (size_t output = 0; output < tx->vout.size(); ++output) {
            if (MarkerKind(tx->vout[output].scriptPubKey) != 1) continue;
            if (output > std::numeric_limits<uint32_t>::max()) {
                error = "ECXFv3 output index overflow";
                return false;
            }
            const auto action = VerifyForcedActionV3Output(*tx, output, policy_asset, economics, economic_hash, parent, error);
            if (!action) return false;
            const std::array<unsigned char,1> kind{action->Kind()};
            if (custody_only && !drivechain::haskell::ExchangeCustodyCheck(4,{},kind)) {
                error="fresh exact-custody profile cannot execute this forced action class";
                return false;
            }
            std::vector<unsigned char> fields(next.begin(), next.end());
            const uint256 txid = tx->GetHash();
            if (!locators.emplace(txid, static_cast<uint32_t>(output)).second) {
                error = "duplicate ECXFv3 source locator";
                return false;
            }
            fields.insert(fields.end(), txid.begin(), txid.end());
            Number(fields, sidechain_height);
            Number(fields, parent);
            Number(fields, output, 4);
            fields.insert(fields.end(), action->Payload().begin(), action->Payload().end());
            const auto entry = drivechain::haskell::ExchangeForcedV3BlockBytes(0, fields);
            if (!entry) {
                error = "ECXFv3 source entry or persistent admission budget is invalid";
                return false;
            }
            const auto entry_hash = Hash("ECX/exact-forced-entry/v3-u128", *entry);
            std::vector<unsigned char> step(next.begin() + 33, next.begin() + 81);
            step.insert(step.end(), entry_hash.begin(), entry_hash.end());
            const auto root = Hash("ECX/exact-forced-step/v3-u128", step);
            fields.assign(next.begin(), next.end());
            fields.insert(fields.end(), root.begin(), root.end());
            Number(fields, parent);
            fields.push_back(action->Kind());
            const auto updated = drivechain::haskell::ExchangeForcedV3BlockBytes(1, fields);
            if (!updated || updated->size() != next.size()) {
                error = "ECXFv3 source state update rejected";
                return false;
            }
            std::copy(updated->begin(), updated->end(), next.begin());
        }
    }
    result = next;
    return true;
}

bool DeriveForcedV3SourceAppend(const CBlock& block, const CBlockIndex& previous,
    const CAsset& asset, std::span<const unsigned char,259> economics,
    std::span<const unsigned char,32> hash, uint64_t height, uint64_t parent,
    std::array<unsigned char,145>& result, std::string& error)
{
    return DeriveSourceAppend(block,previous,asset,economics,hash,height,parent,result,error,nullptr,false);
}

bool DeriveCustodyForcedV3SourceAppend(const CBlock& block, const CBlockIndex& previous,
    const CAsset& asset, std::span<const unsigned char,259> economics,
    std::span<const unsigned char,32> hash, uint64_t height, uint64_t parent,
    const VerifiedCustodySource* receipt, std::array<unsigned char,145>& result, std::string& error)
{
    std::optional<SourceConsumption> consumed;
    if (receipt) consumed=SourceConsumption{receipt->Transaction(),receipt->ProcessedRoot(),receipt->Cursor()};
    return DeriveSourceAppend(block,previous,asset,economics,hash,height,parent,result,error,consumed ? &*consumed : nullptr,true);
}

bool PrepareCustodySourceAppend(const CBlock& block,const CBlockIndex& previous,const CAsset& asset,
    std::span<const unsigned char,259> economics,std::span<const unsigned char,32> hash,
    uint64_t height,uint64_t parent,const uint256& proposed_tx,const uint256& proposed_root,
    const std::array<unsigned char,16>& proposed_cursor,std::array<unsigned char,145>& result,std::string& error)
{
    const SourceConsumption proposed{proposed_tx,proposed_root,proposed_cursor};
    // Candidate construction only. This does not create a VerifiedCustodySource
    // and is never used by block acceptance or the persisted projection path.
    return DeriveSourceAppend(block,previous,asset,economics,hash,height,parent,result,error,
        proposed_tx.IsNull() ? nullptr : &proposed,true);
}

bool CheckForcedV3SourceAppend(const CBlock& block, const CBlockIndex& previous,
                               const CAsset& policy_asset, std::span<const unsigned char, 259> economics,
                               std::span<const unsigned char, 32> economic_hash, uint64_t height, uint64_t parent, std::string& error)
{
    std::array<unsigned char, 145> expected;
    if (!DeriveForcedV3SourceAppend(block, previous, policy_asset, economics, economic_hash, height, parent, expected, error)) return false;
    if (expected != block.swapForcedState) {
        error = "ECXFv3 claimed header differs from exact ordered source append";
        return false;
    }
    return true;
}
} // namespace forced_block_reference
