#ifndef ELEMENTS_ECX_FORCED_V3_BLOCK_H
#define ELEMENTS_ECX_FORCED_V3_BLOCK_H
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <uint256.h>
class CBlock;
class CBlockIndex;
class CBlockUndo;
class uint256;
struct CAsset;
namespace ecx {
struct ExchangeConsensus;
struct CustodyProjection;
/** Produced only by the native post-script custody projection boundary. */
class VerifiedCustodySource {
    uint256 m_transaction, m_processed_root;
    std::array<unsigned char,16> m_cursor;
    VerifiedCustodySource(const uint256& tx, const uint256& root, const std::array<unsigned char,16>& cursor)
        : m_transaction(tx), m_processed_root(root), m_cursor(cursor) {}
    friend bool DeriveCustodyProjectionAfterScripts(const CBlock&, const CBlockIndex*,
        const CBlockUndo&, uint64_t, const uint256&, uint64_t, uint64_t,
        CustodyProjection&, std::string&, const ExchangeConsensus&);
public:
    const uint256& Transaction() const { return m_transaction; }
    const uint256& ProcessedRoot() const { return m_processed_root; }
    const std::array<unsigned char,16>& Cursor() const { return m_cursor; }
};
/** Fresh profile admits only implemented Account/Clearing queue classes. */
bool DeriveCustodyForcedV3SourceAppend(const CBlock& block, const CBlockIndex& previous,
    const CAsset& policy_asset, std::span<const unsigned char,259> economics,
    std::span<const unsigned char,32> economic_hash, uint64_t height, uint64_t parent,
    const VerifiedCustodySource* receipt, std::array<unsigned char,145>& result, std::string& error);

/** Unverified template construction only: returns proposed bytes, never a receipt. */
bool PrepareCustodySourceAppend(const CBlock&,const CBlockIndex&,const CAsset&,
    std::span<const unsigned char,259>,std::span<const unsigned char,32>,uint64_t,uint64_t,
    const uint256&,const uint256&,const std::array<unsigned char,16>&,
    std::array<unsigned char,145>&,std::string&);

/** Actual header/connection boundary. No fresh outer/settlement deployment is
 * registered, so fresh serialization mode remains unavailable for consensus. */
bool CheckForcedV3DeploymentMode(std::string& error, const ExchangeConsensus* consensus = nullptr);

/** Structural marker check only; not an execution receipt. Null expected txid
 * requires no marker. Otherwise exactly one canonical marker must occur in the
 * actual named transaction, committing all128 forced and64 deposit bits. */
bool CheckForcedV3CursorMarker(const CBlock& block, const CAsset& policy_asset,
                               const uint256& expected_transaction, std::span<const uint64_t, 3> expected_cursor,
                               std::string& error);

/** Derive current block source appends from its actual ordered outputs. Only
 * carry/no-consumption is supported: singleton root and processed prefix stay
 * unchanged. A fresh pinned execution receipt is required to add consumption.
 * It does not prove complete pending history/deadlines even on carry.
 * This structural helper does not authorize activation or attest execution. */
bool DeriveForcedV3SourceAppend(const CBlock& block, const CBlockIndex& previous,
                                const CAsset& policy_asset, std::span<const unsigned char, 259> economics,
                                std::span<const unsigned char, 32> economic_hash, uint64_t sidechain_height,
                                uint64_t authenticated_parent, std::array<unsigned char, 145>& result,
                                std::string& error);
bool CheckForcedV3SourceAppend(const CBlock& block, const CBlockIndex& previous,
                               const CAsset& policy_asset, std::span<const unsigned char, 259> economics,
                               std::span<const unsigned char, 32> economic_hash, uint64_t sidechain_height,
                               uint64_t authenticated_parent, std::string& error);
} // namespace ecx
#endif
