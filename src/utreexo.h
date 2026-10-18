// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef ELEMENTS_UTREEXO_H
#define ELEMENTS_UTREEXO_H

#include <serialize.h>
#include <uint256.h>
#include <bit>
#include <vector>

// Selected with chain parameters, like the other Elements serialization modes.
extern bool g_con_utreexo;

struct UtreexoCommitment {
    uint64_t leaves{0};
    std::vector<uint256> roots;
    bool operator==(const UtreexoCommitment&) const = default;
    bool IsCanonical() const { return leaves < (uint64_t{1} << 63) && roots.size() == size_t(std::popcount(leaves)); }
    template <typename Stream> void Serialize(Stream& s) const {
        s << leaves;
        WriteCompactSize(s, roots.size());
        for (const auto& root : roots) s << root;
    }
    template <typename Stream> void Unserialize(Stream& s) {
        s >> leaves;
        const auto count = ReadCompactSize(s);
        if (count > 63 || leaves >= (uint64_t{1} << 63) || count != uint64_t(std::popcount(leaves)))
            throw std::ios_base::failure("invalid Utreexo commitment shape");
        roots.resize(count);
        for (auto& root : roots) s >> root;
    }
};

class CBlock;
class CBlockHeader;
class CBlockIndex;
class CChainParams;
class CCoinsViewCache;
class Coin;
class COutPoint;
namespace kernel { class BlockTreeDB; }
namespace Consensus { struct Params; }

namespace utreexo {
inline constexpr uint32_t HEADER_BIT{1U << 15};
uint256 Leaf(const uint256& genesis, const COutPoint& outpoint, const Coin& coin);
struct Result {
    UtreexoCommitment commitment;
    std::vector<unsigned char> forest;
};
Result Transition(const std::vector<unsigned char>& previous, const std::vector<uint256>& adds,
                  const std::vector<uint256>& dels);
bool CheckHeader(const CBlockHeader&, const Consensus::Params&, int height);
Result Compute(const CBlock&, const CBlockIndex* previous, const CCoinsViewCache&,
               const CChainParams&, kernel::BlockTreeDB&);
bool Store(kernel::BlockTreeDB&, const uint256& block, const Result&);
void Prepare(CBlock&, const CBlockIndex*, const CCoinsViewCache&, const CChainParams&, kernel::BlockTreeDB&);
}
#endif
