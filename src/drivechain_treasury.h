// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_TREASURY_H
#define BITCOIN_DRIVECHAIN_TREASURY_H

#include <span.h>
#include <crypto/common.h>
#include <haskell/bridge.h>

#include <cstdint>

namespace drivechain {

// Parent-network rules, not interchangeable script aliases.
enum class TreasuryOpcode : uint8_t { NOP5 = 0xb4, NOP8 = 0xb7 };

inline bool ExtractTreasurySlot(Span<const unsigned char> script,
                               TreasuryOpcode opcode, uint8_t& slot)
{
    if (script.size() != 4) return false;
    const auto result = haskell::TreasurySlot(ReadLE32(script.data()), static_cast<uint8_t>(opcode));
    if (result < 0) return false;
    slot = static_cast<uint8_t>(result);
    return true;
}

inline bool IsTreasuryScript(Span<const unsigned char> script,
                             TreasuryOpcode opcode, int expected_slot)
{
    return haskell::TreasuryMatches({script.data(),script.size()}, static_cast<uint8_t>(opcode), expected_slot);
}

} // namespace drivechain

#endif // BITCOIN_DRIVECHAIN_TREASURY_H
