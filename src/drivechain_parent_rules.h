// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVECHAIN_PARENT_RULES_H
#define BITCOIN_DRIVECHAIN_PARENT_RULES_H

#include <drivechain_treasury.h>
#include <elements_drivechain_identity.h>

#include <cstdint>
#include <optional>
#include <string_view>

enum class DrivechainM6ReplayRule {
    SINGLE_CONFIGURED_SLOT_M6,
    SEQUENTIAL_M6,
};

enum class DrivechainWithdrawalHistoryRule {
    UNIQUE_M6ID,
    ALLOW_REPROPOSAL,
};

namespace drivechain {

struct ParentRules {
    TreasuryOpcode treasury_opcode;
    DrivechainM6ReplayRule m6;
    DrivechainWithdrawalHistoryRule history;
    std::string_view bootstrap_domain;
    std::string_view local_rule_domain;
    std::string_view proposal_text;
};

// Replay versions are committed by the frozen protocol manifest. Never infer
// compatibility with a future version or select these rules from runtime flags.
#include <haskell/parent_rules.h>

} // namespace drivechain

#endif // BITCOIN_DRIVECHAIN_PARENT_RULES_H
