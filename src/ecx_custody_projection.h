// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef BITCOIN_ECX_CUSTODY_PROJECTION_H
#define BITCOIN_ECX_CUSTODY_PROJECTION_H

#include <ecx_bond_v2.h>
#include <primitives/transaction.h>

namespace ecx {
/** Standalone exact-ECX projection. Format 6 shares the existing index namespace,
 * but never interprets its fields as bond shares, USDD or legacy capital. */
struct CustodyProjection {
    static constexpr uint16_t VERSION{6};
    uint16_t version{VERSION};
    uint256 exchange_state_root;
    COutPoint state_outpoint;
    uint256 outer_state_root;
    uint256 custody_history_root;
    uint256 program_id;
    uint256 transition_cmr;
    uint256 composition_policy;
    uint256 ecx_configuration;
    uint256 clearing_policy;
    uint256 source_configuration;
    uint256 custodian_registry;
    uint256 vault_asset;
    uint256 vault_script;
    uint256 forced_head;
    uint256 forced_processed_root;
    BigEndianUint128 forced_count;
    BigEndianUint128 forced_cursor;
    uint64_t sequence{0};
    uint64_t controlled_ecx_atoms{0};
    uint8_t profit_lock_insolvent{0};

    SERIALIZE_METHODS(CustodyProjection, obj) {
        READWRITE(obj.version, obj.exchange_state_root, obj.state_outpoint, obj.outer_state_root,
            obj.custody_history_root, obj.program_id, obj.transition_cmr,
            obj.composition_policy, obj.ecx_configuration, obj.clearing_policy,
            obj.source_configuration, obj.custodian_registry, obj.vault_asset,
            obj.vault_script, obj.forced_head, obj.forced_processed_root,
            obj.forced_count, obj.forced_cursor, obj.sequence,
            obj.controlled_ecx_atoms, obj.profit_lock_insolvent);
        if (obj.version != VERSION || obj.profit_lock_insolvent > 1)
            throw std::ios_base::failure("invalid exact-custody projection format");
    }
};
} // namespace ecx
#endif
