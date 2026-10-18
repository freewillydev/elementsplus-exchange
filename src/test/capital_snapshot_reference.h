// Preserved pre-migration assignments; independent of Haskell's serialized layout.
// Included only by ecx_exchange_state_tests.cpp.
static uint256 ReferenceCapitalHash(const unsigned char* data)
{
    uint256 hash;
    std::copy_n(data,32,hash.begin());
    return hash;
}

static ecx::BondV2CapitalSnapshot ReferenceCapitalSnapshot(uint32_t profile,
    std::span<const unsigned char> values, const std::array<uint256,10>& context,
    uint64_t height, uint64_t mtp)
{
    ecx::BondV2CapitalSnapshot snapshot;
    if (profile==0) {
    snapshot = {};
    snapshot.proof_profile = 0;
    snapshot.exchange_state_root = context[0];
    snapshot.configuration_hash = ReferenceCapitalHash(values.data() + 36);
    snapshot.bond_asset_id = ReferenceCapitalHash(values.data() + 276);
    snapshot.bond_deployment_commitment = ReferenceCapitalHash(values.data() + 308);
    snapshot.transition_program_id = context[4];
    snapshot.transition_cmr = context[5];
    snapshot.covenant_state_hash = ReferenceCapitalHash(values.data() + 100);
    snapshot.bond_state_root = ReferenceCapitalHash(values.data() + 340);
    snapshot.funding_state_root = ReferenceCapitalHash(values.data() + 404);
    snapshot.bond_inventory_covenant_hash =
        context[6];
    std::copy_n(values.begin() + 468, 16, snapshot.insurance_reserve.begin());
    snapshot.outstanding_share_atoms = ReadBE64(values.data() + 484);
    snapshot.issued_share_atoms = UINT64_C(2100000000000000);
    snapshot.inventory_share_atoms =
        snapshot.issued_share_atoms - snapshot.outstanding_share_atoms;
    std::copy_n(values.begin() + 492, 16, snapshot.nav_per_whole_share.begin());
    std::copy_n(values.begin() + 508, 16, snapshot.full_bound_deficit.begin());
    std::copy_n(values.begin() + 524, 16, snapshot.target_reserve.begin());
    std::copy_n(values.begin() + 540, 16, snapshot.coverage_bps.begin());
    snapshot.capital_mode = values[556];
    snapshot.minimum_authenticated_price = ReadBE64(values.data() + 557);
    snapshot.maximum_authenticated_price = ReadBE64(values.data() + 565);
    snapshot.funding_epoch = ReadBE64(values.data() + 573);
    snapshot.funding_rate_ppm = static_cast<int32_t>(ReadBE32(values.data() + 581));
    snapshot.redemption_queue_root = ReferenceCapitalHash(values.data() + 372);
    snapshot.redemption_head = ReadBE64(values.data() + 585);
    snapshot.redemption_tail = ReadBE64(values.data() + 593);
    snapshot.queued_redemption_share_atoms = ReadBE64(values.data() + 601);
    snapshot.oracle_certificate_hash = ReferenceCapitalHash(values.data() + 609);
    snapshot.oracle_valid_through_parent_mtp = ReadBE64(values.data() + 641);
    snapshot.oracle_mode = values[649];
    snapshot.encrypted_availability_root = ReferenceCapitalHash(values.data() + 650);
    snapshot.bond_inbox_head_root = ReferenceCapitalHash(values.data() + 682);
    snapshot.bond_inbox_entry_count = ReadBE64(values.data() + 714);
    snapshot.bond_inbox_processed_root = ReferenceCapitalHash(values.data() + 722);
    snapshot.bond_inbox_processed_cursor = ReadBE64(values.data() + 754);
    snapshot.bond_inbox_outcome_root = ReferenceCapitalHash(values.data() + 762);
    snapshot.bond_inbox_outcome_count = ReadBE64(values.data() + 794);
    snapshot.node_bond_inbox_head_root = snapshot.bond_inbox_head_root;
    snapshot.node_bond_inbox_entry_count = snapshot.bond_inbox_entry_count;
    snapshot.matcher_execution_receipt_batch_root = ReferenceCapitalHash(values.data() + 802);
    snapshot.previous_matcher_execution_sequence = ReadBE64(values.data() + 834);
    snapshot.matcher_execution_sequence = ReadBE64(values.data() + 842);
    // V2 has no treasury/operations allocation. The legacy fee pool is a
    // consensus invariant and is therefore projected as exact zero only.
    snapshot.legacy_fee_pool.fill(0);
    return snapshot;
    }
    if (profile==1) {
    snapshot = {};
    snapshot.proof_profile = 1;
    snapshot.exchange_state_root = context[0];
    snapshot.configuration_hash = ReferenceCapitalHash(values.data() + 4);
    snapshot.bond_asset_id = ReferenceCapitalHash(values.data() + 452);
    snapshot.bond_deployment_commitment = ReferenceCapitalHash(values.data() + 484);
    snapshot.transition_program_id = context[4];
    snapshot.transition_cmr = context[5];
    snapshot.covenant_state_hash = ReferenceCapitalHash(values.data() + 68);
    snapshot.bond_inventory_covenant_hash = ReferenceCapitalHash(values.data() + 516);
    snapshot.bond_state_root = ReferenceCapitalHash(values.data() + 548);
    snapshot.funding_state_root = ReferenceCapitalHash(values.data() + 580);
    snapshot.redemption_queue_root = ReferenceCapitalHash(values.data() + 612);
    snapshot.oracle_certificate_hash = ReferenceCapitalHash(values.data() + 644);
    snapshot.matcher_execution_receipt_batch_root = ReferenceCapitalHash(values.data() + 676);
    snapshot.encrypted_availability_root = ReferenceCapitalHash(values.data() + 228);
    snapshot.bond_inbox_head_root = ReferenceCapitalHash(values.data() + 708);
    snapshot.bond_inbox_processed_root = ReferenceCapitalHash(values.data() + 740);
    snapshot.bond_inbox_outcome_root = ReferenceCapitalHash(values.data() + 772);
    snapshot.node_bond_inbox_head_root = snapshot.bond_inbox_head_root;

    static constexpr size_t SCALAR_OFFSET{4 + 40 * 32};
    snapshot.minimum_authenticated_price = ReadBE64(values.data() + SCALAR_OFFSET + 24);
    snapshot.maximum_authenticated_price = ReadBE64(values.data() + SCALAR_OFFSET + 40);
    snapshot.issued_share_atoms = ReadBE64(values.data() + SCALAR_OFFSET + 48);
    snapshot.outstanding_share_atoms = ReadBE64(values.data() + SCALAR_OFFSET + 56);
    snapshot.inventory_share_atoms = ReadBE64(values.data() + SCALAR_OFFSET + 64);
    snapshot.queued_redemption_share_atoms = ReadBE64(values.data() + SCALAR_OFFSET + 72);
    snapshot.funding_epoch = ReadBE64(values.data() + SCALAR_OFFSET + 80);
    snapshot.oracle_valid_through_parent_mtp = ReadBE64(values.data() + SCALAR_OFFSET + 88);
    std::copy_n(values.begin() + SCALAR_OFFSET + 96, 16, snapshot.global_funding_index_numerator.begin());
    static constexpr size_t WIDE_OFFSET{SCALAR_OFFSET + 112};
    std::copy_n(values.begin() + WIDE_OFFSET + 32, 16, snapshot.full_bound_deficit.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 48, 16, snapshot.target_reserve.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 64, 16, snapshot.insurance_reserve.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 80, 16, snapshot.controlled_usdd_atoms.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 96, 16, snapshot.matcher_execution_sequence.bytes.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 112, 16, snapshot.nav_per_whole_share.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 128, 16, snapshot.coverage_bps.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 144, 16, snapshot.redemption_head.bytes.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 160, 16, snapshot.redemption_tail.bytes.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 176, 16, snapshot.bond_inbox_entry_count.bytes.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 192, 16, snapshot.bond_inbox_processed_cursor.bytes.begin());
    std::copy_n(values.begin() + WIDE_OFFSET + 208, 16, snapshot.bond_inbox_outcome_count.bytes.begin());
    snapshot.node_bond_inbox_entry_count = snapshot.bond_inbox_entry_count;
    snapshot.funding_rate_ppm =
        static_cast<int32_t>(ReadBE32(values.data() + WIDE_OFFSET + 224));
    snapshot.capital_mode = values[WIDE_OFFSET + 228];
    snapshot.oracle_mode = values[WIDE_OFFSET + 229];
    snapshot.operationally_safe = values[WIDE_OFFSET + 230];
    snapshot.legacy_fee_pool.fill(0);
    return snapshot;
    }
    snapshot = {};
    snapshot.proof_profile = 1;
    snapshot.exchange_state_root = context[0];
    snapshot.configuration_hash =
        context[1];
    snapshot.bond_asset_id = context[2];
    snapshot.bond_deployment_commitment =
        context[3];
    snapshot.transition_program_id =
        context[4];
    snapshot.transition_cmr =
        context[5];
    snapshot.covenant_state_hash = ReferenceCapitalHash(values.data()+132);
    snapshot.bond_state_root = ReferenceCapitalHash(values.data() + 260);
    snapshot.funding_state_root = ReferenceCapitalHash(values.data() + 292);
    snapshot.bond_inventory_covenant_hash =
        context[6];
    snapshot.issued_share_atoms = UINT64_C(2100000000000000);
    snapshot.inventory_share_atoms = snapshot.issued_share_atoms;
    snapshot.coverage_bps[14] = 0x30;
    snapshot.coverage_bps[15] = 0xd4;
    snapshot.minimum_authenticated_price = ReadBE64(values.data() + 348);
    snapshot.maximum_authenticated_price = ReadBE64(values.data() + 356);
    snapshot.funding_epoch = mtp / UINT64_C(28800);
    snapshot.redemption_queue_root = context[7];
    snapshot.bond_inbox_head_root =
        context[8];
    snapshot.bond_inbox_processed_root = snapshot.bond_inbox_head_root;
    snapshot.node_bond_inbox_head_root = snapshot.bond_inbox_head_root;
    snapshot.bond_inbox_outcome_root = context[9];
    snapshot.last_transition_sidechain_height = static_cast<uint64_t>(height);
    snapshot.operationally_safe = 1;

    return snapshot;
}

// Preserved genesis assignments, independent of the Haskell layout table.
static ecx::BondV2CapitalSnapshot ReferenceGenesisCapitalSnapshot(
    const std::array<uint256,15>& hashes, uint64_t height, uint64_t mtp, uint64_t price)
{
    ecx::BondV2CapitalSnapshot snapshot{};
    snapshot.proof_profile = 0;
    snapshot.exchange_state_root = hashes[0];
    snapshot.configuration_hash = hashes[1];
    snapshot.bond_asset_id = hashes[2];
    snapshot.bond_deployment_commitment = hashes[3];
    snapshot.transition_program_id = hashes[4];
    snapshot.transition_cmr = hashes[5];
    snapshot.covenant_state_hash = hashes[6];
    snapshot.bond_state_root = hashes[7];
    snapshot.funding_state_root = hashes[8];
    snapshot.bond_inventory_covenant_hash = hashes[9];
    snapshot.issued_share_atoms = 2'100'000'000'000'000;
    snapshot.inventory_share_atoms = 2'100'000'000'000'000;
    snapshot.coverage_bps[14] = 0x30;
    snapshot.coverage_bps[15] = 0xd4;
    snapshot.capital_mode = 0;
    snapshot.minimum_authenticated_price = price;
    snapshot.maximum_authenticated_price = price;
    snapshot.funding_epoch = mtp / 28'800;
    snapshot.redemption_queue_root = hashes[10];
    snapshot.oracle_valid_through_parent_mtp = mtp;
    snapshot.encrypted_availability_root = hashes[11];
    snapshot.bond_inbox_head_root = hashes[12];
    snapshot.bond_inbox_processed_root = snapshot.bond_inbox_head_root;
    snapshot.bond_inbox_outcome_root = hashes[13];
    snapshot.node_bond_inbox_head_root = snapshot.bond_inbox_head_root;
    snapshot.matcher_execution_receipt_batch_root = hashes[14];
    snapshot.last_transition_sidechain_height = height;
    return snapshot;
}
