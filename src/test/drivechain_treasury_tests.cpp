// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivechain_treasury.h>
#include <drivechain_parent_rules.h>
#include <elements_drivechain_bootstrap.h>
#include <boost/test/unit_test.hpp>
#include <vector>
#include <limits>

BOOST_AUTO_TEST_SUITE(drivechain_treasury_tests)

BOOST_AUTO_TEST_CASE(bootstrap_generated_catalog_matches_original_fields)
{
    using Slot = ElementsDrivechainBootstrap::Slot;
    constexpr std::array<Slot, 7> expected{{
        Slot{2, "44923e8adf714f49838fa096a59d3913811b8af07cca03b82843b76fe9ca6cd9", "0000000000000000000000000000000000000000000000000000000000000000", 4294967295, 0},
        Slot{4, "e5cfe12a22ff7245baf797dc7e966033afeaddd7dfe5a8379e37a8751fa55a2a", "0000000000000000000000000000000000000000000000000000000000000000", 4294967295, 0},
        Slot{9, "61375db9dc0fe8c2b3aabdadcd7a5ea542ca9162cc8c89992bb3e6c5869ce039", "57dd0496215533d258e6c08119f3952ce12c3f804523e307d4de983eccc991a0", 0, 302000000},
        Slot{13, "76b3820beb056fe6674013ed4eddd9e074bb2621107ecab886eebd0a175c4f17", "0000000000000000000000000000000000000000000000000000000000000000", 4294967295, 0},
        Slot{98, "2fb3d32db5bf9f82624a07313ed09713fd271f06f3276034830dba0131280c8c", "0000000000000000000000000000000000000000000000000000000000000000", 4294967295, 0},
        Slot{99, "d9825e315ab563c70f38496d0867ecde37a9791b746d47fcec5290a8eda05597", "0000000000000000000000000000000000000000000000000000000000000000", 4294967295, 0},
        Slot{255, "3459ab323378afbc87c8719f5807448a79849c481c5a23930a9aa8c93ef5d144", "0000000000000000000000000000000000000000000000000000000000000000", 4294967295, 0},
    }};
    constexpr auto actual = ElementsDrivechainBootstrap::SlotsForReplayVersion(4);
    static_assert(actual && actual->size() == 7);
    static_assert(ElementsDrivechainBootstrap::SlotsForReplayVersion(5)->data() == nullptr);
    BOOST_REQUIRE_EQUAL(actual->size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        BOOST_CHECK_EQUAL((*actual)[i].slot, expected[i].slot);
        BOOST_CHECK_EQUAL(std::string((*actual)[i].active), expected[i].active);
        BOOST_CHECK_EQUAL(std::string((*actual)[i].ctip_txid), expected[i].ctip_txid);
        BOOST_CHECK_EQUAL((*actual)[i].ctip_vout, expected[i].ctip_vout);
        BOOST_CHECK_EQUAL((*actual)[i].ctip_value, expected[i].ctip_value);
    }
    for (uint32_t version = 0; version <= 1024; ++version) {
        const auto slots = ElementsDrivechainBootstrap::SlotsForReplayVersion(version);
        BOOST_CHECK_EQUAL(slots.has_value(), version == 4 || version == 5);
    }
}

BOOST_AUTO_TEST_CASE(bootstrap_slots_do_not_cross_networks)
{
    const auto legacy = ElementsDrivechainBootstrap::SlotsForReplayVersion(4);
    const auto beta = ElementsDrivechainBootstrap::SlotsForReplayVersion(5);
    BOOST_REQUIRE(legacy);
    BOOST_REQUIRE(beta);
    BOOST_CHECK_EQUAL(legacy->size(), 7);
    BOOST_CHECK(beta->empty());
    for (const auto& slot : *legacy) BOOST_CHECK(slot.slot != 24);
    for (const uint32_t version : {0U, 3U, 6U, 0xffffffffU}) {
        BOOST_CHECK(!ElementsDrivechainBootstrap::SlotsForReplayVersion(version));
    }
}

BOOST_AUTO_TEST_CASE(parent_rules_are_versioned_and_fail_closed)
{
    const auto legacy = drivechain::ParentRulesForVersion(4);
    const auto beta = drivechain::ParentRulesForVersion(5);
    BOOST_REQUIRE(legacy);
    BOOST_REQUIRE(beta);
    BOOST_CHECK(legacy->treasury_opcode == drivechain::TreasuryOpcode::NOP5);
    BOOST_CHECK(legacy->m6 == DrivechainM6ReplayRule::SINGLE_CONFIGURED_SLOT_M6);
    BOOST_CHECK(legacy->history == DrivechainWithdrawalHistoryRule::UNIQUE_M6ID);
    BOOST_CHECK(beta->treasury_opcode == drivechain::TreasuryOpcode::NOP8);
    BOOST_CHECK(beta->m6 == DrivechainM6ReplayRule::SEQUENTIAL_M6);
    BOOST_CHECK(beta->history == DrivechainWithdrawalHistoryRule::ALLOW_REPROPOSAL);
    BOOST_CHECK(legacy->bootstrap_domain == "ELEMENTS_ALPHANET_PARENT_REPLAY_BOOTSTRAP_V1");
    BOOST_CHECK(beta->bootstrap_domain == "ELEMENTS_BETANET_PARENT_REPLAY_BOOTSTRAP_V1");
    BOOST_CHECK(legacy->local_rule_domain == "ELEMENTS_SLOT24_SINGLE_M6_PER_PARENT_BLOCK_V1");
    BOOST_CHECK(beta->local_rule_domain == "ELEMENTS_SLOT24_SEQUENTIAL_M6_REPROPOSAL_V1");
    BOOST_CHECK(legacy->proposal_text == "Elements Drivechain v11; parameterized controller profile; replay v4; annex v2; one M6 per parent block; withdrawal accumulator v1; BIP301 checkpoint v1; Simplicity active; slot 24");
    BOOST_CHECK(beta->proposal_text == "Elements Drivechain Betanet v1; parameterized controller profile; replay v5; annex v2; sequential M6; withdrawal accumulator v1; BIP301 checkpoint v1; Simplicity active; slot 24");
    for (const uint32_t version : {0U, 1U, 2U, 3U, 6U, 255U, 0xffffffffU}) {
        BOOST_CHECK(!drivechain::ParentRulesForVersion(version));
    }
    const auto frozen = drivechain::ParentRulesForVersion(ElementsDrivechainIdentity::PARENT_REPLAY_VERSION);
    BOOST_REQUIRE(frozen);
    BOOST_CHECK(frozen->treasury_opcode == drivechain::FROZEN_PARENT_RULES.treasury_opcode);
    BOOST_CHECK(frozen->m6 == drivechain::FROZEN_PARENT_RULES.m6);
    BOOST_CHECK(frozen->history == drivechain::FROZEN_PARENT_RULES.history);
}

BOOST_AUTO_TEST_CASE(parent_opcode_and_all_slots)
{
    for (const auto opcode : {drivechain::TreasuryOpcode::NOP5, drivechain::TreasuryOpcode::NOP8}) {
        for (int n = 0; n < 256; ++n) {
            const std::vector<unsigned char> script{static_cast<uint8_t>(opcode), 1, static_cast<uint8_t>(n), 0x51};
            uint8_t slot{0};
            BOOST_CHECK(drivechain::ExtractTreasurySlot(script, opcode, slot));
            BOOST_CHECK_EQUAL(slot, n);
            BOOST_CHECK(drivechain::IsTreasuryScript(script, opcode, n));
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, (n + 1) % 256));
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, -1));
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, 256));
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, std::numeric_limits<int>::min()));
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, std::numeric_limits<int>::max()));
            const auto other = opcode == drivechain::TreasuryOpcode::NOP5
                ? drivechain::TreasuryOpcode::NOP8 : drivechain::TreasuryOpcode::NOP5;
            BOOST_CHECK(!drivechain::ExtractTreasurySlot(script, other, slot));
        }
    }
}

BOOST_AUTO_TEST_CASE(noncanonical_and_truncated_scripts)
{
    for (const auto opcode : {drivechain::TreasuryOpcode::NOP5, drivechain::TreasuryOpcode::NOP8}) {
        const auto byte = static_cast<uint8_t>(opcode);
        const std::vector<std::vector<unsigned char>> invalid{
            {}, {byte}, {byte, 1}, {byte, 1, 24},
            {byte, 1, 24, 0x51, 0}, {byte, 1, 24, 0},
            {byte, 0x4c, 1, 24, 0x51}, {byte, 0x4d, 1, 0, 24, 0x51},
            {byte, 0x4e, 1, 0, 0, 0, 24, 0x51}, {byte, 0x51, 0x51},
        };
        for (const auto& script : invalid) {
            uint8_t slot{99};
            BOOST_CHECK(!drivechain::ExtractTreasurySlot(script, opcode, slot));
            BOOST_CHECK_EQUAL(slot, 99);
            BOOST_CHECK(!drivechain::IsTreasuryScript(script, opcode, 24));
        }
    }
}

BOOST_AUTO_TEST_CASE(unknown_parent_opcode)
{
    for (int n = 0; n < 256; ++n) {
        if (n == 0xb4 || n == 0xb7) continue;
        const std::vector<unsigned char> script{static_cast<uint8_t>(n), 1, 24, 0x51};
        uint8_t slot{99};
        BOOST_CHECK(!drivechain::ExtractTreasurySlot(
            script, static_cast<drivechain::TreasuryOpcode>(n), slot));
        BOOST_CHECK_EQUAL(slot, 99);
        BOOST_CHECK(!drivechain::IsTreasuryScript(script, static_cast<drivechain::TreasuryOpcode>(n), 24));
    }
}

BOOST_AUTO_TEST_SUITE_END()
