// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/haskell_reference.h>
#include <test/data/usdd_mainnet_segment.raw.h>
#include <test/data/usdd_mainnet_journal.raw.h>
#include <init.h>
#include <elements_drivechain_identity.h>
#include <haskell/simplicity_ffi.h>
#include <primitives/confidential.h>
#include <script/usdd_sp1_annex.h>
#include <script/usdd_sp1_verifier_ffi.h>
#include <usdd_sp1_verifier_identity.h>
#include <util/strencodings.h>

#include <array>
#include <optional>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(usdd_sp1_verifier_identity_tests)

BOOST_AUTO_TEST_CASE(startup_admission_orders_every_failure_and_skips_inactive)
{
    const char* errors[]{
        "USDD SP1 activation has no frozen verifier semantic identity",
        "USDD SP1 activation requires the pinned verifier, but this binary was built without it",
        "linked USDD SP1 verifier ABI does not match the production identity",
        "linked USDD SP1 verifier semantic-identity format does not match the production identity",
        "linked USDD SP1 verifier could not export its semantic identity",
        "linked USDD SP1 verifier semantics do not match the production identity"};
    for (unsigned mask = 0; mask < 64; ++mask) {
        unsigned failure = 0;
        while (failure < 6 && (mask & (1U << failure))) ++failure;
        for (bool diagnostic : {false,true}) {
            unsigned calls = 0;
            std::string error{"stale"};
            const bool accepted = drivechain::haskell::VerifierStartup(true, [&](uint32_t step) {
                BOOST_CHECK_EQUAL(step, calls++);
                return bool(mask & (1U << step));
            }, diagnostic ? &error : nullptr);
            BOOST_CHECK_EQUAL(accepted, failure == 6);
            BOOST_CHECK_EQUAL(calls, std::min(6U,failure+1));
            BOOST_CHECK_EQUAL(error, diagnostic ? (failure == 6 ? "" : errors[failure]) : "stale");
        }
    }
    std::string error{"stale"};
    const auto unexpected = [](uint32_t) -> bool { throw std::logic_error("unexpected verifier read"); };
    BOOST_CHECK(drivechain::haskell::VerifierStartup(false, unexpected, &error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_THROW(drivechain::haskell::VerifierStartup(true, unexpected, nullptr), std::logic_error);
}

BOOST_AUTO_TEST_CASE(inactive_gate_does_not_require_a_native_archive)
{
    std::string error;
    std::array<uint8_t, 32> unset{};
    BOOST_CHECK(CheckUsddSp1VerifierStartupIdentity(false, unset, &error));
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_CASE(activation_rejects_an_unfrozen_identity)
{
    std::string error;
    std::array<uint8_t, 32> unset{};
    BOOST_CHECK(!CheckUsddSp1VerifierStartupIdentity(true, unset, &error));
    BOOST_CHECK_EQUAL(
        error,
        "USDD SP1 activation has no frozen verifier semantic identity");
}

BOOST_AUTO_TEST_CASE(activation_requires_the_exact_linked_semantics)
{
    std::string error;
    std::array<uint8_t, 32> expected{};
    expected[0] = 1;
#if defined(HAVE_USDD_SP1_VERIFIER)
    BOOST_REQUIRE_EQUAL(
        usdd_sp1_verifier_semantic_identity(expected.data(), expected.size()),
        USDD_SP1_VERIFIER_ACCEPTED);
    BOOST_CHECK(CheckUsddSp1VerifierStartupIdentity(true, expected, &error));
    expected.back() ^= 1;
    BOOST_CHECK(!CheckUsddSp1VerifierStartupIdentity(true, expected, &error));
    BOOST_CHECK_EQUAL(
        error,
        "linked USDD SP1 verifier semantics do not match the production identity");
#else
    BOOST_CHECK(!CheckUsddSp1VerifierStartupIdentity(true, expected, &error));
    BOOST_CHECK_EQUAL(
        error,
        "USDD SP1 activation requires the pinned verifier, but this binary was built without it");
#endif
}

BOOST_AUTO_TEST_CASE(patched_verifier_preserves_the_genesis_transcript)
{
    static constexpr std::array<uint8_t, 32> CORRECTED_VERIFIER{{
        0x6b, 0x02, 0x92, 0x57, 0x0f, 0xa1, 0x20, 0xae,
        0x88, 0x57, 0x43, 0xa3, 0x91, 0xeb, 0xa1, 0x8a,
        0x1e, 0x53, 0x04, 0x55, 0x28, 0x46, 0x48, 0xcf,
        0xde, 0x30, 0xdc, 0x28, 0xbf, 0x3b, 0x64, 0xa9,
    }};
    static constexpr std::array<uint8_t, 32> CORRECTED_PROFILE{{
        0x6f, 0xd5, 0xa5, 0xe5, 0x57, 0x69, 0x32, 0x0c,
        0xc1, 0xc6, 0xa4, 0x97, 0x64, 0x4d, 0x0b, 0xc7,
        0xa6, 0x42, 0xee, 0xd8, 0x44, 0x2a, 0xb1, 0x70,
        0x3a, 0xf3, 0x04, 0xcf, 0xac, 0x25, 0x3d, 0x25,
    }};
    BOOST_CHECK_EQUAL_COLLECTIONS(
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_SEMANTIC_IDENTITY.begin(),
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_SEMANTIC_IDENTITY.end(),
        CORRECTED_VERIFIER.begin(), CORRECTED_VERIFIER.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        ElementsDrivechainIdentity::PARAMETERIZED_CONTROLLER_PROFILE_ID.begin(),
        ElementsDrivechainIdentity::PARAMETERIZED_CONTROLLER_PROFILE_ID.end(),
        CORRECTED_PROFILE.begin(), CORRECTED_PROFILE.end());
#if defined(HAVE_USDD_SP1_VERIFIER)
    std::array<uint8_t, 32> linked{};
    BOOST_REQUIRE_EQUAL(
        usdd_sp1_verifier_semantic_identity(linked.data(), linked.size()),
        USDD_SP1_VERIFIER_ACCEPTED);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        linked.begin(), linked.end(),
        UsddSp1VerifierRelease::SEMANTIC_IDENTITY.begin(),
        UsddSp1VerifierRelease::SEMANTIC_IDENTITY.end());
    std::string error;
    BOOST_CHECK(CheckCanonicalUsddSp1VerifierStartupIdentity(&error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(!CheckUsddSp1VerifierStartupIdentity(true, CORRECTED_VERIFIER, &error));
    BOOST_CHECK_EQUAL(error, "linked USDD SP1 verifier semantics do not match the production identity");
#endif
}

BOOST_AUTO_TEST_CASE(production_fee_asset_is_immutable)
{
    const CAsset pegged{uint256S(ElementsDrivechainIdentity::PEGGED_ASSET)};
    CAsset resolved;
    std::string error;

    const std::vector<std::optional<std::string>> inputs{
        std::nullopt,"",pegged.GetHex(),std::string(64,'0'),std::string(64,'A'),
        std::string(64,'1'),std::string(63,'1'),std::string(65,'1'),std::string(64,'z'),
        "0x"+std::string(62,'1'),std::string(63,'1')+" ",std::string(63,'1')+std::string(1,'\0')};
    for (const bool canonical : {false,true}) {
        for (const auto& configured : inputs) {
            const auto parsed = configured ? uint256::FromHex(*configured) : std::optional<uint256>{pegged.id};
            const bool allowed = parsed && (!canonical || *parsed == pegged.id);
            const CAsset sentinel{uint256::ONE};
            CAsset actual{sentinel};
            std::string message{"stale"};
            BOOST_CHECK_EQUAL(ResolveElementsFeeAsset(configured,pegged,canonical,actual,&message),allowed);
            BOOST_CHECK(actual == (allowed ? CAsset{*parsed} : sentinel));
            BOOST_CHECK_EQUAL(message,!parsed ? "-feeasset must be exactly 64 hexadecimal characters" :
                !allowed ? "-feeasset must equal the immutable Elements pegged asset" : "");
        }
    }

    BOOST_CHECK(ResolveElementsFeeAsset(std::nullopt, pegged, true, resolved, &error));
    BOOST_CHECK(resolved == pegged);
    BOOST_CHECK(ResolveElementsFeeAsset(pegged.GetHex(), pegged, true, resolved, &error));
    BOOST_CHECK(resolved == pegged);

    BOOST_CHECK(!ResolveElementsFeeAsset(std::string(64, '1'), pegged, true, resolved, &error));
    BOOST_CHECK_EQUAL(error, "-feeasset must equal the immutable Elements pegged asset");
    BOOST_CHECK(!ResolveElementsFeeAsset("not-an-asset", pegged, true, resolved, &error));
    BOOST_CHECK_EQUAL(error, "-feeasset must be exactly 64 hexadecimal characters");
}

#if defined(HAVE_USDD_SP1_VERIFIER)
// Real Windows receipt, compiled into the test only, never the daemon.
BOOST_AUTO_TEST_CASE(windows_mainnet_segment_is_not_a_mint)
{
    const auto sha256 = [](const std::vector<unsigned char>& bytes) {
        std::array<unsigned char, 32> digest{};
        CSHA256().Write(bytes.data(), bytes.size()).Finalize(digest.data());
        return digest;
    };
    const auto read = [&](const auto& fixture, size_t size, const char* hash) {
        const auto* begin = reinterpret_cast<const unsigned char*>(fixture.data());
        const std::vector<unsigned char> bytes(begin, begin + fixture.size());
        BOOST_REQUIRE_EQUAL(bytes.size(), size);
        BOOST_REQUIRE_EQUAL(HexStr(sha256(bytes)), hash);
        return bytes;
    };
    auto proof = read(test::data::usdd_mainnet_segment, 1'273'035,
        "2ed9cab58fcb22430f503ffc1dc73404f274708e0fda4726d8f5f22786fffbd0");
    const auto journal = read(test::data::usdd_mainnet_journal, 466,
        "be9ab3e6a9f8850a5f903607668b885827f9a560b2c6c4c947836623d0fc3a42");
    // The pinned Rust compatibility probe decodes this exact SDK envelope and
    // proves that its first 1,272,546 bytes are the canonical compressed proof.
    proof.resize(1'272'546);
    const auto program = ParseHex("327a8b856ff3efc438c60b521dc0ce081584878274f1b456080fdc77773d5ce0");
    const auto journal_hash = sha256(journal);
    for (const bool replace_with_hash : {false, true}) {
        const std::vector<unsigned char> values = replace_with_hash
            ? std::vector<unsigned char>{journal_hash.begin(), journal_hash.end()} : journal;
        const auto digest = sha256(values);
        for (const uint8_t kind : {1, 3}) {
            BOOST_TEST_CONTEXT("statement=" << unsigned(kind) << " hashed-output=" << replace_with_hash) {
                std::vector<unsigned char> annex{'\x50','U','S','D','D','S','P','1',0,1,1,kind,1,0,0};
                annex.resize(usdd::SP1_ANNEX_HEADER_SIZE);
                WriteBE32(annex.data() + 15, values.size());
                WriteBE32(annex.data() + 19, proof.size());
                std::copy(program.begin(), program.end(), annex.begin() + 23);
                annex.insert(annex.end(), values.begin(), values.end());
                annex.insert(annex.end(), proof.begin(), proof.end());
                usdd::Sp1ProofAnnexView view;
                const auto parsed = usdd::ParseUsddSp1ProofAnnex(annex, view);
                BOOST_CHECK(parsed == (kind == 3 && !replace_with_hash
                    ? usdd::Sp1AnnexError::INVALID_STRONG_EXECUTION_PUBLIC_VALUES : usdd::Sp1AnnexError::OK));
                BOOST_CHECK(usdd::VerifyUsddSp1AnnexForJournal(annex, program, digest) == usdd::Sp1VerifierResult::REJECTED);
                const auto read_annex = [](const void* context, const unsigned char** data, size_t* size) {
                    const auto& bytes = *static_cast<const std::vector<unsigned char>*>(context);
                    *data = bytes.data();
                    *size = bytes.size();
                    return true;
                };
                BOOST_CHECK(!elements_haskell_verify_jet(usdd_sp1_verifier_abi_version, usdd_sp1_verify_annex,
                    read_annex, &annex, program.data(), digest.data()));
            }
        }
    }
}
#endif

BOOST_AUTO_TEST_SUITE_END()
