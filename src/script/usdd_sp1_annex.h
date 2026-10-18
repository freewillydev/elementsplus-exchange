// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_USDD_SP1_ANNEX_H
#define BITCOIN_SCRIPT_USDD_SP1_ANNEX_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <span.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <elements_drivechain_identity.h>
#include <haskell/bridge.h>

#if defined(HAVE_USDD_SP1_VERIFIER)
#include <script/usdd_sp1_verifier_ffi.h>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

/**
 * Versioned envelope for an opaque SP1 proof carried in a Taproot annex.
 *
 * Parsing this envelope does not verify the proof. In particular, callers
 * must not interpret ParseUsddSp1ProofAnnex() success as authorization to mint
 * or release an asset. The mint controller must invoke the environmental SP1
 * verifier jet with both its frozen guest program ID and SHA-256 of the exact
 * canonical journal it consumed.
 *
 * All integer fields are unsigned big-endian:
 *
 *   0       1   Taproot annex tag (0x50)
 *   1       8   magic: "USDDSP1\0"
 *   9       1   envelope version (1)
 *   10      1   proof system (1 = SP1 compressed)
 *   11      1   statement kind (1 = finalized Ethereum state transition,
 *               3 = V11 controller strong execution)
 *   12      1   public digest mode (1 = SHA-256)
 *   13      2   flags (must be zero)
 *   15      4   public-values byte length
 *   19      4   proof byte length
 *   23     32   SP1 HashableKey::hash_bytes program ID: eight canonical
 *               KoalaBear field words in big-endian order (not SHA256(vkey))
 *   55      n   public values followed by opaque proof bytes
 */
namespace usdd {

static constexpr unsigned char SP1_ANNEX_TAG{0x50};
static constexpr std::array<unsigned char, 8> SP1_ANNEX_MAGIC{{'U', 'S', 'D', 'D', 'S', 'P', '1', 0x00}};
static constexpr std::size_t SP1_ANNEX_HEADER_SIZE{55};
static constexpr std::size_t SP1_ANNEX_MAX_SIZE{
    ElementsDrivechainIdentity::USDD_SP1_ANNEX_MAX_BYTES};
static constexpr std::size_t SP1_PUBLIC_VALUES_MAX_SIZE{16 * 1024};
static_assert(SP1_ANNEX_MAX_SIZE ==
              ElementsDrivechainIdentity::USDD_SP1_ANNEX_MAX_BYTES);
static_assert(SP1_PUBLIC_VALUES_MAX_SIZE ==
              ElementsDrivechainIdentity::USDD_SP1_PUBLIC_VALUES_MAX_BYTES);

enum class Sp1StatementKind : uint8_t {
    ETH_STATE_V1 = 1,
    CONTROLLER_STRONG_EXECUTION_V2 = 3,
};
static_assert(
    ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
            static_cast<uint8_t>(Sp1StatementKind::ETH_STATE_V1) ||
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
            static_cast<uint8_t>(Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2));

enum class Sp1AnnexError {
    OK,
    NOT_USDD,
    TOO_LARGE,
    TRUNCATED,
    BAD_MAGIC,
    BAD_VERSION,
    BAD_PROOF_SYSTEM,
    BAD_STATEMENT_KIND,
    BAD_DIGEST_MODE,
    BAD_FLAGS,
    EMPTY_PUBLIC_VALUES,
    PUBLIC_VALUES_TOO_LARGE,
    INVALID_STRONG_EXECUTION_PUBLIC_VALUES,
    EMPTY_PROOF,
    ZERO_GUEST_PROGRAM_ID,
    LENGTH_MISMATCH,
};

enum class Sp1ConsensusGateResult {
    NOT_USDD,
    MALFORMED,
    WRONG_CONTROLLER_CMR,
    WRONG_GUEST_PROGRAM_ID,
    MALFORMED_PUBLIC_VALUES,
    DEPLOYMENT_UNCONFIGURED,
    WRONG_INBOUND_MINT_DOMAIN,
    BMM_CONTEXT_MISSING,
    VERIFIER_UNAVAILABLE,
    READY_FOR_JET,
};

enum class Sp1ProofIdentityResult {
    MATCH,
    WRONG_CONTROLLER_CMR,
    WRONG_GUEST_PROGRAM_ID,
    MALFORMED_PUBLIC_VALUES,
    DEPLOYMENT_UNCONFIGURED,
    WRONG_INBOUND_MINT_DOMAIN,
};



/** Result exposed to the future generated environmental verifier jet. */
enum class Sp1VerifierResult {
    VERIFIED,
    REJECTED,
    UNAVAILABLE,
};

struct Sp1ProofAnnexView {
    Sp1StatementKind statement_kind{Sp1StatementKind::ETH_STATE_V1};
    Span<const unsigned char> guest_program_id{};
    Span<const unsigned char> public_values{};
    Span<const unsigned char> proof{};
};

inline bool IsUsddSp1ProofAnnex(Span<const unsigned char> annex)
{
    // Reserve 0x50 || "USDD" as the protocol namespace.  A malformed annex in
    // this namespace is rejected instead of being mistaken for an unrelated
    // Taproot annex.
    // A matching five-byte probe is necessarily truncated, never a valid proof.
    return drivechain::haskell::UsddAnnex(
        {annex.data(), std::min(annex.size(), size_t{5})}, 5, {}) ==
        static_cast<uint32_t>(Sp1AnnexError::TRUNCATED);
}

inline uint32_t ReadUint32BE(Span<const unsigned char> bytes, std::size_t offset)
{
    return ReadBE32(bytes.data() + offset);
}


// Only call after successful annex validation; the returned spans borrow input.
inline Sp1ProofAnnexView ValidatedSp1AnnexView(Span<const unsigned char> annex)
{
    const uint32_t public_size = ReadUint32BE(annex, 15);
    return {static_cast<Sp1StatementKind>(annex[11]), annex.subspan(23, 32),
        annex.subspan(SP1_ANNEX_HEADER_SIZE, public_size),
        annex.subspan(SP1_ANNEX_HEADER_SIZE + public_size, ReadUint32BE(annex, 19))};
}

inline Sp1AnnexError ParseUsddSp1ProofAnnex(Span<const unsigned char> annex, Sp1ProofAnnexView& result)
{
    result = {};
    static_assert(SP1_ANNEX_HEADER_SIZE == 55 && SP1_PUBLIC_VALUES_MAX_SIZE == 16384);
    const auto error = static_cast<Sp1AnnexError>(drivechain::haskell::UsddAnnex(
        {annex.data(), annex.size()}, SP1_ANNEX_MAX_SIZE, {
            ElementsDrivechainIdentity::USDD_SP1_ANNEX_ENVELOPE_VERSION,
            ElementsDrivechainIdentity::USDD_SP1_ANNEX_PROOF_SYSTEM,
            ElementsDrivechainIdentity::USDD_SP1_ANNEX_DIGEST_MODE}));
    if (error != Sp1AnnexError::OK) return error;
    result = ValidatedSp1AnnexView(annex);
    return Sp1AnnexError::OK;
}

inline Sp1ConsensusGateResult AdmitSp1Annex(uint32_t lane, Span<const unsigned char> annex,
    bool bmm, bool active, const std::function<int32_t(const Sp1ProofAnnexView&)>& identity)
{
    return static_cast<Sp1ConsensusGateResult>(drivechain::haskell::UsddAdmission(
        lane, {annex.data(), annex.size()}, SP1_ANNEX_MAX_SIZE, {
            ElementsDrivechainIdentity::USDD_SP1_ANNEX_ENVELOPE_VERSION,
            ElementsDrivechainIdentity::USDD_SP1_ANNEX_PROOF_SYSTEM,
            ElementsDrivechainIdentity::USDD_SP1_ANNEX_DIGEST_MODE}, bmm, active,
        [&](uint32_t) { return static_cast<int32_t>(identity(ValidatedSp1AnnexView(annex))); }));
}

inline const char* Sp1AnnexErrorString(Sp1AnnexError error)
{
    switch (error) {
    case Sp1AnnexError::OK: return "ok";
    case Sp1AnnexError::NOT_USDD: return "not a USDD annex";
    case Sp1AnnexError::TOO_LARGE: return "annex exceeds frozen maximum";
    case Sp1AnnexError::TRUNCATED: return "truncated header";
    case Sp1AnnexError::BAD_MAGIC: return "invalid magic";
    case Sp1AnnexError::BAD_VERSION: return "unsupported envelope version";
    case Sp1AnnexError::BAD_PROOF_SYSTEM: return "unsupported proof system";
    case Sp1AnnexError::BAD_STATEMENT_KIND: return "unsupported statement kind";
    case Sp1AnnexError::BAD_DIGEST_MODE: return "unsupported public digest mode";
    case Sp1AnnexError::BAD_FLAGS: return "nonzero reserved flags";
    case Sp1AnnexError::EMPTY_PUBLIC_VALUES: return "empty public values";
    case Sp1AnnexError::PUBLIC_VALUES_TOO_LARGE: return "public values exceed 16 KiB";
    case Sp1AnnexError::INVALID_STRONG_EXECUTION_PUBLIC_VALUES: return "V11 strong-execution public values must be one nonzero 32-byte hash";
    case Sp1AnnexError::EMPTY_PROOF: return "empty proof";
    case Sp1AnnexError::ZERO_GUEST_PROGRAM_ID: return "zero SP1 guest program ID";
    case Sp1AnnexError::LENGTH_MISMATCH: return "declared lengths do not match annex";
    }
    return "unknown USDD annex error";
}

/**
 * Bind the reserved proof lane to the exact controller and guest, then apply
 * the chain's deployment-binding semantics.
 *
 * The CMR is the 32 bytes carried as the Tapsimplicity script item in witness
 * byte order. The guest ID is the exact 32-byte HashableKey representation in
 * the canonical annex. Callers must parse the annex before passing its view.
 */
inline bool SameSp1Identity(Span<const unsigned char> a, Span<const unsigned char> b)
{
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

inline uint32_t RunLegacyIdentity(uint32_t admission, Span<const unsigned char> input,
    Span<const unsigned char> script_cmr, Span<const unsigned char> guest_program_id,
    uint32_t version, Span<const unsigned char> domain, bool bmm = false, bool active = false,
    std::array<uint64_t,4> shape = {})
{
    const auto span = [](const auto& bytes) { return std::span<const unsigned char>{bytes.data(), bytes.size()}; };
    const std::span<const unsigned char> empty{};
    return drivechain::haskell::UsddLegacy(admission, {span(script_cmr),
        span(ElementsDrivechainIdentity::HISTORICAL_V8_CONTROLLER_CMR), span(guest_program_id),
        span(ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID), admission ? empty : span(input),
        span(domain), admission ? span(input) : empty}, {version,
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_DIGEST_MODE,
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND,
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_ENVELOPE_VERSION,
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_PROOF_SYSTEM}, SP1_ANNEX_MAX_SIZE, bmm, active, shape);
}

inline Sp1ProofIdentityResult CheckUsddSp1ProofIdentityForDeployment(
    Span<const unsigned char> script_cmr, Span<const unsigned char> guest_program_id,
    Span<const unsigned char> public_values, uint32_t deployment_binding_version,
    Span<const unsigned char> expected_inbound_mint_domain_id)
{
    return static_cast<Sp1ProofIdentityResult>(RunLegacyIdentity(false, public_values,
        script_cmr, guest_program_id, deployment_binding_version, expected_inbound_mint_domain_id));
}

/**
 * Bind an incompatible V11 strong-execution annex to its exact controller
 * leaf and SP1 guest without importing the legacy V1 journal/domain codec.
 *
 * The caller must supply identities from one immutable V11 chain manifest.
 * This helper deliberately has no default using the active V7 constants, so
 * adding the codec cannot activate V11 or reinterpret a historical network.
 */
inline int32_t StrongExecutionIdentityFacts(
    Span<const unsigned char> script_cmr,
    Span<const unsigned char> guest_program_id,
    Span<const unsigned char> public_values,
    Span<const unsigned char> expected_controller_cmr,
    Span<const unsigned char> expected_guest_program_id)
{
    const auto valid = [](auto bytes) { return bytes.size() == 32 &&
        std::any_of(bytes.begin(), bytes.end(), [](unsigned char byte) { return byte != 0; }); };
    // Facts only: Haskell selects the error precedence before BMM/activation.
    return (!valid(expected_controller_cmr) || !valid(expected_guest_program_id)) |
        ((script_cmr.size() != 32 || !SameSp1Identity(script_cmr, expected_controller_cmr)) << 1) |
        ((guest_program_id.size() != 32 || !SameSp1Identity(guest_program_id, expected_guest_program_id)) << 2) |
        ((!valid(public_values)) << 3);
}

/** Consensus callers must use the immutable chain-identity binding. */
inline Sp1ProofIdentityResult CheckUsddSp1ProofIdentity(
    Span<const unsigned char> script_cmr,
    Span<const unsigned char> guest_program_id,
    Span<const unsigned char> public_values)
{
    return CheckUsddSp1ProofIdentityForDeployment(
        script_cmr, guest_program_id, public_values,
        ElementsDrivechainIdentity::USDD_SP1_DEPLOYMENT_BINDING_VERSION,
        ElementsDrivechainIdentity::USDD_SP1_INBOUND_MINT_DOMAIN_ID);
}

/**
 * Call the pinned Rust verifier boundary for an environmental Simplicity jet.
 *
 * This helper is deliberately not called by the interpreter's annex parser.
 * Verification only becomes authorization when a controller program invokes a
 * generated environmental jet and supplies the digest of the exact canonical
 * journal that the program uses for its state transition.
 */
inline Sp1VerifierResult VerifyUsddSp1AnnexForJournal(
    Span<const unsigned char> annex,
    Span<const unsigned char> expected_program_id,
    Span<const unsigned char> expected_public_values_sha256)
{
#if defined(HAVE_USDD_SP1_VERIFIER)
    static_assert(USDD_SP1_VERIFIER_ABI_VERSION == 1 && USDD_SP1_VERIFIER_ACCEPTED == 0);
#endif
    return static_cast<Sp1VerifierResult>(drivechain::haskell::VerifyJournal(
#if defined(HAVE_USDD_SP1_VERIFIER)
        usdd_sp1_verifier_abi_version, usdd_sp1_verify_annex,
#else
        nullptr, nullptr,
#endif
        annex, expected_program_id, expected_public_values_sha256));
}

inline Sp1ConsensusGateResult GateUsddSp1ProofAnnexForDeployment(
    Span<const unsigned char> annex,
    Span<const unsigned char> script_cmr,
    bool has_authenticated_atomic_bmm_endpoint,
    const uint32_t deployment_binding_version,
    Span<const unsigned char> expected_inbound_mint_domain_id,
    const bool verifier_activation_configured)
{
    return static_cast<Sp1ConsensusGateResult>(RunLegacyIdentity(true, annex, script_cmr, {},
        deployment_binding_version, expected_inbound_mint_domain_id,
        has_authenticated_atomic_bmm_endpoint, verifier_activation_configured));
}

/**
 * Host-side admission gate for the incompatible V11 strong-execution lane.
 *
 * Success grants only the fixed verifier-cost lane. The Simplicity program
 * must still hash its exact typed journal, invoke the environmental verifier
 * jet with the manifest-bound guest ID, and require true. No current network
 * calls this function until a separate V11 Signet identity selects it.
 */
inline Sp1ConsensusGateResult GateUsddSp1StrongExecutionAnnexForDeployment(
    Span<const unsigned char> annex,
    Span<const unsigned char> script_cmr,
    bool has_authenticated_atomic_bmm_endpoint,
    Span<const unsigned char> expected_controller_cmr,
    Span<const unsigned char> expected_guest_program_id,
    const bool verifier_activation_configured)
{
    return AdmitSp1Annex(1, annex, has_authenticated_atomic_bmm_endpoint, verifier_activation_configured,
        [&](const Sp1ProofAnnexView& parsed) { return StrongExecutionIdentityFacts(script_cmr, parsed.guest_program_id,
                parsed.public_values, expected_controller_cmr, expected_guest_program_id); });
}

inline Sp1ConsensusGateResult GateUsddSp1ParameterizedStrongExecutionAnnex(
    Span<const unsigned char> annex,
    bool has_authenticated_atomic_bmm_endpoint,
    const bool verifier_activation_configured)
{
    // Admission alone never authorizes a transition; the verifier jet must pass.
    return AdmitSp1Annex(2, annex, has_authenticated_atomic_bmm_endpoint, verifier_activation_configured, {});
}

inline Sp1ConsensusGateResult GateUsddSp1ProofAnnex(
    Span<const unsigned char> annex,
    Span<const unsigned char> script_cmr,
    bool has_authenticated_atomic_bmm_endpoint)
{
    static_assert(
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
                static_cast<uint8_t>(Sp1StatementKind::ETH_STATE_V1) ||
            ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
                static_cast<uint8_t>(
                    Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2),
        "the chain identity selects an unsupported USDD SP1 statement kind");

    // The chain-identity header is generated and committed by each network.
    // V7 continues through its deployment-domain journal. A separately
    // frozen V11 private-Signet identity selects statement kind 3 and reuses
    // the same fields as the expected strong-execution controller CMR and
    // program ID. This dispatch adds no runtime or operator-controlled switch.
    if constexpr (
        ElementsDrivechainIdentity::USDD_SP1_ANNEX_STATEMENT_KIND ==
        static_cast<uint8_t>(
            Sp1StatementKind::CONTROLLER_STRONG_EXECUTION_V2)) {
        if constexpr (ElementsDrivechainIdentity::V11_PARAMETERIZED_CONTROLLER_PROFILE) {
            return GateUsddSp1ParameterizedStrongExecutionAnnex(
                annex, has_authenticated_atomic_bmm_endpoint,
                ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED);
        }
        return GateUsddSp1StrongExecutionAnnexForDeployment(
            annex, script_cmr, has_authenticated_atomic_bmm_endpoint,
            ElementsDrivechainIdentity::HISTORICAL_V8_CONTROLLER_CMR,
            ElementsDrivechainIdentity::USDD_SP1_GUEST_PROGRAM_ID,
            ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED);
    }
    return GateUsddSp1ProofAnnexForDeployment(
        annex, script_cmr, has_authenticated_atomic_bmm_endpoint,
        ElementsDrivechainIdentity::USDD_SP1_DEPLOYMENT_BINDING_VERSION,
        ElementsDrivechainIdentity::USDD_SP1_INBOUND_MINT_DOMAIN_ID,
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED);
}

} // namespace usdd

#endif // BITCOIN_SCRIPT_USDD_SP1_ANNEX_H
