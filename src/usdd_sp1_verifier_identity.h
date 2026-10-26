// Copyright (c) 2026 The Elements developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_USDD_SP1_VERIFIER_IDENTITY_H
#define BITCOIN_USDD_SP1_VERIFIER_IDENTITY_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <elements_drivechain_identity.h>
#include <script/usdd_sp1_verifier_ffi.h>
#include <haskell/bridge.h>

#include <array>
#include <string>

// Release admission is separate from the immutable genesis transcript. The
// historical transcript remains unchanged; this build requires the patched
// verifier even when replaying that chain. Never accept both implementations.
namespace UsddSp1VerifierRelease {
inline constexpr char VERSION[]{"6.8.1"};
inline constexpr char GIT_COMMIT[]{"c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824"};
inline constexpr std::array<uint8_t, 32> SEMANTIC_IDENTITY{{
    0xa6, 0xb6, 0xb2, 0xc1, 0xf0, 0x91, 0x7d, 0x5d,
    0xfc, 0xa9, 0x90, 0xe5, 0x78, 0x7d, 0xfb, 0xe8,
    0x35, 0x58, 0x1f, 0x0d, 0xb0, 0xfc, 0xc7, 0xa6,
    0x0c, 0x3b, 0x67, 0x0a, 0x87, 0xf4, 0xad, 0x02,
}};
}

/**
 * Enforce the verifier identity required by this release.
 *
 * Keeping this check at startup prevents build-dependent consensus after the
 * proof gate is activated: a node cannot run the sole production network with
 * no verifier, an old ABI, or different verifier semantics. Until activation
 * is configured, every annex remains rejected by the separate consensus gate
 * and omission of the archive is safe.
 */
inline bool CheckUsddSp1VerifierStartupIdentity(
    const bool activation_configured,
    const std::array<uint8_t, 32>& expected_identity,
    std::string* error)
{
    return drivechain::haskell::VerifierIdentity(activation_configured,
        ElementsDrivechainIdentity::REQUIRED_USDD_SP1_VERIFIER_ABI_VERSION,
        ElementsDrivechainIdentity::REQUIRED_USDD_SP1_VERIFIER_SEMANTIC_IDENTITY_VERSION,
        expected_identity,
#if defined(HAVE_USDD_SP1_VERIFIER)
        usdd_sp1_verifier_abi_version, usdd_sp1_verifier_semantic_identity_version,
        usdd_sp1_verifier_semantic_identity,
#else
        nullptr, nullptr, nullptr,
#endif
        error);
}

inline bool CheckCanonicalUsddSp1VerifierStartupIdentity(std::string* error)
{
    return CheckUsddSp1VerifierStartupIdentity(
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_ACTIVATION_CONFIGURED,
        UsddSp1VerifierRelease::SEMANTIC_IDENTITY,
        error);
}

#endif // BITCOIN_USDD_SP1_VERIFIER_IDENTITY_H
