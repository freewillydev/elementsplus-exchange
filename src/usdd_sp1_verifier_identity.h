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

/**
 * Enforce the verifier identity required by the immutable production network.
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
        ElementsDrivechainIdentity::USDD_SP1_VERIFIER_SEMANTIC_IDENTITY,
        error);
}

#endif // BITCOIN_USDD_SP1_VERIFIER_IDENTITY_H
