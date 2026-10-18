// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#ifndef BITCOIN_TEST_ECX_SIMPLICITY_TEST_SHIM_H
#define BITCOIN_TEST_ECX_SIMPLICITY_TEST_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <simplicity/elements/env.h>

/* Test-only C boundary: exercise the real jet frame adapter without exposing
 * private Simplicity C structures to Bitcoin's C++ headers. Returns whether
 * evaluation succeeded; the proof acceptance bit is written to valid. */
bool ecx_test_successor_jet_frame(
    const unsigned char* annex,
    size_t annex_len,
    const unsigned char program[32],
    const unsigned char public_values_digest[32],
    ecx_sp1_groth16_verify_fn verifier,
    void* verifier_context,
    bool* valid);

bool ecx_test_usdd_jet_frame(const unsigned char* annex, size_t annex_len, bool* valid);
bool ecx_test_bond_input_frame(uint32_t index, uint32_t current, uint32_t flags, bool collateral);
bool ecx_test_height_jet_frame(bool present, uint64_t height, bool* accepted, uint64_t* output);
bool ecx_test_environment_admission(const ecx_prior_active_root_env* env, bool* accepted);
bool ecx_test_checkpoint_environment(bool present, const unsigned char* checkpoint, bool* accepted);
bool ecx_test_owned_annex(void);
bool ecx_test_groth16_jet_frame(uint32_t kind, const unsigned char* annex, size_t annex_len,
    const unsigned char program[32], const unsigned char digest[32],
    ecx_sp1_groth16_verify_fn verifier, void* context, bool* valid);

#ifdef __cplusplus
}
#endif

#endif
