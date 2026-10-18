// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#ifndef ELEMENTS_HASKELL_SIMPLICITY_FFI_H
#define ELEMENTS_HASKELL_SIMPLICITY_FFI_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* All functions and buffers must remain valid until this synchronous call returns. */
bool elements_haskell_jet_height(bool present, uint64_t height);
bool elements_haskell_optional_environment(uint32_t kind, uint32_t present, uint32_t fields);
bool elements_haskell_optional_checkpoint(bool present, const unsigned char* checkpoint);
bool elements_haskell_annex_retention(uint64_t full_size, uint64_t body_size,
    const unsigned char* full, const unsigned char* body);
bool elements_haskell_canonical_activation(const unsigned char* input, uint32_t size);
bool elements_haskell_canonical_values(uint32_t version, const unsigned char* input, uint32_t size);
bool elements_haskell_groth16_header(uint32_t version, const unsigned char* input, uint32_t size);
bool elements_haskell_parse_groth16(uint32_t kind, const unsigned char* input, size_t size,
    unsigned char* program, unsigned char* digest, unsigned char* values, uint32_t capacity,
    bool (*hash)(unsigned char*, const unsigned char*, size_t));
bool elements_haskell_groth16_proof(uint32_t kind, const unsigned char* input, size_t size,
    const unsigned char* program, const unsigned char* digest,
    bool (*hash)(unsigned char*, const unsigned char*, size_t),
    bool (*verify)(void*, const unsigned char*, size_t, const uint32_t*, const unsigned char*), void* context);
/* flags: bit 0 peg-in, bit 1 issuance, bit 2 bond identity present. */
bool elements_haskell_bond_input(uint64_t index, uint64_t current, uint32_t flags,
    const unsigned char* actual, const unsigned char* expected);
/* Failed division/overflow leaves both output limbs unchanged. */
bool elements_haskell_muldiv128(uint64_t high, uint64_t low, uint64_t multiplier,
    uint64_t divisor_high, uint64_t divisor_low, uint64_t* output_high, uint64_t* output_low);
bool elements_haskell_verify_jet(
    uint32_t (*version)(void),
    uint32_t (*verify)(uint32_t, const unsigned char*, size_t, const unsigned char*, size_t, const unsigned char*, size_t),
    bool (*read_annex)(const void*, const unsigned char**, size_t*),
    const void* context, const unsigned char* program, const unsigned char* digest);
#ifdef __cplusplus
}
#endif
#endif
