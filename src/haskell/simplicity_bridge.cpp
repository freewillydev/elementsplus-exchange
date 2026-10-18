// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/simplicity_ffi.h>
#include <haskell/domain_abi.h>

extern "C" void elements_hs_runtime_init(void);

namespace {
template <int Success = 1, typename Function, typename... Args>
bool CallSimplicity(Function function, Args... args) noexcept
{
    try {
        elements_hs_runtime_init();
        return function(args...) == Success;
    } catch (...) {
        return false;
    }
}
}

extern "C" bool elements_haskell_jet_height(bool present, uint64_t height)
{
    return CallSimplicity(elements_hs_jet_height_v1,present ? 1 : 0,height);
}

extern "C" bool elements_haskell_optional_environment(uint32_t kind, uint32_t present, uint32_t fields)
{
    return CallSimplicity(elements_hs_optional_environment_v1,kind,present,fields);
}

extern "C" bool elements_haskell_optional_checkpoint(bool present, const unsigned char* checkpoint)
{
    return CallSimplicity(elements_hs_optional_checkpoint_v1,present ? 1 : 0,const_cast<unsigned char*>(checkpoint));
}

extern "C" bool elements_haskell_annex_retention(uint64_t full_size, uint64_t body_size,
    const unsigned char* full, const unsigned char* body)
{
    return CallSimplicity(elements_hs_annex_retention_v1,full_size,body_size,
        const_cast<unsigned char*>(full),const_cast<unsigned char*>(body));
}

extern "C" bool elements_haskell_parse_groth16(uint32_t kind, const unsigned char* input, size_t size,
    unsigned char* program, unsigned char* digest, unsigned char* values, uint32_t capacity,
    bool (*hash)(unsigned char*, const unsigned char*, size_t))
{
    return CallSimplicity(elements_hs_parse_groth16_v1,kind,const_cast<unsigned char*>(input),size,
        program,digest,values,capacity,reinterpret_cast<HsFunPtr>(hash));
}

extern "C" bool elements_haskell_groth16_proof(uint32_t kind, const unsigned char* input, size_t size,
    const unsigned char* program, const unsigned char* digest,
    bool (*hash)(unsigned char*, const unsigned char*, size_t),
    bool (*verify)(void*, const unsigned char*, size_t, const uint32_t*, const unsigned char*), void* context)
{
    return CallSimplicity(elements_hs_groth16_proof_v1,kind,const_cast<unsigned char*>(input),size,
        const_cast<unsigned char*>(program),const_cast<unsigned char*>(digest),
        reinterpret_cast<HsFunPtr>(hash),reinterpret_cast<HsFunPtr>(verify),context);
}

extern "C" bool elements_haskell_bond_input(uint64_t index, uint64_t current, uint32_t flags,
    const unsigned char* actual, const unsigned char* expected)
{
    return CallSimplicity(elements_hs_bond_input_v1,index,current,flags,const_cast<unsigned char*>(actual),
        const_cast<unsigned char*>(expected));
}

extern "C" bool elements_haskell_groth16_header(uint32_t version, const unsigned char* input, uint32_t size)
{
    return CallSimplicity(elements_hs_groth16_header_v1,version,size,const_cast<unsigned char*>(input));
}

extern "C" bool elements_haskell_canonical_values(uint32_t version, const unsigned char* input, uint32_t size)
{
    return CallSimplicity(elements_hs_canonical_values_v1,version,size,const_cast<unsigned char*>(input));
}

extern "C" bool elements_haskell_canonical_activation(const unsigned char* input, uint32_t size)
{
    return CallSimplicity(elements_hs_canonical_activation_v1,size,const_cast<unsigned char*>(input));
}

extern "C" bool elements_haskell_muldiv128(uint64_t high, uint64_t low, uint64_t multiplier,
    uint64_t divisor_high, uint64_t divisor_low, uint64_t* output_high, uint64_t* output_low)
{
    if (!output_high || !output_low) return false;
    uint64_t result[2];
    if (!CallSimplicity(elements_hs_muldiv128_v1,high,low,multiplier,divisor_high,divisor_low,result)) return false;
    *output_high = result[0];
    *output_low = result[1];
    return true;
}

extern "C" bool elements_haskell_verify_jet(
    uint32_t (*version)(),
    uint32_t (*verify)(uint32_t, const unsigned char*, size_t, const unsigned char*, size_t, const unsigned char*, size_t),
    bool (*reader)(const void*, const unsigned char**, size_t*),
    const void* context, const unsigned char* program, const unsigned char* digest)
{
    return CallSimplicity<0>(elements_hs_verify_jet_v1,reinterpret_cast<HsFunPtr>(version), reinterpret_cast<HsFunPtr>(verify),
        reinterpret_cast<HsFunPtr>(reader), const_cast<void*>(context), const_cast<unsigned char*>(program),
        const_cast<unsigned char*>(digest));
}
