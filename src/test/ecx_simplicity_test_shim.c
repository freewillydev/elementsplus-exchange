// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.

#include "ecx_simplicity_test_shim.h"

#include <simplicity/elements/elementsJets.h>
#include <simplicity/elements/exec.h>
#include <simplicity/elements/txEnv.h>
#include <simplicity/frame.h>
#include <string.h>

_Static_assert(ECX_SP1_GROTH16_PROOF_LEN == 356, "Groth16 wire length");
_Static_assert(ECX_SP1_PUBLIC_VALUES_V4_LEN == 609, "V4 wire length");
_Static_assert(ECX_SP1_PUBLIC_VALUES_V5_LEN == 850, "V5 wire length");
_Static_assert(ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN == 364, "activation wire length");
_Static_assert(ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN == 1627, "successor wire length");

bool ecx_test_owned_annex(void)
{
    unsigned char txid[32] = {0}, prev[32] = {0};
    unsigned char full[] = {0x50,0xaa,0xbb,0xcc};
    const unsigned char expected[] = {0x50,0xaa,0xbb,0xcc};
    rawElementsBuffer body = {.buf=full+1,.len=3}, whole = {.buf=full,.len=4}, owned = {0};
    rawElementsInput input = {.prevTxid=prev,.sequence=0xffffffff,.annex=&body,.fullAnnex=&whole};
    rawElementsTransaction raw = {.txid=txid,.input=&input,.numInputs=1};
    elementsTransaction* tx = simplicity_elements_mallocTransaction(&raw);
    input.fullAnnex = NULL;
    elementsTransaction* legacy = simplicity_elements_mallocTransaction(&raw);
    bool ok = tx && legacy &&
        !memcmp(&tx->input[0].annexHash,&legacy->input[0].annexHash,sizeof(tx->input[0].annexHash)) &&
        !memcmp(&tx->inputAnnexesHash,&legacy->inputAnnexesHash,sizeof(tx->inputAnnexesHash)) &&
        !memcmp(&tx->txHash,&legacy->txHash,sizeof(tx->txHash));
    memset(full,0,sizeof(full));
    ok = ok && simplicity_elements_getInputFullAnnex(tx,0,&owned) && owned.len==sizeof(expected) &&
        !memcmp(owned.buf,expected,sizeof(expected));
    ok = ok && !simplicity_elements_getInputFullAnnex(tx,1,&owned) && !owned.buf && !owned.len;
    simplicity_elements_freeTransaction(tx);
    simplicity_elements_freeTransaction(legacy);
    return ok && SIMPLICITY_ELEMENTS_MAX_OWNED_ANNEX_SIZE==1310720U;
}

bool ecx_test_checkpoint_environment(bool present, const unsigned char* checkpoint, bool* accepted)
{
    const unsigned char zero[80] = {0};
    sigInput input = {0};
    elementsTransaction tx = {.input=&input, .numInputs=1};
    elementsTapEnv taproot = {0};
    sha256_midstate genesis = {0};
    ecx_prior_active_root_env roots = {0};
    txEnv env = simplicity_elements_build_txEnv(&tx,&taproot,&genesis,&roots,0,false,0,present,checkpoint);
    *accepted = env.priorActiveBmmParentCheckpointValid;
    return env.priorActiveBmmParentCheckpointPresent == present &&
        memcmp(env.priorActiveBmmParentCheckpoint, checkpoint ? checkpoint : zero, sizeof(zero)) == 0;
}

bool ecx_test_environment_admission(const ecx_prior_active_root_env* env, bool* accepted)
{
    elementsTransaction tx = {0};
    elementsTapEnv taproot = {0};
    const unsigned char genesis[32] = {0};
    simplicity_err error;
    // Empty program must reach the decoder only when the environment is valid.
    const bool permanent = simplicity_elements_execSimplicityWithBlockEnv(
        &error, NULL, &tx, 0, &taproot, genesis, env, NULL, 0, 0, NULL, NULL, 0, NULL, 0);
    *accepted = error == SIMPLICITY_ERR_BITSTREAM_EOF;
    return permanent && (*accepted || error == SIMPLICITY_ERR_DATA_OUT_OF_RANGE);
}

bool ecx_test_height_jet_frame(bool present, uint64_t height, bool* accepted, uint64_t* output)
{
    UWORD buffer[ROUND_UWORD(64)], original[ROUND_UWORD(64)];
    memset(buffer,0xa5,sizeof(buffer));
    memcpy(original,buffer,sizeof(buffer));
    txEnv env = {0};
    env.bondV2ProjectionPresent = present;
    env.currentSidechainHeight = height;
    frameItem dst = initWriteFrame(64,buffer+ROUND_UWORD(64));
    *accepted = simplicity_current_sidechain_height_required(&dst,initReadFrame(0,buffer),&env);
    if (!*accepted) return memcmp(buffer,original,sizeof(buffer))==0;
    frameItem src = initReadFrame(64,buffer);
    *output = simplicity_read64(&src);
    return true;
}

bool ecx_test_bond_input_frame(uint32_t index, uint32_t current, uint32_t flags, bool collateral)
{
    UWORD source[ROUND_UWORD(32)] = {0};
    UWORD output[1] = {0};
    frameItem writer = initWriteFrame(32, source + ROUND_UWORD(32));
    simplicity_write32(&writer,index);
    sigInput inputs[3] = {0};
    for (size_t i=0; i<3; ++i) {
        inputs[i].isPegin = (flags & 1) != 0;
        inputs[i].issuance.type = (flags & 128) ? REISSUANCE : (flags & 2) ? NEW_ISSUANCE : NO_ISSUANCE;
        inputs[i].txo.scriptPubKey.s[0] = (flags & 8) ? (collateral ? 9 : 7) : 8;
    }
    elementsTransaction transaction = {0};
    transaction.input = (flags & 64) ? NULL : inputs;
    transaction.numInputs = 3;
    txEnv env = {0};
    env.tx = (flags & 32) ? NULL : &transaction;
    env.ix = current;
    env.bondV2IdentityPresent = (flags & 4) != 0;
    env.bondV2InsuranceReserveScriptSha256.s[0] = 7;
    env.bondV2CollateralVaultScriptSha256.s[0] = 9;
    frameItem dst = initWriteFrame(0,output+1);
    const txEnv* environment = (flags & 16) ? NULL : &env;
    return collateral ? simplicity_bond_v2_collateral_vault_input_required(&dst,initReadFrame(32,source),environment)
                      : simplicity_bond_v2_insurance_reserve_input_required(&dst,initReadFrame(32,source),environment);
}

bool ecx_test_usdd_jet_frame(const unsigned char* annex, size_t annex_len, bool* valid)
{
    if (!valid || annex_len > UINT_FAST32_MAX || (!annex && annex_len)) return false;
    UWORD source[ROUND_UWORD(512)] = {0};
    UWORD output[ROUND_UWORD(1)] = {0};
    sigInput input = {0};
    input.fullAnnex = annex;
    input.fullAnnexLen = (uint_fast32_t)annex_len;
    input.hasFullAnnex = annex != NULL;
    elementsTransaction transaction = {0};
    transaction.input = &input;
    transaction.numInputs = 1;
    txEnv env = {0};
    env.tx = &transaction;
    frameItem dst = initWriteFrame(1, output + ROUND_UWORD(1));
    if (!simplicity_verify_sp1_compressed_sha256(&dst, initReadFrame(512, source), &env)) return false;
    frameItem result = initReadFrame(1, output);
    *valid = readBit(&result);
    return true;
}

bool ecx_test_groth16_jet_frame(
    uint32_t kind,
    const unsigned char* annex,
    size_t annex_len,
    const unsigned char program[32],
    const unsigned char public_values_digest[32],
    ecx_sp1_groth16_verify_fn verifier,
    void* verifier_context,
    bool* valid)
{
    if (!valid || kind>4) return false;
    *valid = false;
    if ((!annex && annex_len) || !program || !public_values_digest || annex_len > UINT_FAST32_MAX) return false;

    UWORD source[ROUND_UWORD(512)] = {0};
    UWORD output[ROUND_UWORD(1)] = {0};
    frameItem writer = initWriteFrame(512, source + ROUND_UWORD(512));
    write8s(&writer, program, 32);
    write8s(&writer, public_values_digest, 32);

    sigInput input = {0};
    input.annex = annex;
    input.annexLen = (uint_fast32_t)annex_len;
    elementsTransaction transaction = {0};
    transaction.input = &input;
    transaction.numInputs = 1;
    txEnv env = {0};
    env.tx = &transaction;
    env.verifySp1Groth16 = verifier;
    env.verifySp1Groth16Context = verifier_context;

    frameItem dst = initWriteFrame(1, output + ROUND_UWORD(1));
    bool (*const jets[])(frameItem*,frameItem,const txEnv*) = {
        simplicity_verify_sp1_groth16_sha256,
        simplicity_verify_sp1_groth16_v3_public_values_v4_sha256,
        simplicity_verify_sp1_groth16_v4_public_values_v5_sha256,
        simplicity_verify_sp1_groth16_v5_incremental_activation_sha256,
        simplicity_verify_sp1_groth16_v6_incremental_successor_sha256};
    if (!jets[kind](&dst, initReadFrame(512, source), &env)) return false;
    frameItem result = initReadFrame(1, output);
    *valid = readBit(&result);
    return true;
}

bool ecx_test_successor_jet_frame(const unsigned char* annex, size_t annex_len,
    const unsigned char program[32], const unsigned char digest[32],
    ecx_sp1_groth16_verify_fn verifier, void* context, bool* valid)
{
    return ecx_test_groth16_jet_frame(4,annex,annex_len,program,digest,verifier,context,valid);
}
