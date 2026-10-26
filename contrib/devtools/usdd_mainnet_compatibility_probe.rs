//! Offline compatibility probe, not a mint/activation command.
//! Link against the exact Rust verifier build used by the candidate node.
use std::{env, fs, io::Cursor};
use bincode::Options;
use slop_tensor::{Dimensions, Tensor};
use sp1_verifier::SP1Proof;
use usdd_core::{hash_bytes, Hash32};
use usdd_sp1_verifier::{ffi::usdd_sp1_verify_annex, identity::semantic_identity,
    raw_vkey_hash_from_program_id, verify_raw_compressed_public_values_sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 { return Err("expected sealed segment.sp1 and expected-journal.bin".into()); }
    let envelope = fs::read(&args[1])?;
    let journal = fs::read(&args[2])?;
    assert_eq!(hex(hash_bytes(&envelope).as_bytes()),
        "2ed9cab58fcb22430f503ffc1dc73404f274708e0fda4726d8f5f22786fffbd0");
    assert_eq!(hex(hash_bytes(&journal).as_bytes()),
        "be9ab3e6a9f8850a5f903607668b885827f9a560b2c6c4c947836623d0fc3a42");
    assert_eq!(hex(semantic_identity().as_bytes()),
        "a6b6b2c1f0917d5dfca990e5787dfbe835581f0db0fcc7a60c3b670a87f4ad02");
    // SDK save() prefixes its envelope with SP1Proof. Decode with the pinned
    // type, then check canonical bytes; the proof authenticates the journal.
    let mut cursor = Cursor::new(&envelope);
    let proof: SP1Proof = bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(1_310_720).deserialize_from(&mut cursor)?;
    assert!(matches!(proof, SP1Proof::Compressed(_)));
    let raw = bincode::serialize(&proof)?;
    assert_eq!(&raw, &envelope[..cursor.position() as usize]);
    let program = Hash32([
        0x32,0x7a,0x8b,0x85,0x6f,0xf3,0xef,0xc4,0x38,0xc6,0x0b,0x52,0x1d,0xc0,0xce,0x08,
        0x15,0x84,0x87,0x82,0x74,0xf1,0xb4,0x56,0x08,0x0f,0xdc,0x77,0x77,0x3d,0x5c,0xe0]);
    let key = raw_vkey_hash_from_program_id(program)?;
    let verify = |proof: &[u8], values: &[u8], id| {
        verify_raw_compressed_public_values_sha256(proof, values, &key, id)
    };
    verify(&raw, &journal, program)?;
    let mut changed = journal.clone();
    changed[0] ^= 1;
    assert!(verify(&raw, &changed, program).is_err());
    let mut wrong_program = program;
    wrong_program.0[31] ^= 1;
    assert!(verify(&raw, &journal, wrong_program).is_err());
    assert!(verify(&raw[..raw.len()-1], &journal, program).is_err());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(verify(&trailing, &journal, program).is_err());

    // Exercise both tensor-bearing opening paths inside a genuine receipt,
    // through the public adapter, rather than only testing Tensor in isolation.
    for query_phase in [false, true] {
        let mut malformed = proof.clone();
        let SP1Proof::Compressed(inner) = &mut malformed else { unreachable!() };
        let basefold = &mut inner.proof.evaluation_proof.pcs_proof.basefold_proof;
        let openings = if query_phase {
            &mut basefold.query_phase_openings_and_proofs
        } else {
            &mut basefold.component_polynomials_query_openings_and_proofs
        };
        let tensor = &mut openings.first_mut().ok_or("missing opening fixture")?.values;
        tensor.dimensions = Dimensions::try_from([tensor.dimensions.total_len() + 1])?;
        let encoded = bincode::serialize(&malformed)?;
        assert!(matches!(verify(&encoded, &journal, program),
            Err(usdd_sp1_verifier::VerificationError::MalformedProof)));
    }
    println!("PASS: malformed component and query tensors reject at the public proof boundary");

    // Inner segment output is neither the legacy strict mint journal nor the
    // V11 32-byte strong-execution output. Neither ABI lane may authorize it.
    let digest = hash_bytes(&journal);
    for kind in [1u8, 3u8] {
        let mut annex = b"\x50USDDSP1\0".to_vec();
        annex.extend_from_slice(&[1,1,kind,1,0,0]);
        annex.extend_from_slice(&(journal.len() as u32).to_be_bytes());
        annex.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        annex.extend_from_slice(program.as_bytes());
        annex.extend_from_slice(&journal);
        annex.extend_from_slice(&raw);
        // All buffers are owned, correctly bounded and live for the call.
        let result = unsafe { usdd_sp1_verify_annex(1, annex.as_ptr(), annex.len(),
            program.as_bytes().as_ptr(),32,digest.as_bytes().as_ptr(),32) };
        assert_eq!(result,1,"inner segment must not authorize a mint");
    }
    println!("PASS: real mainnet segment verifies; altered journal/program/truncated/trailing proof reject; both mint ABI lanes reject inner proof");
    println!("raw_proof_bytes={} journal_bytes={}",raw.len(),journal.len());

    // Regression for GHSA-p7v2-jjv3-8p8f. This is only a malformed tensor,
    // not a forged execution proof. Compatibility does not imply soundness.
    let mut tensor = Tensor::<u32>::from(vec![1,2,3]);
    tensor.dimensions = Dimensions::try_from([2,2])?;
    let encoded = bincode::serialize(&tensor)?;
    if bincode::deserialize::<Tensor<u32>>(&encoded).is_ok() {
        eprintln!("BLOCKED: pinned verifier accepts mismatched tensor storage/dimensions (GHSA-p7v2-jjv3-8p8f); not release-qualified");
        std::process::exit(2);
    }
    println!("PASS: malformed tensor storage/dimensions rejected");
    Ok(())
}
