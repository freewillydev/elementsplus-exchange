//! Local full-forest engine. No script, confidential-proof or chain-selection rules.
use rustreexo::{mem_forest::MemForest, node_hash::BitcoinNodeHash, stump::Stump};
use std::{collections::HashSet, io::Cursor, panic::catch_unwind, slice};

type Hash = BitcoinNodeHash;
type Emit = unsafe extern "C" fn(*mut core::ffi::c_void, *const u8, usize, *const u8, usize, u64) -> u32;

fn commitment(forest: &MemForest<Hash>) -> Stump<Hash> {
    Stump { leaves: forest.leaves, roots: forest.get_roots().iter().map(|n| n.get_data()).collect() }
}

fn transition(source: &[u8], adds: &[Hash], dels: &[Hash]) -> Result<(Vec<u8>, Stump<Hash>), String> {
    if !source.is_empty() {
        let header = source.get(..16).ok_or("truncated forest header")?;
        let leaves = u64::from_le_bytes(header[..8].try_into().unwrap());
        let roots = u64::from_le_bytes(header[8..].try_into().unwrap());
        if leaves >= (1u64 << 63) || roots != u64::from(leaves.count_ones()) {
            return Err("malformed forest header".into());
        }
    }
    let mut reader = Cursor::new(source);
    let mut forest = if source.is_empty() { MemForest::new() } else {
        MemForest::deserialize(&mut reader).map_err(|e| e.to_string())?
    };
    if reader.position() != source.len() as u64 { return Err("trailing forest bytes".into()); }
    let before = commitment(&forest);
    if before.leaves >= (1u64 << 63) || before.roots.len() != before.leaves.count_ones() as usize {
        return Err("malformed forest shape".into());
    }
    for items in [adds, dels] {
        if items.iter().collect::<HashSet<_>>().len() != items.len() {
            return Err("duplicate leaf".into());
        }
    }
    for hash in adds {
        if forest.prove(&[*hash]).is_ok() { return Err("existing leaf added".into()); }
    }
    let proof = forest.prove(dels)?;
    // Independently verify the full-forest transition against its authenticated
    // compact state; do not trust cached internal nodes when deleting leaves.
    if !before.verify(&proof, dels).map_err(|e| e.to_string())? {
        return Err("invalid deletion proof".into());
    }
    let expected = before.modify(adds, dels, &proof).map_err(|e| e.to_string())?;
    forest.modify(adds, dels)?;
    let after = commitment(&forest);
    if after != expected { return Err("forest/stump divergence".into()); }
    let mut encoded = Vec::new();
    forest.serialize(&mut encoded).map_err(|e| e.to_string())?;
    Ok((encoded, after))
}

/// All pointers borrow caller memory for this call only. The callback copies the
/// result before return. A panic never unwinds into Haskell or C++.
#[no_mangle]
pub unsafe extern "C" fn elements_utreexo_v1(
    source: *const u8, source_len: usize, adds: *const u8, add_count: usize,
    dels: *const u8, del_count: usize, emit: Emit, context: *mut core::ffi::c_void,
) -> u32 {
    if (source_len != 0 && source.is_null()) || (add_count != 0 && adds.is_null()) ||
        (del_count != 0 && dels.is_null()) || source_len > isize::MAX as usize ||
        add_count > isize::MAX as usize / 32 || del_count > isize::MAX as usize / 32 { return 1; }
    catch_unwind(|| {
        let bytes = |ptr, len| if len == 0 { &[][..] } else { slice::from_raw_parts(ptr, len) };
        let hashes = |ptr, count| bytes(ptr, count * 32).chunks_exact(32)
            .map(|b| Hash::new(b.try_into().expect("fixed hash width"))).collect::<Vec<_>>();
        let Ok((encoded, state)) = transition(bytes(source, source_len), &hashes(adds, add_count), &hashes(dels, del_count)) else { return 1; };
        let roots: Vec<u8> = state.roots.iter().flat_map(|h| h.iter().copied()).collect();
        emit(context, encoded.as_ptr(), encoded.len(), roots.as_ptr(), state.roots.len(), state.leaves)
    }).unwrap_or(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(i: u8) -> Hash { Hash::new([i; 32]) }
    #[test]
    fn restart_and_branch() {
        let (a, state) = transition(&[], &[h(1),h(2)], &[]).unwrap();
        assert_eq!(state.leaves, 2);
        let (b, right) = transition(&a, &[h(3)], &[h(1)]).unwrap();
        assert_eq!(transition(&b, &[], &[]).unwrap().1, right);
        let (_, left) = transition(&a, &[h(4)], &[h(2)]).unwrap();
        assert_ne!(left.roots, right.roots);
        assert_eq!(transition(&a, &[], &[]).unwrap().1, state);
    }
    #[test]
    fn fail_closed() {
        let (a, _) = transition(&[], &[h(1)], &[]).unwrap();
        assert!(transition(&a, &[h(1)], &[]).is_err());
        assert!(transition(&a, &[], &[h(2)]).is_err());
        assert!(transition(&a, &[], &[h(1),h(1)]).is_err());
        assert!(transition(&a, &[h(2),h(2)], &[]).is_err());
        let mut trailing = a.clone(); trailing.push(0);
        assert!(transition(&trailing, &[], &[]).is_err());
        assert!(transition(&a[..a.len()-1], &[], &[]).is_err());
        let mut malformed = a.clone();
        malformed[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(transition(&malformed, &[], &[]).is_err());
    }
    #[test]
    fn repeated_updates_match_compact_verifier() {
        let mut state = Vec::new();
        for i in 1..100 {
            let dels = if i > 1 { vec![h(i-1)] } else { vec![] };
            state = transition(&state, &[h(i)], &dels).unwrap().0;
        }
        assert!(transition(&state, &[], &[h(99)]).is_ok());
        assert!(transition(&state, &[], &[h(98)]).is_err());
    }
    #[test]
    fn batch_deletions_and_reinsertions() {
        let original: Vec<_> = (1..100).map(h).collect();
        let (encoded, _) = transition(&[], &original, &[]).unwrap();
        let dels: Vec<_> = original.iter().rev().step_by(3).copied().collect();
        let (after, expected) = transition(&encoded, &[h(100)], &dels).unwrap();
        let mut reordered = dels.clone();
        reordered.reverse();
        assert_eq!(transition(&encoded, &[h(100)], &reordered).unwrap().1, expected);
        assert!(transition(&after, &[], &dels).is_err());
        assert!(transition(&after, &dels, &[h(100)]).is_ok());
        let (_, empty) = transition(&encoded, &[], &original).unwrap();
        assert_eq!(empty.leaves, original.len() as u64);
        assert!(empty.roots.iter().all(|root| *root == Hash::default()));
    }
}
