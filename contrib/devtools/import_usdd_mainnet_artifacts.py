#!/usr/bin/env python3
"""Import sealed Windows USDD build/proof inputs; never activate a deployment.

Only the exact reviewed packets are accepted. Their scripts are data, not run.
The finality segment is an inner receipt, not a controller or mint proof.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile

PACKETS = (
    ("qualification-v1-run1-return.tar.gz",
     "c74bff8e68f8284aa1a49024ea16a2f6b18a96a504a700765b194d28448641fd",
     "evidence/RETURN-MANIFEST.json", "programs"),
    ("qualification-v1-run1-memory-retry1-return.tar.gz",
     "d54f675ba52f4a5dcdc8a1973a816243a2f167ec485684f09774fcc84c81c726",
     "RETURN-MANIFEST.json", "segment-proof"),
)
MAX_PACKET_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def verify_packet(path, expected, manifest_name):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PACKET_BYTES:
        raise ValueError("packet must be a bounded regular file")
    raw = path.read_bytes()
    if digest(raw) != expected:
        raise ValueError("packet SHA256 mismatch: " + path.name)
    # Read the same authenticated bytes, not a reopened path.
    import io
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 1000 or sum(m.size for m in members) > MAX_EXPANDED_BYTES:
            raise ValueError("expanded packet exceeds limits")
        names = set()
        files = {}
        for member in members:
            name = PurePosixPath(member.name)
            if (not member.isfile() or name.is_absolute() or ".." in name.parts or
                    "\\" in member.name or str(name) != member.name or member.name in names):
                raise ValueError("unsafe/duplicate archive member: " + member.name)
            names.add(member.name)
            files[member.name] = archive.extractfile(member).read()
    manifest = json.loads(files[manifest_name], object_pairs_hook=unique_object)
    if names != set(manifest) | {manifest_name}:
        raise ValueError("archive/manifest member mismatch")
    for name, entry in manifest.items():
        if len(files[name]) != entry["bytes"] or digest(files[name]) != entry["sha256"]:
            raise ValueError("member hash/size mismatch: " + name)
    return files


def program_catalog(programs, receipt):
    builds = json.loads(programs["evidence/build-complete-result-v2.json"])
    runtime = json.loads(programs["evidence/runtime-result.json"])
    if not builds["all_source_closures_unchanged"] or not runtime["all_source_closures_unchanged"]:
        raise ValueError("worker changed sealed source")
    if runtime["mock_proofs_used"] or runtime["recursive_verification_disabled"]:
        raise ValueError("worker verification was bypassed")
    if set(builds["roles"]) != set(runtime["roles"]) or len(builds["roles"]) != 8:
        raise ValueError("wrong program role closure")
    result = {}
    for role, build in builds["roles"].items():
        first, second = build["ELFs"]
        elf = programs[first["path"]]
        if elf != programs[second["path"]] or digest(elf) != first["sha256"]:
            raise ValueError("repeat ELF mismatch: " + role)
        if elf[:6] != b"\x7fELF\x02\x01" or int.from_bytes(elf[18:20], "little") != 243:
            raise ValueError("not a RISC-V 64-bit ELF: " + role)
        identities = [json.loads(programs[f"runtime-results/identity-{role.replace('/', '-')}-{n}.json"])
                      for n in (1, 2)]
        state = runtime["roles"][role]
        for identity in identities:
            words = identity["vkey_u32"]
            if len(words) != 8 or any(type(w) is not int or not 0 <= w < 0x7f000001 for w in words):
                raise ValueError("noncanonical program key: " + role)
            program = b"".join(w.to_bytes(4, "big") for w in words).hex()
            if (not identity["passed"] or identity["elf_sha256"] != digest(elf) or
                    program != identity["program_id_hash_bytes"] or
                    program != state["program_id_hash_bytes"]):
                raise ValueError("program identity mismatch: " + role)
        result[role] = {"elf": "programs/" + first["path"], "elf_bytes": len(elf),
                        "elf_sha256": digest(elf), "program_id": program,
                        "repeat_build_identical": True,
                        "execution_passed": state["execution_passed"],
                        "execution_status": state["execution_status"],
                        "compressed_proof_verified": False}
    role = "v11/ethereum-finality-segment-v2"
    proof = json.loads(receipt["retry/results/v11-mainnet-segment-compressed-proof.json"])
    data = receipt["retry/proofs/v11-mainnet-segment.sp1"]
    journal = receipt["prior/packet/qualification/v11-segment-vectors/expected-journal.bin"]
    if (proof["program_id_hash_bytes"] != result[role]["program_id"] or
            proof["proof_sha256"] != digest(data) or proof["journal_sha256"] != digest(journal) or
            not proof["passed"] or not proof["proof_verified_after_reload"] or
            not proof["tampered_journal_rejected"] or proof["live_mint_qualified"]):
        raise ValueError("segment proof qualification mismatch")
    result[role].update(compressed_proof_verified=True, proof_sha256=digest(data),
                        journal_sha256=digest(journal))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new artifact directory")
    args = parser.parse_args()
    verified = [(label, verify_packet(args.packets / filename, pin, manifest))
                for filename, pin, manifest, label in PACKETS]
    programs = program_catalog(verified[0][1], verified[1][1])
    # Validate everything before creating any output. Never overwrite old evidence.
    args.output.mkdir(parents=True, exist_ok=False)
    for label, files in verified:
        for name, data in files.items():
            path = args.output / label / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)
    result = {"schema": "elements-usdd-mainnet-import-v1",
              "packets": [{"name": name, "sha256": pin} for name, pin, _, _ in PACKETS],
              "verified_members": {label: len(files) for label, files in verified},
              "programs": programs,
              "activation_performed": False, "live_mint_qualified": False,
              "release_blockers": ["native SP1 tensor-shape fix and requalification",
                                   "authentic terminal/controller proof and deployment closure"]}
    with (args.output / "import.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
