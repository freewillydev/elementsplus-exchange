# Ethereum-mainnet USDD proof integration

The October 25 Windows return is now an authenticated input to this node's
release tooling. It does not by itself activate USDD, mint assets, update the
live chain or qualify a final release.

## Imported inputs

`contrib/release/usdd-mainnet-programs-20261025.json` records all eight rebuilt
programs, exact ELF/program hashes, packet pins and per-role qualification.
Two clean builds on the same Windows/WSL worker produced identical ELF bytes
and SP1 identities for every role. This is repeat-build reproducibility, not
independent-machine reproduction. The source target is Ethereum mainnet,
chain 1, with canonical USDT at `dac17f958d2ee523a2206206994597c13d831ec7`.

Only `v11/ethereum-finality-segment-v2` has a completed compressed proof.
Its program ID is
`327a8b856ff3efc438c60b521dc0ce081584878274f1b456080fdc77773d5ce0`.
The SDK proof envelope is 1,273,035 bytes; the raw proof is 1,272,546 bytes;
the authenticated segment journal is 466 bytes. These are different formats.
Standalone heartbeat execution and rejection tests passed, but no standalone
proof was generated. Mint has a wrong-token rejection fixture, not a successful
mint proof. The other recursive/terminal roles have reproducible builds but
still need authentic positive proof-chain qualification.

Import the two unchanged return packets into a new directory:

```sh
python3 contrib/devtools/import_usdd_mainnet_artifacts.py \
  --packets /absolute/path/to/worker-return \
  --output /absolute/path/to/new-release-inputs
```

The importer checks both independently pinned archive hashes, all 232 members,
every manifest entry, RISC-V ELF pairs, canonical key encodings and matching
proof/program/journal identities before writing output. It rejects links,
traversal, duplicate entries and overwrites. Imported scripts are never run.
The generated `import.json` retains release blockers instead of relabelling
component verification as mint or deployment qualification.

## Node boundary

The native verifier is already parameterized by an expected program ID and
public-values digest supplied by the executed Simplicity leaf. The segment
receipt belongs inside the recursive finality/terminal/controller workflow.
It must not replace the historical single-guest constants or become a
host-mutable list of accepted mint programs.

`contrib/devtools/usdd_mainnet_compatibility_probe.rs` links to the candidate
node's exact Rust verifier build. It verifies the real saved segment receipt,
rejects changed journal/program IDs and truncated/trailing proof bytes, and
checks that both existing mint ABI statement lanes reject this inner receipt.
It uses the same adapter implementation and semantic identity; this does not
constitute a successful mint transaction or complete controller execution.

The native `windows_mainnet_segment_is_not_a_mint` release test uses the
hash-pinned return through the node's real C++/Haskell/Rust journal and
Simplicity-jet adapters. It checks both statement kinds with the original
journal and with the journal replaced by its hash. All four repackaging attempts
are rejected. This is a negative authorization test, not proof of a valid mint.
The unchanged proof and journal are now hash-pinned test data in
`src/test/data/usdd_mainnet_segment.raw` and `usdd_mainnet_journal.raw`.
They are compiled into the test executable, not the daemon. The case runs in
the default native suite whenever the USDD verifier is linked; it no longer
needs an external fixture directory. To run just this case:

```sh
/absolute/path/to/build/bin/test_elements \
  --run_test=usdd_sp1_verifier_identity_tests/windows_mainnet_segment_is_not_a_mint \
  --report_level=detailed
```

The test checks fixture sizes/hashes and rejects all four repackagings through
the linked verifier boundary. It never contacts a node or uses a wallet.

## SP1 6.8.1 qualification

The old SP1 6.3.1 dependency accepted a tensor whose storage length did not
match its dimensions, as described in
[GHSA-p7v2-jjv3-8p8f](https://github.com/succinctlabs/sp1/security/advisories/GHSA-p7v2-jjv3-8p8f).
Canonical bincode round-tripping alone did not repair the mismatch. The local
node build now links USDD and ECX verifier archives using SP1 **6.8.1** and
the locked corresponding SP1/slop dependency graph. Source reconstruction
patches, toolchain details and archive/semantic pins are recorded in
[`contrib/release/sp1-6.8.1`](../contrib/release/sp1-6.8.1/README.md).

The actual Windows finality-segment proof verifies with 6.8.1. Changed journal
and program identities, truncated/trailing proofs, and malformed tensor shapes
in both component and query paths of that real proof reject. Storage/dimension
combinations and overflow cases have dedicated regression tests. A prior real
USDD authorizing proof also verifies; the ECX Groth16 fixture passes all 24
positive and mutation checks. These checks do not generate a new mint proof.

The final local native/Qt build passed, followed by **1,725 native tests and
58,866,212 assertions**, plus all eight ABI/type/runtime/workflow CTests. The
native suite includes the Windows segment rejection case. Existing platform,
thread-safety and Rust archive duplicate-symbol warnings remain visible.

Canonical startup requires the new verifier semantic identity from
`UsddSp1VerifierRelease` and rejects the old implementation. The historical
6.3.1 fields serialized in `elements_drivechain_identity.h` remain unchanged
to preserve the already defined genesis/assets; they are not a runtime
allowlist for the vulnerable verifier. The recursion-key root is unchanged.
Deploying this narrower proof-validation rule still needs a coordinated node
upgrade; passing local tests does not update remote nodes.

No AWS deployment, activation, commit or publication is established by this
qualification. Linux/other supported target builds, independent reproduction
and full mint/controller qualification remain separate release requirements.

The final deployment additionally requires authentic terminal/controller
proofs and the exact mainnet vault/runtime, asset, child-chain and controller
configuration. No existing Sepolia deployment, old guest key or inner segment
proof substitutes for that closure.
