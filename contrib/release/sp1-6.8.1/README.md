# SP1 6.8.1 verifier source and local qualification

These patches reconstruct the USDD and ECX verifier sources used by the
October 25 local macOS node qualification. They do not activate a chain,
publish a release, deploy a node, or qualify the complete USDD mint/controller
workflow. `manifest.json` pins source archives, patches, and the resulting
local static libraries separately from the verifier's semantic identity.

## Reconstruct sources

Obtain `usdd-verifier-source.tar.gz` and `ecx-verifier-source.tar.gz` from the
existing [source release](https://github.com/freewillydev/liquid-drivechain-signet-adaptation/releases/tag/elements-betanet-20261022-linux-c9116d76).
Verify their SHA256 values against `manifest.json` before extraction. Use new
directories; never apply these patches to an unrelated working tree.

The USDD archive's source root is `source/` (the archived older dependency vendor
tree is not the new dependency closure). Extract that root, then apply
`usdd.patch` from its root. The ECX archive's root is `./`; extract it into a
separate directory and apply `ecx.patch` there. Use absolute patch paths:

```sh
git apply --check /path/to/node/contrib/release/sp1-6.8.1/usdd.patch
git apply /path/to/node/contrib/release/sp1-6.8.1/usdd.patch
```

Use the equivalent commands with `ecx.patch` in the ECX source directory.
The qualification replay reconstructed all 195 USDD and 26 ECX source files
byte-identically to the built sources. That proves source reconstruction, not
independent-machine binary reproducibility.

## Build and test

The qualified host is macOS arm64, deployment target 11.0. USDD used Rust 1.90.0;
ECX used Rust 1.92.0. Keep `Cargo.lock` files unchanged. Resolve the new locked
dependencies with Cargo's checksum checks; the old 6.3.1 vendor tree alone is
insufficient. Build outside the node tree with separate target directories.

USDD, from its source root:

```sh
MACOSX_DEPLOYMENT_TARGET=11.0 cargo +1.90.0 build --locked --release -p usdd-sp1-verifier
MACOSX_DEPLOYMENT_TARGET=11.0 cargo +1.90.0 test --locked --release -p usdd-sp1-verifier
```

ECX, from its source root:

```sh
MACOSX_DEPLOYMENT_TARGET=11.0 cargo +1.92.0 build --locked --release --manifest-path zkvm/verifier-ffi/Cargo.toml
MACOSX_DEPLOYMENT_TARGET=11.0 cargo +1.92.0 test --locked --release --manifest-path zkvm/verifier-ffi/Cargo.toml
```

Pass the resulting absolute archive paths and independently reviewed SHA256
values as `USDD_SP1_VERIFIER_ARCHIVE` / `USDD_SP1_VERIFIER_SHA256` and
`ECX_SP1_VERIFIER_ARCHIVE` / `ECX_SP1_VERIFIER_SHA256` to the node build. Retain
all existing archive snapshot, ABI-link, target and startup identity gates.
Do not treat a freshly computed hash as independent approval of an archive.
The macOS archive hashes below are not Linux build pins or a promise that
arbitrary paths/toolchains yield identical archive bytes.

The historical exported name `ecx_sp1_6_3_1_verify_groth16_sha256` remains an
ABI compatibility name. Its implementation in this source uses SP1 6.8.1.
The frozen genesis transcript likewise remains historical; the node's runtime
USDD startup pin is the new semantic identity, not the original one.

## Evidence and remaining work

- USDD default tests: 31 passed; genuine positive authorizing fixture: passed
  separately. Tensor tests include storage/dimension mismatch and overflow.
- Windows Ethereum-mainnet finality segment: verified with 6.8.1; modified
  journal/program, truncated/trailing proof, and malformed component/query
  tensor proof paths rejected. Inner finality proofs cannot authorize mint.
- ECX: three FFI and 26 interface unit tests passed; 24 genuine Groth16 fixture
  positive/mutation checks passed.
- Complete current node/Qt build passed. Native suite: 1,725 tests,
  58,866,212 assertions passed. Eight CTests passed.

The real finality proof is test data, not a mint deployment artifact. Genuine
mainnet vault/deposit, terminal/controller proof chain, end-to-end mint and
redemption, supported-target builds, independent reproduction, and coordinated
deployment remain to be qualified. No test-network USDT or mock fixture is
accepted as evidence of real Ethereum-mainnet USDT backing.
