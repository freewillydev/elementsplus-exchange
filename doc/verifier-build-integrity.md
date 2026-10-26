# Verifier Build Integrity

Every supplied external consensus archive requires an independently trusted
lowercase SHA-256 pin at configuration time:

| Archive option | Required digest option |
| --- | --- |
| `USDD_SP1_VERIFIER_ARCHIVE` | `USDD_SP1_VERIFIER_SHA256` |
| `ECX_SP1_VERIFIER_ARCHIVE` | `ECX_SP1_VERIFIER_SHA256` |
| `ECX_FORCED_V3_ADMISSION_ARCHIVE` | `ECX_FORCED_V3_ADMISSION_SHA256` |

CMake rejects missing/malformed/mismatching pins, symlink archives and thin
archives (whose external objects would not be hash-pinned). ABI checks and links
use a verified build-local copy. Every dependent build rechecks both the input
and copy, including incremental builds. Existing ABI, semantic-identity and
direct-install snapshot integrity checks also apply. Only self-contained,
single-target ar archives are supported; qualify each macOS architecture
separately instead of supplying a universal/fat container. Existing
macOS deployment-target checks still apply. Builds with no archive retain their
existing fail-closed feature activation gates; they are not full-featured releases.

`contrib/release/verifier-pins-linux-20261022.cmake` records the previously
offline-tested Ubuntu 24.04 x86_64 archives from overlay
`c9116d76987a60359805ef9cea270dec69df0b6269f4cc3934ffffb854e6d643`.
Load it with `cmake -C contrib/release/verifier-pins-linux-20261022.cmake ...`
only when using those exact archives. Their source-package digests were:

- USDD: `2e383aee28428191db58d02bdc92bbb17a58848fd49c24668109c9695966b197`
- ECX: `f0bad62f7ae6481d62388ba8c83806996d6c2adfbc483e7a6b596e6faa7bade0`

For a different target/toolchain, independently build and review the verifier
source and lockfiles, qualify genuine valid and invalid proofs, and record the
approved archive digest before configuring. Do not automatically hash whatever
file was downloaded and pass that as its own trust anchor. A changed archive
needs review, not an automatic checksum refresh. These historical Linux pins do
not qualify the current dirty source tree, another platform, new guest programs,
or production mainnet.

Hash checks cannot protect against an attacker who can change the pins, build
scripts, compiler, build directory or final executable. Package provenance must
also bind the exact node source, dependency sources/toolchains, archive hashes,
test results and distributed binary hashes. Static archives are not loaded at
daemon startup, so runtime semantic checks do not replace this build gate.

Regression command: `python3 contrib/devtools/test_verifier_pins.py`.
