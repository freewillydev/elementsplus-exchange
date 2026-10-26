# Existing-Proposal Slot-24 Test Deployment

This profile is explicitly for operator-authorized testing on Betanet slot24.
It authenticates the existing Elements proposal
`866e33f1e4c854fadea9f9792064708ced3633bc963b000a03d4d4ac2e1a2400`,
activated at parent970715. That proposal describes historical replay-v4 rules;
this child uses current Betanet replay-v5/NOP8 rules. It is NOT the historical
Alpha network, nor a claim that the parent proposal commits the new child code.

The independent child manifest, genesis and asset commit the new rules. Full
parent replay, exact proposal matching, mined BMM authentication, deposit and
withdrawal checks remain required. No runtime slot/proposal bypass was added.

## Explicit testing only

Ordinary node startup requires `acceptbetanettestprofile=1`. Without it the node
refuses before networking or locking the data directory. This acknowledgement
does not authenticate a new proposal, change consensus or enable bidding.
`drivechainl1blocksync` separately defaults to 0. Existing functional-test-only
binaries are not release binaries and retain their isolated fixture admission.

A production release requires a new reviewed child identity and a matching
parent proposal committing its actual rules. Changing a local description or
adding an opt-in cannot retroactively change the proposal miners activated.

## Parent network and treasury

The immutable replay bootstrap is height 967679, before the Betanet fork. Its
empty CTIP is an initial replay state, not an assertion that slot 24 was already
active. Replay must authenticate the subsequent proposal activation and treasury
history before deposits or withdrawals are authorized.

Since Bitcoin shares this genesis and bootstrap, operational parent-RPC checks
also require height **967680** to equal
`00000000000000030101ba5cfea54b22becc79f95dc6040beb76e01dd9d04042`.
This is checked before real header authentication, replay-cache use and local
wallet bidding, including manual bids. Missing, malformed or wrong-network
responses fail closed and revoke the published replay epoch. Cached BMM edges
and anchor snapshots recheck the network before live hash comparisons; a wrong
network or unavailable identity is not evidence of a reorg and must not trigger
child rollback. A later successful identity check alone cannot reauthorize old
cache entries; authenticated replay must publish its epoch again.
This does not alter the serialized child manifest/genesis.
It detects wrong-network configuration; it does not make a compromised parent
RPC trustworthy or replace parent consensus validation.

This is the ECX Betanet protocol, not unmodified Bitcoin BIP300:
[the pinned ECX parent source](https://github.com/ecash-com/bitcoin/blob/ca64033c137457a3c8ca394186759819a2ab0694/src/script/script.h)
assigns `OP_DRIVECHAIN` to `OP_NOP8` (`0xb7`). The companion enforcer's
`NetworkParams::betanet()` likewise selects NOP8. Switching to Bitcoin's public
BIP300 NOP5 encoding would reject this network's deposits. Neither a reserved
opcode nor standardness alone protects the treasury: protection requires the
actual parent miner/enforcer soft-fork rules. A generic Bitcoin node or an
incompatible enforcer is not an acceptable substitute.

The node still trusts its authenticated local parent for active-chain selection.
Header proof-of-work checks and replay do not remove that trust. Keep the parent
on a protected host; cookie-authenticated loopback HTTP is not encrypted and
does not protect against same-user host compromise. Locked validation has a
bounded RPC deadline, but parent availability remains a liveness dependency.

- Genesis: `a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f`
- Native asset: `5836dcc06130dcf6a65b6ac493813fd65559955283e44cc3f07966294eccb2c8`
- P2P magic: `3b5ff18b`
- Data namespace: `elements-betanet-slot24-v1`

Use a fresh data directory and fresh sidechain wallet. Never relabel the old
slot130 or Alpha databases. Existing USDD/futures deployments require new
chain-specific bindings; their old state does not migrate into this genesis.

Validation on October2: all23 independent identity tests and99 focused native
tests/34872 assertions passed. Native startup independently reproduces the
genesis and authenticates parent replay. This is not full release qualification
or proof of mined-block inclusion. No enforcer source changes were made.
