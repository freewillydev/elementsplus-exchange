# Enforcer protocol snapshot

Unmodified CUSF protobuf schemas from ekulkisnek/bip300301_enforcer commit
`6479946ea5d8b85d22af8b55297d89d831166860`, `proto/cusf`.
The build generates Haskell types; tests must use these same official wire schemas,
not reflection services whose methods accept `google.protobuf.Struct`.

The direct client exposes only the seven methods selected in EnforcerCodec.hs.
Adding other services to the protocol snapshot does not authorize calling them.
