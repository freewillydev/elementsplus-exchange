# Secure native Drivechain RPC setup

The current network is `-chain=elements`, data subdirectory `elements-v11`,
slot 24. It is not the historical Liquid-signet chain. See
[identity and peg operations](drivechain-peg-operations.md).

## Parent and wallet RPC

Run the fully validating parent on the same trusted host, with `txindex`
enabled and RPC bound only to loopback. The native default port is 18302:

```ini
mainchainrpchost=127.0.0.1
mainchainrpcport=18302
mainchainrpccookiefile=/absolute/path/to/parent-bitcoin/.cookie
drivechainl1blocksync=0
```

Do not configure `mainchainrpcuser` or `mainchainrpcpassword`. On POSIX the
rotating cookie must be a regular non-symlink file owned by the Elements user,
mode 0600, containing the canonical `__cookie__:` plus 64 hex characters.
The native default cookie location has no `signet/` suffix.
DNS names (including `localhost`), LAN addresses and inline parent credentials
are rejected. An explicit `mainchainrpccredentialfile` is also supported for a
trusted same-host bridge: it must be an owner-only, non-symlink private file
containing `user:password`, and cannot be combined with cookie or inline
credential options. Prefer the rotating cookie for direct parent access.
Verify the frozen parent checkpoint before using funds.

Elements' own authenticated JSON-RPC defaults to port 7065 and is restricted to
numeric loopback (IPv4 127/8 or IPv6 ::1). Use its generated cookie. Local
`rpcauth`/static credentials remain supported for existing clients. Native
`rest=1` is rejected because that listener bypasses RPC authentication.
Do not expose either HTTP listener on a LAN/public interface.

These local HTTP connections are authenticated but **not encrypted**. They
rely on trusted same-host isolation. Remote wallet access needs a separately
authenticated TLS tunnel/proxy with a narrow allowlist; never expose raw RPC.
This configuration does not protect against compromise of the host/user.

## Enforcer mutual TLS

All active enforcer operations, including BMM, withdrawal submission and
validation-data queries, use the same authenticated unary gRPC path. There is
no plaintext ConnectJSON fallback, bearer-cookie alternative, or PATH search.

The Haskell client is linked into the node and uses the gRPC C core directly.
No grpcurl executable, subprocess, shell, or server reflection is needed.
Remove the obsolete `drivechainbmmgrpcurl` setting from existing configurations.
Requests use generated bindings for the pinned enforcer protocol. Transport
retries are disabled; application retry policy remains with the caller.

If the enforcer serves plaintext gRPC, bind it to `127.0.0.1:50051` and use
the bundled mTLS proxy on `127.0.0.1:55051`. The proxy-to-enforcer hop is
plaintext on the trusted host; this is not end-to-end TLS inside the enforcer.
Do not forward that plaintext listener to another host or an untrusted network.

```sh
contrib/drivechain-mtls/generate-certs.sh /absolute/path/to/elements-v11/enforcer-tls
contrib/drivechain-mtls/run-stunnel-proxy.sh /absolute/path/to/elements-v11/enforcer-tls
```

Configure absolute paths (relative credential paths resolve under the network
data directory):

```ini
drivechainbmmgrpcaddr=127.0.0.1:55051
drivechainbmmgrpcca=/absolute/path/to/elements-v11/enforcer-tls/ca.pem
drivechainbmmgrpccert=/absolute/path/to/elements-v11/enforcer-tls/elements-client.pem
drivechainbmmgrpckey=/absolute/path/to/elements-v11/enforcer-tls/elements-client-key.pem
drivechainbmmgrpcauthority=enforcer.local
```

On POSIX, credential files and their immediate directory must be owned by the
Elements user and not group/other writable; files must not be symlinks. The
client private key requires mode 0600. The endpoint must be numeric loopback,
even with TLS. An optional deprecated `drivechainbmmwalletaddr` must exactly
match it; `drivechainbmmconnectauthcookie` is unsupported.
The overall Haskell migration still requires a native macOS/Linux toolchain;
Windows packaging is not qualified. This transport change does not change that.
The configured authority is used for TLS server-name verification as well as
the request authority, including when connecting to a numeric loopback endpoint.

Run isolated transport regression tests (no live enforcer or funds):

```sh
cmake --build build --target haskell_grpc_probe -j1
python3 src/haskell/test/grpc_transport.py build/bin/haskell_grpc_probe /path/to/temporary-directory
```

Tests require Python grpcio/protobuf, protoc, bash, and openssl. The build needs
Cabal and gRPC C-core development libraries; Haskell dependency sources are pinned
in `src/haskell/GrpcDependencies.cmake`. Match native dependency deployment targets
to the intended release OS; locally installed libraries are not portable releases.
Missing/wrong client credentials must fail the TLS handshake. No plaintext or
insecure-certificate fallback is provided.

## Production and rotation

Automatic `drivechainl1blocksync` currently defaults **on**. Explicitly set it
to 0 during read-only setup. Enforcer calls fail closed at use when credentials
are invalid; this is not a guarantee of a startup TLS probe.
A native `sendtomainchain` burn can be created without an available enforcer,
so verify the submission path before burning coins.

The helper issues a 365-day CA and 90-day server/client certificates and refuses
to overwrite existing credentials. Move the CA private key offline. Monitor
expiry in advance:

```sh
openssl x509 -checkend 1209600 -noout -in /absolute/path/to/enforcer-tls/elements-client.pem
openssl x509 -checkend 1209600 -noout -in /absolute/path/to/enforcer-tls/server.pem
```

Rotate using a newly issued private directory. Stop block production/Elements
and the proxy, switch both configurations to the new matching credentials,
start the proxy, verify authentication, then restart Elements. Do not delete
working credentials before verification. Stop the foreground proxy with its
supervisor or Ctrl-C.

Check listeners with `lsof -nP -iTCP -sTCP:LISTEN`: ports 18302, 7065, 50051
and 55051 must not listen publicly. No environment variables may bypass
withdrawal event verification or silently select another fee/slot/endpoint.
The legacy ECX-only `drivechainpegoutmainfeesats` option is not the native
`sendtomainchain` RPC's explicit coin-denominated `mainchainfee` argument.
