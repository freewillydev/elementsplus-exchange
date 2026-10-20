#!/usr/bin/env bash
# Compatibility entry point. The C-core gRPC client requires HTTP/2 ALPN,
# which the old stunnel configuration did not provide.
set -euo pipefail
exec bash "$(dirname "$0")/run-mtls-proxy.sh" "$@"
