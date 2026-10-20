#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 CREDENTIAL_DIRECTORY [LISTEN_HOST:PORT] [UPSTREAM_HOST:PORT]" >&2
  exit 2
fi

command -v haproxy >/dev/null 2>&1 || {
  echo "HAProxy is required for authenticated HTTP/2 (macOS: brew install haproxy)" >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required" >&2
  exit 1
}

credentials=$(cd "$1" && pwd -P)
listen=${2:-127.0.0.1:55051}
upstream=${3:-127.0.0.1:50051}
for file in ca.pem server.pem server-key.pem; do
  [[ -f "$credentials/$file" && ! -L "$credentials/$file" ]] || {
    echo "missing non-symlink credential: $credentials/$file" >&2
    exit 1
  }
done

stat_owner_mode() {
  if stat -f '%u %Lp' "$1" >/dev/null 2>&1; then
    stat -f '%u %Lp' "$1"
  else
    stat -c '%u %a' "$1"
  fi
}

read -r directory_owner directory_mode < <(stat_owner_mode "$credentials")
if [[ $directory_owner != "$(id -u)" || $((8#$directory_mode & 8#022)) -ne 0 ]]; then
  echo "credential directory must be owned by the current user and deny group/other write access: $credentials" >&2
  exit 1
fi

for file in ca.pem server.pem; do
  read -r file_owner file_mode < <(stat_owner_mode "$credentials/$file")
  if [[ $file_owner != "$(id -u)" || $((8#$file_mode & 8#022)) -ne 0 ]]; then
    echo "certificate must be owned by the current user and deny group/other write access: $credentials/$file" >&2
    exit 1
  fi
done
read -r key_owner key_mode < <(stat_owner_mode "$credentials/server-key.pem")
if [[ $key_owner != "$(id -u)" || $((8#$key_mode & 8#077)) -ne 0 ]]; then
  echo "server key must be owned by the current user and deny all group/other access: $credentials/server-key.pem" >&2
  exit 1
fi

openssl verify -purpose sslserver -CAfile "$credentials/ca.pem" \
  "$credentials/server.pem" >/dev/null
openssl pkey -in "$credentials/server-key.pem" -check -noout >/dev/null
certificate_key=$(openssl x509 -in "$credentials/server.pem" -pubkey -noout | \
  openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)
private_key=$(openssl pkey -in "$credentials/server-key.pem" -pubout -outform DER 2>/dev/null | \
  openssl dgst -sha256)
if [[ -z $certificate_key || $certificate_key != "$private_key" ]]; then
  echo "server certificate does not match server private key" >&2
  exit 1
fi

is_loopback_endpoint() {
  local endpoint=$1 octet port
  if [[ $endpoint =~ ^127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,5})$ ]]; then
    port=${BASH_REMATCH[4]}
    for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"; do
      [[ $octet == 0 || $octet != 0* ]] || return 1
      ((10#$octet <= 255)) || return 1
    done
  elif [[ $endpoint =~ ^\[::1\]:([0-9]{1,5})$ ]]; then
    port=${BASH_REMATCH[1]}
  else
    return 1
  fi
  ((10#$port >= 1 && 10#$port <= 65535))
}

is_loopback_endpoint "$listen" || {
  echo "refusing non-loopback or invalid TLS listen endpoint: $listen" >&2; exit 1
}
is_loopback_endpoint "$upstream" || {
  echo "refusing non-loopback or invalid plaintext upstream: $upstream" >&2; exit 1
}

umask 077
configuration=$(mktemp -d "${TMPDIR:-/tmp}/elements-enforcer-mtls.XXXXXX")
proxy_pid=
cleanup() {
  if [[ -n $proxy_pid ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  rm -rf "$configuration"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
cat "$credentials/server.pem" "$credentials/server-key.pem" >"$configuration/server.pem"
cp "$credentials/ca.pem" "$configuration/ca.pem"
cat >"$configuration/haproxy.cfg" <<EOF
global
  nbthread 1
  maxconn 64
defaults
  mode tcp
  timeout connect 5s
  timeout client 10m
  timeout server 10m
frontend enforcer_tls
  bind $listen ssl crt server.pem ca-file ca.pem verify required ssl-min-ver TLSv1.2 alpn h2
  tcp-request content reject unless { ssl_c_s_dn(cn) -m str elements-client }
  tcp-request content reject unless { ssl_fc_alpn -m str h2 }
  default_backend enforcer_loopback
backend enforcer_loopback
  server enforcer $upstream
EOF

# Keep the supervisor alive so signals also reap the proxy and remove its
# temporary private PEM bundle. No credentials are written to the repository.
(cd "$configuration" && exec haproxy -db -f haproxy.cfg) &
proxy_pid=$!
wait "$proxy_pid"
