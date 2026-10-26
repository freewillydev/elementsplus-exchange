#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 CREDENTIAL_DIRECTORY [CA_DIRECTORY] [CLIENT_ID]" >&2
  exit 2
fi

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required" >&2
  exit 1
}

umask 077
destination=$1
client_id=${3:-elements-client}
if [[ ! $client_id =~ ^[a-z][a-z0-9-]{0,62}$ ]]; then
  echo "client identity must be a lowercase DNS label (1-63 characters)" >&2
  exit 1
fi
if [[ -L $destination ]]; then
  echo "credential and CA directories must not be symlinks" >&2
  exit 1
fi
mkdir -p "$destination"
destination=$(cd "$destination" && pwd -P)
chmod 0700 "$destination"
ca_directory=${2:-${destination}-ca}
if [[ -L $ca_directory ]]; then
  echo "credential and CA directories must not be symlinks" >&2
  exit 1
fi
mkdir -p "$ca_directory"
ca_directory=$(cd "$ca_directory" && pwd -P)
if [[ $ca_directory == "$destination" || $ca_directory == "$destination/"* || $destination == "$ca_directory/"* ]]; then
  echo "CA and runtime credential directories must be separate, non-nested directories" >&2
  exit 1
fi
chmod 0700 "$ca_directory"

files=(
  ca-key.pem ca.pem server-key.pem server.pem
  elements-client-key.pem elements-client.pem
)
for file in "${files[@]}"; do
  if [[ -e "$destination/$file" || -L "$destination/$file" ]]; then
    echo "refusing to overwrite $destination/$file" >&2
    exit 1
  fi
done
for file in ca-key.pem ca.pem ca.srl; do
  if [[ -e "$ca_directory/$file" || -L "$ca_directory/$file" ]]; then
    echo "refusing to overwrite $ca_directory/$file" >&2
    exit 1
  fi
done

temporary=$(mktemp -d "$destination/.issue.XXXXXX")
trap 'rm -rf "$temporary"' EXIT

openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
  -subj '/CN=Elements Drivechain Local CA' \
  -keyout "$ca_directory/ca-key.pem" -out "$ca_directory/ca.pem"
cp "$ca_directory/ca.pem" "$destination/ca.pem"

openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -subj '/CN=enforcer.local' \
  -keyout "$destination/server-key.pem" -out "$temporary/server.csr"
cat >"$temporary/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:enforcer.local,IP:127.0.0.1,IP:::1
EOF
openssl x509 -req -sha256 -days 90 \
  -in "$temporary/server.csr" -CA "$destination/ca.pem" \
  -CAkey "$ca_directory/ca-key.pem" -CAserial "$ca_directory/ca.srl" -CAcreateserial \
  -extfile "$temporary/server.ext" -out "$destination/server.pem"

openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=$client_id" \
  -keyout "$destination/elements-client-key.pem" \
  -out "$temporary/client.csr"
cat >"$temporary/client.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:$client_id
EOF
openssl x509 -req -sha256 -days 90 \
  -in "$temporary/client.csr" -CA "$destination/ca.pem" \
  -CAkey "$ca_directory/ca-key.pem" -CAserial "$ca_directory/ca.srl" \
  -extfile "$temporary/client.ext" -out "$destination/elements-client.pem"

chmod 0600 "$ca_directory/ca-key.pem" "$destination/server-key.pem" \
  "$destination/elements-client-key.pem"
chmod 0644 "$destination/ca.pem" "$destination/server.pem" \
  "$destination/elements-client.pem"

openssl verify -CAfile "$destination/ca.pem" \
  "$destination/server.pem" "$destination/elements-client.pem"
openssl x509 -checkend 86400 -noout -in "$destination/server.pem"
openssl x509 -checkend 86400 -noout -in "$destination/elements-client.pem"

echo "created mutually authenticated TLS credentials in $destination"
echo "client identity: $client_id (configure the proxy to allow this exact identity)"
echo "CA signing key is separate in $ca_directory; keep this directory offline, not on the runtime host"
