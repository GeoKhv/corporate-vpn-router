#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build/module-cache
PKI_DIR=$(mktemp -d /private/tmp/cvr-test-pki.XXXXXX)
FIXTURE_PID=""
trap 'if [[ -n "$FIXTURE_PID" ]]; then kill "$FIXTURE_PID" 2>/dev/null || true; fi; rm -rf "$PKI_DIR"' EXIT
cat > "$PKI_DIR/openssl.cnf" <<'CONF'
[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=Corporate VPN Router Test CA
O=Example Test Only
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
CONF
/usr/bin/openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 -config "$PKI_DIR/openssl.cnf" -keyout "$PKI_DIR/key.pem" -out "$PKI_DIR/ca.pem" 2>/dev/null
/usr/bin/openssl req -new -newkey rsa:2048 -nodes -subj '/CN=wiki.corp.example.com/O=Example Test Only' -keyout "$PKI_DIR/leaf.key" -out "$PKI_DIR/leaf.csr" 2>/dev/null
cat > "$PKI_DIR/leaf.cnf" <<'CONF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:wiki.corp.example.com
CONF
/usr/bin/openssl x509 -req -in "$PKI_DIR/leaf.csr" -CA "$PKI_DIR/ca.pem" -CAkey "$PKI_DIR/key.pem" -CAcreateserial -days 1 -extfile "$PKI_DIR/leaf.cnf" -out "$PKI_DIR/leaf.pem" 2>/dev/null
cat "$PKI_DIR/leaf.pem" "$PKI_DIR/ca.pem" > "$PKI_DIR/server.pem"
export CVR_TEST_CA_FILE="$PKI_DIR/ca.pem"
/usr/bin/python3 Tests/tls_fixture.py "$PKI_DIR" &
FIXTURE_PID=$!
for _ in {1..50}; do if [[ -f "$PKI_DIR/port" ]]; then break; fi; sleep 0.1; done
export CVR_TLS_FIXTURE_PORT=$(cat "$PKI_DIR/port")
SOURCES=()
for file in Sources/*.swift; do
  if [[ "$file" != Sources/main.swift ]]; then SOURCES+=("$file"); fi
done
swiftc -swift-version 5 -Onone -target arm64-apple-macos13.0 -module-cache-path "$PWD/.build/module-cache" \
  -framework AppKit "${SOURCES[@]}" Tests/main.swift -o .build/router-tests
.build/router-tests
test ! -f "$PKI_DIR/unexpected-application-data"
