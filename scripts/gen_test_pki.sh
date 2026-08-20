#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Mock PKI / Kubernetes TLS Secret Generator
# =============================================================================
#
# Certificate hierarchy:
#
#   Example Engineering Root CA
#              |
#              v
#   Example Engineering Intermediate CA 1
#              |
#              v
#   Example Engineering Intermediate CA 2
#              |
#              v
#   api.example.internal (leaf)
#
# Kubernetes Secret:
#
#   Namespace: default
#   Name:      mock-server-tls
#   Type:      kubernetes.io/tls
#
# tls.crt contains:
#
#   1. Leaf certificate
#   2. Intermediate CA 2
#   3. Intermediate CA 1
#
# tls.key contains:
#
#   Leaf private key
#
# The root CA is intentionally NOT included in tls.crt because the root
# normally exists in the client's trust store.
#
# The script also creates:
#
#   full-chain.crt
#
# containing all four certificates for testing/inspection purposes.
# =============================================================================

OUT_DIR="${OUT_DIR:-./pki}"
NAMESPACE="${NAMESPACE:-default}"
SECRET_NAME="${SECRET_NAME:-mock-server-tls}"

# -----------------------------------------------------------------------------
# Cleanup / setup
# -----------------------------------------------------------------------------

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Private keys and CSRs should not be readable by other users.
umask 077

echo
echo "============================================================"
echo "Generating mock PKI"
echo "============================================================"
echo
echo "Output directory : $OUT_DIR"
echo "Kubernetes ns    : $NAMESPACE"
echo "Secret name      : $SECRET_NAME"
echo

# -----------------------------------------------------------------------------
# 1. Root CA
# -----------------------------------------------------------------------------

echo "[1/7] Generating Root CA..."

openssl genrsa \
  -out "$OUT_DIR/root-ca.key" \
  4096

openssl req \
  -x509 \
  -new \
  -sha256 \
  -days 3650 \
  -key "$OUT_DIR/root-ca.key" \
  -out "$OUT_DIR/root-ca.crt" \
  -subj "/C=US/ST=California/L=San Francisco/O=Example Engineering/OU=Security Engineering/CN=Example Engineering Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:2" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# -----------------------------------------------------------------------------
# 2. Intermediate CA 1
# -----------------------------------------------------------------------------

echo "[2/7] Generating Intermediate CA 1..."

openssl genrsa \
  -out "$OUT_DIR/intermediate-ca-1.key" \
  4096

openssl req \
  -new \
  -sha256 \
  -key "$OUT_DIR/intermediate-ca-1.key" \
  -out "$OUT_DIR/intermediate-ca-1.csr" \
  -subj "/C=US/ST=California/L=San Francisco/O=Example Engineering/OU=Security Engineering/CN=Example Engineering Intermediate CA 1"

cat > "$OUT_DIR/intermediate-ca-1.ext" <<'EOF'
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 \
  -req \
  -sha256 \
  -days 1825 \
  -in "$OUT_DIR/intermediate-ca-1.csr" \
  -CA "$OUT_DIR/root-ca.crt" \
  -CAkey "$OUT_DIR/root-ca.key" \
  -CAcreateserial \
  -out "$OUT_DIR/intermediate-ca-1.crt" \
  -extfile "$OUT_DIR/intermediate-ca-1.ext"

# -----------------------------------------------------------------------------
# 3. Intermediate CA 2
# -----------------------------------------------------------------------------

echo "[3/7] Generating Intermediate CA 2..."

openssl genrsa \
  -out "$OUT_DIR/intermediate-ca-2.key" \
  4096

openssl req \
  -new \
  -sha256 \
  -key "$OUT_DIR/intermediate-ca-2.key" \
  -out "$OUT_DIR/intermediate-ca-2.csr" \
  -subj "/C=US/ST=California/L=San Francisco/O=Example Engineering/OU=Platform Security/CN=Example Engineering Intermediate CA 2"

cat > "$OUT_DIR/intermediate-ca-2.ext" <<'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 \
  -req \
  -sha256 \
  -days 1095 \
  -in "$OUT_DIR/intermediate-ca-2.csr" \
  -CA "$OUT_DIR/intermediate-ca-1.crt" \
  -CAkey "$OUT_DIR/intermediate-ca-1.key" \
  -CAcreateserial \
  -out "$OUT_DIR/intermediate-ca-2.crt" \
  -extfile "$OUT_DIR/intermediate-ca-2.ext"

# -----------------------------------------------------------------------------
# 4. Feature-rich leaf certificate
# -----------------------------------------------------------------------------

echo "[4/7] Generating feature-rich leaf certificate..."

# RSA 4096 gives your public_key_info() function something useful to display.
openssl genrsa \
  -out "$OUT_DIR/server.key" \
  4096

openssl req \
  -new \
  -sha256 \
  -key "$OUT_DIR/server.key" \
  -out "$OUT_DIR/server.csr" \
  -subj "/C=US/ST=California/L=San Francisco/O=Example Engineering/OU=Platform Engineering/CN=api.example.internal"

cat > "$OUT_DIR/server.ext" <<'EOF'
# ---------------------------------------------------------------------------
# Leaf certificate extensions
# ---------------------------------------------------------------------------

basicConstraints = critical, CA:FALSE

keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement

extendedKeyUsage = serverAuth, clientAuth

subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

subjectAltName = @alt_names

[alt_names]

# DNS SANs
DNS.1 = api.example.internal
DNS.2 = api.example.com
DNS.3 = api.prod.example.internal
DNS.4 = *.example.internal
DNS.5 = api.default.svc
DNS.6 = api.default.svc.cluster.local

# IPv4 SANs
IP.1 = 10.96.0.100
IP.2 = 192.168.50.20

# IPv6 SAN
IP.3 = 2001:db8:1234::100

# SPIFFE URI SAN
URI.1 = spiffe://example.internal/ns/default/sa/api

# Email SAN
email.1 = tls@example.internal
EOF

openssl x509 \
  -req \
  -sha256 \
  -days 825 \
  -in "$OUT_DIR/server.csr" \
  -CA "$OUT_DIR/intermediate-ca-2.crt" \
  -CAkey "$OUT_DIR/intermediate-ca-2.key" \
  -CAcreateserial \
  -out "$OUT_DIR/server.crt" \
  -extfile "$OUT_DIR/server.ext"

# -----------------------------------------------------------------------------
# 5. Build certificate bundles
# -----------------------------------------------------------------------------

echo "[5/7] Building certificate bundles..."

# Kubernetes TLS convention:
#
#   leaf
#   intermediate 2
#   intermediate 1
#
# Do NOT include the root here.

cat \
  "$OUT_DIR/server.crt" \
  "$OUT_DIR/intermediate-ca-2.crt" \
  "$OUT_DIR/intermediate-ca-1.crt" \
  > "$OUT_DIR/tls.crt"

# Same bundle with a descriptive filename.
cp \
  "$OUT_DIR/tls.crt" \
  "$OUT_DIR/server-chain.crt"

# Full chain containing all four certificates.
#
# This is useful if your CLI has a mode that inspects arbitrary PEM bundles.

cat \
  "$OUT_DIR/server.crt" \
  "$OUT_DIR/intermediate-ca-2.crt" \
  "$OUT_DIR/intermediate-ca-1.crt" \
  "$OUT_DIR/root-ca.crt" \
  > "$OUT_DIR/full-chain.crt"

# Copy the leaf private key to the Kubernetes-standard name.
cp \
  "$OUT_DIR/server.key" \
  "$OUT_DIR/tls.key"

# -----------------------------------------------------------------------------
# 6. Verify certificates and private key
# -----------------------------------------------------------------------------

echo "[6/7] Verifying certificate chain..."

echo
echo "Root CA:"
openssl x509 \
  -in "$OUT_DIR/root-ca.crt" \
  -noout \
  -subject \
  -issuer

echo
echo "Intermediate CA 1:"
openssl x509 \
  -in "$OUT_DIR/intermediate-ca-1.crt" \
  -noout \
  -subject \
  -issuer

echo
echo "Intermediate CA 2:"
openssl x509 \
  -in "$OUT_DIR/intermediate-ca-2.crt" \
  -noout \
  -subject \
  -issuer

echo
echo "Leaf:"
openssl x509 \
  -in "$OUT_DIR/server.crt" \
  -noout \
  -subject \
  -issuer

echo
echo "Chain verification:"

openssl verify \
  -CAfile "$OUT_DIR/root-ca.crt" \
  -untrusted <(
    cat \
      "$OUT_DIR/intermediate-ca-1.crt" \
      "$OUT_DIR/intermediate-ca-2.crt"
  ) \
  "$OUT_DIR/server.crt"

echo
echo "Checking leaf certificate/private-key match..."

CERT_PUBLIC_KEY_HASH="$(
  openssl x509 \
    -in "$OUT_DIR/server.crt" \
    -pubkey \
    -noout |
  openssl pkey \
    -pubin \
    -outform DER |
  openssl sha256
)"

KEY_PUBLIC_KEY_HASH="$(
  openssl pkey \
    -in "$OUT_DIR/server.key" \
    -pubout \
    -outform DER |
  openssl sha256
)"

echo "Certificate public key SHA256: $CERT_PUBLIC_KEY_HASH"
echo "Private key public key SHA256: $KEY_PUBLIC_KEY_HASH"

if [[ "$CERT_PUBLIC_KEY_HASH" == "$KEY_PUBLIC_KEY_HASH" ]]; then
  echo "✓ tls.key matches leaf certificate"
else
  echo "✗ tls.key does NOT match leaf certificate"
  exit 1
fi

# -----------------------------------------------------------------------------
# 7. Create Kubernetes TLS Secret
# -----------------------------------------------------------------------------

echo
echo "[7/7] Creating Kubernetes TLS Secret..."

kubectl create secret tls "$SECRET_NAME" \
  --namespace "$NAMESPACE" \
  --cert="$OUT_DIR/tls.crt" \
  --key="$OUT_DIR/tls.key" \
  --dry-run=client \
  -o yaml \
  > "$OUT_DIR/mock-server-tls.yaml"

kubectl apply \
  -f "$OUT_DIR/mock-server-tls.yaml"

# -----------------------------------------------------------------------------
# Display certificate details
# -----------------------------------------------------------------------------

echo
echo "============================================================"
echo "Leaf certificate details"
echo "============================================================"

openssl x509 \
  -in "$OUT_DIR/server.crt" \
  -noout \
  -subject \
  -issuer \
  -serial \
  -version \
  -dates \
  -fingerprint \
  -sha256

echo
echo "============================================================"
echo "Subject Alternative Names"
echo "============================================================"

openssl x509 \
  -in "$OUT_DIR/server.crt" \
  -noout \
  -ext subjectAltName

echo
echo "============================================================"
echo "Basic Constraints"
echo "============================================================"

openssl x509 \
  -in "$OUT_DIR/server.crt" \
  -noout \
  -ext basicConstraints

echo
echo "============================================================"
echo "Key Usage"
echo "============================================================"

openssl x509 \
  -in "$OUT_DIR/server.crt" \
  -noout \
  -ext keyUsage

echo
echo "============================================================"
echo "Extended Key Usage"
echo "============================================================"

openssl x509 \
  -in "$OUT_DIR/server.crt" \
  -noout \
  -ext extendedKeyUsage

echo
echo "============================================================"
echo "Kubernetes Secret"
echo "============================================================"

kubectl get secret \
  "$SECRET_NAME" \
  --namespace "$NAMESPACE"

echo
echo "============================================================"
echo "Generated Files"
echo "============================================================"

find "$OUT_DIR" \
  -maxdepth 1 \
  -type f \
  -printf '%f\n' |
  sort

echo
echo "============================================================"
echo "Summary"
echo "============================================================"

echo
echo "Certificate hierarchy:"
echo
echo "  Root CA"
echo "    └── Intermediate CA 1"
echo "          └── Intermediate CA 2"
echo "                └── api.example.internal"
echo

echo "Kubernetes Secret:"
echo "  $NAMESPACE/$SECRET_NAME"
echo "  type: kubernetes.io/tls"
echo

echo "tls.crt:"
echo "  1. Leaf"
echo "  2. Intermediate CA 2"
echo "  3. Intermediate CA 1"
echo

echo "tls.key:"
echo "  Leaf private key"
echo

echo "Additional test bundle:"
echo "  $OUT_DIR/full-chain.crt"
echo "  (Leaf + Intermediate 2 + Intermediate 1 + Root)"
echo

echo "Done."

