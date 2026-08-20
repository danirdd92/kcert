"""Parsing PEM bundles and reading fiels off x509 certificates."""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from .errors import KCertError


def split_pem_certificates(pem_bundle: bytes) -> list[bytes]:
    marker = b"-----BEGIN CERTIFICATE-----"
    parts = pem_bundle.split(marker)
    certs = [marker + part for part in parts[1:] if part.strip()]

    if not certs:
        raise KCertError("No PEM certificated found in tls.crt")
    return certs


def load_bundle(pem_bundle: bytes) -> list[x509.Certificate]:
    """Parse a PEM bundle, the first certificate is the leaf, the rest are the Intermediate and root certificates."""
    return [
        x509.load_pem_x509_certificate(block)
        for block in split_pem_certificates(pem_bundle)
    ]


def name_to_str(name: x509.Name) -> str:
    return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)


def name_short(name: x509.Name) -> str:
    cn = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cn:
        return str(cn[0].value)

    org = name.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if org:
        return str(org[0].value)

    return name_to_str(name)


def days_remianing(not_after: datetime) -> int:
    now = datetime.now(timezone.utc)
    return (not_after - now).days


def public_key_info(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size} bits"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name} bits"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(key).__name__


def fingerprint(cert: x509.Certificate, algo: hashes.HashAlgorithm) -> str:
    digest = cert.fingerprint(algo)
    return ":".join(f"{b:02X}" for b in digest)


def get_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []

    entries: list[str] = []
    for name in ext.value:
        if isinstance(name, x509.DNSName):
            entries.append(f"DNS:{name.value}")
        elif isinstance(name, x509.IPAddress):
            entries.append(f"IP:{name.value}")
        elif isinstance(name, x509.RFC822Name):
            entries.append(f"email:{name.value}")
        elif isinstance(name, x509.UniformResourceIdentifier):
            entries.append(f"URI:{name.value}")
    return entries

def get_basic_constraints(cert: x509.Certificate) -> str:
  try:
     ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
  except x509.ExtensionNotFound:
    return "not present"
  if ext.value.ca:
    path_len = ext.value.path_length
    return f"CA:TRUE (path length: {path_len if path_len is not None else 'none'})"
  return "CA:FALSE"

def get_key_usage(cert: x509.Certificate) -> list[str]:
    try:
      key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
      return []

    flags = [
      "digital_signature",
      "content_commitment",
      "key_encipherment",
      "data_encipherment",
      "key_agreement",
      "key_cert_sign",
      "crl_sign"
    ]
    
    return [flag for flag in flags if getattr(key_usage.value, flag, False)]

def get_extended_key_usage(cert: x509.Certificate) -> list[str]:
  try:
    extended_key_usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
  except x509.ExtensionNotFound:
    return []
  return [oid._name for oid in extended_key_usage.value]

def private_key_matches(cert: x509.Certificate, key_pem: bytes) -> bool | None:
  """Determine if the key can be compared, None if it cannot"""
  try:
    private_key = load_pem_private_key(key_pem, password=None)
  except Exception:
    return None

  cert_public_key = cert.public_key()
  
  if isinstance(private_key, rsa.RSAPrivateKey) and isinstance(cert_public_key, rsa.RSAPublicKey) or \
     isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(cert_public_key, ec.EllipticCurvePublicKey):
    return private_key.public_key().public_numbers() == cert_public_key.public_numbers()

  if isinstance(private_key, ed25519.Ed25519PrivateKey) and isinstance(cert_public_key, ed25519.Ed25519PublicKey):
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == cert_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

  return None  