from __future__ import annotations

import json, shutil, subprocess
from dataclasses import dataclass

from .errors import KCertError

TLS_SECRET_TYPE = "kubernetes.io/tls"

@dataclass
class Target:
  namespace: str
  secret_name: str

def parse_target(raw: str) -> Target:
  if "/" not in raw:
    raise KCertError(f"Expected '<namespace>/<secret-name>', got: {raw}")

  namespace, _, secret_name = raw.partition("/")
  if not namespace or not secret_name:
    raise KCertError(f"Expected '<namespace>/<secret-name>', got: {raw}")

  return Target(namespace=namespace, secret_name=secret_name)

def fetch_secret(target: Target, kube_context: str | None) -> dict:
  if shutil.which("kubectl") is None:
    raise KCertError("kubectl is not in PATH or installed!")
  cmd = ["kubectl", "get", "secret", target.secret_name, "--namespace", target.namespace]

  if kube_context:
    cmd += ["--context", kube_context]

  cmd += ["--output", "json"]

  res =  subprocess.run(cmd, capture_output=True, text=True)
  if res.returncode != 0:
    raise KCertError(res.stderr.strip() or "kubectl command failed")
    
  try:
    return json.loads(res.stdout)
  except json.JSONDecodeError as e:
    raise KCertError(f"Failed to parse kubectl output: {e}")

def validate_tls_secret(secret: dict, target: Target) -> None:
  secret_type = secret.get("type")
  if secret_type != TLS_SECRET_TYPE:
    raise KCertError(f"Expected secret type {TLS_SECRET_TYPE}, got: {secret_type}")

  data = secret.get("data", {})
  missing  = [k for k in ("tls.crt", "tls.key") if k not in data]

  if missing:
    raise KCertError(f"Secret is missing required key(s): {', '.join(missing)}")
