from __future__ import annotations

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .certificate import (
  days_remianing,
  fingerprint,
  get_basic_constraints,
  get_extended_key_usage,
  get_key_usage,
  get_sans,
  name_short,
  name_to_str,
  public_key_info
)

from .kube import Target

console = Console()
err_console = Console(stderr=True)

def expiry_status(not_after: datetime) -> Text:
  days = days_remianing(not_after)
  day_notation = "day" if abs(days) == 1 else "days"

  if days < 0:
    return Text(f"EXPIRED {abs(days)} {day_notation} ago", style="bold white on red")
  if days <= 7:
    return Text(f"{days} {day_notation} remaining", style="bold red")
  if days <= 30:
    return Text(f"{days} {day_notation} remaining", style="bold yellow")

  return Text(f"{days} {day_notation} remaining", style="bold green")

def build_leaf_table(cert: x509.Certificate) -> Table:
  table = Table(show_header=False, box=None, padding=(0, 1))
  table.add_column(style="bold cyan", no_wrap=True)
  table.add_column()

  table.add_row("Subject", Text(name_to_str(cert.subject)))
  table.add_row("Issuer", Text(name_to_str(cert.issuer)))
  table.add_row("Self-signed", "yes" if cert.subject == cert.issuer else "no")
  table.add_row("Serial Number", format(cert.serial_number, "X"))
  table.add_row("Version", str(cert.version.name))
  table.add_row("Signature Algorithm", cert.signature_algorithm_oid._name)
  table.add_row("Public Key", public_key_info(cert))

  table.add_row("Not Before", cert.not_valid_before_utc.isoformat())
  table.add_row("Not After", cert.not_valid_after_utc.isoformat())
  table.add_row("Status", expiry_status(cert.not_valid_after_utc))

  sans = get_sans(cert)
  table.add_row("Subject Alt Names", Text("\n".join(sans)) if sans else "-")

  table.add_row("Basic Constraints", get_basic_constraints(cert))

  key_usage = get_key_usage(cert)
  table.add_row("Key Usage", Text("\n".join(key_usage)) if key_usage else "-")

  extended_key_usage = get_extended_key_usage(cert)
  table.add_row("Extended Key Usage", Text("\n".join(extended_key_usage)) if extended_key_usage else "-")

  table.add_row("SHA256 Fingerprint", Text(fingerprint(cert, hashes.SHA256())))
  table.add_row("SHA1 Fingerprint", Text(fingerprint(cert, hashes.SHA1())))

  return table

def build_chain_table(chain_certs: list[x509.Certificate]) -> Table:
  table = Table(title="Chain / Additional Certificates", show_lines=True)
  table.add_column("#", justify="right")
  table.add_column("Subject")
  table.add_column("Issuer")
  table.add_column("Not After")
  table.add_column("Status")

  for i, cert in enumerate(chain_certs, start=1):
    table.add_row(
      str(i),
      Text(name_short(cert.subject)),
      Text(name_short(cert.issuer)),
      cert.not_valid_after_utc.isoformat(),
      expiry_status(cert.not_valid_after_utc),
    )
  return table

def render_report(target: Target, certs: list[x509.Certificate], key_match: bool) -> None:
  leaf, chain = certs[0], certs[1:]
  header = Text()
  header.append(f"{target.namespace}/{target.secret_name}", style="bold")
  header.append(f"  ({len(certs)} certificate(s) in bundle)", style="dim")
  
  console.print(Panel(header, title="TLS Secret", expand=False))
  console.print(Panel(build_leaf_table(leaf), title="Leaf Certificate", expand=False))

  if chain:
    console.print(build_chain_table(chain))

    if key_match is True:
      console.print("[bold green][✓][/bold green] tls.key matches the leaf certificate's public key")
    elif key_match is False:
      console.print("[bold red][✗][/bold red] tls.key does NOT match the leaf certificate's public key")
    else:
      console.print("[dim]- could not verify tls.key against certificate chain (unsupported key type)[/dim]")

def print_error(message: str) -> None:
  err_console.print(f"[bold red][✗] Error:[/bold red] {message}")