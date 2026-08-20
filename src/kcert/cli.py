from __future__ import annotations

import argparse,base64, sys

from .certificate import load_bundle, private_key_matches
from .errors import KCertError
from .kube import fetch_secret, parse_target, validate_tls_secret
from .render import print_error, render_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kcert",
        description="Fetch a Kubernetes TLS secret and print certificate details",
    )
    parser.add_argument(
        "target", help="Secret to inspect, in the form <namespace>/<secret>"
    )
    parser.add_argument(
        "--context",
        dest="kube_context",
        default=None,
        help="kubectl context to use, defaults to current context",
    )

    return parser


def inspect(target: Target, kube_context: str | None) -> None:
    secret = fetch_secret(target, kube_context)
    validate_tls_secret(secret, target)

    data = secret["data"]
    cert_pem = base64.b64decode(data["tls.crt"])
    key_pem = base64.b64decode(data["tls.key"])

    certs = load_bundle(cert_pem)
    key_match = private_key_matches(certs[0], key_pem)

    render_report(target, certs, key_match)


def main() -> int:
    args = build_parser().parse_args()

    try:
        inspect(parse_target(args.target), args.kube_context)
    except KCertError as e:
        print_error(str(e))
        return 1
    except KeyboardInterrupt:
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
