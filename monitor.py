"""
SSL/TLS Certificate Expiry Monitor

Connects to each host:port in a watch list, retrieves its live TLS
certificate, and flags any certificate that's already expired or expiring
soon - the kind of outage that takes down a site or breaks machine-to-
machine auth with zero warning if nobody's watching expiry dates.

Usage:
    python3 monitor.py domains.txt
    python3 monitor.py domains.txt --warn-days 30 --json report.json
"""

import ssl
import socket
import sys
import json
import argparse
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ---------- Config ----------
DEFAULT_WARN_DAYS = 30     # flag as WARNING if fewer days than this remain
DEFAULT_CRITICAL_DAYS = 7  # flag as CRITICAL if fewer days than this remain
CONNECT_TIMEOUT = 10        # seconds


def parse_target(line):
    """Parses a 'host' or 'host:port' line from the watch list (default
    port 443 if omitted). Blank lines and '#' comments are skipped by
    the caller before this is reached."""
    line = line.strip()
    if ":" in line:
        host, port = line.rsplit(":", 1)
        return host, int(port)
    return line, 443


def get_certificate_info(host, port, timeout=CONNECT_TIMEOUT, insecure=False):
    """Opens a real TLS connection to host:port and reads the live
    certificate's expiry. Returns a dict with the result, or an 'error'
    key if the host couldn't be reached or the handshake failed (which
    is itself worth reporting - a cert you can't check is a risk too).

    insecure=True skips hostname/CA-chain verification (but still reads
    the real certificate's dates) - for checking internal services with
    self-signed or private-CA certs, where failing the handshake would
    otherwise make expiry monitoring impossible. Never use this for a
    public-facing host you actually rely on chain validation for."""
    if insecure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}

    if not der_cert:
        return {"host": host, "port": port, "error": "No certificate returned by peer"}

    cert = x509.load_der_x509_certificate(der_cert, default_backend())

    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc

    now = datetime.now(timezone.utc)
    days_remaining = (not_after - now).total_seconds() / 86400

    def _attr(name_oid):
        values = cert.subject.get_attributes_for_oid(name_oid)
        return values[0].value if values else "?"

    def _issuer_attr(name_oid):
        values = cert.issuer.get_attributes_for_oid(name_oid)
        return values[0].value if values else None

    common_name = _attr(x509.oid.NameOID.COMMON_NAME)
    issuer_cn = _issuer_attr(x509.oid.NameOID.COMMON_NAME) or _issuer_attr(x509.oid.NameOID.ORGANIZATION_NAME) or "?"

    return {
        "host": host,
        "port": port,
        "common_name": common_name,
        "issuer": issuer_cn,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": round(days_remaining, 1),
        "checked_at": now.isoformat(),
    }


def classify(result, warn_days, critical_days):
    """Assigns a severity to a successfully-checked certificate based on
    how many days remain. Expired certs are always critical regardless
    of how negative the day count is."""
    days = result["days_remaining"]
    if days < 0:
        return "critical", "EXPIRED"
    if days < critical_days:
        return "critical", "EXPIRING IMMINENTLY"
    if days < warn_days:
        return "warning", "EXPIRING SOON"
    return "ok", "OK"


def load_targets(path):
    targets = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(parse_target(line))
    return targets


def print_report(results, warn_days, critical_days):
    print(f"\nChecked {len(results)} target(s).\n")

    for r in results:
        label = f"{r['host']}:{r['port']}"
        if "error" in r:
            print(f"  [ERROR   ] {label} — could not retrieve certificate: {r['error']}")
            continue

        severity, status = classify(r, warn_days, critical_days)
        severity_label = {"critical": "CRITICAL", "warning": "WARNING ", "ok": "OK      "}[severity]
        print(f"  [{severity_label}] {label} — {status}")
        print(f"             CN: {r['common_name']}  |  Issuer: {r['issuer']}")
        print(f"             Expires: {r['not_after']}  ({r['days_remaining']} days remaining)\n")

    checked = [r for r in results if "error" not in r]
    errored = [r for r in results if "error" in r]
    critical = sum(1 for r in checked if classify(r, warn_days, critical_days)[0] == "critical")
    warning = sum(1 for r in checked if classify(r, warn_days, critical_days)[0] == "warning")
    ok = sum(1 for r in checked if classify(r, warn_days, critical_days)[0] == "ok")
    print(f"Summary — critical: {critical}, warning: {warning}, ok: {ok}, unreachable: {len(errored)}")


def main():
    parser = argparse.ArgumentParser(description="Check TLS certificate expiry for a list of hosts.")
    parser.add_argument("targets_file", help="File with one 'host' or 'host:port' per line")
    parser.add_argument("--warn-days", type=int, default=DEFAULT_WARN_DAYS,
                         help=f"Warn if fewer than this many days remain (default {DEFAULT_WARN_DAYS})")
    parser.add_argument("--critical-days", type=int, default=DEFAULT_CRITICAL_DAYS,
                         help=f"Critical if fewer than this many days remain (default {DEFAULT_CRITICAL_DAYS})")
    parser.add_argument("--json", help="Write a JSON report to this path")
    parser.add_argument("--timeout", type=int, default=CONNECT_TIMEOUT, help="Connection timeout in seconds")
    parser.add_argument("--insecure", action="store_true",
                         help="Skip hostname/CA-chain verification (for internal/self-signed certs). "
                              "Still reports the real expiry date - only use for hosts you don't need chain trust on.")
    args = parser.parse_args()

    try:
        targets = load_targets(args.targets_file)
    except FileNotFoundError:
        print(f"Targets file not found: {args.targets_file}")
        sys.exit(1)

    if not targets:
        print("No targets to check.")
        sys.exit(0)

    results = [get_certificate_info(host, port, args.timeout, args.insecure) for host, port in targets]
    print_report(results, args.warn_days, args.critical_days)

    if args.json:
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "warn_days": args.warn_days,
            "critical_days": args.critical_days,
            "results": results,
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.json}")

    checked = [r for r in results if "error" not in r]
    has_critical = any(classify(r, args.warn_days, args.critical_days)[0] == "critical" for r in checked)
    has_errors = any("error" in r for r in results)
    if has_critical or has_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
