# SSL/TLS Certificate Expiry Monitor

A tool that connects to a list of hosts, retrieves their live TLS certificates, and flags anything expired or expiring soon — the kind of outage (a site going down, or machine-to-machine auth breaking) that's completely preventable but still happens constantly because nobody's watching expiry dates until it's too late.

## What This Project Does

- **Real TLS handshakes** against every host:port in a watch list — not a WHOIS or DNS-based guess, the actual certificate the server presents right now
- **Three-tier severity**: OK, WARNING (expiring soon), CRITICAL (expiring imminently or already expired) — configurable thresholds
- **Reports unreachable hosts as findings, not silent skips** — a certificate you can't check is itself a risk worth surfacing (firewall change, service down, DNS issue)
- **`--insecure` mode for internal services** — checks self-signed or private-CA certificates' real expiry dates without needing them in your trust store, while still properly rejecting untrusted certs by default for anything you expect public CA trust on
- JSON report + CI-friendly exit code (non-zero on critical findings or unreachable hosts)

## Example Output

```
Checked 4 target(s).

  [CRITICAL] internal-api.corp:8443 — EXPIRING IMMINENTLY
             CN: internal-api.corp  |  Issuer: Corp Internal CA
             Expires: 2026-10-14T19:35:16+00:00  (3.0 days remaining)

  [OK      ] api.example.com:443 — OK
             CN: api.example.com  |  Issuer: Let's Encrypt
             Expires: 2027-10-11T19:35:16+00:00  (365.0 days remaining)

  [ERROR   ] staging.example.com:9999 — could not retrieve certificate: Connection refused

  [WARNING ] github.com:443 — EXPIRING SOON
             CN: github.com  |  Issuer: Egress Gateway SDS Issuing CA (production)
             Expires: 2026-11-08T01:26:57+00:00  (27.2 days remaining)

Summary — critical: 1, warning: 1, ok: 1, unreachable: 1
```

(That GitHub result is real output from actually checking github.com — not a mock.)

## Tech Stack

- Python 3.11
- `cryptography` — parses the certificate's real validity dates from the raw DER bytes exchanged during the TLS handshake (standard library `ssl.getpeercert()` only decodes fields for *validated* certs, which breaks `--insecure` mode for self-signed/internal certs)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Copy the example target list and edit it for your own hosts:

```bash
cp domains.example.txt domains.txt
# edit domains.txt - one host or host:port per line, '#' for comments
python3 monitor.py domains.txt
```

Options:

```bash
python3 monitor.py domains.txt --warn-days 45 --critical-days 14   # tune thresholds
python3 monitor.py domains.txt --json report.json                   # write a full JSON report
python3 monitor.py domains.txt --insecure                            # check self-signed/internal certs too
```

### Testing it without relying on real domains

Real-world certs change expiry dates over time, so for a deterministic test, generate two self-signed certs with controlled validity periods and serve them locally:

```bash
openssl req -x509 -newkey rsa:2048 -keyout critical_key.pem -out critical_cert.pem -days 3 -nodes -subj "/CN=localhost"
openssl req -x509 -newkey rsa:2048 -keyout ok_key.pem -out ok_cert.pem -days 365 -nodes -subj "/CN=localhost"
```

Serve each on its own port (any simple Python `ssl`-wrapped socket server works), point the monitor at both plus a closed port, and it should report one CRITICAL, one OK, and one unreachable-error — exactly the three non-happy-path branches the classifier has to get right.

## Tuning

- `--warn-days` / `--critical-days` — how many days remaining counts as each severity (defaults: 30 / 7)
- `--timeout` — how long to wait for the TLS handshake before treating a host as unreachable

## Architecture

```
domains.txt (host or host:port per line)
        |
        v
Real TLS handshake per target (socket + ssl, or --insecure context for self-signed)
        |
        v
Parse raw DER certificate (cryptography) -> notBefore / notAfter / CN / issuer
        |
        v
days_remaining = notAfter - now
        |
        v
Classify: OK / WARNING / CRITICAL (or EXPIRED if days_remaining < 0)
        |
        v
Console report + JSON report, CI-friendly exit code
```

## Project Structure

```
ssl-cert-expiry-monitor/
├── monitor.py              # Main CLI: TLS handshake, cert parsing, classification, reporting
├── domains.example.txt     # Sample target list format
├── requirements.txt
└── README.md
```

## What I Learned

- Python's built-in `ssl.getpeercert()` only decodes the certificate into a usable dict when the chain validates — which means it silently can't help you read the expiry of a self-signed or private-CA cert, exactly the certs internal infrastructure monitoring most needs to check. Pulling the raw DER bytes and parsing them with `cryptography` instead decouples "can I read this cert's dates" from "do I trust this cert's chain."
- Why an unreachable host needs to be its own reported category, not a silent skip — a certificate monitor that goes quiet on a host it can't reach is indistinguishable from one that checked it and found no problem, which is the opposite of what you want from a monitoring tool
- Keeping chain/hostname validation on by default and making `--insecure` an explicit opt-in, so the common path (public-facing services) still gets proper security, and the internal-services path is a conscious choice rather than an accidental weakening
- Building a deterministic test harness (self-signed certs with controlled validity periods served locally) instead of depending on the current state of some real domain's certificate, which changes over time and would make the test flaky

## Next Steps

- Email/Slack/webhook alerting when a check crosses into WARNING or CRITICAL, instead of requiring someone to read the console output
- Scheduled runs (cron / systemd timer) with state tracking, so it only alerts on a *change* in status rather than every run
- Certificate chain validation details (intermediate expiry, not just the leaf cert — a surprisingly common real-world outage cause)
- HTML dashboard report, consistent with the other projects in this portfolio
