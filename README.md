# NetScanTools PRO — AeRoLogic Modular Suite (AeroRoute)

A PyQt6 desktop network-diagnostics toolkit: ping monitoring with live latency
graphs, system network activity, bandwidth speed tests, DNS intelligence, SSL
certificate scanning, WHOIS lookups, and packet payload decoding.

## Modules

| Tab | What it does | Real / limited |
|---|---|---|
| Discovery & Ping Monitor | ICMP/TCP ping table with avg/jitter/loss, sparkline graphs, traceroute, JSON import/export | Real |
| System Network Activity | Per-interface I/O counters and active connections via psutil | Real |
| Bandwidth Speed Test | Download/upload/ping via speedtest-cli | Real |
| Packet Analysis & Decrypter | Base64 / hex / single-byte-XOR decoders, TCP/UDP test-payload sender | Real (TCP/UDP send); ICMP send is simulated — raw sockets need admin/root |
| Packet Capture (Simulated) | **Demo only** — randomly generated rows for UI testing | Simulated, not live traffic |
| DNS & Internet Intelligence | A / AAAA / CNAME / MX / TXT / NS / SOA lookups (dnspython), run on a worker thread | Real |
| SSL & Security | TLS certificate details for a host on port 443, run on a worker thread | Real |
| WHOIS & Utilities | Per-TLD WHOIS server discovery via IANA with one registrar-referral follow, run on a worker thread | Real, but limited: IP queries return the IANA/RIR referral only; full RIR referral chasing is not implemented |

## Architecture

Network operations follow a UI → Worker → Service → Network → Signal → UI
pattern. The `modules/` package holds Qt-free service modules
(`target_validation`, `packet_codecs`, `dns_service`, `whois_service`,
`ssl_service`, `ping_stats`, `target_io`, `observation`, `observation_query`) that contain the real logic and are
unit-tested without PyQt6. Thin Qt widgets call them from `QThread` workers
and receive results through signals — workers never touch widgets directly.

All user-supplied targets go through `modules/target_validation.py`
(classify IPv4 / IPv6 / hostname, normalize URLs, reject shell metacharacters).

Ping metrics: failed probes affect packet-loss only — they never invent
latency samples (no placeholder values). Jitter here is the simple
consecutive-sample delta |latest − previous|, not RFC 3550 interarrival
jitter. Each target has at most one probe in flight at a time.

Network operations use bounded timeouts where the underlying API supports
explicit timeout control (DNS 5 s, WHOIS 10 s, SSL 5 s, ping 2–3 s,
packet send 3 s, geolocation 3 s). OS resolver calls such as reverse DNS
do not expose an application-level timeout and are isolated from the GUI
thread.

## Install & run

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Or use the launchers: `run.sh` (Linux/macOS) / `run.bat` (Windows) — they create
the venv and install dependencies for you.

## Requirements

Python ≥ 3.10. Dependencies are pinned in `requirements.txt`:
PyQt6, pyqtgraph, psutil, netifaces, speedtest-cli, dnspython.

If `netifaces` fails to build (unmaintained since 2021), swap it for the
drop-in fork `netifaces2` — no code changes needed.

## Testing

```bash
pip install -r requirements-dev.txt   # pytest
python -m pytest                      # 83 tests, no network access required
```

The suite exercises the real service functions (validation, codecs, DNS,
WHOIS, ping statistics/scheduling, import/export) with mocked network
boundaries. GUI widgets are not automated.

## Notes & limitations

- The packet-capture tab is explicitly simulated; real capture would need
  libpcap/scapy and elevated privileges.
- The ICMP option in the packet generator is simulated for the same reason
  (raw sockets need admin/root). TCP/UDP sends are real.
- WHOIS for IP addresses returns the IANA referral, not the full RIR record.
- `speedtest-cli` uses its own internal timeouts.
- Reverse DNS runs on worker threads (never the GUI thread) and is cached
  per target, since the OS resolver offers no application-level timeout.
- Use responsibly and in compliance with local laws.

© 2026 AeRoLogic. All rights reserved.
