# NetScanTools PRO — AeRoLogic Modular Suite (AeroRoute)

A PyQt6 desktop network-diagnostics toolkit: ping monitoring with live latency
graphs, system network activity, bandwidth speed tests, DNS intelligence, SSL
certificate scanning, WHOIS lookups, and packet payload decoding.

## Modules

| Tab | What it does |
|---|---|
| Discovery & Ping Monitor | ICMP/TCP ping table with avg/jitter/loss, sparkline graphs, traceroute, JSON import/export |
| System Network Activity | Per-interface I/O counters and active connections via psutil |
| Bandwidth Speed Test | Download/upload/ping via speedtest-cli |
| Packet Analysis & Decrypter | Base64 / hex / single-byte-XOR decoders, TCP/UDP test-payload sender |
| Packet Capture (Simulated) | **Demo only** — randomly generated rows for UI testing, not live traffic |
| DNS & Internet Intelligence | A / AAAA / CNAME / MX / TXT / NS / SOA lookups (dnspython) |
| SSL & Security | TLS certificate details for a host on port 443 |
| WHOIS & Utilities | Per-TLD WHOIS server discovery via IANA, with registrar-referral follow |

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

## Notes & limitations

- The packet-capture tab is explicitly simulated; real capture would need
  libpcap/scapy and elevated privileges.
- The ICMP option in the packet generator is simulated for the same reason
  (raw sockets need admin/root). TCP/UDP sends are real.
- DNS/WHOIS/SSL lookups run in the GUI thread — the UI may briefly pause on
  slow networks.
- Use responsibly and in compliance with local laws.

© 2026 AeRoLogic. All rights reserved.
