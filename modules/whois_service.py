"""WHOIS lookup service. Qt-free so it can be unit tested.

Behavior (deliberately limited, see README):
  - domains: the authoritative WHOIS server is discovered per-TLD via IANA;
    .com/.net go straight to whois.verisign-grs.com; one registrar referral
    ("Registrar WHOIS Server:") is followed
  - IP addresses: queried against whois.iana.org, which returns the
    responsible RIR referral — full RIR referral chasing is NOT implemented

The GUI layer (modules/whois_utils.py) calls perform_whois() from a worker
thread; results come back through Qt signals.
"""
import re
import socket
from urllib.parse import urlparse

from .target_validation import classify_target

IANA_SERVER = "whois.iana.org"
VERISIGN_SERVER = "whois.verisign-grs.com"  # authoritative for .com / .net
WHOIS_TIMEOUT = 10  # seconds: every network operation is bounded


def whois_query(server, query, timeout=WHOIS_TIMEOUT, _socket_factory=socket.socket):
    """Raw WHOIS query over TCP/43. The socket is always closed.

    `_socket_factory` is injectable for tests.
    """
    s = _socket_factory(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, 43))
        s.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="ignore")
    finally:
        s.close()


def tld_whois_server(tld, query_fn=None):
    """Ask IANA which WHOIS server is authoritative for a TLD."""
    query = query_fn or whois_query
    try:
        resp = query(IANA_SERVER, tld)
        m = re.search(r"(?im)^whois:\s*(\S+)", resp)
        return m.group(1) if m else None
    except Exception:
        return None


def clean_whois_query(raw):
    """Sanitize user input. Returns None for anything unsafe/empty."""
    q = (raw or "").strip()
    if "://" in q:
        q = urlparse(q).hostname or q
    q = q.strip().lower().rstrip(".")
    if not q or any(c in q for c in " \t\r\n;|&$`'\"\\"):
        return None
    # Must still be a plausible domain or IP literal.
    if classify_target(q) is None:
        return None
    return q


def perform_whois(raw_query, query_fn=None, tld_server_fn=None):
    """Run the lookup. Returns a human-readable string.

    `query_fn` / `tld_server_fn` are injectable for tests.
    Raises ValueError for invalid input.
    """
    query = clean_whois_query(raw_query)
    if not query:
        raise ValueError(f"invalid WHOIS query: {raw_query!r}")
    qfn = query_fn or whois_query
    tfn = tld_server_fn or tld_whois_server

    kind = classify_target(query)
    if kind in ("ipv4", "ipv6"):
        # IANA answers with the responsible RIR referral.
        return qfn(IANA_SERVER, query)

    tld = query.rsplit(".", 1)[-1]
    server = VERISIGN_SERVER if tld in ("com", "net") else (tfn(tld) or IANA_SERVER)
    text = f"[via {server}]\n" + qfn(server, query)

    # Follow one registrar referral (typical for .com/.net thin registries).
    m = re.search(r"(?im)^Registrar WHOIS Server:\s*(\S+)", text)
    if m and m.group(1).lower() != server.lower():
        ref = m.group(1)
        try:
            text += f"\n\n--- Referral: {ref} ---\n" + qfn(ref, query)
        except Exception as e:
            text += f"\n[referral query to {ref} failed: {e}]"
    return text
