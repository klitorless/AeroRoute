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

from .observation import EvidenceKind, Observation
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


def perform_whois(raw_query, query_fn=None, tld_server_fn=None, *, sink=None):
    """Run the lookup. Returns a human-readable string.

    `query_fn` / `tld_server_fn` are injectable for tests.
    Raises ValueError for invalid input.

    `sink`, when given, is an optional callable accepting one Observation
    (e.g. a caller-owned ``ObservationLog.record``). One Observation
    (``kind="whois.lookup"``, ``evidence=OBSERVED``) is emitted per
    completed lookup, built from the structured pre-render results — the
    normalized query, the servers contacted in order, the referral
    outcome, and each server's raw response text. The display string is
    never parsed to build the observation. The service never stores
    observations; callers without a sink see byte-identical behavior.
    """
    query = clean_whois_query(raw_query)
    if not query:
        raise ValueError(f"invalid WHOIS query: {raw_query!r}")
    qfn = query_fn or whois_query
    tfn = tld_server_fn or tld_whois_server

    kind = classify_target(query)
    # Structured pre-render results, in contact order. The human-readable
    # string below is assembled from these; the observation is built from
    # these, never from the rendered string.
    responses = []  # [(server, raw_text)]
    referral = None

    if kind in ("ipv4", "ipv6"):
        # IANA answers with the responsible RIR referral.
        raw = qfn(IANA_SERVER, query)
        responses.append((IANA_SERVER, raw))
        text = raw
    else:
        tld = query.rsplit(".", 1)[-1]
        server = VERISIGN_SERVER if tld in ("com", "net") else (tfn(tld) or IANA_SERVER)
        raw = qfn(server, query)
        responses.append((server, raw))
        text = f"[via {server}]\n" + raw

        # Follow one registrar referral (typical for .com/.net thin registries).
        m = re.search(r"(?im)^Registrar WHOIS Server:\s*(\S+)", text)
        if m and m.group(1).lower() != server.lower():
            ref = m.group(1)
            try:
                ref_raw = qfn(ref, query)
                responses.append((ref, ref_raw))
                text += f"\n\n--- Referral: {ref} ---\n" + ref_raw
                referral = {"server": ref, "followed": True}
            except Exception as e:
                text += f"\n[referral query to {ref} failed: {e}]"
                referral = {"server": ref, "followed": False,
                            "error": f"{type(e).__name__}: {e}"}

    if sink is not None:
        sink(Observation(
            kind="whois.lookup",
            source="whois",
            target=query,
            evidence=EvidenceKind.OBSERVED,
            data={
                "query": query,
                "target_type": kind,
                "responses": [{"server": s, "text": t}
                              for s, t in responses],
                "referral": referral,
            },
        ))
    return text
