"""TLS certificate inspection service. Qt-free so it can be unit tested.

The GUI layer (modules/ssl_scanner.py) calls perform_ssl_scan() from a
worker thread; results come back through Qt signals.
"""
import socket
import ssl

from .observation import EvidenceKind, Observation
from .target_validation import normalize_target

SSL_TIMEOUT = 5  # seconds: connect + handshake are bounded


def _rdn_pairs(rdn):
    """Convert a getpeercert() RDN tuple into JSON-friendly [name, value] pairs."""
    return [[name, value] for name, value in (x[0] for x in (rdn or []))]


def perform_ssl_scan(raw_host, port=443, timeout=SSL_TIMEOUT, *, sink=None):
    """Fetch and format the peer certificate. Returns a readable string.

    Raises ValueError for invalid input; other exceptions propagate to the
    caller (the GUI worker converts them to an error message).

    `sink`, when given, is an optional callable accepting one Observation
    (e.g. a caller-owned ``ObservationLog.record``). One Observation
    (``kind="ssl.connection"``, ``evidence=OBSERVED``) is emitted per
    completed scan, built from the structured pre-render facts — the
    normalized host, the negotiated TLS version and cipher, and the peer
    certificate fields. The display string is never parsed to build the
    observation, and the observation records only what was observed, never
    a security judgment. The service never stores observations; callers
    without a sink see byte-identical behavior.
    """
    norm = normalize_target(raw_host)
    if norm is None:
        raise ValueError(f"invalid host: {raw_host!r}")
    kind, host = norm
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
    # Structured pre-render facts. The human-readable string below is
    # assembled from these; the observation is built from these, never
    # from the rendered string.
    subject = dict(x[0] for x in cert.get('subject', []))
    issuer = dict(x[0] for x in cert.get('issuer', []))
    cipher_name, tls_version, cipher_bits = cipher or (None, None, None)
    info = f"--- Certificate Details for {host} ---\n"
    info += f"Subject: {subject}\n"
    info += f"Issuer: {issuer}\n"
    info += f"Version: {cert.get('version')}\n"
    info += f"Not Before: {cert.get('notBefore')}\n"
    info += f"Not After: {cert.get('notAfter')}\n"
    info += f"Cipher Suite: {cipher}\n"
    if sink is not None:
        sink(Observation(
            kind="ssl.connection",
            source="ssl",
            target=host,
            evidence=EvidenceKind.OBSERVED,
            data={
                "host": host,
                "port": port,
                "tls_version": tls_version,
                "cipher_suite": cipher_name,
                "cipher_bits": cipher_bits,
                "certificate": {
                    "subject": _rdn_pairs(cert.get("subject")),
                    "issuer": _rdn_pairs(cert.get("issuer")),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": [
                        [t, v] for t, v in (cert.get("subjectAltName") or [])
                    ],
                },
            },
        ))
    return info
