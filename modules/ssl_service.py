"""TLS certificate inspection service. Qt-free so it can be unit tested.

The GUI layer (modules/ssl_scanner.py) calls perform_ssl_scan() from a
worker thread; results come back through Qt signals.
"""
import socket
import ssl

from .target_validation import normalize_target

SSL_TIMEOUT = 5  # seconds: connect + handshake are bounded


def perform_ssl_scan(raw_host, port=443, timeout=SSL_TIMEOUT):
    """Fetch and format the peer certificate. Returns a readable string.

    Raises ValueError for invalid input; other exceptions propagate to the
    caller (the GUI worker converts them to an error message).
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
    info = f"--- Certificate Details for {host} ---\n"
    info += f"Subject: {dict(x[0] for x in cert.get('subject', []))}\n"
    info += f"Issuer: {dict(x[0] for x in cert.get('issuer', []))}\n"
    info += f"Version: {cert.get('version')}\n"
    info += f"Not Before: {cert.get('notBefore')}\n"
    info += f"Not After: {cert.get('notAfter')}\n"
    info += f"Cipher Suite: {cipher}\n"
    return info
