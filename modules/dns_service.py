"""DNS lookup service. Qt-free so it can be unit tested.

The GUI layer (modules/dns_tools.py) calls perform_dns_lookup() from a
worker thread; results come back through Qt signals.
"""
import socket

from .target_validation import normalize_target

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA")
RESOLVER_LIFETIME = 5  # seconds: every query is bounded


def _default_resolver():
    resolver = dns.resolver.Resolver()
    resolver.lifetime = RESOLVER_LIFETIME
    return resolver


def perform_dns_lookup(domain, resolver=None):
    """Full record lookup. Returns a human-readable multi-line string.

    `resolver` is injectable for tests (must expose .resolve(name, rtype)).
    Raises ValueError for invalid input.
    """
    norm = normalize_target(domain)
    if norm is None:
        raise ValueError(f"invalid domain: {domain!r}")
    kind, name = norm
    if kind != "hostname":
        raise ValueError(f"not a hostname: {domain!r}")
    if not DNSPYTHON_AVAILABLE:
        return basic_dns_lookup(name)

    res = resolver if resolver is not None else _default_resolver()
    lines = []
    for rtype in RECORD_TYPES:
        lines.append(f"--- {rtype} ---")
        try:
            for r in res.resolve(name, rtype):
                lines.append(f"  {r.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            lines.append(f"  (no data: {type(e).__name__})")
        except Exception as e:
            lines.append(f"  (error: {e})")
    # Best-effort reverse lookup on the first A record.
    try:
        ip = res.resolve(name, "A")[0].to_text()
        host, _, _ = socket.gethostbyaddr(ip)
        lines.append(f"--- PTR ({ip}) ---\n  {host}")
    except Exception:
        # PTR is informational only; a missing record is not an error.
        pass
    return "\n".join(lines)


def basic_dns_lookup(domain):
    """Fallback when dnspython is unavailable: A + PTR via the OS resolver."""
    norm = normalize_target(domain)
    if norm is None:
        raise ValueError(f"invalid domain: {domain!r}")
    kind, name = norm
    if kind != "hostname":
        raise ValueError(f"not a hostname: {domain!r}")
    ip = socket.gethostbyname(name)
    host, aliases, ips = socket.gethostbyaddr(ip)
    return (f"Primary IP: {ip}\nCanonical Hostname: {host}\n"
            f"Aliases: {aliases}\nAll Associated IPs: {ips}")
