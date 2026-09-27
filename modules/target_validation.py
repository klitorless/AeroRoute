"""Centralized target validation and normalization.

Every module that accepts a user-supplied network target (ping, DNS, WHOIS,
SSL, packet generator) should go through here instead of inventing its own
rules. This module is intentionally Qt-free so it can be unit tested.

Kinds:
    "ipv4"     - dotted-quad address, e.g. 192.168.1.1
    "ipv6"     - e.g. ::1
    "hostname" - DNS name, e.g. example.com

Normalization:
    - surrounding whitespace is stripped
    - full URLs are reduced to their hostname ("https://example.com/x" -> "example.com")
    - a single trailing dot is removed ("example.com." -> "example.com")
    - hostnames are lowercased (DNS is case-insensitive); IP literals are
      left untouched
"""
import ipaddress
import re
from urllib.parse import urlparse

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
# Characters that must never appear in a target: whitespace and anything
# that could be interpreted by a shell if the value ever reaches one.
_FORBIDDEN_RE = re.compile(r"[\s;|&$`'\"\\]")


def clean_target(raw):
    """Normalize raw user input. Returns "" for empty input."""
    text = (raw or "").strip()
    if "://" in text:
        text = urlparse(text).hostname or text
    text = text.strip().rstrip(".")
    return text


def classify_target(target):
    """Return "ipv4", "ipv6", "hostname", or None if not a valid target."""
    if not target or _FORBIDDEN_RE.search(target):
        return None
    try:
        addr = ipaddress.ip_address(target)
        return "ipv4" if addr.version == 4 else "ipv6"
    except ValueError:
        pass
    if _HOSTNAME_RE.match(target.lower()):
        return "hostname"
    return None


def is_valid_target(target):
    """True if the (already cleaned) target is usable."""
    return classify_target(target) is not None


def normalize_target(raw):
    """Clean + validate + normalize. Returns (kind, normalized) or None."""
    cleaned = clean_target(raw)
    kind = classify_target(cleaned)
    if kind is None:
        return None
    if kind == "hostname":
        cleaned = cleaned.lower()
    return kind, cleaned
