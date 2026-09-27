"""Import/export helpers for ping-monitor targets. Qt-free, unit tested.

The GUI layer (MainWindow.import_targets / export_targets) handles the file
dialogs; everything about parsing, validating, and capping lives here.
"""
import json

from .target_validation import normalize_target

MAX_IMPORTS = 50
METHODS = ("ICMP", "TCP")


def parse_target_import(items, existing=(), max_imports=MAX_IMPORTS):
    """Validate a decoded JSON import payload.

    Returns a list of (ip, method) tuples ready to add. Rules:
      - payload must be a list, otherwise ValueError
      - entries must be dicts containing "ip"
      - the ip is cleaned/normalized; invalid entries are skipped
      - method defaults to ICMP; anything outside METHODS falls back to ICMP
      - duplicates (against `existing` and within the payload) are skipped
      - at most `max_imports` entries are returned

    Raises ValueError on malformed JSON text (use parse_target_import_json).
    """
    if not isinstance(items, list):
        raise ValueError("expected a JSON list of targets")
    seen = set(existing)
    out = []
    for item in items:
        if len(out) >= max_imports:
            break
        if not isinstance(item, dict) or "ip" not in item:
            continue
        norm = normalize_target(str(item["ip"]))
        if norm is None:
            continue
        kind, cleaned = norm
        method = str(item.get("method", "ICMP")).upper()
        if method not in METHODS:
            method = "ICMP"
        # Dedupe by normalized target string here; the monitor dedupes
        # again post-DNS-resolution at add time (hostnames -> IPs).
        if cleaned in seen:
            continue
        seen.add(cleaned)
        out.append((cleaned, method))
    return out


def parse_target_import_json(text, existing=(), max_imports=MAX_IMPORTS):
    """Parse raw JSON text, then validate. Raises ValueError on bad JSON."""
    try:
        items = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"malformed JSON: {e}")
    return parse_target_import(items, existing, max_imports)


def serialize_targets(pairs):
    """Serialize [(ip, method), ...] to the JSON import format."""
    return json.dumps([{"ip": ip, "method": m} for ip, m in pairs], indent=4)
