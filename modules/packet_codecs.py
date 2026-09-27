"""Packet payload decoders. Qt-free so they can be unit tested.

Each function raises ValueError on undecodable input; the GUI layer catches
it and shows the message to the user.
"""
import base64


def decode_base64(data):
    """Decode a Base64 string to text. Raises ValueError on bad input."""
    text = (data or "").strip()
    if not text:
        raise ValueError("empty input")
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as e:
        raise ValueError(f"invalid Base64: {e}")
    return raw.decode("utf-8", errors="ignore")


def decode_hex(data):
    """Decode a hex string (whitespace-insensitive) to text."""
    text = "".join((data or "").split())
    if not text:
        raise ValueError("empty input")
    try:
        raw = bytes.fromhex(text)
    except ValueError as e:
        raise ValueError(f"invalid hex: {e}")
    return raw.decode("utf-8", errors="ignore")


def xor_brute_decode(data):
    """Single-byte XOR brute force.

    Returns a list of "Key 0xNN: <text>" for every key whose output looks
    like printable ASCII (checked against the first 32 bytes).
    """
    blob = bytes(data or b"")
    if not blob:
        raise ValueError("empty input")
    results = []
    for key in range(1, 256):
        unmasked = bytes(b ^ key for b in blob)
        head = unmasked[:32]
        if all(32 <= b < 127 or b in (9, 10, 13) for b in head):
            results.append(f"Key 0x{key:02X}: {unmasked.decode('utf-8', errors='ignore')}")
    return results
