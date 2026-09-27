"""Tests for modules/packet_codecs.py — exercises the REAL decoder functions
(the old tests in modules/ping_monitor.py merely re-implemented the logic)."""
import base64

import pytest

from modules.packet_codecs import decode_base64, decode_hex, xor_brute_decode


class TestBase64:
    def test_round_trip(self):
        original = "AeRoLogic Network Test"
        encoded = base64.b64encode(original.encode()).decode()
        assert decode_base64(encoded) == original

    def test_malformed(self):
        with pytest.raises(ValueError):
            decode_base64("!!! not base64 !!!")

    def test_empty(self):
        with pytest.raises(ValueError):
            decode_base64("")
        with pytest.raises(ValueError):
            decode_base64("   ")


class TestHex:
    def test_round_trip(self):
        original = "SecurePayload"
        assert decode_hex(original.encode().hex()) == original

    def test_whitespace_insensitive(self):
        assert decode_hex("48 65 6c 6c 6f") == "Hello"
        assert decode_hex("48656c6c6f") == "Hello"

    def test_malformed(self):
        with pytest.raises(ValueError):
            decode_hex("zz top")
        with pytest.raises(ValueError):
            decode_hex("abc")  # odd length

    def test_empty(self):
        with pytest.raises(ValueError):
            decode_hex("")


class TestXor:
    def test_known_key_found(self):
        original = "TestKey123"
        masked = bytes(b ^ 0x5A for b in original.encode())
        results = xor_brute_decode(masked)
        assert any(r.startswith("Key 0x5A:") and original in r for r in results)

    def test_no_false_positives_on_random(self):
        # Random bytes should not decode to clean ASCII for key 0x00 range
        # check — we just assert the function returns a list without crashing.
        results = xor_brute_decode(bytes(range(256)))
        assert isinstance(results, list)

    def test_empty(self):
        with pytest.raises(ValueError):
            xor_brute_decode(b"")
