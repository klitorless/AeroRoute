"""Tests for modules/target_validation.py — the shared validation layer."""
import pytest

from modules.target_validation import (
    clean_target,
    classify_target,
    is_valid_target,
    normalize_target,
)


class TestClassify:
    def test_valid_ipv4(self):
        assert classify_target("192.168.1.1") == "ipv4"
        assert classify_target("8.8.8.8") == "ipv4"

    def test_valid_ipv6(self):
        assert classify_target("::1") == "ipv6"
        assert classify_target("2001:db8::1") == "ipv6"

    def test_valid_hostname(self):
        assert classify_target("google.com") == "hostname"
        assert classify_target("sub.domain-example.co.uk") == "hostname"

    def test_malformed_ip(self):
        assert classify_target("999.999.999.999") is None
        assert classify_target("1.2.3") is None

    def test_malformed_hostname(self):
        assert classify_target("-bad-.com") is None
        assert classify_target("example..com") is None
        assert classify_target("not a host!") is None
        assert classify_target("localhost") is None  # single label: not a FQDN

    def test_empty_input(self):
        assert classify_target("") is None
        assert classify_target(None) is None
        assert classify_target("   ") is None

    def test_injection_shapes_rejected(self):
        for bad in ["8.8.8.8; rm -rf /", "host && whoami", "a|b.com",
                    "x$(id).com", "a`b.com", "a'b.com"]:
            assert classify_target(bad) is None, bad


class TestClean:
    def test_url_normalization(self):
        assert clean_target("https://example.com/path?q=1") == "example.com"
        assert clean_target("http://192.168.1.1:8080/x") == "192.168.1.1"

    def test_trailing_dot_and_whitespace(self):
        assert clean_target("  example.com.  ") == "example.com"

    def test_empty(self):
        assert clean_target("") == ""
        assert clean_target(None) == ""


class TestNormalize:
    def test_hostname_lowercased(self):
        assert normalize_target("Example.COM") == ("hostname", "example.com")

    def test_ip_untouched(self):
        assert normalize_target("192.168.1.1") == ("ipv4", "192.168.1.1")

    def test_invalid_returns_none(self):
        assert normalize_target("not a host!") is None
        assert normalize_target("") is None

    def test_is_valid_target_agrees(self):
        assert is_valid_target("8.8.8.8")
        assert not is_valid_target("8.8.8.8; evil")
