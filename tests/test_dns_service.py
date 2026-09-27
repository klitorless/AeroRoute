"""Tests for modules/dns_service.py.

dnspython is not installed in this environment, so the `dns` package is
stubbed in sys.modules and modules.dns_service is reloaded against the stub.
This exercises the REAL record-type handling, error mapping, and input
validation — not a copy of it.
"""
import importlib
import sys
import types
from unittest.mock import patch

import pytest


def _install_dns_stub():
    dns = types.ModuleType("dns")
    resolver_mod = types.ModuleType("dns.resolver")
    exception_mod = types.ModuleType("dns.exception")

    class DNSError(Exception):
        pass

    class NoAnswer(DNSError):
        pass

    class NXDOMAIN(DNSError):
        pass

    class NoNameservers(DNSError):
        pass

    class Timeout(DNSError):
        pass

    resolver_mod.NoAnswer = NoAnswer
    resolver_mod.NXDOMAIN = NXDOMAIN
    resolver_mod.NoNameservers = NoNameservers
    exception_mod.Timeout = Timeout
    dns.resolver = resolver_mod
    dns.exception = exception_mod
    sys.modules["dns"] = dns
    sys.modules["dns.resolver"] = resolver_mod
    sys.modules["dns.exception"] = exception_mod
    return resolver_mod, exception_mod


_resolver_mod, _exception_mod = _install_dns_stub()

import modules.dns_service as dns_service

importlib.reload(dns_service)
assert dns_service.DNSPYTHON_AVAILABLE is True


class FakeRdata:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


class FakeResolver:
    """Minimal stub of dns.resolver.Resolver."""

    def __init__(self, data=None, errors=None):
        self.data = data or {}
        self.errors = errors or {}

    def resolve(self, name, rtype):
        key = (name, rtype)
        if key in self.errors:
            raise self.errors[key]
        if key in self.data:
            return [FakeRdata(t) for t in self.data[key]]
        raise _resolver_mod.NoAnswer()


def _resolver(**kwargs):
    return FakeResolver(**kwargs)


class TestFullLookup:
    def test_a_record_reported(self):
        r = _resolver(data={("example.com", "A"): ["93.184.216.34"]})
        with patch.object(dns_service.socket, "gethostbyaddr",
                          side_effect=Exception("no ptr")):
            out = dns_service.perform_dns_lookup("example.com", resolver=r)
        assert "--- A ---" in out
        assert "93.184.216.34" in out

    def test_multiple_record_types(self):
        r = _resolver(data={
            ("example.com", "A"): ["93.184.216.34"],
            ("example.com", "MX"): ["10 mail.example.com."],
            ("example.com", "TXT"): ['"v=spf1 -all"'],
        })
        with patch.object(dns_service.socket, "gethostbyaddr",
                          side_effect=Exception("no ptr")):
            out = dns_service.perform_dns_lookup("example.com", resolver=r)
        assert "10 mail.example.com." in out
        assert "v=spf1 -all" in out

    def test_no_answer_mapped(self):
        r = _resolver(errors={("example.com", "MX"): _resolver_mod.NoAnswer()})
        with patch.object(dns_service.socket, "gethostbyaddr",
                          side_effect=Exception("no ptr")):
            out = dns_service.perform_dns_lookup("example.com", resolver=r)
        assert "(no data: NoAnswer)" in out

    def test_nxdomain_mapped(self):
        r = _resolver(errors={("nope.invalid", "A"): _resolver_mod.NXDOMAIN()})
        with patch.object(dns_service.socket, "gethostbyaddr",
                          side_effect=Exception("no ptr")):
            out = dns_service.perform_dns_lookup("nope.invalid", resolver=r)
        assert "(no data: NXDOMAIN)" in out

    def test_timeout_mapped(self):
        r = _resolver(errors={("example.com", "A"): _exception_mod.Timeout()})
        with patch.object(dns_service.socket, "gethostbyaddr",
                          side_effect=Exception("no ptr")):
            out = dns_service.perform_dns_lookup("example.com", resolver=r)
        assert "(no data: Timeout)" in out

    def test_ptr_section_when_available(self):
        r = _resolver(data={("example.com", "A"): ["93.184.216.34"]})
        with patch.object(dns_service.socket, "gethostbyaddr",
                          return_value=("host.example.com", [], [])):
            out = dns_service.perform_dns_lookup("example.com", resolver=r)
        assert "--- PTR (93.184.216.34) ---" in out
        assert "host.example.com" in out

    def test_resolver_lifetime_bounded(self):
        assert dns_service.RESOLVER_LIFETIME == 5


class TestInputValidation:
    def test_invalid_domain_rejected(self):
        with pytest.raises(ValueError):
            dns_service.perform_dns_lookup("not a host!", resolver=_resolver())

    def test_ip_literal_rejected(self):
        with pytest.raises(ValueError):
            dns_service.perform_dns_lookup("8.8.8.8", resolver=_resolver())

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            dns_service.perform_dns_lookup("", resolver=_resolver())

    def test_url_normalized(self):
        r = _resolver(data={("example.com", "A"): ["93.184.216.34"]})
        with patch.object(dns_service.socket, "gethostbyaddr",
                          side_effect=Exception("no ptr")):
            out = dns_service.perform_dns_lookup("https://example.com/x", resolver=r)
        assert "93.184.216.34" in out


class TestBasicFallback:
    def test_basic_lookup_path(self):
        with patch.object(dns_service.socket, "gethostbyname", return_value="93.184.216.34"), \
             patch.object(dns_service.socket, "gethostbyaddr",
                          return_value=("host.example.com", [], ["93.184.216.34"])):
            out = dns_service.basic_dns_lookup("example.com")
        assert "Primary IP: 93.184.216.34" in out
        assert "host.example.com" in out

    def test_basic_lookup_rejects_bad_input(self):
        with pytest.raises(ValueError):
            dns_service.basic_dns_lookup("8.8.8.8; evil")
