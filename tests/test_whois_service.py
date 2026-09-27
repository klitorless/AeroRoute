"""Tests for modules/whois_service.py — injected query functions and a fake
socket, so no real network access is needed."""
import socket

import pytest

from modules import whois_service
from modules.whois_service import (
    clean_whois_query,
    perform_whois,
    tld_whois_server,
    whois_query,
    IANA_SERVER,
    VERISIGN_SERVER,
)


class TestCleanQuery:
    def test_url_stripped(self):
        assert clean_whois_query("https://Example.COM/path") == "example.com"

    def test_trailing_dot_stripped(self):
        assert clean_whois_query("example.com.") == "example.com"

    def test_ip_allowed(self):
        assert clean_whois_query("8.8.8.8") == "8.8.8.8"

    def test_rejects_shell_chars(self):
        assert clean_whois_query("example.com; id") is None
        assert clean_whois_query("a|b.com") is None
        assert clean_whois_query("") is None
        assert clean_whois_query("   ") is None

    def test_rejects_garbage(self):
        assert clean_whois_query("not a host!") is None


class TestPerformWhois:
    def test_com_goes_to_verisign(self):
        calls = []

        def fake_query(server, query, timeout=10):
            calls.append((server, query))
            return "ok"

        out = perform_whois("example.com", query_fn=fake_query)
        assert calls[0][0] == VERISIGN_SERVER
        assert f"[via {VERISIGN_SERVER}]" in out

    def test_other_tld_uses_iana_discovery(self):
        calls = []

        def fake_query(server, query, timeout=10):
            calls.append((server, query))
            return "ok"

        out = perform_whois("example.org", query_fn=fake_query,
                            tld_server_fn=lambda tld: "whois.pir.org")
        assert calls[0][0] == "whois.pir.org"

    def test_tld_discovery_failure_falls_back_to_iana(self):
        calls = []

        def fake_query(server, query, timeout=10):
            calls.append((server, query))
            return "ok"

        perform_whois("example.org", query_fn=fake_query,
                      tld_server_fn=lambda tld: None)
        assert calls[0][0] == IANA_SERVER

    def test_registrar_referral_followed_once(self):
        calls = []

        def fake_query(server, query, timeout=10):
            calls.append(server)
            if server == VERISIGN_SERVER:
                return "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: whois.registrar.example\n"
            return "registrar full data"

        out = perform_whois("example.com", query_fn=fake_query)
        assert "whois.registrar.example" in calls
        assert "--- Referral: whois.registrar.example ---" in out
        assert "registrar full data" in out

    def test_referral_failure_is_reported_not_fatal(self):
        def fake_query(server, query, timeout=10):
            if server == VERISIGN_SERVER:
                return "Registrar WHOIS Server: whois.down.example\n"
            raise ConnectionError("boom")

        out = perform_whois("example.com", query_fn=fake_query)
        assert "referral query to whois.down.example failed" in out

    def test_ip_goes_to_iana(self):
        calls = []

        def fake_query(server, query, timeout=10):
            calls.append(server)
            return "RIR referral"

        out = perform_whois("8.8.8.8", query_fn=fake_query)
        assert calls == [IANA_SERVER]
        assert out == "RIR referral"

    def test_invalid_input_raises(self):
        with pytest.raises(ValueError):
            perform_whois("not a host!", query_fn=lambda s, q, timeout=10: "")


class TestTldDiscovery:
    def test_parses_whois_line(self):
        server = tld_whois_server(
            "org", query_fn=lambda s, q, timeout=10: "domain: ORG\nwhois: whois.pir.org\n")
        assert server == "whois.pir.org"

    def test_missing_line_returns_none(self):
        assert tld_whois_server("org", query_fn=lambda s, q, timeout=10: "nothing") is None

    def test_query_error_returns_none(self):
        def boom(s, q, timeout=10):
            raise ConnectionError("down")

        assert tld_whois_server("org", query_fn=boom) is None


class FakeSocket:
    instances = []

    def __init__(self, *args, **kwargs):
        self.closed = False
        self.timeout = None
        self.sent = b""
        self.fail_on_connect = False
        FakeSocket.instances.append(self)

    def settimeout(self, t):
        self.timeout = t

    def connect(self, addr):
        if self.fail_on_connect:
            raise ConnectionError("connect failed")

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        return b""

    def close(self):
        self.closed = True


class TestSocketHandling:
    def setup_method(self):
        FakeSocket.instances = []

    def test_socket_closed_on_success(self):
        out = whois_query("whois.example", "example.com",
                          _socket_factory=FakeSocket)
        assert out == ""
        assert FakeSocket.instances[0].closed is True

    def test_socket_closed_on_connect_error(self):
        def failing_factory(*a, **k):
            s = FakeSocket(*a, **k)
            s.fail_on_connect = True
            return s

        with pytest.raises(ConnectionError):
            whois_query("whois.example", "example.com",
                        _socket_factory=failing_factory)
        assert FakeSocket.instances[0].closed is True

    def test_timeout_is_bounded(self):
        whois_query("whois.example", "example.com", _socket_factory=FakeSocket)
        assert FakeSocket.instances[0].timeout == whois_service.WHOIS_TIMEOUT

    def test_query_line_sent(self):
        whois_query("whois.example", "example.com", _socket_factory=FakeSocket)
        assert FakeSocket.instances[0].sent == b"example.com\r\n"
