"""Tests for modules/whois_service.py — injected query functions and a fake
socket, so no real network access is needed."""
import json
import socket

import pytest

from modules import whois_service
from modules.observation import EvidenceKind, Observation, ObservationLog
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


class TestWhoisObservations:
    """Optional observation sink on perform_whois (Architecture Step 3).

    One Observation per completed lookup, built from the structured
    pre-render results — never by parsing the display string.
    """

    def test_no_sink_preserves_output(self):
        def fake_query(server, query, timeout=10):
            return "Domain Name: EXAMPLE.COM\n"

        out = perform_whois("example.com", query_fn=fake_query)
        assert out == f"[via {VERISIGN_SERVER}]\nDomain Name: EXAMPLE.COM\n"

    def test_successful_lookup_emits_one_observation(self):
        log = ObservationLog()

        def fake_query(server, query, timeout=10):
            return "Domain Name: EXAMPLE.COM\n"

        out = perform_whois("Example.COM", query_fn=fake_query,
                            sink=log.record)
        assert len(log) == 1
        obs = list(log)[0]
        assert obs.kind == "whois.lookup"
        assert obs.source == "whois"
        assert obs.target == "example.com"  # normalized query
        assert obs.evidence is EvidenceKind.OBSERVED
        assert obs.data["query"] == "example.com"
        assert obs.data["target_type"] == "hostname"
        assert obs.data["responses"] == [
            {"server": VERISIGN_SERVER,
             "text": "Domain Name: EXAMPLE.COM\n"}
        ]
        assert obs.data["referral"] is None
        # The human-readable output is unchanged by the sink.
        assert out == f"[via {VERISIGN_SERVER}]\nDomain Name: EXAMPLE.COM\n"

    def test_referral_lookup_emits_single_observation(self):
        log = ObservationLog()

        def fake_query(server, query, timeout=10):
            if server == VERISIGN_SERVER:
                return ("Domain Name: EXAMPLE.COM\n"
                        "Registrar WHOIS Server: whois.registrar.example\n")
            return "registrar full data"

        perform_whois("example.com", query_fn=fake_query, sink=log.record)
        assert len(log) == 1
        obs = list(log)[0]
        assert [r["server"] for r in obs.data["responses"]] == [
            VERISIGN_SERVER, "whois.registrar.example"]
        assert obs.data["responses"][1]["text"] == "registrar full data"
        assert obs.data["referral"] == {
            "server": "whois.registrar.example", "followed": True}

    def test_referral_failure_recorded_in_observation(self):
        log = ObservationLog()

        def fake_query(server, query, timeout=10):
            if server == VERISIGN_SERVER:
                return "Registrar WHOIS Server: whois.down.example\n"
            raise ConnectionError("boom")

        out = perform_whois("example.com", query_fn=fake_query,
                            sink=log.record)
        assert len(log) == 1
        obs = list(log)[0]
        assert obs.data["referral"]["followed"] is False
        assert obs.data["referral"]["server"] == "whois.down.example"
        assert "ConnectionError" in obs.data["referral"]["error"]
        # Existing rendering of the failure is unchanged.
        assert "referral query to whois.down.example failed" in out

    def test_ip_lookup_emits_observation(self):
        log = ObservationLog()
        out = perform_whois(
            "8.8.8.8",
            query_fn=lambda s, q, timeout=10: "RIR referral",
            sink=log.record)
        assert out == "RIR referral"
        assert len(log) == 1
        obs = list(log)[0]
        assert obs.kind == "whois.lookup"
        assert obs.target == "8.8.8.8"
        assert obs.data["target_type"] == "ipv4"
        assert obs.data["responses"] == [
            {"server": IANA_SERVER, "text": "RIR referral"}]

    def test_observation_data_is_json_friendly(self):
        log = ObservationLog()

        def fake_query(server, query, timeout=10):
            if server == VERISIGN_SERVER:
                return "Registrar WHOIS Server: whois.down.example\n"
            raise ConnectionError("boom")

        perform_whois("example.com", query_fn=fake_query, sink=log.record)
        obs = list(log)[0]
        # Payload contents must serialize without custom encoders
        # (data itself is an immutable MappingProxyType view by design).
        assert json.loads(json.dumps(dict(obs.data))) == dict(obs.data)

    def test_invalid_input_raises_without_emitting(self):
        log = ObservationLog()
        with pytest.raises(ValueError):
            perform_whois("not a host!", query_fn=lambda s, q, timeout=10: "",
                          sink=log.record)
        assert len(log) == 0

    def test_repeated_lookups_produce_independent_observations(self):
        log = ObservationLog()

        def fake_query(server, query, timeout=10):
            return f"data for {query}"

        perform_whois("example.com", query_fn=fake_query, sink=log.record)
        perform_whois("example.org", query_fn=fake_query,
                      tld_server_fn=lambda tld: "whois.pir.org",
                      sink=log.record)
        assert len(log) == 2
        first, second = list(log)
        assert first.target == "example.com"
        assert second.target == "example.org"
        # Independent payloads: not aliased to each other or to service state.
        assert first.data["responses"] is not second.data["responses"]
        assert first.data["responses"][0]["text"] == "data for example.com"
        assert second.data["responses"][0]["text"] == "data for example.org"
        # Top-level data is immutable.
        with pytest.raises(TypeError):
            first.data["query"] = "tampered"

    def test_sink_is_caller_owned_not_global(self):
        log_a, log_b = ObservationLog(), ObservationLog()

        def fake_query(server, query, timeout=10):
            return "ok"

        perform_whois("example.com", query_fn=fake_query, sink=log_a.record)
        perform_whois("example.com", query_fn=fake_query)  # no sink
        assert len(log_a) == 1
        assert len(log_b) == 0
