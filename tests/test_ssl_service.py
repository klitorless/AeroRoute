"""Tests for modules/ssl_service.py observation emission (Architecture Step 4).

perform_ssl_scan() keeps its existing rendered-string contract; an optional
sink additionally receives one structured Observation per completed scan.
The observation records only what was observed (negotiated TLS version,
cipher, certificate fields) — never a security judgment.

Network access is faked via monkeypatch: no test touches a real socket.
The module is Qt-free; importing it must not pull in PyQt6.
"""
import json
import socket
import sys

import pytest

import modules.ssl_service as ssl_service
from modules.observation import EvidenceKind, ObservationLog
from modules.ssl_service import perform_ssl_scan

CERT = {
    "subject": ((("countryName", "US"),), (("commonName", "example.com"),)),
    "issuer": ((("organizationName", "Example CA"),),),
    "version": 3,
    "serialNumber": "0A1B2C3D",
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Jan  1 00:00:00 2027 GMT",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
}
CIPHER = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

EXPECTED_OUTPUT = (
    "--- Certificate Details for example.com ---\n"
    "Subject: {'countryName': 'US', 'commonName': 'example.com'}\n"
    "Issuer: {'organizationName': 'Example CA'}\n"
    "Version: 3\n"
    "Not Before: Jan  1 00:00:00 2026 GMT\n"
    "Not After: Jan  1 00:00:00 2027 GMT\n"
    f"Cipher Suite: {CIPHER!r}\n"
)


class _FakeSSLSocket:
    def __init__(self, cert, cipher):
        self._cert = cert
        self._cipher = cipher

    def getpeercert(self):
        return self._cert

    def cipher(self):
        return self._cipher

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeContext:
    def __init__(self, sslsock):
        self._sslsock = sslsock

    def wrap_socket(self, sock, server_hostname=None):
        return self._sslsock


@pytest.fixture
def fake_tls(monkeypatch):
    """Route perform_ssl_scan's network calls to fakes (no real network)."""
    sslsock = _FakeSSLSocket(dict(CERT), CIPHER)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: _FakeSocket())
    monkeypatch.setattr(ssl_service.ssl, "create_default_context",
                        lambda: _FakeContext(sslsock))
    return sslsock


class TestNoSink:
    def test_output_unchanged_without_sink(self, fake_tls):
        assert perform_ssl_scan("example.com") == EXPECTED_OUTPUT

    def test_output_unchanged_with_sink(self, fake_tls):
        log = ObservationLog()
        assert perform_ssl_scan("example.com", sink=log.record) == EXPECTED_OUTPUT


class TestSslConnectionObservation:
    def test_successful_scan_emits_one_observation(self, fake_tls):
        log = ObservationLog()
        perform_ssl_scan("example.com", sink=log.record)
        assert len(log) == 1
        obs = log.by_kind("ssl.connection")[0]
        assert obs.source == "ssl"
        assert obs.target == "example.com"
        assert obs.evidence is EvidenceKind.OBSERVED

    def test_observation_data_structured(self, fake_tls):
        log = ObservationLog()
        perform_ssl_scan("example.com", sink=log.record)
        data = log.by_kind("ssl.connection")[0].data
        assert data["host"] == "example.com"
        assert data["port"] == 443
        assert data["tls_version"] == "TLSv1.3"
        assert data["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert data["cipher_bits"] == 256
        cert = data["certificate"]
        assert cert["subject"] == [["countryName", "US"],
                                   ["commonName", "example.com"]]
        assert cert["issuer"] == [["organizationName", "Example CA"]]
        assert cert["version"] == 3
        assert cert["serial_number"] == "0A1B2C3D"
        assert cert["not_before"] == "Jan  1 00:00:00 2026 GMT"
        assert cert["not_after"] == "Jan  1 00:00:00 2027 GMT"
        assert cert["subject_alt_names"] == [["DNS", "example.com"],
                                             ["DNS", "www.example.com"]]

    def test_observation_data_json_friendly(self, fake_tls):
        log = ObservationLog()
        perform_ssl_scan("example.com", sink=log.record)
        obs = log.by_kind("ssl.connection")[0]
        # MappingProxyType container needs dict() conversion; contents must
        # serialize cleanly.
        parsed = json.loads(json.dumps(dict(obs.data)))
        assert parsed["tls_version"] == "TLSv1.3"

    def test_no_security_judgment_in_data(self, fake_tls):
        log = ObservationLog()
        perform_ssl_scan("example.com", sink=log.record)
        text = json.dumps(dict(log.by_kind("ssl.connection")[0].data)).lower()
        for word in ("insecure", "weak", "vulnerable", "secure", "safe"):
            assert word not in text

    def test_emitted_data_not_aliased_to_service_state(self, fake_tls):
        log = ObservationLog()
        perform_ssl_scan("example.com", sink=log.record)
        obs = log.by_kind("ssl.connection")[0]
        # Mutating the underlying cert after emission must not alter the
        # recorded observation...
        fake_tls._cert["subject"] = ((("commonName", "evil.example"),),)
        fake_tls._cert["serialNumber"] = "CHANGED"
        assert obs.data["certificate"]["subject"] == [
            ["countryName", "US"], ["commonName", "example.com"]]
        assert obs.data["certificate"]["serial_number"] == "0A1B2C3D"
        # ...and the top-level data mapping itself is immutable.
        with pytest.raises(TypeError):
            obs.data["tls_version"] = "TLSv1.2"

    def test_repeated_scans_produce_independent_observations(self, fake_tls):
        log = ObservationLog()
        perform_ssl_scan("example.com", sink=log.record)
        perform_ssl_scan("example.com", sink=log.record)
        assert len(log.by_kind("ssl.connection")) == 2
        first, second = log.by_kind("ssl.connection")
        assert first is not second
        assert first.data["tls_version"] == second.data["tls_version"]

    def test_sink_is_caller_owned(self, fake_tls):
        log1, log2 = ObservationLog(), ObservationLog()
        perform_ssl_scan("example.com", sink=log1.record)
        assert len(log1) == 1
        assert len(log2) == 0


class TestFailureBehavior:
    def test_connection_failure_propagates_without_observation(self, monkeypatch):
        log = ObservationLog()
        monkeypatch.setattr(socket, "create_connection",
                            _raise_timeout)
        with pytest.raises(socket.timeout):
            perform_ssl_scan("example.com", sink=log.record)
        assert len(log) == 0

    def test_invalid_host_raises_without_observation(self, fake_tls):
        log = ObservationLog()
        with pytest.raises(ValueError):
            perform_ssl_scan("not a host!!", sink=log.record)
        assert len(log) == 0


def _raise_timeout(*a, **k):
    raise socket.timeout("timed out")


class TestQtFree:
    def test_import_does_not_require_qt(self):
        assert "PyQt6" not in sys.modules
        assert "modules.ssl_service" in sys.modules
