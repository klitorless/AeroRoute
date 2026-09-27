"""Tests for modules/packet_sender.py — socket family follows the validated
target kind. The socket layer is fully mocked: no real packets are sent."""
import pytest

from modules.packet_sender import send_test_packet


class FakeSocket:
    def __init__(self, parent):
        self.parent = parent

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, t):
        self.parent.timeouts.append(t)

    def sendto(self, payload, addr):
        self.parent.sent.append((payload, addr))
        return len(payload)

    def sendall(self, payload):
        self.parent.sent.append(payload)


class FakeSocketModule:
    AF_INET = 2
    AF_INET6 = 10
    SOCK_DGRAM = 2

    def __init__(self):
        self.families = []
        self.connections = []
        self.sent = []
        self.timeouts = []

    def socket(self, family, type):
        self.families.append((family, type))
        return FakeSocket(self)

    def create_connection(self, addr, timeout=None):
        self.connections.append((addr, timeout))
        return FakeSocket(self)


class TestUdpFamily:
    def test_ipv4_uses_af_inet(self):
        mod = FakeSocketModule()
        sent = send_test_packet("ipv4", "192.168.1.1", 8080, b"ping", "UDP",
                                _socket=mod)
        assert mod.families == [(FakeSocketModule.AF_INET, FakeSocketModule.SOCK_DGRAM)]
        assert sent == 4
        assert mod.sent[0][1] == ("192.168.1.1", 8080)

    def test_ipv6_uses_af_inet6(self):
        mod = FakeSocketModule()
        send_test_packet("ipv6", "::1", 8080, b"ping", "UDP", _socket=mod)
        assert mod.families == [(FakeSocketModule.AF_INET6, FakeSocketModule.SOCK_DGRAM)]
        assert mod.sent[0][1] == ("::1", 8080)

    def test_hostname_uses_af_inet(self):
        mod = FakeSocketModule()
        send_test_packet("hostname", "example.com", 8080, b"ping", "UDP",
                         _socket=mod)
        assert mod.families == [(FakeSocketModule.AF_INET, FakeSocketModule.SOCK_DGRAM)]

    def test_send_timeout_bounded(self):
        mod = FakeSocketModule()
        send_test_packet("ipv4", "192.168.1.1", 8080, b"ping", "UDP",
                         timeout=7, _socket=mod)
        assert mod.timeouts == [7]


class TestTcp:
    def test_tcp_sends_payload(self):
        mod = FakeSocketModule()
        sent = send_test_packet("ipv4", "192.168.1.1", 443, b"hello", "TCP",
                                _socket=mod)
        assert sent == 5
        assert mod.connections[0][0] == ("192.168.1.1", 443)

    def test_tcp_ipv6_target(self):
        mod = FakeSocketModule()
        send_test_packet("ipv6", "::1", 443, b"hello", "TCP", _socket=mod)
        assert mod.connections[0][0] == ("::1", 443)


class TestInvalidInput:
    def test_invalid_kind_rejected(self):
        with pytest.raises(ValueError):
            send_test_packet("bogus", "1.2.3.4", 80, b"x", "UDP",
                             _socket=FakeSocketModule())

    def test_invalid_proto_rejected(self):
        with pytest.raises(ValueError):
            send_test_packet("ipv4", "1.2.3.4", 80, b"x", "ICMP",
                             _socket=FakeSocketModule())

    def test_socket_error_propagates(self):
        class BrokenModule(FakeSocketModule):
            def socket(self, family, type):
                raise OSError("no route")

        with pytest.raises(OSError):
            send_test_packet("ipv4", "192.168.1.1", 8080, b"ping", "UDP",
                             _socket=BrokenModule())
