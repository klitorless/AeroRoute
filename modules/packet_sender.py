"""Test-payload sender. Qt-free so it can be unit tested.

The socket family follows the validated target kind, so an IPv6 target
never ends up on an IPv4 socket:
  ipv4     -> AF_INET
  ipv6     -> AF_INET6
  hostname -> AF_INET (unchanged historical behavior; the OS resolver
              handles the name, same as before this change)

TCP uses create_connection(), which resolves hostnames and IP literals
(v4 and v6) itself. Returns the number of bytes sent.
"""
import socket

SEND_TIMEOUT = 3  # seconds: connect and send are bounded


def send_test_packet(kind, target, port, payload, proto, timeout=SEND_TIMEOUT,
                     _socket=socket):
    """Send one UDP/TCP test payload. Returns bytes sent.

    Raises ValueError for an invalid kind/protocol. `_socket` is
    injectable so tests never touch the real network.
    """
    if kind not in ("ipv4", "ipv6", "hostname"):
        raise ValueError(f"invalid target kind: {kind!r}")
    if proto not in ("TCP", "UDP"):
        raise ValueError(f"unsupported protocol: {proto!r}")

    if proto == "TCP":
        with _socket.create_connection((target, port), timeout=timeout) as s:
            s.sendall(payload)
            return len(payload)

    family = _socket.AF_INET6 if kind == "ipv6" else _socket.AF_INET
    with _socket.socket(family, _socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        return s.sendto(payload, (target, port))
