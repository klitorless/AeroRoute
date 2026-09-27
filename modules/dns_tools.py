import socket
from urllib.parse import urlparse
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA")


class DNSToolsWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.target_input = QLineEdit("example.com")
        resolve_btn = QPushButton("Lookup DNS Records")
        resolve_btn.setStyleSheet("background-color: #2196F3; color: white;")
        resolve_btn.clicked.connect(self.lookup_dns)
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        if not DNSPYTHON_AVAILABLE:
            layout.addWidget(QLabel(
                "<i>dnspython not installed — showing A/PTR only. "
                "Run: pip install dnspython</i>"))

        layout.addWidget(QLabel("Target Domain:"))
        layout.addWidget(self.target_input)
        layout.addWidget(resolve_btn)
        layout.addWidget(QLabel("DNS Results:"))
        layout.addWidget(self.output)
        self.setLayout(layout)

    @staticmethod
    def _clean(domain):
        d = (domain or "").strip()
        if "://" in d:
            d = urlparse(d).hostname or d
        return d.strip().rstrip(".")

    def lookup_dns(self):
        domain = self._clean(self.target_input.text())
        if not domain:
            return
        if DNSPYTHON_AVAILABLE:
            self.output.setPlainText(self._full_lookup(domain))
        else:
            self.output.setPlainText(self._basic_lookup(domain))

    def _full_lookup(self, domain):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        lines = []
        for rtype in _RECORD_TYPES:
            lines.append(f"--- {rtype} ---")
            try:
                for r in resolver.resolve(domain, rtype):
                    lines.append(f"  {r.to_text()}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout) as e:
                lines.append(f"  (no data: {type(e).__name__})")
            except Exception as e:
                lines.append(f"  (error: {e})")
        # Reverse lookup on the first A record, if any.
        try:
            a = resolver.resolve(domain, "A")
            ip = a[0].to_text()
            host, _, _ = socket.gethostbyaddr(ip)
            lines.append(f"--- PTR ({ip}) ---\n  {host}")
        except Exception:
            pass
        return "\n".join(lines)

    def _basic_lookup(self, domain):
        # Fallback when dnspython is unavailable: A + PTR only.
        try:
            ip = socket.gethostbyname(domain)
            host, aliases, ips = socket.gethostbyaddr(ip)
            return (f"Primary IP: {ip}\nCanonical Hostname: {host}\n"
                    f"Aliases: {aliases}\nAll Associated IPs: {ips}")
        except Exception as e:
            return f"DNS Lookup Error: {e}"
