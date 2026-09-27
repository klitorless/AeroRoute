import re
import socket
from urllib.parse import urlparse
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit

_IANA = "whois.iana.org"
_VERISIGN = "whois.verisign-grs.com"  # authoritative for .com / .net


def _whois_query(server, query, timeout=10):
    """Raw WHOIS query. Socket is always closed, even on error."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, 43))
        s.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="ignore")
    finally:
        s.close()


def _tld_whois_server(tld):
    """Ask IANA which WHOIS server is authoritative for a TLD."""
    try:
        resp = _whois_query(_IANA, tld)
        m = re.search(r"(?im)^whois:\s*(\S+)", resp)
        return m.group(1) if m else None
    except Exception:
        return None


def _clean_query(raw):
    q = (raw or "").strip()
    if "://" in q:
        q = urlparse(q).hostname or q
    q = q.strip().lower().rstrip(".")
    if not q or any(c in q for c in " \t\r\n;|&$`"):
        return None
    return q


class WhoisWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.target_input = QLineEdit("example.com")
        whois_btn = QPushButton("Query WHOIS")
        whois_btn.setStyleSheet("background-color: #FF5722; color: white;")
        whois_btn.clicked.connect(self.query_whois)
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        layout.addWidget(QLabel("Domain or IP:"))
        layout.addWidget(self.target_input)
        layout.addWidget(whois_btn)
        layout.addWidget(QLabel("WHOIS Response:"))
        layout.addWidget(self.output)
        self.setLayout(layout)

    def query_whois(self):
        query = _clean_query(self.target_input.text())
        if not query:
            self.output.setPlainText("Invalid query.")
            return
        try:
            if re.fullmatch(r"[\d.]+", query) or ":" in query:
                # IP address: IANA returns the responsible RIR referral.
                text = _whois_query(_IANA, query)
            else:
                tld = query.rsplit(".", 1)[-1]
                if tld in ("com", "net"):
                    server = _VERISIGN
                else:
                    server = _tld_whois_server(tld) or _IANA
                text = f"[via {server}]\n" + _whois_query(server, query)
                # Follow one registrar referral (typical for .com/.net).
                m = re.search(r"(?im)^Registrar WHOIS Server:\s*(\S+)", text)
                if m and m.group(1).lower() != server.lower():
                    ref = m.group(1)
                    try:
                        text += f"\n\n--- Referral: {ref} ---\n" + _whois_query(ref, query)
                    except Exception as e:
                        text += f"\n[referral query to {ref} failed: {e}]"
            self.output.setPlainText(text or "(empty response)")
        except Exception as e:
            self.output.setPlainText(f"WHOIS Error: {e}")
