import ssl, socket
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit

class SSLScannerWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.target_input = QLineEdit("google.com")
        scan_btn = QPushButton("Scan SSL/TLS Certificate")
        scan_btn.setStyleSheet("background-color: #9C27B0; color: white;")
        scan_btn.clicked.connect(self.scan_ssl)
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        
        layout.addWidget(QLabel("Target Host (Port 443):"))
        layout.addWidget(self.target_input)
        layout.addWidget(scan_btn)
        layout.addWidget(QLabel("Certificate Details:"))
        layout.addWidget(self.output)
        self.setLayout(layout)
        
    def scan_ssl(self):
        host = self.target_input.text().strip()
        if not host: return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    info = f"--- Certificate Details for {host} ---\n"
                    info += f"Subject: {dict(x[0] for x in cert.get('subject', []))}\n"
                    info += f"Issuer: {dict(x[0] for x in cert.get('issuer', []))}\n"
                    info += f"Version: {cert.get('version')}\n"
                    info += f"Not Before: {cert.get('notBefore')}\n"
                    info += f"Not After: {cert.get('notAfter')}\n"
                    info += f"Cipher Suite: {cipher}\n"
                    self.output.setPlainText(info)
        except Exception as e:
            self.output.setPlainText(f"SSL Scan Error: {e}")