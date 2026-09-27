import os
import subprocess
import socket
import re
import ipaddress
from urllib.parse import urlparse
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QTextEdit
from PyQt6.QtCore import pyqtSignal, QObject, QThread

class TraceWorker(QObject):
    line_received = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):
        cmd = ['tracert', self.target] if os.name == 'nt' else ['traceroute', self.target]
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(process.stdout.readline, ""):
                if line:
                    self.line_received.emit(line.strip())
            process.stdout.close()
            process.wait()
        except Exception as e:
            self.line_received.emit(f"Error: {str(e)}")
        finally:
            self.finished.emit()

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About AeRoLogic")
        self.setMinimumSize(400, 500)
        layout = QVBoxLayout()
        content = """
        <h2>NetScanTools PRO - Modular Suite</h2>
        <p><b>Entity:</b> AeRoLogic</p>
        <p><b>Email:</b> AeRoLogic@usa.com</p>
        <p><b>GitHub:</b> <a href="https://github.com/AeRoLogic.io">AeRoLogicIO</a></p>
        <h3>Modules</h3>
        <ul>
            <li>Discovery & Ping Monitor</li>
            <li>System Network Activity</li>
            <li>Packet Analysis & Payload Decrypter</li>
            <li>DNS & Internet Intelligence</li>
            <li>SSL & Security Scanner</li>
            <li>WHOIS & Utilities</li>
        </ul>
        <h3>Disclaimer</h3>
        <p><b>AeRoLogic</b> assumes no responsibility for network utility usage. Compliance with local laws is strictly the user's responsibility.</p>
        """
        lbl = QLabel(content)
        lbl.setWordWrap(True)
        lbl.setOpenExternalLinks(True)
        layout.addWidget(lbl)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)
        self.setLayout(layout)

def is_valid_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target))

def get_clean_target(user_input):
    if "://" in user_input:
        return urlparse(user_input).hostname
    return user_input

def resolve_hostname(target):
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

class TraceDialog(QDialog):
    def __init__(self, target, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Trace: {target}")
        self.resize(600, 400)
        layout = QVBoxLayout()
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text)
        self.setLayout(layout)
        
        # Safe Threading Setup using QThread and pyqtSignal
        self.thread = QThread()
        self.worker = TraceWorker(target)
        self.worker.moveToThread(self.thread)
        
        self.thread.started.connect(self.worker.run)
        self.worker.line_received.connect(self.text.append)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        
        self.thread.start()

    def closeEvent(self, event):
        if self.thread.isRunning():
            self.thread.quit()
            self.thread.wait()
        event.accept()