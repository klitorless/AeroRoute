from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from PyQt6.QtCore import QObject, QThread, pyqtSignal

from .dns_service import perform_dns_lookup, DNSPYTHON_AVAILABLE


class DnsWorker(QObject):
    """Runs perform_dns_lookup() off the GUI thread.

    UI -> Worker -> Service -> Network -> Signal -> UI.
    Never touches widgets directly; results return via signals.
    """
    result = pyqtSignal(str)
    error = pyqtSignal(str)
    done = pyqtSignal()

    def __init__(self, domain):
        super().__init__()
        self.domain = domain

    def run(self):
        try:
            self.result.emit(perform_dns_lookup(self.domain))
        except ValueError as e:
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(f"DNS Lookup Error: {e}")
        finally:
            self.done.emit()


class DNSToolsWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.target_input = QLineEdit("example.com")
        self.resolve_btn = QPushButton("Lookup DNS Records")
        self.resolve_btn.setStyleSheet("background-color: #2196F3; color: white;")
        self.resolve_btn.clicked.connect(self.start_lookup)
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        if not DNSPYTHON_AVAILABLE:
            layout.addWidget(QLabel(
                "<i>dnspython not installed — showing A/PTR only. "
                "Run: pip install dnspython</i>"))

        layout.addWidget(QLabel("Target Domain:"))
        layout.addWidget(self.target_input)
        layout.addWidget(self.resolve_btn)
        layout.addWidget(QLabel("DNS Results:"))
        layout.addWidget(self.output)
        self.setLayout(layout)

        self.thread = None
        self.worker = None

    def start_lookup(self):
        domain = self.target_input.text()
        self.resolve_btn.setEnabled(False)
        self.output.setPlainText("Looking up...")

        self.thread = QThread()
        self.worker = DnsWorker(domain)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.result.connect(self.output.setPlainText)
        self.worker.error.connect(self.output.setPlainText)
        self.worker.done.connect(self.thread.quit)
        self.worker.done.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(lambda: self.resolve_btn.setEnabled(True))
        self.thread.start()
