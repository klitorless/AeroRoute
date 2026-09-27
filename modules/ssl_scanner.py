from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from PyQt6.QtCore import QObject, QThread, pyqtSignal

from .ssl_service import perform_ssl_scan


class SslWorker(QObject):
    """Runs perform_ssl_scan() off the GUI thread.

    UI -> Worker -> Service -> Network -> Signal -> UI.
    Never touches widgets directly; results return via signals.
    """
    result = pyqtSignal(str)
    error = pyqtSignal(str)
    done = pyqtSignal()

    def __init__(self, host):
        super().__init__()
        self.host = host

    def run(self):
        try:
            self.result.emit(perform_ssl_scan(self.host))
        except ValueError as e:
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(f"SSL Scan Error: {e}")
        finally:
            self.done.emit()


class SSLScannerWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.target_input = QLineEdit("google.com")
        self.scan_btn = QPushButton("Scan SSL/TLS Certificate")
        self.scan_btn.setStyleSheet("background-color: #9C27B0; color: white;")
        self.scan_btn.clicked.connect(self.start_scan)
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        layout.addWidget(QLabel("Target Host (Port 443):"))
        layout.addWidget(self.target_input)
        layout.addWidget(self.scan_btn)
        layout.addWidget(QLabel("Certificate Details:"))
        layout.addWidget(self.output)
        self.setLayout(layout)

        self.thread = None
        self.worker = None

    def start_scan(self):
        host = self.target_input.text()
        self.scan_btn.setEnabled(False)
        self.output.setPlainText("Scanning...")

        self.thread = QThread()
        self.worker = SslWorker(host)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.result.connect(self.output.setPlainText)
        self.worker.error.connect(self.output.setPlainText)
        self.worker.done.connect(self.thread.quit)
        self.worker.done.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(lambda: self.scan_btn.setEnabled(True))
        self.thread.start()
