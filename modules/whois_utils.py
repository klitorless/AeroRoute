from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from PyQt6.QtCore import QObject, QThread, pyqtSignal

from .whois_service import perform_whois


class WhoisWorker(QObject):
    """Runs perform_whois() off the GUI thread.

    UI -> Worker -> Service -> Network -> Signal -> UI.
    Never touches widgets directly; results return via signals.
    """
    result = pyqtSignal(str)
    error = pyqtSignal(str)
    done = pyqtSignal()

    def __init__(self, query):
        super().__init__()
        self.query = query

    def run(self):
        try:
            self.result.emit(perform_whois(self.query))
        except ValueError as e:
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(f"WHOIS Error: {e}")
        finally:
            self.done.emit()


class WhoisWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.target_input = QLineEdit("example.com")
        self.whois_btn = QPushButton("Query WHOIS")
        self.whois_btn.setStyleSheet("background-color: #FF5722; color: white;")
        self.whois_btn.clicked.connect(self.start_query)
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        layout.addWidget(QLabel("Domain or IP:"))
        layout.addWidget(self.target_input)
        layout.addWidget(self.whois_btn)
        layout.addWidget(QLabel("WHOIS Response:"))
        layout.addWidget(self.output)
        self.setLayout(layout)

        self.thread = None
        self.worker = None

    def start_query(self):
        query = self.target_input.text()
        self.whois_btn.setEnabled(False)
        self.output.setPlainText("Querying...")

        self.thread = QThread()
        self.worker = WhoisWorker(query)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.result.connect(self.output.setPlainText)
        self.worker.error.connect(self.output.setPlainText)
        self.worker.done.connect(self.thread.quit)
        self.worker.done.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(lambda: self.whois_btn.setEnabled(True))
        self.thread.start()
