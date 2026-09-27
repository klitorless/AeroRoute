import time, base64, socket
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, 
    QTableWidgetItem, QTextEdit, QLabel, QCheckBox, QFileDialog, 
    QTabWidget, QSpinBox, QComboBox, QMessageBox, QLineEdit
)
from PyQt6.QtCore import QTimer

class PacketAnalysisWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        sub_tabs = QTabWidget()
        
        # Sub-Tab 1: Capture & File Logging
        cap_widget = QWidget()
        cap_layout = QVBoxLayout()
        cap_controls = QHBoxLayout()
        
        self.cap_btn = QPushButton("Start Capture")
        self.cap_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        self.cap_btn.clicked.connect(self.toggle_capture)
        self.is_capturing = False
        
        self.log_checkbox = QCheckBox("Log Packets to File")
        self.log_path_btn = QPushButton("Select Log File...")
        self.log_path_btn.clicked.connect(self.select_log_file)
        self.log_file_path = "packet_capture.log"
        
        cap_controls.addWidget(self.cap_btn)
        cap_controls.addWidget(self.log_checkbox)
        cap_controls.addWidget(self.log_path_btn)
        
        self.cap_table = QTableWidget(0, 5)
        self.cap_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Destination", "Protocol", "Info / Length"])
        for i, w in enumerate([120, 140, 140, 90, 300]): self.cap_table.setColumnWidth(i, w)
        
        cap_layout.addLayout(cap_controls)
        sim_note = QLabel("<i>Demo mode: rows below are randomly generated for UI testing — "
                          "this is NOT live network traffic.</i>")
        sim_note.setWordWrap(True)
        cap_layout.addWidget(sim_note)
        cap_layout.addWidget(self.cap_table)
        cap_widget.setLayout(cap_layout)
        sub_tabs.addTab(cap_widget, "Packet Capture (Simulated)")
        
        # Sub-Tab 2: Packet Decrypter
        decrypt_widget = QWidget()
        decrypt_layout = QVBoxLayout()
        self.payload_input = QTextEdit()
        self.payload_input.setPlaceholderText("Paste raw hex, Base64, or encoded packet payload here...")
        
        dec_controls = QHBoxLayout()
        b64_btn = QPushButton("Decode Base64"); b64_btn.clicked.connect(self.decode_base64)
        hex_btn = QPushButton("Decode Hex"); hex_btn.clicked.connect(self.decode_hex)
        xor_btn = QPushButton("XOR Brute-Decode"); xor_btn.clicked.connect(self.decode_xor)
        dec_controls.addWidget(b64_btn); dec_controls.addWidget(hex_btn); dec_controls.addWidget(xor_btn)
        
        self.decrypt_output = QTextEdit(); self.decrypt_output.setReadOnly(True)
        self.decrypt_output.setPlaceholderText("Decoded plaintext output will appear here...")
        
        decrypt_layout.addWidget(QLabel("Raw Packet Payload:"))
        decrypt_layout.addWidget(self.payload_input)
        decrypt_layout.addLayout(dec_controls)
        decrypt_layout.addWidget(QLabel("Decrypted Output:"))
        decrypt_layout.addWidget(self.decrypt_output)
        decrypt_widget.setLayout(decrypt_layout)
        sub_tabs.addTab(decrypt_widget, "Packet Decrypter")

        # Sub-Tab 3: Packet Generator
        gen_widget = QWidget()
        gen_layout = QVBoxLayout()
        self.gen_target = QLineEdit("127.0.0.1")
        self.gen_port = QSpinBox(); self.gen_port.setRange(1, 65535); self.gen_port.setValue(80)
        self.gen_proto = QComboBox(); self.gen_proto.addItems(["TCP", "UDP", "ICMP"])
        self.gen_payload = QLineEdit("AeRoLogic Test Payload")
        send_gen_btn = QPushButton("Send Custom Packet")
        send_gen_btn.setStyleSheet("background-color: #2196F3; color: white;")
        send_gen_btn.clicked.connect(self.generate_packet)
        self.gen_output = QTextEdit(); self.gen_output.setReadOnly(True)
        
        gen_layout.addWidget(QLabel("Target IP:")); gen_layout.addWidget(self.gen_target)
        gen_layout.addWidget(QLabel("Port:")); gen_layout.addWidget(self.gen_port)
        gen_layout.addWidget(QLabel("Protocol:")); gen_layout.addWidget(self.gen_proto)
        gen_layout.addWidget(QLabel("Payload:")); gen_layout.addWidget(self.gen_payload)
        gen_layout.addWidget(send_gen_btn); gen_layout.addWidget(self.gen_output)
        gen_widget.setLayout(gen_layout)
        sub_tabs.addTab(gen_widget, "Packet Generator")

        layout.addWidget(sub_tabs)
        self.setLayout(layout)
        
        self.cap_timer = QTimer()
        self.cap_timer.timeout.connect(self.simulate_packet_capture)

    def select_log_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Select Log File", "", "Log Files (*.log);;All Files (*)")
        if path:
            self.log_file_path = path
            QMessageBox.information(self, "Log File Selected", f"Packets will be logged to:\n{path}")

    def toggle_capture(self):
        self.is_capturing = not self.is_capturing
        if self.is_capturing:
            self.cap_btn.setText("Stop Capture")
            self.cap_btn.setStyleSheet("background-color: #f44336; color: white;")
            self.cap_timer.start(1000)
        else:
            self.cap_btn.setText("Start Capture")
            self.cap_btn.setStyleSheet("background-color: #4CAF50; color: white;")
            self.cap_timer.stop()

    def simulate_packet_capture(self):
        import random
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        src = f"192.168.1.{random.randint(2, 254)}"
        dst = "8.8.8.8"
        proto = random.choice(["TCP", "UDP", "ICMP", "TLSv1.3"])
        info = f"Seq={random.randint(1000,9999)} Len={random.randint(64, 1500)}"
        
        row = self.cap_table.rowCount()
        if row > 100: self.cap_table.removeRow(0)
        row = self.cap_table.rowCount()
        self.cap_table.insertRow(row)
        self.cap_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.cap_table.setItem(row, 1, QTableWidgetItem(src))
        self.cap_table.setItem(row, 2, QTableWidgetItem(dst))
        self.cap_table.setItem(row, 3, QTableWidgetItem(proto))
        self.cap_table.setItem(row, 4, QTableWidgetItem(info))
        
        if self.log_checkbox.isChecked():
            try:
                with open(self.log_file_path, "a", encoding="utf-8") as f:
                    f.write(f"[{timestamp}] SRC: {src} | DST: {dst} | PROTO: {proto} | INFO: {info}\n")
            except Exception as e:
                print(f"Logging Error: {e}")

    def decode_base64(self):
        try:
            data = self.payload_input.toPlainText().strip()
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            self.decrypt_output.setPlainText(decoded)
        except Exception as e:
            self.decrypt_output.setPlainText(f"Base64 Decode Error: {e}")

    def decode_hex(self):
        try:
            data = self.payload_input.toPlainText().strip().replace(" ", "")
            decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
            self.decrypt_output.setPlainText(decoded)
        except Exception as e:
            self.decrypt_output.setPlainText(f"Hex Decode Error: {e}")

    def decode_xor(self):
        try:
            data = self.payload_input.toPlainText().encode('utf-8', errors='ignore')
            results = []
            for key in range(1, 256):
                unmasked = bytes([b ^ key for b in data])
                if all(32 <= b < 127 or b in (9, 10, 13) for b in unmasked[:20]):
                    results.append(f"Key 0x{key:02X}: {unmasked.decode('utf-8', errors='ignore')}")
            if results: self.decrypt_output.setPlainText("\n".join(results))
            else: self.decrypt_output.setPlainText("No clear ASCII results found via single-byte XOR brute-force.")
        except Exception as e:
            self.decrypt_output.setPlainText(f"XOR Decryption Error: {e}")

    def generate_packet(self):
        target = self.gen_target.text().strip()
        port = self.gen_port.value()
        proto = self.gen_proto.currentText()
        payload = self.gen_payload.text().encode("utf-8", errors="ignore")
        try:
            if proto == "TCP":
                with socket.create_connection((target, port), timeout=3) as s:
                    s.sendall(payload)
                self.gen_output.append(f"[+] TCP: sent {len(payload)} bytes to {target}:{port}")
            elif proto == "UDP":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(3)
                    s.sendto(payload, (target, port))
                self.gen_output.append(f"[+] UDP: sent {len(payload)} bytes to {target}:{port}")
            else:
                # ICMP needs raw sockets (admin/root) — kept simulated.
                self.gen_output.append(
                    f"[*] ICMP send is simulated (raw sockets need elevated privileges): "
                    f"payload '{self.gen_payload.text()}' to {target}")
        except Exception as e:
            self.gen_output.append(f"[!] {proto} send to {target}:{port} failed: {e}")