import sys
import os
import json
import time
import socket
import subprocess
import re
import ipaddress
import urllib.request
import logging

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

# Reverse-DNS cache: gethostbyaddr is slow and was previously called on
# every ping result for every target. Resolved once, reused afterwards.
_RDNS_CACHE = {}

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QLineEdit, QPushButton, QVBoxLayout, QWidget, QHBoxLayout, 
    QLabel, QComboBox, QSpinBox, QFileDialog, QTabWidget, QSystemTrayIcon, QMenu,
    QProgressBar, QGroupBox, QMessageBox
)
from PyQt6.QtGui import QColor, QIcon, QPixmap, QPainter, QAction, QFont
from PyQt6.QtCore import Qt, QThreadPool, QRunnable, pyqtSignal, QTimer, QObject, QThread

import pyqtgraph as pg

# Local AeRoLogic Modules
from utils import AboutDialog, TraceDialog, is_valid_target, get_clean_target, resolve_hostname
from modules.system_activity import SystemActivityWidget
from modules.packet_analysis import PacketAnalysisWidget
from modules.dns_tools import DNSToolsWidget
from modules.ssl_scanner import SSLScannerWidget
from modules.whois_utils import WhoisWidget
from modules.ping_stats import new_target_state, record_result, mark_inflight, successful_latencies
from modules.target_io import parse_target_import_json, serialize_targets, MAX_IMPORTS

# Handle Speedtest Dependency
try:
    import speedtest
    SPEEDTEST_AVAILABLE = True
except ImportError:
    SPEEDTEST_AVAILABLE = False

# ==========================================
# Worker Threads & Signals
# ==========================================

class PingSignals(QObject):
    finished = pyqtSignal(str, bool, float, str)
    loc_found = pyqtSignal(str, str)

class LocationFetcher(QRunnable):
    def __init__(self, ip, signals):
        super().__init__()
        self.ip = ip
        self.signals = signals

    def run(self):
        try:
            if ipaddress.ip_address(self.ip).is_private:
                return
            url = f"https://ipwho.is/{self.ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'AeRoRoute/1.0'})
            with urllib.request.urlopen(req, timeout=3) as res:
                d = json.loads(res.read().decode())
                if d.get("success") is True:
                    city = d.get("city", "Unknown")
                    country = d.get("country", "Unknown")
                    self.signals.loc_found.emit(self.ip, f"{city}, {country}")
        except Exception as e:
            logging.debug("Location lookup failed for %s: %s", self.ip, e)

class PingTask(QRunnable):
    def __init__(self, ip, size, method, signals):
        super().__init__()
        self.ip = ip
        self.size = size
        self.method = method
        self.signals = signals

    def run(self):
        success, latency = False, 0.0
        if self.method == "ICMP":
            cmd = ['ping', '-n', '1', '-w', '1000', '-l', str(self.size), self.ip] if os.name == 'nt' else ['ping', '-c', '1', '-W', '1', '-s', str(self.size), self.ip]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=3)
                if "TTL" in out or "1 received" in out or "bytes from" in out:
                    success = True
                    match = re.search(r'time[=<]\s*([\d\.]+)', out, re.IGNORECASE)
                    latency = float(match.group(1)) if match else 0.0
            except Exception as e:
                logging.debug("ICMP ping failed for %s: %s", self.ip, e)
        else:
            start = time.perf_counter()
            try:
                with socket.create_connection((self.ip, 443), timeout=2):
                    latency = (time.perf_counter() - start) * 1000
                    success = True
            except Exception as e:
                logging.debug("TCP ping failed for %s: %s", self.ip, e)

        host = _RDNS_CACHE.get(self.ip)
        if host is None:
            try:
                host, _, _ = socket.gethostbyaddr(self.ip)
            except Exception as e:
                logging.debug("Reverse DNS failed for %s: %s", self.ip, e)
                host = self.ip
            _RDNS_CACHE[self.ip] = host

        self.signals.finished.emit(self.ip, success, latency, host)

# ==========================================
# Speed Test Module Integration
# ==========================================

class SpeedTestWorker(QObject):
    progress = pyqtSignal(str, int)
    results = pyqtSignal(dict)
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def run(self):
        try:
            st = speedtest.Speedtest(secure=True)
            
            self.progress.emit("Finding optimal server...", 20)
            st.get_best_server()
            
            self.progress.emit("Testing Download Speed...", 40)
            dl_speed = st.download() / 1_000_000  # Convert bps to Mbps
            
            self.progress.emit("Testing Upload Speed...", 70)
            up_speed = st.upload() / 1_000_000    # Convert bps to Mbps
            
            self.progress.emit("Finalizing...", 95)
            res = st.results.dict()
            
            self.results.emit({
                "ping": res["ping"],
                "download": dl_speed,
                "upload": up_speed,
                "server": res["server"]["sponsor"],
                "location": res["server"]["name"]
            })
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.progress.emit("Idle", 100)
            self.finished.emit()

class SpeedTestTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        # UI Elements
        self.status_lbl = QLabel("Status: Ready to test")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        
        self.run_btn = QPushButton("Run Bandwidth Test")
        self.run_btn.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold; padding: 10px;")
        self.run_btn.clicked.connect(self.start_test)
        
        if not SPEEDTEST_AVAILABLE:
            self.run_btn.setEnabled(False)
            self.run_btn.setText("Missing speedtest-cli (Run: pip install speedtest-cli)")
            self.run_btn.setStyleSheet("background-color: #9e9e9e; color: white; padding: 10px;")
            
        # Results Display
        results_group = QGroupBox("Speed Test Results")
        results_layout = QVBoxLayout()
        
        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        
        self.ping_lbl = QLabel("Ping: - ms")
        self.ping_lbl.setFont(font)
        
        self.dl_lbl = QLabel("Download: - Mbps")
        self.dl_lbl.setFont(font)
        self.dl_lbl.setStyleSheet("color: #4CAF50;")
        
        self.ul_lbl = QLabel("Upload: - Mbps")
        self.ul_lbl.setFont(font)
        self.ul_lbl.setStyleSheet("color: #FF9800;")
        
        self.server_lbl = QLabel("Server: -")
        
        results_layout.addWidget(self.ping_lbl)
        results_layout.addWidget(self.dl_lbl)
        results_layout.addWidget(self.ul_lbl)
        results_layout.addWidget(self.server_lbl)
        results_group.setLayout(results_layout)
        
        layout.addWidget(self.status_lbl)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.run_btn)
        layout.addWidget(results_group)
        layout.addStretch()
        
        self.setLayout(layout)
        
        self.thread = None
        self.worker = None

    def start_test(self):
        self.run_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.ping_lbl.setText("Ping: Testing...")
        self.dl_lbl.setText("Download: Testing...")
        self.ul_lbl.setText("Upload: Testing...")
        self.server_lbl.setText("Server: Locating...")
        
        self.thread = QThread()
        self.worker = SpeedTestWorker()
        self.worker.moveToThread(self.thread)
        
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.update_progress)
        self.worker.results.connect(self.display_results)
        self.worker.error.connect(self.display_error)
        
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(lambda: self.run_btn.setEnabled(True))
        
        self.thread.start()

    def update_progress(self, msg, val):
        self.status_lbl.setText(f"Status: {msg}")
        self.progress_bar.setValue(val)

    def display_results(self, data):
        self.ping_lbl.setText(f"Ping: {data['ping']:.1f} ms")
        self.dl_lbl.setText(f"Download: {data['download']:.2f} Mbps")
        self.ul_lbl.setText(f"Upload: {data['upload']:.2f} Mbps")
        self.server_lbl.setText(f"Server: {data['server']} ({data['location']})")

    def display_error(self, err_msg):
        QMessageBox.critical(self, "Speed Test Error", f"An error occurred:\n{err_msg}")
        self.status_lbl.setText("Status: Error")

# ==========================================
# Main Application Window
# ==========================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScanTools PRO - AeRoLogic Modular Suite")
        self.setGeometry(100, 100, 1600, 750)
        self.stats = {}
        self.monitoring_enabled = True
        
        # Centralized signal instance
        self.ping_signals = PingSignals()
        self.ping_signals.finished.connect(self.on_result)
        self.ping_signals.loc_found.connect(self.update_loc_cell)

        self.init_system_tray()

        self.tabs = QTabWidget()
        self.ping_tab = QWidget()
        self.init_ping_tab()
        
        # Add Tabs
        self.tabs.addTab(self.ping_tab, "Discovery & Ping Monitor")
        self.tabs.addTab(SystemActivityWidget(), "System Network Activity")
        self.tabs.addTab(SpeedTestTab(), "Bandwidth Speed Test")
        self.tabs.addTab(PacketAnalysisWidget(), "Packet Analysis & Decrypter")
        self.tabs.addTab(DNSToolsWidget(), "DNS & Internet Intelligence")
        self.tabs.addTab(SSLScannerWidget(), "SSL & Security")
        self.tabs.addTab(WhoisWidget(), "WHOIS & Utilities")

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        
        footer = QHBoxLayout()
        footer.addWidget(QLabel("© 2026 AeRoLogic. All rights reserved."))
        about_btn = QPushButton("About")
        about_btn.setFixedWidth(80)
        about_btn.setStyleSheet("background-color: #b86500; color: white;")
        about_btn.clicked.connect(lambda: AboutDialog(self).exec())
        footer.addWidget(about_btn)
        footer.addStretch()
        main_layout.addLayout(footer)
        
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.run_updates)
        self.timer.start(3000)
        QTimer.singleShot(1000, self.add_gateway)

    def init_system_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QColor(33, 150, 243))
        painter.drawEllipse(4, 4, 56, 56)
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "NET")
        painter.end()
        self.tray_icon.setIcon(QIcon(pixmap))
        
        tray_menu = QMenu()
        self.toggle_monitoring_action = QAction("Enable Ping Monitoring", self, checkable=True)
        self.toggle_monitoring_action.setChecked(True)
        self.toggle_monitoring_action.triggered.connect(lambda c: setattr(self, 'monitoring_enabled', c))
        tray_menu.addAction(self.toggle_monitoring_action)
        tray_menu.addSeparator()
        tray_menu.addAction("Show Application", self.showNormal)
        tray_menu.addAction("Exit Suite", QApplication.instance().quit)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

    def init_ping_tab(self):
        layout = QVBoxLayout()
        self.table = QTableWidget(0, 14)
        self.table.setHorizontalHeaderLabels([
            "Target", "IP", "Loc", "Status", "Lat", "Avg", "Jitter", "Loss", "History", "Graph", "Control", "Method", "Trace", "Action"
        ])
        widths = [220, 120, 175, 100, 65, 65, 65, 50, 180, 240, 50, 80, 50, 70]
        for i, w in enumerate(widths):
            self.table.setColumnWidth(i, w)
        
        self.ip_input = QLineEdit()
        self.ip_input.returnPressed.connect(self.add_device)
        
        # [SECURITY FIX] Bound the packet size to standard ICMP limits
        self.size_input = QSpinBox()
        self.size_input.setRange(1, 65500)
        self.size_input.setValue(32)
        self.size_input.setFixedWidth(70)
        
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(500, 10000)
        self.interval_spin.setValue(3000)
        self.interval_spin.setSuffix(" ms")
        self.interval_spin.valueChanged.connect(lambda v: self.timer.setInterval(v))
        
        add_btn = QPushButton("Add Target")
        add_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        add_btn.clicked.connect(lambda: self.add_device())
        exp_btn = QPushButton("Export")
        exp_btn.clicked.connect(self.export_targets)
        imp_btn = QPushButton("Import")
        imp_btn.clicked.connect(self.import_targets)
        
        h = QHBoxLayout()
        h.addWidget(QLabel("IP/Host:"))
        h.addWidget(self.ip_input)
        h.addWidget(QLabel("Bytes:"))
        h.addWidget(self.size_input)
        h.addWidget(QLabel("Interval:"))
        h.addWidget(self.interval_spin)
        h.addWidget(add_btn)
        h.addWidget(exp_btn)
        h.addWidget(imp_btn)
        
        layout.addWidget(self.table)
        layout.addLayout(h)
        self.ping_tab.setLayout(layout)

    def closeEvent(self, event):
        self.timer.stop()
        event.accept()
        
    def add_gateway(self):
        try:
            import netifaces
            gw = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, [None])[0]
            if gw:
                self.ip_input.setText(gw)
                self.add_device("Gateway")
        except Exception as e:
            # netifaces is optional; a missing/broken install only means no
            # gateway shortcut, which is not worth surfacing to the user.
            logging.debug("Gateway auto-detect skipped: %s", e)

    def add_device(self, name="-", method="ICMP"):
        user_input = self.ip_input.text().strip()
        target_host = get_clean_target(user_input)
        target_ip = resolve_hostname(target_host)
        if not target_ip or not is_valid_target(target_ip) or target_ip in self.stats:
            return
        
        self.stats[target_ip] = new_target_state()
        QThreadPool.globalInstance().start(LocationFetcher(target_ip, self.ping_signals))
        
        row = self.table.rowCount()
        self.table.insertRow(row)
        for i in range(14):
            self.table.setItem(row, i, QTableWidgetItem("-"))
        self.table.setItem(row, 1, QTableWidgetItem(target_ip))
        self.table.setItem(row, 0, QTableWidgetItem(name if name != "-" else target_host))
        
        plot_widget = pg.PlotWidget()
        plot_widget.hideAxis('left')
        plot_widget.hideAxis('bottom')
        self.stats[target_ip]["curve"] = plot_widget.plot(pen='y')
        self.table.setCellWidget(row, 9, plot_widget)
        
        cb = QComboBox()
        cb.addItems(["ICMP", "TCP"])
        cb.setCurrentText(method)
        self.table.setCellWidget(row, 11, cb)
        
        btn = QPushButton("Pause")
        btn.setFixedWidth(50)
        btn.setStyleSheet("background-color: #FF9800; color: white;")
        btn.clicked.connect(self.toggle_row)
        self.table.setCellWidget(row, 10, btn)
        
        tr = QPushButton("Trace")
        tr.setFixedWidth(50)
        tr.setStyleSheet("background-color: #2196F3; color: white;")
        tr.clicked.connect(lambda: TraceDialog(target_ip, self).show())
        self.table.setCellWidget(row, 12, tr)
        
        rm = QPushButton("Remove")
        rm.setFixedWidth(70)
        rm.setStyleSheet("background-color: #f44336; color: white;")
        rm.clicked.connect(self.remove_row)
        self.table.setCellWidget(row, 13, rm)
        
        hist = QComboBox()
        hist.addItem("Max: - | Min: -")
        self.table.setCellWidget(row, 8, hist)
        self.ip_input.clear()

    def update_loc_cell(self, ip, loc):
        row = self.find_row(ip)
        if row != -1:
            self.table.item(row, 2).setText(loc)

    def find_row(self, target):
        return next((r for r in range(self.table.rowCount()) if self.table.item(r, 1).text() == target), -1)
    
    def toggle_row(self):
        btn = self.sender()
        row = self.table.indexAt(btn.pos()).row()
        target = self.table.item(row, 1).text()
        self.stats[target]["active"] = not self.stats[target]["active"]
        btn.setText("Pause" if self.stats[target]["active"] else "Play")
        btn.setStyleSheet("background-color: #FF9800" if self.stats[target]["active"] else "background-color: #4CAF50")
        
    def remove_row(self):
        row = self.table.indexAt(self.sender().pos()).row()
        self.stats.pop(self.table.item(row, 1).text(), None)
        self.table.removeRow(row)

    def run_updates(self):
        if not self.monitoring_enabled:
            return
        for r in range(self.table.rowCount()):
            target = self.table.item(r, 1).text()
            # mark_inflight() claims the probe slot: a target with a probe
            # already outstanding is skipped, so slow targets can never
            # stack up overlapping probes.
            if not mark_inflight(self.stats, target):
                continue
            pkg_size = self.size_input.value()
            task = PingTask(target, pkg_size, self.table.cellWidget(r, 11).currentText(), self.ping_signals)
            QThreadPool.globalInstance().start(task)

    def on_result(self, target, success, lat, host):
        row = self.find_row(target)
        if row == -1:
            return
        s = self.stats.get(target)
        if s is None:
            return  # row was removed while the probe was in flight
        # record_result() clears the inflight flag and derives metrics.
        # Failed probes affect loss only — they never invent latency samples.
        m = record_result(s, success, lat)

        stat = "OFFLINE" if not success else ("ONLINE" if lat < 100 else "HIGH LATENCY")
        status_color = "#B71C1C" if not success else ("#1B5E20" if lat < 100 else "#F57F17")

        for i in range(8):
            self.table.item(row, i).setBackground(QColor("#B71C1C" if not success else Qt.GlobalColor.transparent))

        self.table.item(row, 0).setText(host)
        self.table.item(row, 3).setText(stat)
        self.table.item(row, 3).setBackground(QColor(status_color))
        self.table.item(row, 4).setText(f"{lat:.1f}ms" if success else "-")
        self.table.item(row, 5).setText(f"{m['avg']:.1f}ms" if m["avg"] is not None else "-")
        self.table.item(row, 6).setText(f"{m['jitter']:.1f}ms" if success else "-")
        self.table.item(row, 7).setText(f"{m['loss']:.0f}%")

        hist = self.table.cellWidget(row, 8)
        if m["max"] is not None:
            hist.setItemText(0, f"Max: {m['max']:.1f} | Min: {m['min']:.1f}")
        else:
            hist.setItemText(0, "Max: - | Min: -")
        hist.insertItem(1, f"Last: {lat:.1f}ms" if success else "Last: Offline")

        while hist.count() > 20:
            hist.removeItem(hist.count() - 1)

        if s["curve"]:
            s["curve"].setData(successful_latencies(s)[-50:])

    def export_targets(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Targets", "", "JSON (*.json)")
        if path:
            pairs = [(self.table.item(r, 1).text(), self.table.cellWidget(r, 11).currentText())
                     for r in range(self.table.rowCount())]
            try:
                with open(path, 'w') as f:
                    f.write(serialize_targets(pairs))
            except OSError as e:
                print(f"[ERROR] Failed to export targets: {e}")

    def import_targets(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Targets", "", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, 'r') as f:
                text = f.read()
        except OSError as e:
            print(f"[ERROR] Failed to import targets: {e}")
            return
        try:
            # Parsing, validation, dedupe, and the import cap all live in
            # modules/target_io.py (unit tested); the GUI just adds results.
            entries = parse_target_import_json(text, existing=self.stats.keys())
        except ValueError as e:
            print(f"[ERROR] Failed to import targets: {e}")
            return
        if len(entries) == MAX_IMPORTS:
            print(f"[WARNING] Import cap reached. Only {MAX_IMPORTS} targets loaded.")
        for target, method in entries:
            self.ip_input.setText(target)
            self.add_device(method=method)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())