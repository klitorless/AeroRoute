import socket
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem
from PyQt6.QtCore import QTimer

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class SystemActivityWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        if not PSUTIL_AVAILABLE:
            warn = QLabel("<b>Warning:</b> 'psutil' library is not installed. Install via: pip install psutil")
            warn.setStyleSheet("color: red;")
            layout.addWidget(warn)
            self.setLayout(layout)
            return

        layout.addWidget(QLabel("<b>Local Network Interfaces (I/O Counters):</b>"))
        self.iface_table = QTableWidget(0, 5)
        self.iface_table.setHorizontalHeaderLabels(["Interface", "Bytes Sent", "Bytes Recv", "Packets Sent", "Packets Recv"])
        for i, w in enumerate([150, 130, 130, 130, 130]): self.iface_table.setColumnWidth(i, w)
        layout.addWidget(self.iface_table)

        layout.addWidget(QLabel("<b>Active Laptop Connections (Process $\rightarrow$ Remote Server):</b>"))
        self.conn_table = QTableWidget(0, 6)
        self.conn_table.setHorizontalHeaderLabels(["Process", "PID", "Protocol", "Laptop Address (Local)", "Remote Server", "Status"])
        for i, w in enumerate([150, 70, 80, 180, 180, 120]): self.conn_table.setColumnWidth(i, w)
        layout.addWidget(self.conn_table)

        self.setLayout(layout)
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_stats)
        self.timer.start(2000)
        self.refresh_stats()

    def refresh_stats(self):
        if not PSUTIL_AVAILABLE: return
        try:
            io_counters = psutil.net_io_counters(pernic=True)
            self.iface_table.setRowCount(len(io_counters))
            for row, (iface, stats) in enumerate(io_counters.items()):
                self.iface_table.setItem(row, 0, QTableWidgetItem(iface))
                self.iface_table.setItem(row, 1, QTableWidgetItem(f"{stats.bytes_sent:,}"))
                self.iface_table.setItem(row, 2, QTableWidgetItem(f"{stats.bytes_recv:,}"))
                self.iface_table.setItem(row, 3, QTableWidgetItem(f"{stats.packets_sent:,}"))
                self.iface_table.setItem(row, 4, QTableWidgetItem(f"{stats.packets_recv:,}"))

            conns = psutil.net_connections(kind='inet')[:60]
            self.conn_table.setRowCount(len(conns))
            for row, c in enumerate(conns):
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "Awaiting / Listening"
                status = c.status if c.status else "-"
                pid = str(c.pid) if c.pid else "-"
                pname = "-"
                if c.pid:
                    try: pname = psutil.Process(c.pid).name()
                    except: pass
                
                self.conn_table.setItem(row, 0, QTableWidgetItem(pname))
                self.conn_table.setItem(row, 1, QTableWidgetItem(pid))
                self.conn_table.setItem(row, 2, QTableWidgetItem(proto))
                self.conn_table.setItem(row, 3, QTableWidgetItem(laddr))
                self.conn_table.setItem(row, 4, QTableWidgetItem(raddr))
                self.conn_table.setItem(row, 5, QTableWidgetItem(status))
        except Exception as e:
            print(f"System Activity Refresh Error: {e}")