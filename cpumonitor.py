from collections import deque
import sys
import psutil
from PySide6.QtWidgets import (
    QApplication, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QFrame, QLineEdit, QPushButton,
    QAbstractItemView
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QFont
import pyqtgraph as pg
import time

UPDATE_INTERVAL_MS = 300  
HISTORY_LENGTH = 120
PALETTE = {
    'bg': '#0f1724',
    'panel': '#0b1220',
    'muted': '#94a3b8',
    'accent1': '#60a5fa',
    'accent2': '#34d399',
    'accent3': '#f472b6',
    'danger': '#fb7185'
}

pg.setConfigOptions(background=PALETTE['bg'], foreground='w')
class ProcessMonitorThread(QThread):
    updated = Signal(float, float)  

    def __init__(self, pid):
        super().__init__()
        self.pid = pid
        self.running = True

    def run(self):
        try:
            p = psutil.Process(self.pid)
            p.cpu_percent(interval=None)  
            while self.running:
                cpu = p.cpu_percent(interval=None)
                mem = p.memory_info().rss / (1024*1024)
                self.updated.emit(cpu, mem)
                time.sleep(0.3)  
        except Exception:
            self.updated.emit(0.0, 0.0)

    def stop(self):
        self.running = False
        self.wait()

def qlabel(text, size=12, bold=False):
    lbl = QLabel(text)
    f = lbl.font()
    f.setPointSize(size)
    f.setBold(bold)
    lbl.setFont(f)
    lbl.setStyleSheet(f"color: {PALETTE['muted']}")
    return lbl

class CpuMonitor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System & Process Monitor")
        self.resize(1200, 700)
        self.setStyleSheet(f"background:{PALETTE['bg']};")

        self.cpu_history = deque([0]*HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.mem_history = deque([0]*HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.net_sent_history = deque([0]*HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.net_recv_history = deque([0]*HISTORY_LENGTH, maxlen=HISTORY_LENGTH)

        self.selected_pid = None
        self.proc_cpu_hist = deque([0]*HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.proc_mem_hist = deque([0]*HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.proc_thread = None

        self.last_net = psutil.net_io_counters()
        self._setup_ui()

        self.timer = QTimer()
        self.timer.timeout.connect(self._update_all)
        self.timer.start(UPDATE_INTERVAL_MS)

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        left = QFrame()
        left.setStyleSheet(f"background:{PALETTE['panel']}; border-radius:8px;")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 12, 12)

        header = QLabel("System Overview")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setStyleSheet(f"color: {PALETTE['accent1']}")
        left_layout.addWidget(header)

        stats_row = QHBoxLayout()
        self.cpu_label = QLabel("CPU: -- %")
        self.cpu_label.setStyleSheet(f"color: {PALETTE['accent1']}; font-size: 16pt; font-weight: bold;")
        self.mem_label = QLabel("Memory: -- %")
        self.mem_label.setStyleSheet(f"color: {PALETTE['accent2']}; font-size: 16pt; font-weight: bold;")
        self.process_count_label = QLabel("Processes: --")
        self.process_count_label.setStyleSheet(f"color: {PALETTE['muted']}; font-size: 14pt; font-weight: bold;")
        stats_row.addWidget(self.cpu_label)
        stats_row.addStretch()
        stats_row.addWidget(self.mem_label)
        stats_row.addStretch()
        stats_row.addWidget(self.process_count_label)
        left_layout.addLayout(stats_row)

        self.cpu_plot = pg.PlotWidget(title='CPU Usage (%)')
        self._style_plot(self.cpu_plot)
        left_layout.addWidget(self.cpu_plot, 2)

        self.mem_plot = pg.PlotWidget(title='Memory Usage (%)')
        self._style_plot(self.mem_plot)
        left_layout.addWidget(self.mem_plot, 2)

        self.net_plot = pg.PlotWidget(title='Network (KB/s) — sent / recv')
        self._style_plot(self.net_plot)
        left_layout.addWidget(self.net_plot, 1)

        right = QFrame()
        right.setStyleSheet(f"background:{PALETTE['panel']}; border-radius:8px;")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(12, 12, 12, 12)

        header2 = QLabel("Processes")
        header_font2 = QFont()
        header_font2.setPointSize(16)
        header_font2.setBold(True)
        header2.setFont(header_font2)
        header2.setStyleSheet(f"color: {PALETTE['accent2']}")
        right_layout.addWidget(header2)

        search_row = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText('Filter by name or PID...')
        self.search_edit.textChanged.connect(self._populate_process_table)
        self.refresh_btn = QPushButton('Refresh')
        self.refresh_btn.clicked.connect(self._populate_process_table)
        search_row.addWidget(self.search_edit)
        search_row.addWidget(self.refresh_btn)
        right_layout.addLayout(search_row)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(['PID', 'Name', 'CPU %', 'Memory %', 'Memory MB', 'Threads', 'Status'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.cellClicked.connect(self._on_table_select)
        right_layout.addWidget(self.table, 3)

        detail_label = qlabel('Selected process details', size=12, bold=True)
        right_layout.addWidget(detail_label)

        self.proc_cpu_plot = pg.PlotWidget(title='Process CPU (%)')
        self._style_plot(self.proc_cpu_plot)
        self.proc_cpu_plot.getAxis('left').setTickFont(QFont('Arial', 12))
        right_layout.addWidget(self.proc_cpu_plot, 1)

        self.proc_mem_plot = pg.PlotWidget(title='Process Memory (MB)')
        self._style_plot(self.proc_mem_plot)
        self.proc_mem_plot.getAxis('left').setTickFont(QFont('Arial', 12))
        self.proc_mem_plot.setYRange(0, 1000)
        right_layout.addWidget(self.proc_mem_plot, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([600, 600])

        self._init_plot_items()

    def _style_plot(self, plot):
        plot.showGrid(x=False, y=True, alpha=0.2)
        plot.getAxis('left').setPen(pg.mkPen('w'))
        plot.getAxis('bottom').setPen(pg.mkPen('w'))
        plot.setBackground(PALETTE['panel'])
        plot.getPlotItem().getViewBox().setMenuEnabled(False)
        plot.getPlotItem().setMouseEnabled(x=False, y=False)

    def _init_plot_items(self):
        self.cpu_curve = self.cpu_plot.plot(list(self.cpu_history), pen=pg.mkPen(PALETTE['accent1'], width=2))
        self.mem_curve = self.mem_plot.plot(list(self.mem_history), pen=pg.mkPen(PALETTE['accent2'], width=2))
        self.net_sent_curve = self.net_plot.plot(list(self.net_sent_history), pen=pg.mkPen(PALETTE['accent1'], width=2))
        self.net_recv_curve = self.net_plot.plot(list(self.net_recv_history), pen=pg.mkPen(PALETTE['accent2'], width=2))

        self.proc_cpu_curve = self.proc_cpu_plot.plot(list(self.proc_cpu_hist), pen=pg.mkPen(PALETTE['accent3'], width=2))
        self.proc_mem_curve = self.proc_mem_plot.plot(list(self.proc_mem_hist), pen=pg.mkPen(PALETTE['accent2'], width=2))

    def _update_all(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        self.cpu_history.append(cpu)
        self.mem_history.append(mem)

        now_net = psutil.net_io_counters()
        interval_s = UPDATE_INTERVAL_MS / 1000.0
        sent_k = (now_net.bytes_sent - self.last_net.bytes_sent) / 1024.0 / interval_s
        recv_k = (now_net.bytes_recv - self.last_net.bytes_recv) / 1024.0 / interval_s
        self.net_sent_history.append(sent_k)
        self.net_recv_history.append(recv_k)
        self.last_net = now_net

        self.cpu_label.setText(f"CPU: {cpu:.1f} %")
        self.mem_label.setText(f"Memory: {mem:.1f} %")
        self.cpu_curve.setData(list(self.cpu_history))
        self.mem_curve.setData(list(self.mem_history))
        self.net_sent_curve.setData(list(self.net_sent_history))
        self.net_recv_curve.setData(list(self.net_recv_history))

        self._populate_process_table(update_only=False)

    def _fetch_processes(self):
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'status']):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        procs.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        return procs

    def _populate_process_table(self, update_only=False):
        search = self.search_edit.text().strip().lower() if self.search_edit else ''
        procs = self._fetch_processes()
        self.process_count_label.setText(f"Processes: {len(procs)}")
        self.table.setRowCount(0)

        for info in procs:
            pid = info.get('pid')
            name = info.get('name') or ''
            cpu = info.get('cpu_percent') or 0.0
            mem_percent = info.get('memory_percent') or 0.0
            threads = info.get('num_threads') or 0
            status = info.get('status') or ''

            mem_mb = 0
            try:
                mem_mb = psutil.Process(pid).memory_info().rss / (1024 * 1024)
            except Exception:
                pass

            if search and search not in name.lower() and search not in str(pid):
                continue

            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(str(pid)))
            self.table.setItem(r, 1, QTableWidgetItem(name))
            self.table.setItem(r, 2, QTableWidgetItem(f"{cpu:.1f}"))
            self.table.setItem(r, 3, QTableWidgetItem(f"{mem_percent:.1f}"))
            self.table.setItem(r, 4, QTableWidgetItem(f"{mem_mb:.0f}"))
            self.table.setItem(r, 5, QTableWidgetItem(str(threads)))
            self.table.setItem(r, 6, QTableWidgetItem(status))

        if self.selected_pid is not None:
            for row in range(self.table.rowCount()):
                pid_item = self.table.item(row, 0)
                if pid_item and int(pid_item.text()) == self.selected_pid:
                    self.table.selectRow(row)
                    break

    def _on_table_select(self, row, col):
        pid_item = self.table.item(row, 0)
        if not pid_item:
            return
        pid = int(pid_item.text())
        self.selected_pid = pid
        self.proc_cpu_hist = deque([0]*HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.proc_mem_hist = deque([0]*HISTORY_LENGTH, maxlen=HISTORY_LENGTH)
        self.proc_cpu_curve.setData(list(self.proc_cpu_hist))
        self.proc_mem_curve.setData(list(self.proc_mem_hist))

        if self.proc_thread:
            self.proc_thread.stop()
        self.proc_thread = ProcessMonitorThread(pid)
        self.proc_thread.updated.connect(self._update_selected_process)
        self.proc_thread.start()

    def _update_selected_process(self, cpu, mem):
        self.proc_cpu_hist.append(cpu)
        self.proc_mem_hist.append(mem)
        self.proc_cpu_curve.setData(list(self.proc_cpu_hist))
        self.proc_mem_curve.setData(list(self.proc_mem_hist))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CpuMonitor()
    window.show()
    sys.exit(app.exec())
