import os
import sys
import ctypes
import time
import threading,queue
from datetime import datetime
import socket
import psutil,subprocess
import pydivert
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import customtkinter as ctk
from graphviz import Digraph
import tempfile
from PIL import Image, ImageTk
import uuid


FILTER = "tcp"
MAX_PAYLOAD = 200

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)
    sys.exit()

def get_process_name_and_exe(src_ip, src_port, dst_ip, dst_port):
    for conn in psutil.net_connections(kind='inet'):
        try:
            if ((conn.laddr.ip == src_ip and conn.laddr.port == src_port) or
                (conn.raddr and conn.raddr.ip == dst_ip and conn.raddr.port == dst_port)):
                p = psutil.Process(conn.pid)
                return p.name(), p.exe()
        except:
            continue
    return "N/A", "N/A"

import hashlib

def safe_node_id(text: str) -> str:
    return "n" + hashlib.md5(text.encode()).hexdigest()


def parse_http(data_bytes):
    try:
        text = data_bytes.decode('utf-8', errors='replace')
        lines = text.splitlines()
        if lines:
            first_line = lines[0]
            headers = "\n".join(lines[1:10])
            return first_line, headers
    except:
        return None, None
    return None, None

def resolve_domain(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, log_callback):
        super().__init__()
        self.log_callback = log_callback

    def on_created(self, event):
        self.log_callback("CREATED", event.src_path)

    def on_deleted(self, event):
        self.log_callback("DELETED", event.src_path)

    def on_modified(self, event):
        self.log_callback("UPDATED", event.src_path)

    def on_moved(self, event):
        self.log_callback("MOVED", f"{event.src_path} → {event.dest_path}")

class FileMonitor:
    def __init__(self, path, log_callback):
        self.path = path
        self.log_callback = log_callback
        self.event_handler = FileMonitorHandler(self.log_callback)
        self.observer = Observer()

    def start(self):
        if not os.path.exists(self.path):
            self.log_callback("SYSTEM", f"Path does not exist: {os.path.abspath(self.path)}")
            return
        self.observer.schedule(self.event_handler, self.path, recursive=True)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()


class TaskWindow(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("📊 Process Monitor")
        self.geometry("1000x600")
        self.configure(fg_color="#0b0b0b")

        label1 = ctk.CTkLabel(self, text="🟢 Started Tasks", text_color="#00ff00", font=("Consolas", 15, "bold"))
        label2 = ctk.CTkLabel(self, text="🔴 Closed Tasks", text_color="#ff2b2b", font=("Consolas", 15, "bold"))
        label3 = ctk.CTkLabel(self, text="📄 Closed List", text_color="#cccccc", font=("Consolas", 15, "bold"))
        label4 = ctk.CTkLabel(self, text="👤 Parent Process", text_color="#ffff00", font=("Consolas", 15, "bold"))

        label1.grid(row=0, column=0, sticky="ew", pady=(5,0))
        label2.grid(row=0, column=1, sticky="ew", pady=(5,0))
        label3.grid(row=2, column=0, sticky="ew", pady=(5,0))
        label4.grid(row=2, column=1, sticky="ew", pady=(5,0))

        self.text1 = ctk.CTkTextbox(self, fg_color="#111111", text_color="#00ff00", font=("Consolas", 13))
        self.text2 = ctk.CTkTextbox(self, fg_color="#111111", text_color="#ff2b2b", font=("Consolas", 13))
        self.text3 = ctk.CTkTextbox(self, fg_color="#111111", text_color="#cccccc", font=("Consolas", 13))
        self.text4 = ctk.CTkTextbox(self, fg_color="#111111", text_color="#ffff00", font=("Consolas", 13))

        self.text1.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.text2.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        self.text3.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)
        self.text4.grid(row=3, column=1, sticky="nsew", padx=5, pady=5)

        self.rowconfigure(1, weight=1)
        self.rowconfigure(3, weight=1)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        self.stop_task_btn = ctk.CTkButton(self, text="⏹ Stop Task Monitor",
                                           fg_color="#ff2b2b", hover_color="#990000",
                                           text_color="white",
                                           command=self.destroy)
        self.stop_task_btn.grid(row=4, column=0, columnspan=2, pady=10)

        self.task_running = True
        t = threading.Thread(target=self.monitor_tasks, daemon=True)
        t.start()

    def monitor_tasks(self):
        seen = {}
        while self.task_running and self.winfo_exists():
            current_pids = set(psutil.pids())
            new_pids = current_pids - set(seen.keys())
            for pid in new_pids:
                try:
                    p = psutil.Process(pid)
                    name = p.name()
                    parent = p.parent().name() if p.parent() else "None"
                    ts = datetime.now().strftime("%H:%M:%S")
                    self.text1.insert("end", f"[{ts}] {name} (PID={pid})\n")
                    self.text4.insert("end", f"[{ts}] {name} ← {parent}\n")
                    self.text1.see("end")
                    self.text4.see("end")
                    seen[pid] = name
                except: pass
            closed_pids = set(seen.keys()) - current_pids
            for pid in closed_pids:
                ts = datetime.now().strftime("%H:%M:%S")
                self.text2.insert("end", f"[{ts}] {seen[pid]} (PID={pid})\n")
                self.text3.insert("end", f"[{ts}] {seen[pid]}\n")
                self.text2.see("end")
                self.text3.see("end")
                del seen[pid]
            time.sleep(1)

def parse_http(data_bytes):
    try:
        text = data_bytes.decode('utf-8', errors='replace')
        lines = text.splitlines()
        if lines:
            first_line = lines[0]
            headers = "\n".join(lines[1:10])
            return first_line, headers
    except:
        return None, None
    return None, None

def resolve_domain_safe(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

class NetworkMonitorWindow(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("🌐 Network Monitor")
        self.geometry("1000x650")
        self.configure(fg_color="#0b0b0b")

        self.process_filter_var = ctk.StringVar()
        self.ip_filter_var = ctk.StringVar()

        filter_frame = ctk.CTkFrame(self, fg_color="#1b1b1b")
        filter_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(filter_frame, text="Process Filter:", text_color="#ffffff").pack(side="left", padx=5)
        self.process_entry = ctk.CTkEntry(filter_frame, width=200, textvariable=self.process_filter_var)
        self.process_entry.pack(side="left", padx=5)
        ctk.CTkLabel(filter_frame, text="IP Filter:", text_color="#ffffff").pack(side="left", padx=5)
        self.ip_entry = ctk.CTkEntry(filter_frame, width=200, textvariable=self.ip_filter_var)
        self.ip_entry.pack(side="left", padx=5)
        ctk.CTkButton(filter_frame, text="Apply Filter", command=self.apply_filter).pack(side="left", padx=5)
        ctk.CTkButton(filter_frame, text="Stop Network Monitor", fg_color="#ff2b2b", hover_color="#990000",
                      command=self.stop_monitor).pack(side="right", padx=5)
    
        ctk.CTkButton(filter_frame, text="Graph", fg_color="#ffaa00", hover_color="#cc8800",
              command=self.show_graph).pack(side="right", padx=5)


        self.text_box = ctk.CTkTextbox(self, fg_color="#111111", text_color="#cccccc", font=("Consolas", 13))
        self.text_box.pack(fill="both", expand=True, padx=10, pady=5)

        self.text_box.tag_config("time", foreground="#aaaaaa")
        self.text_box.tag_config("process", foreground="#00ff00")
        self.text_box.tag_config("exe", foreground="#ff8800")
        self.text_box.tag_config("ip", foreground="#00aaff")
        self.text_box.tag_config("payload", foreground="#ffff00")
        self.text_box.tag_config("gray", foreground="#888888")

        self.running = True
        self.packet_queue = queue.Queue()
        self.all_packets = []

        threading.Thread(target=self.monitor_network_thread, daemon=True).start()
        self.after(100, self.process_packet_queue)

    def monitor_network_thread(self):
        try:
            with pydivert.WinDivert("tcp") as w:
                for packet in w:
                    if not self.running:
                        break
                    self.packet_queue.put(packet)
                    w.send(packet)
        except Exception as e:
            self.packet_queue.put({"error": str(e)})
    def show_graph(self):
        if not hasattr(self, "_graph_window") or not getattr(self, "_graph_window", None):
            self._graph_window = ctk.CTkToplevel(self)
            win = self._graph_window
            win.title("🌐 Network Graph")
            win.geometry("1200x850")
            win.configure(fg_color="#0b0b0b")

            canvas_frame = ctk.CTkFrame(win)
            canvas_frame.pack(fill="both", expand=True)

            self._graph_canvas = ctk.CTkCanvas(canvas_frame, bg="#0b0b0b", highlightthickness=0)
            h_scroll = ctk.CTkScrollbar(canvas_frame, orientation="horizontal", command=self._graph_canvas.xview)
            v_scroll = ctk.CTkScrollbar(canvas_frame, orientation="vertical", command=self._graph_canvas.yview)
            self._graph_canvas.configure(xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)

            h_scroll.pack(side="bottom", fill="x")
            v_scroll.pack(side="right", fill="y")
            self._graph_canvas.pack(side="left", fill="both", expand=True)

            def zoom(event):
                factor = 1.1 if event.delta > 0 else 0.9
                self._graph_canvas.scale("all", 0, 0, factor, factor)
                self._graph_canvas.config(scrollregion=self._graph_canvas.bbox("all"))

            self._graph_canvas.bind("<MouseWheel>", zoom)

        def update_graph():
            if not self._graph_window.winfo_exists():
                return  

            dot = Digraph(comment="Network Graph", format="png", engine="fdp")

            dot.attr(bgcolor="black")
            dot.attr("node", style="filled", fontname="Consolas", fontsize="12")

            edges = set()
            for pkt in self.all_packets:
                try:
                    src_ip, dst_ip = pkt.src_addr, pkt.dst_addr
                    src_port, dst_port = pkt.src_port, pkt.dst_port
                    proc_name, exe_path = get_process_name_and_exe(src_ip, src_port, dst_ip, dst_port)
                    if proc_name == "N/A":
                        continue

                    proc_node = f"{proc_name}\n{exe_path}"
                    ip_node = dst_ip

                    safe_proc_node = proc_node.replace("\\", "_").replace(":", "_").replace("/", "_").replace(",", "_")
                    safe_ip_node = ip_node.replace("\\", "_").replace(":", "_").replace("/", "_").replace(",", "_")

                    dot.node(safe_proc_node, fillcolor="#0066ff", fontcolor="white", shape="box")
                    dot.node(safe_ip_node, fillcolor="#00cc00", fontcolor="black", shape="ellipse")

                    edge = (safe_proc_node, safe_ip_node)
                    if edge not in edges:
                        dot.edge(safe_proc_node, safe_ip_node, color="white")
                        edges.add(edge)
                except:
                    continue

            if not edges:
                return  

            outpath = os.path.join(tempfile.gettempdir(), f"network_graph_{uuid.uuid4().hex}")
            dot.render(outpath, format="png", cleanup=True)
            img_path = outpath + ".png"

            img = Image.open(img_path)
            img_width, img_height = img.size

            tk_img = ImageTk.PhotoImage(img)
            self._graph_canvas.delete("all")
            self._graph_canvas.create_image(0, 0, anchor="nw", image=tk_img)
            self._graph_canvas.image = tk_img
            self._graph_canvas.config(scrollregion=(0, 0, img_width, img_height))

            self._graph_window.after(5000, update_graph)

        update_graph()


    def process_packet_queue(self):
        while not self.packet_queue.empty():
            pkt = self.packet_queue.get()
            self.all_packets.append(pkt)

            if isinstance(pkt, dict) and "error" in pkt:
                self.text_box.insert("end", f"Error: {pkt['error']}\n", "gray")
                continue

            try:
                src_ip, dst_ip = pkt.src_addr, pkt.dst_addr
                src_port, dst_port = pkt.src_port, pkt.dst_port
                payload = bytes(pkt.payload)
                ts = datetime.now().strftime("%H:%M:%S")

                proc_name, exe_path = get_process_name_and_exe(src_ip, src_port, dst_ip, dst_port)

                process_filter = self.process_filter_var.get().strip().lower()
                ip_filter = self.ip_filter_var.get().strip()
                if process_filter and process_filter not in proc_name.lower():
                    continue
                if ip_filter and (ip_filter not in src_ip and ip_filter not in dst_ip):
                    continue

                try:
                    payload_text = payload.decode("utf-8", errors="replace")[:MAX_PAYLOAD]
                except:
                    payload_text = "[Non-UTF8 Data]"

                self.text_box.insert("end", f"[{ts}] Process: {proc_name} ({exe_path})\n", "process")
                self.text_box.insert("end", f"From: {src_ip}:{src_port}\n", "ip")
                self.text_box.insert("end", f"To:   {dst_ip}:{dst_port}\n", "ip")
                self.text_box.insert("end", "Payload:\n", "gray")
                self.text_box.insert("end", payload_text + "\n\n", "payload")
                self.text_box.see("end")

            except Exception as e:
                self.text_box.insert("end", f"[ERROR] {e}\n", "gray")

        if self.running:
            self.after(100, self.process_packet_queue)

    def apply_filter(self):
        self.text_box.delete("1.0", "end")
        for pkt in self.all_packets:
            try:
                src_ip, dst_ip = pkt.src_addr, pkt.dst_addr
                src_port, dst_port = pkt.src_port, pkt.dst_port
                proc_name, exe_path = get_process_name_and_exe(src_ip, src_port, dst_ip, dst_port)
                process_filter = self.process_filter_var.get().strip().lower()
                ip_filter = self.ip_filter_var.get().strip()
                if process_filter and process_filter not in proc_name.lower():
                    continue
                if ip_filter and (ip_filter not in src_ip and ip_filter not in dst_ip):
                    continue
                try:
                    payload_text = bytes(pkt.payload).decode("utf-8", errors="replace")[:MAX_PAYLOAD]
                except:
                    payload_text = "[Non-UTF8 Data]"

                ts = datetime.now().strftime("%H:%M:%S")
                self.text_box.insert("end", f"[{ts}] Process: {proc_name} ({exe_path})\n", "process")
                self.text_box.insert("end", f"From: {src_ip}:{src_port}\n", "ip")
                self.text_box.insert("end", f"To:   {dst_ip}:{dst_port}\n", "ip")
                self.text_box.insert("end", "Payload:\n", "gray")
                self.text_box.insert("end", payload_text + "\n\n", "payload")
            except:
                continue

    def stop_monitor(self):
        self.running = False
        self.destroy()
        
class AboutWindow(ctk.CTkToplevel):
    def __init__(self, master, contents=None):
        super().__init__(master)
        self.title("ℹ️ About")
        self.geometry("800x500")
        self.configure(fg_color="#0b0b0b")
        
        container = ctk.CTkFrame(self, fg_color="#0b0b0b")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_box = ctk.CTkTextbox(container, fg_color="#0b0b0b", text_color="#cccccc",
                                       font=("Consolas", 14), wrap="word")
        self.text_box.pack(fill="both", expand=True, side="left", padx=(0, 5), pady=5)

        scrollbar = ctk.CTkScrollbar(container, orientation="vertical", command=self.text_box.yview)
        scrollbar.pack(side="right", fill="y")
        self.text_box.configure(yscrollcommand=scrollbar.set)

        if contents:
            for title, text in contents:
                self.text_box.insert("end", f"{title}\n", "title")
                self.text_box.insert("end", f"{text}\n\n")

        self.text_box.tag_config("title", foreground="#00ccff")
        self.text_box.configure(state="disabled")
        close_btn = ctk.CTkButton(self, text="Close", fg_color="#ff2b2b", hover_color="#990000",
                                  command=self.destroy)
        close_btn.pack(pady=10)


    def add_section(self, title, text):
        title_label = ctk.CTkLabel(self.scrollable_frame, text=title, font=("Consolas", 18, "bold"),
                                   text_color="#00ccff", anchor="w")
        title_label.pack(fill="x", pady=(10,0))
        text_label = ctk.CTkLabel(self.scrollable_frame, text=text, font=("Consolas", 14),
                                  text_color="#cccccc", wraplength=750, justify="left")
        text_label.pack(fill="x", pady=(2,10))

class MonitorApp(ctk.CTk):
    def __init__(self, path="."):
        super().__init__()
        self.title("𝙼𝚊𝚗𝚝𝚒𝚜")
        self.geometry("950x550")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        try:
            self.iconbitmap("mantis_.ico")
        except:
            pass
        self.bg_color = "#0b0b0b"
        self.configure(fg_color=self.bg_color)

        self.bg_frame = ctk.CTkFrame(self, fg_color=self.bg_color)
        self.bg_frame.pack(fill="both", expand=True)
        self.label = ctk.CTkLabel(self.bg_frame, text="💀 Mantis Monitor Suite 💀",
                                  font=("Consolas", 26, "bold"),
                                  text_color="#ff2b2b")
        self.label.pack(pady=10)
        self.button_frame = ctk.CTkFrame(self.bg_frame, fg_color=self.bg_color)
        self.button_frame.pack(pady=10)

        ctk.CTkButton(self.button_frame, text="📁 File Monitor",
              fg_color="#ff2b2b", hover_color="#990000",
              corner_radius=15,
              command=self.open_file_monitor).grid(row=0, column=0, padx=10, pady=10)
        ctk.CTkButton(self.button_frame, text="📊 Process Monitor",
                       fg_color="#0066ff", hover_color="#0044aa",
                       corner_radius=15,
                       command=self.open_task_monitor).grid(row=0, column=1, padx=10)
        ctk.CTkButton(self.button_frame, text="🌐 Network Monitor",
                       fg_color="#00cc00", hover_color="#009900",
                       corner_radius=15,
                       command=self.open_network_monitor).grid(row=0, column=2, padx=10)
        ctk.CTkButton(self.button_frame, text="ℹ️ About",
                       fg_color="#ffaa00", hover_color="#ff8800",
                       corner_radius=15,
                       command=self.open_about).grid(row=0, column=3, padx=10)
        ctk.CTkButton(self.button_frame, text="💻 CPU Monitor",
               fg_color="#ffaa00", hover_color="#cc8800",
               corner_radius=15,
               command=self.open_cpu_monitor).grid(row=0, column=4, padx=10)

        self.footer_label = ctk.CTkLabel(self.bg_frame, text="MANTIS\nMonitoring All Network, Tasks, Integrated Systems",
                                         font=("Consolas", 20, "bold"),
                                         text_color="#ff0000")
        self.footer_label.pack(side="bottom", pady=10)

        self.file_monitor_window = None
        self.task_monitor_window = None
        self.network_monitor_window = None
        self.file_monitor = None
        self.about_window = None
        self.path = path

    def open_file_monitor(self):
        if not self.file_monitor_window or not self.file_monitor_window.winfo_exists():
            self.file_monitor_window = FileMonitorWindow(self, self.path)

    def open_task_monitor(self):
        if not self.task_monitor_window or not self.task_monitor_window.winfo_exists():
            self.task_monitor_window = TaskWindow(self)

    def open_network_monitor(self):
        if not self.network_monitor_window or not self.network_monitor_window.winfo_exists():
            self.network_monitor_window = NetworkMonitorWindow(self)

    def open_cpu_monitor(self):
        os.system("cpumonitor.exe")

    def open_about(self):
        if self.about_window and self.about_window.winfo_exists():
            self.about_window.lift()
            return

        contents = [
            ("What does mantis mean?","Monitoring All Network, Tasks, and Integrated Systems"),
            ("What is Mantis?", "Mantis is a monitoring tool built to monitor files, tasks, and requests sent from your system!\nWith this tool, you can understand how an exe file behaves with your files, what tasks it creates or closes, what requests it sends to where with what data!\nThis tool is released as open source and you can use it for free!"),
            ("Features", "- File Monitoring (You can see what files/folders have been created, edited, or deleted)\n- Task Manager Monitoring (You can see which tasks were created by which program, which tasks are opened, and which tasks are currently running.)\n- Network Monitoring\n"),
            ("Contact", "To report a bug or submit a new idea, send a message to Telegram or GitHub :)\nGithub: https://github.com/Mr-Spect3r\nTelegram: https://t.me/MrEsfelurm"),
            ("Why did I create Mantis?","I designed this tool for analyzing programs\nYou can read it here: https://github.com/Mr-Spect3r/MANTIS/blob/main/writeup.md")
        ]
        self.about_window = AboutWindow(self, contents)

class FileMonitorWindow(ctk.CTkToplevel):
    def __init__(self, master, path="."):
        super().__init__(master)
        self.title("📁 File Monitor")
        self.geometry("950x600")
        self.configure(fg_color="#0b0b0b")

        self.path = path
        self.file_monitor = None
        self.is_monitoring = False
        self.logs = []  

        top_frame = ctk.CTkFrame(self, fg_color="#0b0b0b")
        top_frame.pack(fill="x", pady=(8,4), padx=8)
        self.path_button = ctk.CTkButton(top_frame, text="📂 Open Folder",
                                         fg_color="#ffaa00", hover_color="#ff8800",
                                         command=self.select_path)
        self.path_button.pack(side="left", padx=(0,8))
        self.path_label = ctk.CTkLabel(top_frame, text=f"Current Path: {self.path}",
                                       text_color="#cccccc")
        self.path_label.pack(side="left")

        filter_frame = ctk.CTkFrame(self, fg_color="#1b1b1b")
        filter_frame.pack(fill="x", pady=6, padx=8)

        self.name_filter = ctk.StringVar()
        self.ext_filter = ctk.StringVar()
        self.type_filter = ctk.StringVar()

        ctk.CTkLabel(filter_frame, text="Filename:", text_color="#ffffff").pack(side="left", padx=6)
        ctk.CTkEntry(filter_frame, textvariable=self.name_filter, width=150).pack(side="left", padx=6)

        ctk.CTkLabel(filter_frame, text="Ext:", text_color="#ffffff").pack(side="left", padx=6)
        ctk.CTkEntry(filter_frame, textvariable=self.ext_filter, width=90).pack(side="left", padx=6)

        ctk.CTkLabel(filter_frame, text="Type:", text_color="#ffffff").pack(side="left", padx=6)
        ctk.CTkOptionMenu(filter_frame, variable=self.type_filter,
                          values=["ALL", "CREATED", "DELETED", "UPDATED", "MOVED"]).pack(side="left", padx=6)
        self.type_filter.set("ALL")
        ctk.CTkButton(filter_frame, text="Apply Filter", command=self.apply_filter).pack(side="left", padx=8)

        self.log_box = ctk.CTkTextbox(self, width=850, height=350, fg_color="#111111",
                                      text_color="#cccccc", font=("Consolas", 14))
        self.log_box.pack(pady=10, padx=10, fill="both", expand=True)
        self.log_box.tag_config("CREATED", foreground="#00ff00")
        self.log_box.tag_config("UPDATED", foreground="#ffff00")
        self.log_box.tag_config("DELETED", foreground="#ff2b2b")
        self.log_box.tag_config("MOVED", foreground="#00ffff")
        self.log_box.tag_config("SYSTEM", foreground="#ff8800")
        self.log_box.tag_config("time", foreground="#aaaaaa")
        self.log_box.tag_config("path", foreground="#ffffff")

        btn_frame = ctk.CTkFrame(self, fg_color="#0b0b0b")
        btn_frame.pack(pady=6)

        self.start_button = ctk.CTkButton(btn_frame, text="▶ Start Monitoring",
                                          fg_color="#ff2b2b", hover_color="#990000",
                                          command=self.start_monitoring)
        self.start_button.grid(row=0, column=0, padx=6)
        self.stop_button = ctk.CTkButton(btn_frame, text="⏹ Stop Monitoring",
                                         fg_color="#444444", hover_color="#666666",
                                         state="disabled", command=self.stop_monitoring)
        self.stop_button.grid(row=0, column=1, padx=6)

        ctk.CTkButton(btn_frame, text="🧹 Clear Display", fg_color="#ffaa00",
                      command=self.clear_display).grid(row=0, column=2, padx=6)
        ctk.CTkButton(btn_frame, text="🧼 Clear All", fg_color="#cc6600",
                      command=self.clear_all).grid(row=0, column=3, padx=6)

        ctk.CTkButton(btn_frame, text="💾 Save Log", fg_color="#0066ff",
                      command=self.save_logs).grid(row=0, column=4, padx=6)

        try:
            self.name_filter.trace_add("write", lambda *args: self.apply_filter())
            self.ext_filter.trace_add("write", lambda *args: self.apply_filter())
            self.type_filter.trace_add("write", lambda *args: self.apply_filter())
        except Exception:
            self.name_filter.trace("w", lambda *args: self.apply_filter())
            self.ext_filter.trace("w", lambda *args: self.apply_filter())
            self.type_filter.trace("w", lambda *args: self.apply_filter())

    def _split_moved_paths(self, path_str):
        if "→" in path_str:
            parts = [p.strip() for p in path_str.split("→")]
            return parts
        return [path_str]

    def passes_filter(self, log):
        name_f = self.name_filter.get().strip().lower()
        ext_f = self.ext_filter.get().strip().lower().lstrip(".")
        type_f = self.type_filter.get().strip()

        if type_f != "ALL" and log["action"] != type_f:
            return False

        if name_f:
            ok = False
            for p in self._split_moved_paths(log["path"]):
                if name_f in os.path.basename(p).lower() or name_f in p.lower():
                    ok = True
                    break
            if not ok:
                return False

        if ext_f:
            ok = False
            for p in self._split_moved_paths(log["path"]):
                _, ext = os.path.splitext(p)
                if ext.lower().lstrip(".") == ext_f:
                    ok = True
                    break
            if not ok:
                return False

        return True

    def log_callback(self, action, file_path):
        clean_path = os.path.normpath(file_path).replace("/", "\\")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {"time": timestamp, "action": action, "path": clean_path}
        self.logs.append(log_entry)

        if self.passes_filter(log_entry):
            self.log_box.insert("end", f"[{timestamp}] ", "time")
            self.log_box.insert("end", f"{action} → ", action)
            self.log_box.insert("end", f"{clean_path}\n", "path")
            self.log_box.see("end")


    def apply_filter(self):
        self.log_box.delete("1.0", "end")
        for log in self.logs:
            if self.passes_filter(log):
                self.log_box.insert("end", f"[{log['time']}] ", "time")
                self.log_box.insert("end", f"{log['action']} → ", log["action"])
                self.log_box.insert("end", f"{log['path']}\n", "path")
        self.log_box.see("end")

    def clear_display(self):
        self.log_box.delete("1.0", "end")

    def clear_all(self):
        self.logs = []
        self.log_box.delete("1.0", "end")

    def save_logs(self):
        import json
        grouped = {}
        for log in self.logs:
            try:
                date_key = datetime.strptime(log["time"], "%Y-%m-%d %H:%M:%S").strftime("%Y/%m/%d")
            except Exception:
                date_key = log["time"].split(" ")[0].replace("-", "/")
            if date_key not in grouped:
                grouped[date_key] = {"CREATED": [], "DELETED": [], "UPDATED": [], "MOVED": [], "SYSTEM": []}

            action = log["action"] if log["action"] in grouped[date_key] else "SYSTEM"
            grouped[date_key][action].append(f"[{log['time']}] {log['path']}")

        filename = f"logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(grouped, f, indent=4, ensure_ascii=False)
            self.log_box.insert("end", f"\n[SYSTEM] Logs saved to {filename}\n", "SYSTEM")
            self.log_box.see("end")
        except Exception as e:
            self.log_box.insert("end", f"\n[SYSTEM] Save failed: {e}\n", "SYSTEM")

    def select_path(self):
        from tkinter import filedialog
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.path = folder_selected
            self.path_label.configure(text=f"Current Path: {self.path}")

    def start_monitoring(self):
        if self.is_monitoring:
            return
        self.file_monitor = FileMonitor(self.path, self.log_callback)
        self.file_monitor.start()
        self.is_monitoring = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.log_callback("SYSTEM", f"Started monitoring: {os.path.abspath(self.path)}")

    def stop_monitoring(self):
        if not self.is_monitoring:
            return
        try:
            self.file_monitor.stop()
        except Exception:
            pass
        self.is_monitoring = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.log_callback("SYSTEM", "Stopped monitoring")


if __name__ == "__main__":
    if not is_admin():
        run_as_admin()
    app = MonitorApp(path=f"C:\\Users\\{os.getlogin()}")
    app.mainloop()
