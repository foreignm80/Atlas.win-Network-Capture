import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import queue
import time
from datetime import datetime

from scapy.all import AsyncSniffer, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


def format_bytes(num):
    step_unit = 1024.0
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < step_unit:
            return f"{num:3.1f} {unit}"
        num /= step_unit
    return f"{num:.1f} PB"


class NetworkMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Atlas.win - Network Capture")
        self.geometry("1100x650")
        self.minsize(900, 500)
        self.overrideredirect(True)
        self.configure(fg_color="#050608")

        self.packet_queue = queue.Queue(maxsize=5000)
        self.sniffer = None
        self.capturing = False
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = None
        self.active_filter_ip = ""
        self.max_rows = 500
        self.last_packet_time = None

        self._drag_start_x = 0
        self._drag_start_y = 0

        self.interface_var = tk.StringVar()
        self.packets_var = tk.StringVar(value="0")
        self.bytes_var = tk.StringVar(value="0 B")
        self.rate_var = tk.StringVar(value="0 pkt/s")
        self.status_var = tk.StringVar(value="Idle")

        self._build_ui()
        self._load_interfaces()
        self.after(200, self._poll_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _build_ui(self):
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        title_bar = ctk.CTkFrame(self, height=36, corner_radius=0, fg_color="#0b0d13")
        title_bar.grid(row=0, column=0, sticky="ew")
        title_bar.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            title_bar,
            text="2k26 seceret",
            anchor="w",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        title_label.grid(row=0, column=0, padx=10, pady=4, sticky="w")

        close_button = ctk.CTkButton(
            title_bar,
            text="✕",
            width=32,
            height=26,
            command=self.on_closing,
            fg_color="transparent",
            hover_color="#ff4b5c",
            text_color="#ffffff",
            corner_radius=6,
            border_width=0,
        )
        close_button.grid(row=0, column=1, padx=6, pady=4)

        title_bar.bind("<Button-1>", self._start_move)
        title_bar.bind("<B1-Motion>", self._on_move)
        title_label.bind("<Button-1>", self._start_move)
        title_label.bind("<B1-Motion>", self._on_move)

        controls_frame = ctk.CTkFrame(self, fg_color="#111319")
        controls_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(10, 5))
        controls_frame.grid_columnconfigure(3, weight=1)

        interface_label = ctk.CTkLabel(controls_frame, text="Interface:")
        interface_label.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="w")

        self.interface_combo = ctk.CTkComboBox(controls_frame, variable=self.interface_var, values=[])
        self.interface_combo.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="ew")

        filter_label = ctk.CTkLabel(controls_frame, text="Filter IP (optional):")
        filter_label.grid(row=0, column=2, padx=(10, 5), pady=10, sticky="e")

        self.filter_entry = ctk.CTkEntry(controls_frame, placeholder_text="e.g. 192.168.1.100")
        self.filter_entry.grid(row=0, column=3, padx=(0, 10), pady=10, sticky="ew")

        self.start_button = ctk.CTkButton(controls_frame, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=4, padx=(10, 5), pady=10)

        self.stop_button = ctk.CTkButton(controls_frame, text="Stop", command=self.stop_capture, state="disabled")
        self.stop_button.grid(row=0, column=5, padx=(0, 10), pady=10)

        stats_frame = ctk.CTkFrame(self, fg_color="#111319")
        stats_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 5))
        stats_frame.grid_columnconfigure((0, 1, 2), weight=1)

        packets_label_title = ctk.CTkLabel(stats_frame, text="Packets:")
        packets_label_title.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        packets_label = ctk.CTkLabel(stats_frame, textvariable=self.packets_var)
        packets_label.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

        bytes_label_title = ctk.CTkLabel(stats_frame, text="Total Bytes:")
        bytes_label_title.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        bytes_label = ctk.CTkLabel(stats_frame, textvariable=self.bytes_var)
        bytes_label.grid(row=1, column=1, padx=10, pady=(0, 10), sticky="w")

        rate_label_title = ctk.CTkLabel(stats_frame, text="Rate:")
        rate_label_title.grid(row=0, column=2, padx=10, pady=5, sticky="w")
        rate_label = ctk.CTkLabel(stats_frame, textvariable=self.rate_var)
        rate_label.grid(row=1, column=2, padx=10, pady=(0, 10), sticky="w")

        self.status_label = ctk.CTkLabel(stats_frame, textvariable=self.status_var)
        self.status_label.grid(row=2, column=0, columnspan=3, padx=10, pady=(0, 10), sticky="w")

        table_frame = ctk.CTkFrame(self, fg_color="#050608")
        table_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#050608",
            foreground="#ffffff",
            fieldbackground="#050608",
            rowheight=24,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#111319",
            foreground="#ffffff",
            borderwidth=0,
        )
        style.map(
            "Treeview",
            background=[("selected", "#1f6aa5")],
            foreground=[("selected", "#ffffff")],
        )

        columns = ("time", "src", "dst", "proto", "length", "info")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.heading("time", text="Time")
        self.tree.heading("src", text="Source")
        self.tree.heading("dst", text="Destination")
        self.tree.heading("proto", text="Proto")
        self.tree.heading("length", text="Length")
        self.tree.heading("info", text="Info")

        self.tree.column("time", width=80, anchor="center")
        self.tree.column("src", width=160, anchor="w")
        self.tree.column("dst", width=160, anchor="w")
        self.tree.column("proto", width=60, anchor="center")
        self.tree.column("length", width=80, anchor="e")
        self.tree.column("info", width=400, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

    def _load_interfaces(self):
        try:
            interfaces = get_if_list()
        except Exception as exc:
            messagebox.showerror("Error", f"Could not list interfaces: {exc}")
            interfaces = []
        if interfaces:
            self.interface_combo.configure(values=interfaces)
            self.interface_combo.set(interfaces[0])

    def start_capture(self):
        if self.capturing:
            return
        iface = self.interface_var.get().strip()
        if not iface:
            messagebox.showwarning("Interface required", "Select a network interface first.")
            return
        self.active_filter_ip = self.filter_entry.get().strip()
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.last_packet_time = None
        self.status_var.set("Capturing...")
        self._clear_table()
        try:
            self.sniffer = AsyncSniffer(iface=iface, prn=self._process_packet, store=False)
            self.sniffer.start()
            self.capturing = True
            self._update_controls_state()
        except Exception as exc:
            messagebox.showerror("Error starting capture", str(exc))
            self.sniffer = None
            self.capturing = False

    def stop_capture(self):
        if not self.capturing:
            return
        try:
            if self.sniffer is not None:
                self.sniffer.stop()
        except Exception:
            pass
        self.sniffer = None
        self.capturing = False
        self._update_controls_state()
        self.status_var.set("Idle")

    def _update_controls_state(self):
        if self.capturing:
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.interface_combo.configure(state="disabled")
        else:
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.interface_combo.configure(state="readonly")

    def _clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _process_packet(self, packet):
        try:
            length = len(packet)
        except Exception:
            length = 0
        timestamp = datetime.now().strftime("%H:%M:%S")
        src = "?"
        dst = "?"
        proto = ""
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = packet.__class__.__name__
        info = packet.summary()
        if len(info) > 120:
            info = info[:117] + "..."
        if self.active_filter_ip:
            ip = self.active_filter_ip
            if src != ip and dst != ip:
                return
        try:
            self.packet_queue.put_nowait((timestamp, src, dst, proto, length, info))
        except queue.Full:
            pass

    def _poll_queue(self):
        updated = False
        while True:
            try:
                timestamp, src, dst, proto, length, info = self.packet_queue.get_nowait()
            except queue.Empty:
                break
            self.total_packets += 1
            self.total_bytes += length
            self._insert_row(timestamp, src, dst, proto, length, info)
            updated = True
        if updated:
            self._update_stats()
            if self.capturing:
                self.status_var.set("Traffic detected.")
        elif self.capturing and self.start_time:
            now = time.time()
            if self.total_packets == 0 and now - self.start_time > 3:
                self.status_var.set("TP is not plugged in.")
        self.after(200, self._poll_queue)

    def _insert_row(self, timestamp, src, dst, proto, length, info):
        self.tree.insert("", "end", values=(timestamp, src, dst, proto, length, info))
        children = self.tree.get_children()
        if len(children) > self.max_rows:
            for iid in children[:-self.max_rows]:
                self.tree.delete(iid)

    def _update_stats(self):
        self.packets_var.set(str(self.total_packets))
        self.bytes_var.set(format_bytes(float(self.total_bytes)))
        if self.capturing and self.start_time:
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                rate = self.total_packets / elapsed
                self.rate_var.set(f"{rate:.1f} pkt/s")
            else:
                self.rate_var.set("0 pkt/s")
        else:
            self.rate_var.set("0 pkt/s")

    def _start_move(self, event):
        self._drag_start_x = event.x
        self._drag_start_y = event.y

    def _on_move(self, event):
        x = self.winfo_pointerx() - self._drag_start_x
        y = self.winfo_pointery() - self._drag_start_y
        self.geometry(f"+{x}+{y}")

    def on_closing(self):
        try:
            if self.capturing and self.sniffer is not None:
                self.sniffer.stop()
        except Exception:
            pass
        self.destroy()


def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = NetworkMonitorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
