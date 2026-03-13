#!/usr/bin/env python3
"""
Web Server Fingerprinting Tool — GUI Dashboard
Requires: tkinter (built-in with Python)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from fingerprinter import probe_host, probe_multiple, PORT_MAP, FingerprintResult

# ──────────────────────────────────────────────
#  Color palette — dark terminal aesthetic
# ──────────────────────────────────────────────
BG       = "#0d1117"
BG2      = "#161b22"
BG3      = "#21262d"
ACCENT   = "#58a6ff"
GREEN    = "#3fb950"
RED      = "#f85149"
YELLOW   = "#d29922"
PURPLE   = "#bc8cff"
FG       = "#c9d1d9"
FG2      = "#8b949e"
BORDER   = "#30363d"
FONT_MONO = ("Consolas", 10) if sys.platform == "win32" else ("Courier", 10)
FONT_UI   = ("Segoe UI", 10) if sys.platform == "win32" else ("Helvetica", 10)
FONT_H1   = ("Segoe UI", 16, "bold") if sys.platform == "win32" else ("Helvetica", 16, "bold")
FONT_H2   = ("Segoe UI", 11, "bold") if sys.platform == "win32" else ("Helvetica", 11, "bold")


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tw = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(self.tw, text=self.text, bg=BG3, fg=FG,
                       font=FONT_UI, relief="solid", bd=1, padx=6, pady=4)
        lbl.pack()

    def hide(self, _=None):
        if self.tw:
            self.tw.destroy()
            self.tw = None


class FingerprintApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Web Server Fingerprinting Tool")
        self.geometry("1100x750")
        self.configure(bg=BG)
        self.resizable(True, True)
        self._results_store = {}
        self._scanning = False
        self._build_ui()

    # ──────────────────────────────────────────
    #  UI construction
    # ──────────────────────────────────────────
    def _build_ui(self):
        self._style_ttk()

        # ── Header bar
        header = tk.Frame(self, bg=BG2, height=56)
        header.pack(fill="x")
        header.pack_propagate(False)

        title_lbl = tk.Label(header, text="⚡ Web Server Fingerprinting Tool",
                             font=FONT_H1, bg=BG2, fg=ACCENT)
        title_lbl.pack(side="left", padx=20, pady=12)

        subtitle = tk.Label(header, text="Identify server type & version via banner analysis",
                            font=FONT_UI, bg=BG2, fg=FG2)
        subtitle.pack(side="left", padx=0, pady=12)

        # ── Main split: left panel + right panel
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=10, pady=8)

        left = tk.Frame(main, bg=BG, width=340)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)

        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_left(left)
        self._build_right(right)

    def _build_left(self, parent):
        # ── Input card
        card = self._card(parent, "🎯  Target Configuration")
        card.pack(fill="x", pady=(0, 8))

        tk.Label(card, text="Host(s)  — one per line", font=FONT_UI,
                 bg=BG2, fg=FG2).pack(anchor="w", padx=12, pady=(4, 2))
        self.host_text = tk.Text(card, height=6, bg=BG3, fg=FG,
                                 insertbackground=ACCENT, relief="flat",
                                 font=FONT_MONO, bd=0)
        self.host_text.pack(fill="x", padx=12, pady=(0, 4))
        self.host_text.insert("1.0", "example.com\nhttpforever.com")

        tk.Label(card, text="Ports", font=FONT_UI, bg=BG2, fg=FG2).pack(
            anchor="w", padx=12, pady=(4, 2))

        port_frame = tk.Frame(card, bg=BG2)
        port_frame.pack(fill="x", padx=12, pady=(0, 8))

        self.port_vars = {}
        port_defs = [("80 HTTP", (80, "HTTP", False)),
                     ("443 HTTPS", (443, "HTTPS", True)),
                     ("8080", (8080, "HTTP", False)),
                     ("8443", (8443, "HTTPS", True)),
                     ("21 FTP", (21, "FTP", False))]
        for i, (label, val) in enumerate(port_defs):
            var = tk.BooleanVar(value=(i < 2))
            self.port_vars[label] = (var, val)
            cb = tk.Checkbutton(port_frame, text=label, variable=var,
                                bg=BG2, fg=FG, selectcolor=BG3,
                                activebackground=BG2, activeforeground=ACCENT,
                                font=FONT_UI, cursor="hand2")
            cb.grid(row=i//3, column=i%3, sticky="w", pady=2)

        tk.Label(card, text="Timeout (s)", font=FONT_UI, bg=BG2, fg=FG2).pack(
            anchor="w", padx=12)
        self.timeout_var = tk.DoubleVar(value=5.0)
        timeout_spin = tk.Spinbox(card, from_=1, to=30, increment=0.5,
                                  textvariable=self.timeout_var,
                                  bg=BG3, fg=FG, insertbackground=ACCENT,
                                  buttonbackground=BG3, relief="flat",
                                  font=FONT_UI, width=8)
        timeout_spin.pack(anchor="w", padx=12, pady=(2, 8))

        # ── Action buttons
        btn_frame = tk.Frame(parent, bg=BG)
        btn_frame.pack(fill="x", pady=4)

        self.scan_btn = self._button(btn_frame, "▶  Start Scan", self._start_scan,
                                     ACCENT, BG, bold=True)
        self.scan_btn.pack(fill="x", pady=(0, 4))

        self._button(btn_frame, "📂  Load Hosts File", self._load_file,
                     BG3, FG).pack(fill="x", pady=(0, 4))
        self._button(btn_frame, "💾  Export JSON", self._export_json,
                     BG3, FG).pack(fill="x", pady=(0, 4))
        self._button(btn_frame, "🗑   Clear Results", self._clear_results,
                     BG3, RED).pack(fill="x")

        # ── Progress
        prog_card = self._card(parent, "📊  Progress")
        prog_card.pack(fill="x", pady=(8, 0))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(prog_card, variable=self.progress_var,
                                             maximum=100, mode="indeterminate",
                                             style="Accent.Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x", padx=12, pady=8)
        self.status_lbl = tk.Label(prog_card, text="Idle", font=FONT_UI,
                                   bg=BG2, fg=FG2)
        self.status_lbl.pack(padx=12, pady=(0, 8))

        # ── Stats
        stats_card = self._card(parent, "🔢  Session Stats")
        stats_card.pack(fill="x", pady=(8, 0))
        self.stat_labels = {}
        for key, init in [("Hosts scanned", "0"), ("Ports probed", "0"),
                           ("Servers found", "0"), ("Errors", "0")]:
            row = tk.Frame(stats_card, bg=BG2)
            row.pack(fill="x", padx=12, pady=2)
            tk.Label(row, text=key, font=FONT_UI, bg=BG2, fg=FG2).pack(side="left")
            lbl = tk.Label(row, text=init, font=(FONT_UI[0], 10, "bold"),
                           bg=BG2, fg=ACCENT)
            lbl.pack(side="right")
            self.stat_labels[key] = lbl

    def _build_right(self, parent):
        # ── Notebook tabs
        self.nb = ttk.Notebook(parent, style="Dark.TNotebook")
        self.nb.pack(fill="both", expand=True)

        # Tab 1: Results table
        tab_results = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab_results, text="  Results  ")
        self._build_results_tab(tab_results)

        # Tab 2: Raw banner
        tab_raw = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab_raw, text="  Raw Banner  ")
        self._build_raw_tab(tab_raw)

        # Tab 3: SSL info
        tab_ssl = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab_ssl, text="  SSL Info  ")
        self._build_ssl_tab(tab_ssl)

        # Tab 4: Log
        tab_log = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab_log, text="  Log  ")
        self._build_log_tab(tab_log)

    def _build_results_tab(self, parent):
        cols = ("Host", "Port", "Protocol", "Server", "Version",
                "Status", "Time (ms)", "SSL")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings",
                                  style="Dark.Treeview", selectmode="browse")
        widths = [160, 60, 80, 130, 120, 70, 80, 60]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=40)
        self.tree.tag_configure("success", foreground=GREEN)
        self.tree.tag_configure("error",   foreground=RED)
        self.tree.tag_configure("unknown", foreground=YELLOW)

        vsb = ttk.Scrollbar(parent, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _build_raw_tab(self, parent):
        tk.Label(parent, text="Select a result row to view its raw banner",
                 font=FONT_UI, bg=BG, fg=FG2).pack(anchor="w", padx=10, pady=6)
        self.raw_text = scrolledtext.ScrolledText(parent, bg=BG3, fg=GREEN,
                                                   insertbackground=ACCENT,
                                                   font=FONT_MONO, relief="flat")
        self.raw_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.raw_text.configure(state="disabled")

    def _build_ssl_tab(self, parent):
        tk.Label(parent, text="SSL/TLS certificate details for selected host",
                 font=FONT_UI, bg=BG, fg=FG2).pack(anchor="w", padx=10, pady=6)
        self.ssl_text = scrolledtext.ScrolledText(parent, bg=BG3, fg=PURPLE,
                                                   insertbackground=ACCENT,
                                                   font=FONT_MONO, relief="flat")
        self.ssl_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.ssl_text.configure(state="disabled")

    def _build_log_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(parent, bg=BG3, fg=FG2,
                                                   insertbackground=ACCENT,
                                                   font=FONT_MONO, relief="flat")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_text.configure(state="disabled")
        self.log_text.tag_config("info",    foreground=ACCENT)
        self.log_text.tag_config("success", foreground=GREEN)
        self.log_text.tag_config("error",   foreground=RED)
        self.log_text.tag_config("warn",    foreground=YELLOW)

    # ──────────────────────────────────────────
    #  ttk styling
    # ──────────────────────────────────────────
    def _style_ttk(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Dark.Treeview",
                    background=BG2, foreground=FG, fieldbackground=BG2,
                    rowheight=26, font=FONT_UI, borderwidth=0)
        s.configure("Dark.Treeview.Heading",
                    background=BG3, foreground=ACCENT,
                    font=(FONT_UI[0], 10, "bold"), relief="flat")
        s.map("Dark.Treeview", background=[("selected", BG3)],
              foreground=[("selected", ACCENT)])
        s.configure("Dark.TNotebook", background=BG, borderwidth=0)
        s.configure("Dark.TNotebook.Tab",
                    background=BG2, foreground=FG2,
                    padding=[14, 6], font=FONT_UI)
        s.map("Dark.TNotebook.Tab",
              background=[("selected", BG3)],
              foreground=[("selected", ACCENT)])
        s.configure("Accent.Horizontal.TProgressbar",
                    troughcolor=BG3, background=ACCENT, thickness=6)
        s.configure("TScrollbar", background=BG3, troughcolor=BG2,
                    arrowcolor=FG2, borderwidth=0)

    # ──────────────────────────────────────────
    #  Helpers
    # ──────────────────────────────────────────
    def _card(self, parent, title):
        frame = tk.LabelFrame(parent, text=f" {title} ",
                              bg=BG2, fg=ACCENT, font=FONT_H2,
                              relief="flat", bd=1, highlightthickness=1,
                              highlightbackground=BORDER)
        return frame

    def _button(self, parent, text, cmd, bg, fg, bold=False):
        f = (FONT_UI[0], FONT_UI[1], "bold") if bold else FONT_UI
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg, activebackground=BG3,
                         activeforeground=ACCENT, relief="flat",
                         font=f, cursor="hand2", pady=7)

    def _log(self, msg, tag="info"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _set_status(self, msg):
        self.status_lbl.configure(text=msg)

    def _update_stats(self):
        all_r = [r for results in self._results_store.values() for r in results]
        hosts = len(self._results_store)
        probed = len(all_r)
        found = len([r for r in all_r if r.success and r.server_name != "Unknown"])
        errors = len([r for r in all_r if not r.success])
        self.stat_labels["Hosts scanned"].configure(text=str(hosts))
        self.stat_labels["Ports probed"].configure(text=str(probed))
        self.stat_labels["Servers found"].configure(text=str(found))
        self.stat_labels["Errors"].configure(text=str(errors))

    # ──────────────────────────────────────────
    #  Scanning
    # ──────────────────────────────────────────
    def _start_scan(self):
        if self._scanning:
            return
        hosts_raw = self.host_text.get("1.0", "end").strip()
        hosts = [h.strip() for h in hosts_raw.splitlines() if h.strip()]
        if not hosts:
            messagebox.showwarning("No hosts", "Please enter at least one host.")
            return

        port_map = [val for (var, val) in self.port_vars.values() if var.get()]
        if not port_map:
            messagebox.showwarning("No ports", "Select at least one port.")
            return

        timeout = self.timeout_var.get()
        self._scanning = True
        self.scan_btn.configure(text="⏳  Scanning…", state="disabled")
        self.progress_bar.start(12)
        self._set_status(f"Scanning {len(hosts)} host(s)…")
        self._log(f"Starting scan: {len(hosts)} host(s) × {len(port_map)} port(s)", "info")

        def worker():
            for host in hosts:
                results = probe_host(host, port_map, timeout)
                self._results_store.setdefault(host, [])
                for r in results:
                    self._results_store[host].append(r)
                    self.after(0, self._add_row, r)
                    tag = "success" if r.success else "error"
                    self.after(0, self._log, f"  {r.summary()}", tag)
            self.after(0, self._scan_done)

        threading.Thread(target=worker, daemon=True).start()

    def _scan_done(self):
        self._scanning = False
        self.progress_bar.stop()
        self.progress_var.set(100)
        self.scan_btn.configure(text="▶  Start Scan", state="normal")
        self._set_status("Scan complete ✓")
        self._update_stats()
        self._log("Scan complete.", "success")

    def _add_row(self, r: FingerprintResult):
        if r.success:
            ssl_mark = "🔒" if r.ssl_info else ""
            tag = "success" if r.server_name != "Unknown" else "unknown"
            self.tree.insert("", "end", iid=f"{r.host}:{r.port}",
                             values=(r.host, r.port, r.protocol,
                                     r.server_name, r.server_version,
                                     r.status_code, f"{r.response_time_ms:.0f}", ssl_mark),
                             tags=(tag,))
        else:
            self.tree.insert("", "end", iid=f"{r.host}:{r.port}:{id(r)}",
                             values=(r.host, r.port, r.protocol,
                                     "ERROR", r.error, "", "", ""),
                             tags=("error",))

    def _on_select(self, _=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        # Find matching result
        parts = iid.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 0

        result = None
        for r in self._results_store.get(host, []):
            if r.port == port:
                result = r
                break
        if not result:
            return

        # Raw banner
        self.raw_text.configure(state="normal")
        self.raw_text.delete("1.0", "end")
        self.raw_text.insert("end", result.raw_banner or "(no banner)")
        self.raw_text.configure(state="disabled")

        # SSL info
        self.ssl_text.configure(state="normal")
        self.ssl_text.delete("1.0", "end")
        if result.ssl_info:
            self.ssl_text.insert("end", json.dumps(result.ssl_info, indent=2))
        else:
            self.ssl_text.insert("end", "(no SSL / not an HTTPS connection)")
        self.ssl_text.configure(state="disabled")

    # ──────────────────────────────────────────
    #  Other actions
    # ──────────────────────────────────────────
    def _load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"),
                                                      ("All files", "*.*")])
        if not path:
            return
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.host_text.delete("1.0", "end")
        self.host_text.insert("1.0", "\n".join(lines))
        self._log(f"Loaded {len(lines)} hosts from {path}", "info")

    def _export_json(self):
        if not self._results_store:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON", "*.json")])
        if not path:
            return
        out = {}
        for host, results in self._results_store.items():
            out[host] = []
            for r in results:
                out[host].append({
                    "port": r.port, "protocol": r.protocol,
                    "server_name": r.server_name, "server_version": r.server_version,
                    "status_code": r.status_code,
                    "response_time_ms": round(r.response_time_ms, 2),
                    "ssl_info": r.ssl_info, "headers": r.headers, "error": r.error,
                })
        with open(path, "w") as f:
            json.dump(out, f, indent=2)
        self._log(f"Exported results to {path}", "success")
        messagebox.showinfo("Exported", f"Saved to:\n{path}")

    def _clear_results(self):
        self._results_store.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.raw_text.configure(state="normal")
        self.raw_text.delete("1.0", "end")
        self.raw_text.configure(state="disabled")
        self.ssl_text.configure(state="normal")
        self.ssl_text.delete("1.0", "end")
        self.ssl_text.configure(state="disabled")
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.progress_var.set(0)
        self._set_status("Idle")
        self._update_stats()


if __name__ == "__main__":
    app = FingerprintApp()
    app.mainloop()
