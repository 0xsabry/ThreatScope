"""
ThreatScope V2 — Premium Desktop GUI
Author: 0xSABRY

Professional DFIR analysis interface built with CustomTkinter.
Optimized for speed: canvas-based charts, text-based data views.
"""

import sys
import math
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import customtkinter as ctk

from config import VERSION, APP_NAME
from core.analyzer import LogAnalyzer
from ai.ai_core import NarrativeEngine, AnalystCopilot, TrainingMode
from export.exporters import export_json, export_csv, export_stix

try:
    from export.exporters import export_pdf
    PDF_AVAILABLE = True
except Exception:
    PDF_AVAILABLE = False
try:
    from export.exporters import export_docx
    DOCX_AVAILABLE = True
except Exception:
    DOCX_AVAILABLE = False


# ============================================================
# Premium Color Palette
# ============================================================
C = {
    "bg":           "#060b14",
    "bg_alt":       "#0c1322",
    "card":         "#0f1729",
    "card_hover":   "#141e33",
    "sidebar":      "#080d19",
    "input":        "#131c2e",
    "border":       "#1a2744",
    "accent":       "#00c8ff",
    "accent2":      "#6366f1",
    "accent_dim":   "#0091b8",
    "text":         "#e8edf5",
    "text2":        "#9ca8c0",
    "text3":        "#5b6a85",
    "critical":     "#ff3b5c",
    "high":         "#ff8c42",
    "medium":       "#ffc233",
    "low":          "#4a9eff",
    "success":      "#00e68a",
    "white":        "#ffffff",
}

SEV_C = {"critical": C["critical"], "high": C["high"],
         "medium": C["medium"], "low": C["low"], "informational": C["text3"]}

F = "Segoe UI"
FM = "Consolas"


# ============================================================
# Canvas Chart Helpers (No matplotlib — instant rendering)
# ============================================================
def draw_donut(canvas, w, h, data, colors):
    """Draw a donut chart on a canvas. Returns instantly."""
    canvas.delete("all")
    total = sum(data.values())
    if total == 0:
        canvas.create_text(w // 2, h // 2, text="No data", fill=C["text3"],
                           font=(F, 12))
        return

    cx, cy, r = w // 2, h // 2, min(w, h) // 2 - 30
    inner_r = r * 0.55
    start = 90

    for label, value in data.items():
        extent = -(value / total) * 360
        color = colors.get(label, C["text3"])
        canvas.create_arc(cx - r, cy - r, cx + r, cy + r,
                          start=start, extent=extent,
                          fill=color, outline=C["card"], width=2, style="pieslice")
        # Label
        mid_angle = math.radians(start + extent / 2)
        lx = cx + (r + 18) * math.cos(mid_angle)
        ly = cy - (r + 18) * math.sin(mid_angle)
        pct = f"{value / total * 100:.0f}%"
        canvas.create_text(lx, ly, text=f"{label} {pct}", fill=color,
                           font=(F, 9, "bold"), anchor="center")
        start += extent

    # Inner circle (donut hole)
    canvas.create_oval(cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r,
                       fill=C["card"], outline=C["card"])
    canvas.create_text(cx, cy - 8, text=str(total), fill=C["text"],
                       font=(F, 22, "bold"))
    canvas.create_text(cx, cy + 14, text="total", fill=C["text3"],
                       font=(F, 10))


def draw_hbar(canvas, w, h, data, color=None, max_items=8):
    """Draw horizontal bar chart on canvas. Returns instantly."""
    canvas.delete("all")
    if not data:
        canvas.create_text(w // 2, h // 2, text="No data", fill=C["text3"],
                           font=(F, 12))
        return

    items = data[:max_items]
    max_val = max(v for _, v in items) if items else 1
    bar_h = max(16, min(24, (h - 20) // len(items) - 6))
    y = 10

    for label, value in items:
        # Truncate label
        disp = label if len(label) <= 18 else label[:16] + ".."
        canvas.create_text(8, y + bar_h // 2, text=disp, fill=C["text2"],
                           font=(FM, 9), anchor="w")
        bar_x = 140
        bar_w = max(4, int((w - bar_x - 60) * (value / max_val)))
        c = color or C["accent"]
        canvas.create_rectangle(bar_x, y + 2, bar_x + bar_w, y + bar_h - 2,
                                fill=c, outline="", width=0)
        canvas.create_text(bar_x + bar_w + 6, y + bar_h // 2, text=str(value),
                           fill=C["text2"], font=(FM, 9), anchor="w")
        y += bar_h + 4


# ============================================================
# Main Application
# ============================================================
class ThreatScopeGUI(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} V{VERSION}")
        self.geometry("1480x880")
        self.minsize(1100, 650)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=C["bg"])

        self.analyzer = None
        self.results = None
        self.copilot = AnalystCopilot()
        self.narrative_engine = NarrativeEngine()
        self.current_page = "dashboard"

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self.main = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(0, weight=1)

        self.pages = {}
        self._show("dashboard")

    # ============================================================
    # Sidebar
    # ============================================================
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=C["sidebar"],
                           border_width=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        self.sidebar = sb

        # Brand
        ctk.CTkLabel(sb, text="THREATSCOPE", font=(F, 20, "bold"),
                     text_color=C["accent"]).pack(padx=20, pady=(24, 0), anchor="w")
        ctk.CTkLabel(sb, text=f"V{VERSION}  •  0xSABRY", font=(F, 10),
                     text_color=C["text3"]).pack(padx=20, anchor="w")

        # Divider
        ctk.CTkFrame(sb, height=1, fg_color=C["border"]).pack(fill="x", padx=16, pady=14)

        # File controls
        self.file_lbl = ctk.CTkLabel(sb, text="No file loaded", font=(F, 10),
                                      text_color=C["text3"], wraplength=190)
        self.file_lbl.pack(padx=20, anchor="w")

        bf = ctk.CTkFrame(sb, fg_color="transparent")
        bf.pack(fill="x", padx=16, pady=(8, 0))

        self.btn_browse = ctk.CTkButton(bf, text="Browse File", height=38,
                                         font=(F, 13, "bold"),
                                         fg_color=C["accent"], hover_color=C["accent_dim"],
                                         text_color="#000", corner_radius=8,
                                         command=self._browse)
        self.btn_browse.pack(fill="x")

        self.btn_analyze = ctk.CTkButton(bf, text="Analyze", height=38,
                                          font=(F, 13, "bold"),
                                          fg_color=C["success"], hover_color="#00b36b",
                                          text_color="#000", corner_radius=8,
                                          command=self._analyze, state="disabled")
        self.btn_analyze.pack(fill="x", pady=(6, 0))

        self.prog = ctk.CTkProgressBar(sb, mode="indeterminate",
                                        progress_color=C["accent"], height=3)
        self.status_lbl = ctk.CTkLabel(sb, text="", font=(F, 10),
                                        text_color=C["accent"])
        self.status_lbl.pack(padx=20, pady=(4, 0), anchor="w")

        ctk.CTkFrame(sb, height=1, fg_color=C["border"]).pack(fill="x", padx=16, pady=12)

        # Nav
        nav = [("dashboard", "Dashboard"), ("findings", "Findings"),
               ("timeline", "Timeline"), ("mitre", "MITRE ATT&CK"),
               ("iocs", "IOCs"), ("copilot", "AI Copilot"),
               ("narrative", "Narrative"), ("export", "Export")]

        self.nav_btns = {}
        for key, label in nav:
            b = ctk.CTkButton(sb, text=f"  {label}", height=34, font=(F, 13),
                               fg_color="transparent", hover_color=C["card"],
                               text_color=C["text2"], anchor="w", corner_radius=6,
                               command=lambda k=key: self._show(k))
            b.pack(fill="x", padx=10, pady=1)
            self.nav_btns[key] = b

        # Bottom
        ctk.CTkLabel(sb, text="github.com/0xsabry", font=(F, 9),
                     text_color=C["text3"]).pack(side="bottom", padx=20, pady=12, anchor="w")

    # ============================================================
    # Navigation
    # ============================================================
    def _show(self, page):
        self.current_page = page
        for k, b in self.nav_btns.items():
            if k == page:
                b.configure(fg_color=C["card"], text_color=C["accent"])
            else:
                b.configure(fg_color="transparent", text_color=C["text2"])

        for p in self.pages.values():
            p.grid_forget()

        if page not in self.pages:
            builder = getattr(self, f"_page_{page}", None)
            self.pages[page] = builder() if builder else self._page_empty()

        self.pages[page].grid(row=0, column=0, sticky="nsew")

    def _page_empty(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])
        ctk.CTkLabel(f, text="Select a page", font=(F, 16),
                     text_color=C["text3"]).place(relx=0.5, rely=0.5, anchor="center")
        return f

    # ============================================================
    # File & Analysis
    # ============================================================
    def _browse(self):
        fp = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("All Supported", "*.evtx *.log *.txt *.json *.csv *.xml *.syslog"),
                       ("Windows Event Log", "*.evtx"), ("Log Files", "*.log *.txt *.syslog"),
                       ("JSON", "*.json"), ("All", "*.*")])
        if fp:
            self.analyzer = LogAnalyzer(fp)
            self.file_lbl.configure(text=Path(fp).name)
            self.btn_analyze.configure(state="normal")
            self.status_lbl.configure(text="Ready", text_color=C["success"])

    def _analyze(self):
        if not self.analyzer:
            return
        self.btn_analyze.configure(state="disabled")
        self.btn_browse.configure(state="disabled")
        self.prog.pack(fill="x", padx=16, pady=(4, 0))
        self.prog.start()
        self.status_lbl.configure(text="Loading file...", text_color=C["accent"])

        def work():
            try:
                self.analyzer.load()
                n = self.analyzer.total_lines
                self.after(0, lambda: self.status_lbl.configure(
                    text=f"Analyzing {n:,} events..."))
                r = self.analyzer.analyze()
                self.results = r
                self.copilot.set_context(r)
                self.after(0, self._done)
            except Exception as e:
                self.after(0, lambda: self._fail(str(e)))

        threading.Thread(target=work, daemon=True).start()

    def _done(self):
        self.prog.stop()
        self.prog.pack_forget()
        self.btn_analyze.configure(state="normal")
        self.btn_browse.configure(state="normal")
        s = self.results["threat_score"]
        lv = self.results["threat_level"]
        sc = C["critical"] if s >= 60 else C["high"] if s >= 30 else C["success"]
        self.status_lbl.configure(text=f"Score: {s}% ({lv})", text_color=sc)

        for k in list(self.pages.keys()):
            self.pages[k].destroy()
            del self.pages[k]
        self._show("dashboard")

    def _fail(self, err):
        self.prog.stop()
        self.prog.pack_forget()
        self.btn_analyze.configure(state="normal")
        self.btn_browse.configure(state="normal")
        self.status_lbl.configure(text="Error!", text_color=C["critical"])
        messagebox.showerror("Error", err)

    # ============================================================
    # Helpers
    # ============================================================
    def _card(self, parent, **kw):
        return ctk.CTkFrame(parent, corner_radius=10, fg_color=C["card"],
                             border_width=1, border_color=C["border"], **kw)

    def _stat(self, parent, label, value, color=None):
        c = self._card(parent)
        ctk.CTkLabel(c, text=str(value), font=(F, 30, "bold"),
                     text_color=color or C["accent"]).pack(padx=14, pady=(14, 0))
        ctk.CTkLabel(c, text=label, font=(F, 10),
                     text_color=C["text3"]).pack(padx=14, pady=(0, 14))
        return c

    def _title(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=(F, 20, "bold"),
                     text_color=C["text"]).pack(padx=20, pady=(18, 10), anchor="w")

    def _textbox(self, parent, **kw):
        tb = ctk.CTkTextbox(parent, font=(FM, 12), fg_color=C["card"],
                             text_color=C["text"], border_width=1,
                             border_color=C["border"], corner_radius=10,
                             wrap="word", activate_scrollbars=True, **kw)
        return tb

    # ============================================================
    # PAGE: Dashboard
    # ============================================================
    def _page_dashboard(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])
        if not self.results:
            # Empty state
            ef = ctk.CTkFrame(f, fg_color="transparent")
            ef.place(relx=0.5, rely=0.42, anchor="center")
            ctk.CTkLabel(ef, text="THREATSCOPE", font=(F, 42, "bold"),
                         text_color=C["accent"]).pack()
            ctk.CTkLabel(ef, text="Advanced DFIR & Threat Detection Platform",
                         font=(F, 15), text_color=C["text2"]).pack(pady=(2, 24))

            features = ["115+ Detection Rules  •  Sigma & YARA Engine",
                        "MITRE ATT&CK Mapping  •  Behavioral Chains",
                        "IOC Extraction  •  Attack Correlation",
                        "AI Copilot  •  Heuristic Narrative Engine"]
            for feat in features:
                ctk.CTkLabel(ef, text=feat, font=(F, 11),
                             text_color=C["text3"]).pack(pady=1)

            ctk.CTkLabel(ef, text="\nBrowse a log file to begin", font=(F, 12),
                         text_color=C["text3"]).pack(pady=(12, 0))
            return f

        r = self.results
        sm = r["summary"]
        score = r["threat_score"]
        level = r["threat_level"]

        scroll = ctk.CTkScrollableFrame(f, fg_color="transparent",
                                         scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True)
        scroll.grid_columnconfigure(0, weight=1)

        # ── Score Banner ──
        banner = self._card(scroll)
        banner.pack(fill="x", padx=12, pady=(8, 6))
        bi = ctk.CTkFrame(banner, fg_color="transparent")
        bi.pack(fill="x", padx=20, pady=18)
        bi.grid_columnconfigure(1, weight=1)

        sc = C["critical"] if score >= 60 else C["high"] if score >= 30 else C["success"]
        lf = ctk.CTkFrame(bi, fg_color="transparent")
        lf.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(lf, text=f"{score}%", font=(F, 56, "bold"),
                     text_color=sc).pack(anchor="w")
        ctk.CTkLabel(lf, text=level, font=(F, 16, "bold"),
                     text_color=sc).pack(anchor="w")

        rf = ctk.CTkFrame(bi, fg_color="transparent")
        rf.grid(row=0, column=1, sticky="e")
        meta = r["metadata"]
        fname = Path(meta.get("filepath", "")).name or "Unknown"
        for txt in [f"File: {fname}",
                    f"Events: {meta.get('total_events', 0):,}",
                    f"Sigma: {meta.get('sigma_rules_loaded', 0)}  YARA: {meta.get('yara_rules_loaded', 0)}",
                    f"Time: {meta.get('time_range', {}).get('start', 'N/A')}"]:
            ctk.CTkLabel(rf, text=txt, font=(F, 11),
                         text_color=C["text2"]).pack(anchor="e")

        # ── Stats Row ──
        sf = ctk.CTkFrame(scroll, fg_color="transparent")
        sf.pack(fill="x", padx=12, pady=(0, 6))
        sf.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)
        stats = [("Findings", sm["total_findings"], C["accent"]),
                 ("Critical", sm["critical"], C["critical"]),
                 ("High", sm["high"], C["high"]),
                 ("Medium", sm["medium"], C["medium"]),
                 ("MITRE", sm["mitre_techniques"], C["accent2"]),
                 ("IOCs", sm["total_iocs"], C["success"])]
        for i, (l, v, c) in enumerate(stats):
            self._stat(sf, l, v, c).grid(row=0, column=i, sticky="nsew", padx=3)

        # ── Charts Row ──
        cf = ctk.CTkFrame(scroll, fg_color="transparent")
        cf.pack(fill="x", padx=12, pady=(0, 6))
        cf.grid_columnconfigure((0, 1), weight=1)

        # Donut chart
        dc = self._card(cf)
        dc.grid(row=0, column=0, sticky="nsew", padx=(0, 3))
        ctk.CTkLabel(dc, text="Severity Distribution", font=(F, 13, "bold"),
                     text_color=C["text"]).pack(padx=16, pady=(14, 0), anchor="w")
        donut_canvas = tk.Canvas(dc, width=340, height=220, bg=C["card"],
                                  highlightthickness=0, bd=0)
        donut_canvas.pack(padx=16, pady=(4, 14))
        draw_donut(donut_canvas, 340, 220,
                   {"Critical": sm["critical"], "High": sm["high"],
                    "Medium": sm["medium"], "Low": sm["low"]},
                   {"Critical": C["critical"], "High": C["high"],
                    "Medium": C["medium"], "Low": C["low"]})

        # IP Bar chart
        bc = self._card(cf)
        bc.grid(row=0, column=1, sticky="nsew", padx=(3, 0))
        ctk.CTkLabel(bc, text="Top Source IPs", font=(F, 13, "bold"),
                     text_color=C["text"]).pack(padx=16, pady=(14, 0), anchor="w")
        bar_canvas = tk.Canvas(bc, width=440, height=220, bg=C["card"],
                                highlightthickness=0, bd=0)
        bar_canvas.pack(padx=16, pady=(4, 14), fill="x")
        draw_hbar(bar_canvas, 440, 220, r.get("top_ips", []))

        # ── Top Findings ──
        fc = self._card(scroll)
        fc.pack(fill="x", padx=12, pady=(0, 10))
        ctk.CTkLabel(fc, text="Top Findings", font=(F, 13, "bold"),
                     text_color=C["text"]).pack(padx=16, pady=(14, 6), anchor="w")

        tb = self._textbox(fc, height=200)
        tb.pack(fill="x", padx=12, pady=(0, 14))
        lines = []
        for fi in r.get("findings", [])[:15]:
            sev = fi.get("severity", "low").upper()
            title = fi.get("title", "")
            desc = fi.get("description", "")
            mitre = fi.get("mitre", "")
            line = f"[{sev:8s}]  {title}"
            if mitre:
                line += f"  ({mitre})"
            line += f"\n           {desc}\n"
            lines.append(line)
        tb.insert("1.0", "".join(lines) if lines else "No findings")
        tb.configure(state="disabled")

        return f

    # ============================================================
    # PAGE: Findings
    # ============================================================
    def _page_findings(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])
        if not self.results:
            ctk.CTkLabel(f, text="Run analysis first", font=(F, 16),
                         text_color=C["text3"]).place(relx=0.5, rely=0.5, anchor="center")
            return f

        findings = self.results.get("findings", [])

        hdr = ctk.CTkFrame(f, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(18, 8))
        ctk.CTkLabel(hdr, text=f"Findings ({len(findings)})", font=(F, 20, "bold"),
                     text_color=C["text"]).pack(side="left")

        self._findings_var = ctk.StringVar(value="All")
        filt = ctk.CTkSegmentedButton(
            hdr, values=["All", "Critical", "High", "Medium", "Low"],
            font=(F, 11), variable=self._findings_var,
            command=lambda v: self._render_findings(v))
        filt.pack(side="right")

        self._findings_tb = self._textbox(f)
        self._findings_tb.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._render_findings("All")
        return f

    def _render_findings(self, sev_filter):
        findings = self.results.get("findings", [])
        if sev_filter != "All":
            findings = [fi for fi in findings
                        if fi.get("severity", "").lower() == sev_filter.lower()]

        tb = self._findings_tb
        tb.configure(state="normal")
        tb.delete("1.0", "end")

        lines = []
        for fi in findings:
            sev = fi.get("severity", "low").upper()
            title = fi.get("title", "")
            desc = fi.get("description", "")
            mitre = fi.get("mitre", "")
            ts = fi.get("timestamp", "")
            ln = fi.get("line_number", "")

            header = f"[{sev}]  {title}"
            if mitre:
                header += f"    MITRE: {mitre}"
            lines.append(header)
            if desc:
                lines.append(f"    {desc}")
            meta_parts = []
            if ts:
                meta_parts.append(f"Time: {ts}")
            if ln:
                meta_parts.append(f"Line: {ln}")
            if meta_parts:
                lines.append(f"    {' | '.join(meta_parts)}")
            lines.append(f"{'─' * 90}")

        tb.insert("1.0", "\n".join(lines) if lines else "No findings match this filter.")
        tb.configure(state="disabled")

    # ============================================================
    # PAGE: Timeline
    # ============================================================
    def _page_timeline(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])
        if not self.results or not self.results.get("timeline"):
            ctk.CTkLabel(f, text="No timeline data", font=(F, 16),
                         text_color=C["text3"]).place(relx=0.5, rely=0.5, anchor="center")
            return f

        timeline = self.results["timeline"]
        self._title(f, f"Attack Timeline ({len(timeline)} events)")

        tb = self._textbox(f)
        tb.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        lines = []
        for ev in timeline[:300]:
            ts = ev.get("timestamp", "N/A")
            sev = ev.get("severity", "low").upper()
            title = ev.get("title", "")
            lines.append(f"{ts:24s}  [{sev:8s}]  {title}")

        tb.insert("1.0", "\n".join(lines))
        tb.configure(state="disabled")
        return f

    # ============================================================
    # PAGE: MITRE ATT&CK
    # ============================================================
    def _page_mitre(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])
        if not self.results or not self.results.get("mitre_hits"):
            ctk.CTkLabel(f, text="No MITRE ATT&CK data", font=(F, 16),
                         text_color=C["text3"]).place(relx=0.5, rely=0.5, anchor="center")
            return f

        hits = self.results["mitre_hits"]
        total_hits = sum(hits.values())
        self._title(f, f"MITRE ATT&CK ({len(hits)} techniques, {total_hits} total hits)")

        scroll = ctk.CTkScrollableFrame(f, fg_color="transparent",
                                         scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        scroll.grid_columnconfigure(0, weight=1)

        max_count = max(hits.values())
        for tech, count in sorted(hits.items(), key=lambda x: x[1], reverse=True):
            row = ctk.CTkFrame(scroll, corner_radius=6, fg_color=C["card"],
                                height=40)
            row.pack(fill="x", padx=4, pady=2)
            row.pack_propagate(False)

            inner = ctk.CTkFrame(row, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=14)
            inner.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(inner, text=tech, font=(FM, 13, "bold"),
                         text_color=C["accent"], width=100).grid(row=0, column=0, sticky="w")

            # Progress bar
            pbar = ctk.CTkProgressBar(inner, height=10, corner_radius=4,
                                       progress_color=C["success"] if count >= 5 else C["medium"] if count >= 2 else C["critical"],
                                       fg_color=C["input"])
            pbar.grid(row=0, column=1, sticky="ew", padx=12)
            pbar.set(count / max_count)

            ctk.CTkLabel(inner, text=f"{count} hits", font=(FM, 11),
                         text_color=C["text2"], width=60).grid(row=0, column=2, sticky="e")

        return f

    # ============================================================
    # PAGE: IOCs
    # ============================================================
    def _page_iocs(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])
        if not self.results:
            ctk.CTkLabel(f, text="No IOC data", font=(F, 16),
                         text_color=C["text3"]).place(relx=0.5, rely=0.5, anchor="center")
            return f

        iocs = self.results.get("iocs", {})
        self._title(f, f"Indicators of Compromise ({iocs.get('total_iocs', 0)})")

        tb = self._textbox(f)
        tb.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        sections = []

        # Type summary
        by_type = iocs.get("by_type", {})
        if by_type:
            sections.append("═══ IOC TYPE SUMMARY ═══")
            for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                sections.append(f"  {t.upper():20s}  {c}")
            sections.append("")

        # IPs
        top_ips = iocs.get("top_ips", [])
        if top_ips:
            sections.append("═══ SUSPICIOUS IP ADDRESSES ═══")
            for ip in top_ips[:20]:
                sections.append(f"  {ip}")
            sections.append("")

        # Domains
        doms = iocs.get("top_domains", [])
        if doms:
            sections.append("═══ SUSPICIOUS DOMAINS ═══")
            for d in doms[:20]:
                sections.append(f"  {d}")
            sections.append("")

        # Hashes
        hashes = iocs.get("hashes", {})
        all_h = (hashes.get("md5", [])[:10] + hashes.get("sha1", [])[:5] +
                 hashes.get("sha256", [])[:5])
        if all_h:
            sections.append("═══ FILE HASHES ═══")
            for h in all_h:
                sections.append(f"  {h}")
            sections.append("")

        # CVEs
        cves = iocs.get("cves", [])
        if cves:
            sections.append("═══ CVEs REFERENCED ═══")
            for cv in cves:
                sections.append(f"  {cv}")
            sections.append("")

        # URLs
        urls = iocs.get("urls", [])
        if urls:
            sections.append("═══ SUSPICIOUS URLs ═══")
            for u in urls[:15]:
                sections.append(f"  {u}")

        tb.insert("1.0", "\n".join(sections) if sections else "No IOCs extracted.")
        tb.configure(state="disabled")
        return f

    # ============================================================
    # PAGE: AI Copilot
    # ============================================================
    def _page_copilot(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])
        self._title(f, "AI Analyst Copilot")

        self._chat = self._textbox(f)
        self._chat.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        welcome = ("ThreatScope AI Copilot — Ask questions about your analysis.\n\n"
                    "Try: summary, critical findings, IOCs, MITRE techniques,\n"
                    "     recommendations, timeline, correlations, users\n\n")
        self._chat.insert("1.0", welcome)
        self._chat.configure(state="disabled")

        # Quick buttons
        qf = ctk.CTkFrame(f, fg_color="transparent")
        qf.pack(fill="x", padx=12, pady=(0, 4))
        for txt in ["Summary", "Critical", "IOCs", "MITRE", "Recommendations", "Timeline"]:
            ctk.CTkButton(qf, text=txt, height=28, font=(F, 10),
                           fg_color=C["card"], hover_color=C["card_hover"],
                           text_color=C["text2"], corner_radius=6, width=90,
                           border_width=1, border_color=C["border"],
                           command=lambda t=txt: self._ask_copilot(f"Show {t.lower()}")
                           ).pack(side="left", padx=2)

        # Input
        inf = ctk.CTkFrame(f, fg_color="transparent")
        inf.pack(fill="x", padx=12, pady=(0, 12))
        inf.grid_columnconfigure(0, weight=1)

        self._cop_input = ctk.CTkEntry(inf, height=42, font=(F, 13),
                                        placeholder_text="Ask about the analysis...",
                                        fg_color=C["input"], border_color=C["border"],
                                        text_color=C["text"], corner_radius=8)
        self._cop_input.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self._cop_input.bind("<Return>", lambda e: self._ask_copilot())

        ctk.CTkButton(inf, text="Send", width=80, height=42, font=(F, 13, "bold"),
                       fg_color=C["accent"], hover_color=C["accent_dim"],
                       text_color="#000", corner_radius=8,
                       command=self._ask_copilot).grid(row=0, column=1)
        return f

    def _ask_copilot(self, msg=None):
        if msg is None:
            msg = self._cop_input.get().strip()
            self._cop_input.delete(0, "end")
        if not msg:
            return

        self._chat.configure(state="normal")
        self._chat.insert("end", f"\n▸ YOU:  {msg}\n")

        if not self.results:
            self._chat.insert("end", "\n  No analysis loaded. Analyze a file first.\n")
            self._chat.configure(state="disabled")
            self._chat.see("end")
            return

        def work():
            resp = self.copilot.ask(msg)
            self.after(0, lambda: self._show_cop_resp(resp))

        threading.Thread(target=work, daemon=True).start()

    def _show_cop_resp(self, resp):
        self._chat.configure(state="normal")
        self._chat.insert("end", f"\n▹ COPILOT:\n{resp}\n")
        self._chat.configure(state="disabled")
        self._chat.see("end")

    # ============================================================
    # PAGE: Narrative
    # ============================================================
    def _page_narrative(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])

        hdr = ctk.CTkFrame(f, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(18, 8))
        ctk.CTkLabel(hdr, text="Attack Narrative", font=(F, 20, "bold"),
                     text_color=C["text"]).pack(side="left")

        self._gen_btn = ctk.CTkButton(
            hdr, text="Generate", height=36, font=(F, 13, "bold"),
            fg_color=C["accent"], hover_color=C["accent_dim"],
            text_color="#000", corner_radius=8, command=self._gen_narrative)
        self._gen_btn.pack(side="right")

        self._narr_tb = self._textbox(f)
        self._narr_tb.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._narr_tb.insert("1.0",
                              "Click 'Generate' to create a professional attack narrative\n"
                              "from your analysis results. No API key required.\n\n"
                              "The narrative includes:\n"
                              "  • Executive Summary\n"
                              "  • Initial Access Vector\n"
                              "  • Attack Progression\n"
                              "  • Impact Assessment\n"
                              "  • IOCs & MITRE Mapping\n"
                              "  • Recommendations")
        self._narr_tb.configure(state="disabled")
        return f

    def _gen_narrative(self):
        if not self.results:
            messagebox.showinfo("Info", "Analyze a file first.")
            return
        self._gen_btn.configure(state="disabled", text="Generating...")

        def work():
            narr = self.narrative_engine.generate_narrative(self.results)
            self.after(0, lambda: self._show_narrative(narr))

        threading.Thread(target=work, daemon=True).start()

    def _show_narrative(self, narr):
        self._narr_tb.configure(state="normal")
        self._narr_tb.delete("1.0", "end")
        self._narr_tb.insert("1.0", narr)
        self._narr_tb.configure(state="disabled")
        self._gen_btn.configure(state="normal", text="Generate")

    # ============================================================
    # PAGE: Export
    # ============================================================
    def _page_export(self):
        f = ctk.CTkFrame(self.main, fg_color=C["bg"])
        self._title(f, "Export Report")

        scroll = ctk.CTkScrollableFrame(f, fg_color="transparent",
                                         scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        formats = [
            ("JSON", "Full analysis results", "json", True),
            ("CSV", "Findings as spreadsheet", "csv", True),
            ("STIX 2.1", "Threat intel bundle", "stix", True),
            ("PDF", "Professional PDF report", "pdf", PDF_AVAILABLE),
            ("DOCX", "Word document report", "docx", DOCX_AVAILABLE),
        ]

        for name, desc, fmt, avail in formats:
            row = self._card(scroll)
            row.pack(fill="x", padx=4, pady=4)

            inner = ctk.CTkFrame(row, fg_color="transparent")
            inner.pack(fill="x", padx=16, pady=14)
            inner.grid_columnconfigure(1, weight=1)

            tf = ctk.CTkFrame(inner, fg_color="transparent")
            tf.grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(tf, text=name, font=(F, 15, "bold"),
                         text_color=C["text"]).pack(anchor="w")
            label_text = desc
            if not avail:
                label_text += "  (install optional dep)"
            ctk.CTkLabel(tf, text=label_text, font=(F, 11),
                         text_color=C["text3"]).pack(anchor="w")

            ctk.CTkButton(
                inner, text="Export", width=100, height=36, font=(F, 12, "bold"),
                fg_color=C["accent"] if avail else C["input"],
                hover_color=C["accent_dim"] if avail else C["input"],
                text_color="#000" if avail else C["text3"],
                corner_radius=8, state="normal" if avail else "disabled",
                command=lambda fmt_=fmt: self._do_export(fmt_)
            ).grid(row=0, column=2, sticky="e")

        return f

    def _do_export(self, fmt):
        if not self.results:
            messagebox.showinfo("Info", "Analyze a file first.")
            return
        ext = {"json": ".json", "csv": ".csv", "stix": ".json",
               "pdf": ".pdf", "docx": ".docx"}
        fp = filedialog.asksaveasfilename(
            defaultextension=ext.get(fmt, ".json"),
            initialfile=f"threatscope_report{ext.get(fmt, '.json')}")
        if not fp:
            return
        try:
            {"json": export_json, "csv": export_csv, "stix": export_stix,
             "pdf": export_pdf if PDF_AVAILABLE else None,
             "docx": export_docx if DOCX_AVAILABLE else None}[fmt](self.results, fp)
            messagebox.showinfo("Done", f"Saved to:\n{fp}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


# ============================================================
# Entry
# ============================================================
def main():
    app = ThreatScopeGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
