"""
ThreatScope V2 — Premium Desktop GUI
Author: 0xSABRY

Professional DFIR analysis interface built with CustomTkinter.
Features: File analysis, threat dashboard, findings viewer, timeline,
MITRE ATT&CK mapping, IOC extraction, AI Copilot, and export.
"""

import sys
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
from datetime import datetime

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from config import VERSION, APP_NAME
from core.analyzer import LogAnalyzer
from ai.ai_core import NarrativeEngine, AnalystCopilot, TrainingMode
from export.exporters import export_json, export_csv, export_stix

# Try optional exporters
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
# Theme & Color Constants
# ============================================================
COLORS = {
    "bg_dark": "#0a0e17",
    "bg_card": "#111827",
    "bg_card_hover": "#1a2332",
    "bg_sidebar": "#0d1321",
    "bg_input": "#1e293b",
    "border": "#1e293b",
    "border_accent": "#00d4ff",
    "text_primary": "#e2e8f0",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "accent": "#00d4ff",
    "accent_dim": "#0ea5e9",
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "success": "#10b981",
    "warning": "#f59e0b",
    "danger": "#ef4444",
    "chart_bg": "#111827",
}

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "informational": "#64748b",
}

FONT_FAMILY = "Segoe UI"
FONT_MONO = "Cascadia Mono"


# ============================================================
# Main Application
# ============================================================
class ThreatScopeGUI(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        # ── Window Config ──
        self.title(f"{APP_NAME} V{VERSION} — Advanced DFIR Platform")
        self.geometry("1500x900")
        self.minsize(1200, 700)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # ── State ──
        self.analyzer = None
        self.results = None
        self.copilot = AnalystCopilot()
        self.narrative_engine = NarrativeEngine()
        self.training_mode = TrainingMode()
        self.current_page = "dashboard"

        # ── Build UI ──
        self._build_layout()
        self._show_page("dashboard")

    # ============================================================
    # Layout
    # ============================================================
    def _build_layout(self):
        """Build the main application layout with sidebar and content area."""
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0,
                                     fg_color=COLORS["bg_sidebar"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self._build_sidebar()

        # Main content area
        self.content = ctk.CTkFrame(self, corner_radius=0,
                                     fg_color=COLORS["bg_dark"])
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        # Page frames (created lazily)
        self.pages = {}

    def _build_sidebar(self):
        """Build the navigation sidebar."""
        # Logo / Brand
        brand_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_frame.pack(fill="x", padx=16, pady=(20, 5))

        ctk.CTkLabel(brand_frame, text="THREATSCOPE",
                     font=(FONT_FAMILY, 18, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w")
        ctk.CTkLabel(brand_frame, text=f"V{VERSION} — by 0xSABRY",
                     font=(FONT_FAMILY, 10),
                     text_color=COLORS["text_muted"]).pack(anchor="w")

        # Separator
        ctk.CTkFrame(self.sidebar, height=1,
                      fg_color=COLORS["border"]).pack(fill="x", padx=16, pady=12)

        # File controls
        self.file_label = ctk.CTkLabel(self.sidebar, text="No file loaded",
                                        font=(FONT_FAMILY, 10),
                                        text_color=COLORS["text_muted"],
                                        wraplength=180)
        self.file_label.pack(padx=16, anchor="w")

        btn_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(8, 4))

        self.browse_btn = ctk.CTkButton(
            btn_frame, text="  Browse File", height=36,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["accent"], hover_color=COLORS["accent_dim"],
            text_color="#000000", command=self._browse_file
        )
        self.browse_btn.pack(fill="x")

        self.analyze_btn = ctk.CTkButton(
            btn_frame, text="  Analyze", height=36,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["success"], hover_color="#059669",
            text_color="#000000", command=self._run_analysis,
            state="disabled"
        )
        self.analyze_btn.pack(fill="x", pady=(6, 0))

        # Progress bar (hidden by default)
        self.progress = ctk.CTkProgressBar(self.sidebar, mode="indeterminate",
                                            progress_color=COLORS["accent"])
        self.progress.pack(fill="x", padx=16, pady=(4, 0))
        self.progress.pack_forget()

        self.status_label = ctk.CTkLabel(self.sidebar, text="",
                                          font=(FONT_FAMILY, 10),
                                          text_color=COLORS["accent"])
        self.status_label.pack(padx=16, anchor="w")

        # Separator
        ctk.CTkFrame(self.sidebar, height=1,
                      fg_color=COLORS["border"]).pack(fill="x", padx=16, pady=12)

        # Navigation buttons
        nav_items = [
            ("dashboard", "Dashboard"),
            ("findings", "Findings"),
            ("timeline", "Timeline"),
            ("mitre", "MITRE ATT&CK"),
            ("iocs", "IOCs"),
            ("copilot", "AI Copilot"),
            ("narrative", "Attack Narrative"),
            ("export", "Export Report"),
        ]

        self.nav_buttons = {}
        for key, label in nav_items:
            btn = ctk.CTkButton(
                self.sidebar, text=f"   {label}", height=36,
                font=(FONT_FAMILY, 13),
                fg_color="transparent", hover_color=COLORS["bg_card"],
                text_color=COLORS["text_secondary"],
                anchor="w", command=lambda k=key: self._show_page(k)
            )
            btn.pack(fill="x", padx=8, pady=1)
            self.nav_buttons[key] = btn

        # Bottom spacer + version
        self.sidebar.pack_propagate(False)
        bottom = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=16, pady=12)
        ctk.CTkLabel(bottom, text="github.com/0xsabry",
                     font=(FONT_FAMILY, 9),
                     text_color=COLORS["text_muted"]).pack(anchor="w")

    # ============================================================
    # Navigation
    # ============================================================
    def _show_page(self, page_name: str):
        """Switch to a page, creating it if needed."""
        self.current_page = page_name

        # Update nav button styles
        for key, btn in self.nav_buttons.items():
            if key == page_name:
                btn.configure(fg_color=COLORS["bg_card"],
                              text_color=COLORS["accent"])
            else:
                btn.configure(fg_color="transparent",
                              text_color=COLORS["text_secondary"])

        # Hide all pages
        for page in self.pages.values():
            page.grid_forget()

        # Create or show page
        if page_name not in self.pages:
            self.pages[page_name] = self._create_page(page_name)

        self.pages[page_name].grid(row=0, column=0, sticky="nsew")

        # Refresh page data if analysis exists
        if self.results:
            self._refresh_page(page_name)

    def _create_page(self, page_name: str) -> ctk.CTkFrame:
        """Create a page frame."""
        creators = {
            "dashboard": self._create_dashboard_page,
            "findings": self._create_findings_page,
            "timeline": self._create_timeline_page,
            "mitre": self._create_mitre_page,
            "iocs": self._create_iocs_page,
            "copilot": self._create_copilot_page,
            "narrative": self._create_narrative_page,
            "export": self._create_export_page,
        }
        creator = creators.get(page_name, self._create_empty_page)
        return creator()

    def _create_empty_page(self) -> ctk.CTkFrame:
        """Placeholder for unimplemented pages."""
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])
        ctk.CTkLabel(frame, text="Coming Soon",
                     font=(FONT_FAMILY, 24, "bold"),
                     text_color=COLORS["text_muted"]).place(relx=0.5, rely=0.5, anchor="center")
        return frame

    # ============================================================
    # File Handling & Analysis
    # ============================================================
    def _browse_file(self):
        """Open file browser dialog."""
        filepath = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[
                ("All Supported", "*.evtx *.log *.txt *.json *.csv *.xml *.syslog"),
                ("Windows Event Log", "*.evtx"),
                ("Log Files", "*.log *.txt *.syslog"),
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("XML", "*.xml"),
                ("All Files", "*.*"),
            ]
        )
        if filepath:
            self.analyzer = LogAnalyzer(filepath)
            fname = Path(filepath).name
            self.file_label.configure(text=f"File: {fname}")
            self.analyze_btn.configure(state="normal")
            self.status_label.configure(text="Ready to analyze", text_color=COLORS["success"])

    def _run_analysis(self):
        """Run analysis in a background thread."""
        if not self.analyzer:
            return

        self.analyze_btn.configure(state="disabled")
        self.browse_btn.configure(state="disabled")
        self.progress.pack(fill="x", padx=16, pady=(4, 0))
        self.progress.start()
        self.status_label.configure(text="Loading file...", text_color=COLORS["accent"])

        def worker():
            try:
                self.analyzer.load()
                self.after(0, lambda: self.status_label.configure(
                    text=f"Analyzing {self.analyzer.total_lines:,} events..."))
                results = self.analyzer.analyze()
                self.results = results

                # Set AI context
                self.copilot.set_context(results)
                self.training_mode.set_context(results)

                self.after(0, self._on_analysis_complete)
            except Exception as e:
                self.after(0, lambda: self._on_analysis_error(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_analysis_complete(self):
        """Handle successful analysis completion."""
        self.progress.stop()
        self.progress.pack_forget()
        self.analyze_btn.configure(state="normal")
        self.browse_btn.configure(state="normal")

        score = self.results["threat_score"]
        level = self.results["threat_level"]
        total = self.results["summary"]["total_findings"]
        self.status_label.configure(
            text=f"Done! Score: {score}% ({level})",
            text_color=COLORS["critical"] if score >= 60 else COLORS["warning"] if score >= 30 else COLORS["success"]
        )

        # Clear cached pages so they rebuild with new data
        for key in list(self.pages.keys()):
            self.pages[key].destroy()
            del self.pages[key]

        self._show_page("dashboard")

    def _on_analysis_error(self, error: str):
        """Handle analysis error."""
        self.progress.stop()
        self.progress.pack_forget()
        self.analyze_btn.configure(state="normal")
        self.browse_btn.configure(state="normal")
        self.status_label.configure(text=f"Error: {error[:60]}", text_color=COLORS["danger"])
        messagebox.showerror("Analysis Error", f"Failed to analyze file:\n\n{error}")

    # ============================================================
    # Helper: Card Builder
    # ============================================================
    def _make_card(self, parent, title="", pad=16) -> ctk.CTkFrame:
        """Create a styled card frame with optional title."""
        card = ctk.CTkFrame(parent, corner_radius=12,
                             fg_color=COLORS["bg_card"],
                             border_width=1, border_color=COLORS["border"])
        if title:
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=pad, pady=(pad, 4))
            ctk.CTkLabel(header, text=title,
                         font=(FONT_FAMILY, 15, "bold"),
                         text_color=COLORS["text_primary"]).pack(anchor="w")
        return card

    def _make_stat_card(self, parent, label, value, color=None) -> ctk.CTkFrame:
        """Create a stat display card."""
        card = ctk.CTkFrame(parent, corner_radius=10,
                             fg_color=COLORS["bg_card"],
                             border_width=1, border_color=COLORS["border"])
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text=str(value),
                     font=(FONT_FAMILY, 32, "bold"),
                     text_color=color or COLORS["accent"]).pack(padx=16, pady=(16, 2))
        ctk.CTkLabel(card, text=label,
                     font=(FONT_FAMILY, 11),
                     text_color=COLORS["text_muted"]).pack(padx=16, pady=(0, 16))
        return card

    def _make_scrollable(self, parent) -> ctk.CTkScrollableFrame:
        """Create a scrollable frame."""
        return ctk.CTkScrollableFrame(parent, fg_color="transparent",
                                       scrollbar_button_color=COLORS["border"],
                                       scrollbar_button_hover_color=COLORS["accent"])

    # ============================================================
    # PAGE: Dashboard
    # ============================================================
    def _create_dashboard_page(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])

        if not self.results:
            # Empty state
            empty = ctk.CTkFrame(frame, fg_color="transparent")
            empty.place(relx=0.5, rely=0.45, anchor="center")
            ctk.CTkLabel(empty, text="THREATSCOPE",
                         font=(FONT_FAMILY, 36, "bold"),
                         text_color=COLORS["accent"]).pack()
            ctk.CTkLabel(empty, text="Advanced DFIR & Threat Detection Platform",
                         font=(FONT_FAMILY, 14),
                         text_color=COLORS["text_secondary"]).pack(pady=(4, 20))
            ctk.CTkLabel(empty, text="Browse a log file to begin analysis",
                         font=(FONT_FAMILY, 12),
                         text_color=COLORS["text_muted"]).pack()

            features = [
                "115+ Built-in Detection Rules",
                "Sigma & YARA Engine",
                "MITRE ATT&CK Mapping",
                "Behavioral Chain Analysis",
                "IOC Extraction & Correlation",
                "AI-Powered Attack Narrative",
            ]
            feat_frame = ctk.CTkFrame(empty, fg_color="transparent")
            feat_frame.pack(pady=20)
            for feat in features:
                ctk.CTkLabel(feat_frame, text=f"  {feat}",
                             font=(FONT_FAMILY, 11),
                             text_color=COLORS["text_muted"]).pack(anchor="w", pady=1)
            return frame

        # ── With results ──
        scroll = self._make_scrollable(frame)
        scroll.pack(fill="both", expand=True, padx=8, pady=8)

        r = self.results
        summary = r["summary"]
        score = r["threat_score"]
        level = r["threat_level"]

        # ── Threat Score Header ──
        header_card = self._make_card(scroll)
        header_card.pack(fill="x", padx=8, pady=(0, 8))

        header_inner = ctk.CTkFrame(header_card, fg_color="transparent")
        header_inner.pack(fill="x", padx=20, pady=16)
        header_inner.grid_columnconfigure(1, weight=1)

        score_color = COLORS["critical"] if score >= 60 else COLORS["warning"] if score >= 30 else COLORS["success"]

        # Score display
        score_frame = ctk.CTkFrame(header_inner, fg_color="transparent")
        score_frame.grid(row=0, column=0, sticky="w", padx=(0, 30))
        ctk.CTkLabel(score_frame, text=f"{score}%",
                     font=(FONT_FAMILY, 52, "bold"),
                     text_color=score_color).pack(anchor="w")
        ctk.CTkLabel(score_frame, text=f"THREAT LEVEL: {level}",
                     font=(FONT_FAMILY, 14, "bold"),
                     text_color=score_color).pack(anchor="w")

        # Metadata
        meta_frame = ctk.CTkFrame(header_inner, fg_color="transparent")
        meta_frame.grid(row=0, column=1, sticky="e")
        meta = r["metadata"]
        filepath = Path(meta.get("filepath", "")).name or "Unknown"
        ctk.CTkLabel(meta_frame, text=f"File: {filepath}",
                     font=(FONT_FAMILY, 12),
                     text_color=COLORS["text_secondary"]).pack(anchor="e")
        ctk.CTkLabel(meta_frame, text=f"Events: {meta.get('total_events', 0):,}",
                     font=(FONT_FAMILY, 12),
                     text_color=COLORS["text_secondary"]).pack(anchor="e")
        ctk.CTkLabel(meta_frame, text=f"Sigma Rules: {meta.get('sigma_rules_loaded', 0)} | YARA: {meta.get('yara_rules_loaded', 0)}",
                     font=(FONT_FAMILY, 11),
                     text_color=COLORS["text_muted"]).pack(anchor="e")

        # ── Stats Row ──
        stats_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        stats_frame.pack(fill="x", padx=8, pady=(0, 8))
        stats_frame.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        stats = [
            ("Total Findings", summary["total_findings"], COLORS["accent"]),
            ("Critical", summary["critical"], COLORS["critical"]),
            ("High", summary["high"], COLORS["high"]),
            ("Medium", summary["medium"], COLORS["medium"]),
            ("MITRE Techniques", summary["mitre_techniques"], COLORS["accent"]),
            ("IOCs", summary["total_iocs"], COLORS["success"]),
        ]
        for i, (label, value, color) in enumerate(stats):
            card = self._make_stat_card(stats_frame, label, value, color)
            card.grid(row=0, column=i, sticky="nsew", padx=4)

        # ── Charts Row ──
        charts_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        charts_frame.pack(fill="x", padx=8, pady=(0, 8))
        charts_frame.grid_columnconfigure((0, 1), weight=1)

        # Severity Distribution Pie
        sev_card = self._make_card(charts_frame, "Severity Distribution")
        sev_card.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self._draw_severity_pie(sev_card, summary)

        # Top IPs Bar
        ip_card = self._make_card(charts_frame, "Top Source IPs")
        ip_card.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        self._draw_top_ips_bar(ip_card, r.get("top_ips", []))

        # ── Top Findings Preview ──
        findings_card = self._make_card(scroll, "Top Findings")
        findings_card.pack(fill="x", padx=8, pady=(0, 8))
        self._draw_findings_preview(findings_card, r.get("findings", [])[:10])

        return frame

    def _draw_severity_pie(self, parent, summary):
        """Draw severity distribution pie chart."""
        values = [summary["critical"], summary["high"], summary["medium"], summary["low"]]
        labels = ["Critical", "High", "Medium", "Low"]
        colors = [COLORS["critical"], COLORS["high"], COLORS["medium"], COLORS["low"]]

        # Filter zero values
        filtered = [(l, v, c) for l, v, c in zip(labels, values, colors) if v > 0]
        if not filtered:
            ctk.CTkLabel(parent, text="No findings",
                         text_color=COLORS["text_muted"]).pack(pady=30)
            return

        labels, values, colors = zip(*filtered)

        fig = Figure(figsize=(4, 2.8), dpi=100, facecolor=COLORS["chart_bg"])
        ax = fig.add_subplot(111)
        wedges, texts, autotexts = ax.pie(
            values, labels=labels, colors=colors,
            autopct="%1.0f%%", startangle=90,
            textprops={"color": COLORS["text_primary"], "fontsize": 9}
        )
        for t in autotexts:
            t.set_fontsize(8)
            t.set_color("#ffffff")
        ax.set_facecolor(COLORS["chart_bg"])

        canvas = FigureCanvasTkAgg(fig, parent)
        canvas.get_tk_widget().pack(padx=16, pady=(0, 16))
        canvas.draw()

    def _draw_top_ips_bar(self, parent, top_ips):
        """Draw top IPs horizontal bar chart."""
        if not top_ips:
            ctk.CTkLabel(parent, text="No IP data",
                         text_color=COLORS["text_muted"]).pack(pady=30)
            return

        display = top_ips[:8]
        ips = [ip for ip, _ in display]
        counts = [count for _, count in display]

        fig = Figure(figsize=(4, 2.8), dpi=100, facecolor=COLORS["chart_bg"])
        ax = fig.add_subplot(111)
        bars = ax.barh(range(len(ips)), counts, color=COLORS["accent"], height=0.6)
        ax.set_yticks(range(len(ips)))
        ax.set_yticklabels(ips, fontsize=8, color=COLORS["text_secondary"])
        ax.invert_yaxis()
        ax.set_facecolor(COLORS["chart_bg"])
        ax.tick_params(axis="x", colors=COLORS["text_muted"], labelsize=8)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["border"])
        ax.spines["left"].set_color(COLORS["border"])
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, parent)
        canvas.get_tk_widget().pack(padx=16, pady=(0, 16))
        canvas.draw()

    def _draw_findings_preview(self, parent, findings):
        """Draw a preview of top findings."""
        if not findings:
            ctk.CTkLabel(parent, text="No findings to display",
                         text_color=COLORS["text_muted"]).pack(padx=16, pady=16)
            return

        for f in findings:
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)

            sev = f.get("severity", "low").lower()
            sev_color = SEVERITY_COLORS.get(sev, COLORS["text_muted"])

            ctk.CTkLabel(row, text=f"[{sev.upper()}]",
                         font=(FONT_MONO, 11, "bold"),
                         text_color=sev_color, width=80).pack(side="left")
            ctk.CTkLabel(row, text=f.get("title", ""),
                         font=(FONT_FAMILY, 12, "bold"),
                         text_color=COLORS["text_primary"]).pack(side="left", padx=(4, 8))
            ctk.CTkLabel(row, text=f.get("description", "")[:80],
                         font=(FONT_FAMILY, 11),
                         text_color=COLORS["text_secondary"]).pack(side="left", fill="x")

        ctk.CTkFrame(parent, height=8, fg_color="transparent").pack()

    # ============================================================
    # PAGE: Findings
    # ============================================================
    def _create_findings_page(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])

        if not self.results:
            ctk.CTkLabel(frame, text="Run an analysis to see findings",
                         font=(FONT_FAMILY, 16),
                         text_color=COLORS["text_muted"]).place(relx=0.5, rely=0.5, anchor="center")
            return frame

        findings = self.results.get("findings", [])

        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text=f"Security Findings ({len(findings)})",
                     font=(FONT_FAMILY, 20, "bold"),
                     text_color=COLORS["text_primary"]).pack(side="left")

        # Filter
        self.findings_filter = ctk.CTkComboBox(
            header, values=["All", "Critical", "High", "Medium", "Low"],
            width=120, command=lambda v: self._filter_findings(v)
        )
        self.findings_filter.pack(side="right")
        self.findings_filter.set("All")

        # Findings list
        self.findings_scroll = self._make_scrollable(frame)
        self.findings_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._populate_findings(findings)
        return frame

    def _populate_findings(self, findings):
        """Populate findings list."""
        for widget in self.findings_scroll.winfo_children():
            widget.destroy()

        for i, f in enumerate(findings):
            sev = f.get("severity", "low").lower()
            sev_color = SEVERITY_COLORS.get(sev, COLORS["text_muted"])

            card = ctk.CTkFrame(self.findings_scroll, corner_radius=8,
                                 fg_color=COLORS["bg_card"],
                                 border_width=1, border_color=COLORS["border"])
            card.pack(fill="x", padx=4, pady=3)

            # Header row
            hdr = ctk.CTkFrame(card, fg_color="transparent")
            hdr.pack(fill="x", padx=12, pady=(10, 4))

            ctk.CTkLabel(hdr, text=f" {sev.upper()} ",
                         font=(FONT_MONO, 10, "bold"),
                         fg_color=sev_color, corner_radius=4,
                         text_color="#000000" if sev != "low" else "#ffffff",
                         width=70).pack(side="left")

            ctk.CTkLabel(hdr, text=f.get("title", "Unknown"),
                         font=(FONT_FAMILY, 13, "bold"),
                         text_color=COLORS["text_primary"]).pack(side="left", padx=8)

            mitre = f.get("mitre", "")
            if mitre:
                ctk.CTkLabel(hdr, text=f"MITRE: {mitre}",
                             font=(FONT_MONO, 10),
                             text_color=COLORS["accent"]).pack(side="right")

            # Description
            ctk.CTkLabel(card, text=f.get("description", ""),
                         font=(FONT_FAMILY, 11),
                         text_color=COLORS["text_secondary"],
                         wraplength=900, justify="left").pack(fill="x", padx=12, pady=(0, 4), anchor="w")

            # Metadata row
            meta_row = ctk.CTkFrame(card, fg_color="transparent")
            meta_row.pack(fill="x", padx=12, pady=(0, 8))

            ts = f.get("timestamp", "")
            if ts:
                ctk.CTkLabel(meta_row, text=f"Time: {ts}",
                             font=(FONT_MONO, 9),
                             text_color=COLORS["text_muted"]).pack(side="left", padx=(0, 16))

            ln = f.get("line_number", "")
            if ln:
                ctk.CTkLabel(meta_row, text=f"Line: {ln}",
                             font=(FONT_MONO, 9),
                             text_color=COLORS["text_muted"]).pack(side="left")

    def _filter_findings(self, severity_filter):
        """Filter findings by severity."""
        if not self.results:
            return
        findings = self.results.get("findings", [])
        if severity_filter != "All":
            findings = [f for f in findings if f.get("severity", "").lower() == severity_filter.lower()]
        self._populate_findings(findings)

    # ============================================================
    # PAGE: Timeline
    # ============================================================
    def _create_timeline_page(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])

        if not self.results or not self.results.get("timeline"):
            ctk.CTkLabel(frame, text="No timeline data available",
                         font=(FONT_FAMILY, 16),
                         text_color=COLORS["text_muted"]).place(relx=0.5, rely=0.5, anchor="center")
            return frame

        timeline = self.results["timeline"]

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text=f"Attack Timeline ({len(timeline)} events)",
                     font=(FONT_FAMILY, 20, "bold"),
                     text_color=COLORS["text_primary"]).pack(side="left")

        scroll = self._make_scrollable(frame)
        scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        for i, event in enumerate(timeline[:200]):
            sev = event.get("severity", "low").lower()
            sev_color = SEVERITY_COLORS.get(sev, COLORS["text_muted"])

            row = ctk.CTkFrame(scroll, corner_radius=6, fg_color=COLORS["bg_card"],
                                border_width=1, border_color=COLORS["border"])
            row.pack(fill="x", padx=4, pady=2)

            inner = ctk.CTkFrame(row, fg_color="transparent")
            inner.pack(fill="x", padx=12, pady=8)

            # Timeline dot
            dot = ctk.CTkFrame(inner, width=10, height=10, corner_radius=5,
                                fg_color=sev_color)
            dot.pack(side="left", padx=(0, 10))

            # Timestamp
            ts = event.get("timestamp", "N/A")
            ctk.CTkLabel(inner, text=ts,
                         font=(FONT_MONO, 10),
                         text_color=COLORS["text_muted"],
                         width=160).pack(side="left")

            # Severity badge
            ctk.CTkLabel(inner, text=f" {sev.upper()} ",
                         font=(FONT_MONO, 9, "bold"),
                         fg_color=sev_color, corner_radius=3,
                         text_color="#000000" if sev != "low" else "#ffffff",
                         width=60).pack(side="left", padx=6)

            # Title
            ctk.CTkLabel(inner, text=event.get("title", ""),
                         font=(FONT_FAMILY, 12),
                         text_color=COLORS["text_primary"]).pack(side="left", fill="x")

        return frame

    # ============================================================
    # PAGE: MITRE ATT&CK
    # ============================================================
    def _create_mitre_page(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])

        if not self.results or not self.results.get("mitre_hits"):
            ctk.CTkLabel(frame, text="No MITRE ATT&CK data available",
                         font=(FONT_FAMILY, 16),
                         text_color=COLORS["text_muted"]).place(relx=0.5, rely=0.5, anchor="center")
            return frame

        mitre_hits = self.results["mitre_hits"]

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text=f"MITRE ATT&CK Techniques ({len(mitre_hits)})",
                     font=(FONT_FAMILY, 20, "bold"),
                     text_color=COLORS["text_primary"]).pack(side="left")

        # Summary stats
        total_hits = sum(mitre_hits.values())
        ctk.CTkLabel(header, text=f"Total hits: {total_hits}",
                     font=(FONT_FAMILY, 12),
                     text_color=COLORS["text_secondary"]).pack(side="right")

        scroll = self._make_scrollable(frame)
        scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Technique cards sorted by hit count
        for tech, count in sorted(mitre_hits.items(), key=lambda x: x[1], reverse=True):
            card = ctk.CTkFrame(scroll, corner_radius=8, fg_color=COLORS["bg_card"],
                                 border_width=1, border_color=COLORS["border"])
            card.pack(fill="x", padx=4, pady=2)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=16, pady=10)

            # Color by coverage
            if count >= 5:
                cov_color = COLORS["success"]
            elif count >= 2:
                cov_color = COLORS["warning"]
            else:
                cov_color = COLORS["danger"]

            ctk.CTkLabel(inner, text=tech,
                         font=(FONT_MONO, 14, "bold"),
                         text_color=COLORS["accent"]).pack(side="left")

            # Hits bar
            bar_frame = ctk.CTkFrame(inner, fg_color="transparent", width=200)
            bar_frame.pack(side="right")

            ctk.CTkLabel(bar_frame, text=f"{count} hits",
                         font=(FONT_MONO, 11),
                         text_color=cov_color).pack(side="right")

            pb = ctk.CTkProgressBar(bar_frame, width=120, height=8,
                                     progress_color=cov_color,
                                     fg_color=COLORS["bg_input"])
            pb.pack(side="right", padx=8)
            pb.set(min(count / max(mitre_hits.values()), 1.0))

        return frame

    # ============================================================
    # PAGE: IOCs
    # ============================================================
    def _create_iocs_page(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])

        if not self.results:
            ctk.CTkLabel(frame, text="No IOC data available",
                         font=(FONT_FAMILY, 16),
                         text_color=COLORS["text_muted"]).place(relx=0.5, rely=0.5, anchor="center")
            return frame

        iocs = self.results.get("iocs", {})

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text=f"Indicators of Compromise ({iocs.get('total_iocs', 0)})",
                     font=(FONT_FAMILY, 20, "bold"),
                     text_color=COLORS["text_primary"]).pack(side="left")

        scroll = self._make_scrollable(frame)
        scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # IOC type summary
        by_type = iocs.get("by_type", {})
        if by_type:
            type_card = self._make_card(scroll, "IOC Types")
            type_card.pack(fill="x", padx=4, pady=(0, 8))
            for ioc_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                row = ctk.CTkFrame(type_card, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=2)
                ctk.CTkLabel(row, text=ioc_type.upper(),
                             font=(FONT_MONO, 11, "bold"),
                             text_color=COLORS["accent"], width=120).pack(side="left")
                ctk.CTkLabel(row, text=str(count),
                             font=(FONT_MONO, 11),
                             text_color=COLORS["text_primary"]).pack(side="left")
            ctk.CTkFrame(type_card, height=8, fg_color="transparent").pack()

        # Top IPs
        top_ips = iocs.get("top_ips", [])
        if top_ips:
            ip_card = self._make_card(scroll, "Suspicious IP Addresses")
            ip_card.pack(fill="x", padx=4, pady=(0, 8))
            for ip in top_ips[:20]:
                ctk.CTkLabel(ip_card, text=f"  {ip}",
                             font=(FONT_MONO, 12),
                             text_color=COLORS["text_primary"]).pack(anchor="w", padx=16, pady=1)
            ctk.CTkFrame(ip_card, height=8, fg_color="transparent").pack()

        # Top Domains
        top_domains = iocs.get("top_domains", [])
        if top_domains:
            dom_card = self._make_card(scroll, "Suspicious Domains")
            dom_card.pack(fill="x", padx=4, pady=(0, 8))
            for d in top_domains[:20]:
                ctk.CTkLabel(dom_card, text=f"  {d}",
                             font=(FONT_MONO, 12),
                             text_color=COLORS["text_primary"]).pack(anchor="w", padx=16, pady=1)
            ctk.CTkFrame(dom_card, height=8, fg_color="transparent").pack()

        # Hashes
        hashes = iocs.get("hashes", {})
        all_hashes = hashes.get("md5", []) + hashes.get("sha1", []) + hashes.get("sha256", [])
        if all_hashes:
            hash_card = self._make_card(scroll, "File Hashes")
            hash_card.pack(fill="x", padx=4, pady=(0, 8))
            for h in all_hashes[:20]:
                ctk.CTkLabel(hash_card, text=h,
                             font=(FONT_MONO, 10),
                             text_color=COLORS["text_primary"]).pack(anchor="w", padx=16, pady=1)
            ctk.CTkFrame(hash_card, height=8, fg_color="transparent").pack()

        # CVEs
        cves = iocs.get("cves", [])
        if cves:
            cve_card = self._make_card(scroll, "CVEs Referenced")
            cve_card.pack(fill="x", padx=4, pady=(0, 8))
            for cve in cves:
                ctk.CTkLabel(cve_card, text=f"  {cve}",
                             font=(FONT_MONO, 12),
                             text_color=COLORS["danger"]).pack(anchor="w", padx=16, pady=1)
            ctk.CTkFrame(cve_card, height=8, fg_color="transparent").pack()

        return frame

    # ============================================================
    # PAGE: AI Copilot
    # ============================================================
    def _create_copilot_page(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text="AI Analyst Copilot",
                     font=(FONT_FAMILY, 20, "bold"),
                     text_color=COLORS["text_primary"]).pack(side="left")

        # Chat area
        self.chat_display = ctk.CTkTextbox(
            frame, font=(FONT_FAMILY, 12),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_primary"],
            border_width=1, border_color=COLORS["border"],
            corner_radius=10, wrap="word"
        )
        self.chat_display.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self.chat_display.insert("end", "Welcome to ThreatScope AI Copilot!\n\n")
        self.chat_display.insert("end", "Ask questions about your analysis results. Try:\n")
        self.chat_display.insert("end", "  - \"What are the critical findings?\"\n")
        self.chat_display.insert("end", "  - \"Show me the IOCs\"\n")
        self.chat_display.insert("end", "  - \"What MITRE techniques were detected?\"\n")
        self.chat_display.insert("end", "  - \"What are your recommendations?\"\n")
        self.chat_display.insert("end", "  - \"Show me the attack timeline\"\n\n")
        self.chat_display.configure(state="disabled")

        # Quick action buttons
        actions_frame = ctk.CTkFrame(frame, fg_color="transparent")
        actions_frame.pack(fill="x", padx=16, pady=(0, 4))

        quick_actions = [
            "Summary", "Critical Findings", "IOCs",
            "MITRE Techniques", "Recommendations", "Timeline"
        ]
        for action in quick_actions:
            ctk.CTkButton(
                actions_frame, text=action, height=28,
                font=(FONT_FAMILY, 10),
                fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
                border_width=1, border_color=COLORS["border"],
                text_color=COLORS["text_secondary"],
                command=lambda a=action: self._send_copilot(f"Show me the {a.lower()}")
            ).pack(side="left", padx=2)

        # Input area
        input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=16, pady=(0, 16))
        input_frame.grid_columnconfigure(0, weight=1)

        self.copilot_input = ctk.CTkEntry(
            input_frame, height=42,
            font=(FONT_FAMILY, 13),
            placeholder_text="Ask a question about the analysis...",
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"]
        )
        self.copilot_input.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.copilot_input.bind("<Return>", lambda e: self._send_copilot())

        ctk.CTkButton(
            input_frame, text="Send", width=80, height=42,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["accent"], hover_color=COLORS["accent_dim"],
            text_color="#000000", command=self._send_copilot
        ).grid(row=0, column=1)

        return frame

    def _send_copilot(self, message=None):
        """Send a message to the AI copilot."""
        if message is None:
            message = self.copilot_input.get().strip()
            self.copilot_input.delete(0, "end")

        if not message:
            return

        self.chat_display.configure(state="normal")
        self.chat_display.insert("end", f"\n YOU:  {message}\n\n", "user")

        if not self.results:
            self.chat_display.insert("end", " COPILOT:  No analysis loaded. Please analyze a file first.\n\n")
            self.chat_display.configure(state="disabled")
            self.chat_display.see("end")
            return

        # Get response in background
        def worker():
            response = self.copilot.ask(message)
            self.after(0, lambda: self._display_copilot_response(response))

        threading.Thread(target=worker, daemon=True).start()

    def _display_copilot_response(self, response):
        """Display copilot response in chat."""
        self.chat_display.configure(state="normal")
        self.chat_display.insert("end", f" COPILOT:\n{response}\n\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

    # ============================================================
    # PAGE: Attack Narrative
    # ============================================================
    def _create_narrative_page(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text="Attack Narrative",
                     font=(FONT_FAMILY, 20, "bold"),
                     text_color=COLORS["text_primary"]).pack(side="left")

        self.gen_narrative_btn = ctk.CTkButton(
            header, text="Generate Narrative", height=36,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["accent"], hover_color=COLORS["accent_dim"],
            text_color="#000000", command=self._generate_narrative
        )
        self.gen_narrative_btn.pack(side="right")

        self.narrative_display = ctk.CTkTextbox(
            frame, font=(FONT_FAMILY, 12),
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_primary"],
            border_width=1, border_color=COLORS["border"],
            corner_radius=10, wrap="word"
        )
        self.narrative_display.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.narrative_display.insert("end",
            "Click 'Generate Narrative' to create a professional attack narrative "
            "from your analysis results.\n\nThe narrative engine structures findings, "
            "timeline, IOCs, and MITRE techniques into a coherent incident report.")
        self.narrative_display.configure(state="disabled")

        return frame

    def _generate_narrative(self):
        """Generate attack narrative."""
        if not self.results:
            messagebox.showinfo("No Data", "Please analyze a file first.")
            return

        self.gen_narrative_btn.configure(state="disabled", text="Generating...")

        def worker():
            narrative = self.narrative_engine.generate_narrative(self.results)
            self.after(0, lambda: self._display_narrative(narrative))

        threading.Thread(target=worker, daemon=True).start()

    def _display_narrative(self, narrative):
        """Display generated narrative."""
        self.narrative_display.configure(state="normal")
        self.narrative_display.delete("1.0", "end")
        self.narrative_display.insert("end", narrative)
        self.narrative_display.configure(state="disabled")
        self.gen_narrative_btn.configure(state="normal", text="Generate Narrative")

    # ============================================================
    # PAGE: Export
    # ============================================================
    def _create_export_page(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg_dark"])

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text="Export Report",
                     font=(FONT_FAMILY, 20, "bold"),
                     text_color=COLORS["text_primary"]).pack(side="left")

        scroll = self._make_scrollable(frame)
        scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        formats = [
            ("JSON Report", "Full analysis results in JSON format", "json", True),
            ("CSV Report", "Findings exported as CSV spreadsheet", "csv", True),
            ("STIX Bundle", "STIX 2.1 threat intelligence bundle", "stix", True),
            ("PDF Report", "Professional PDF incident report", "pdf", PDF_AVAILABLE),
            ("DOCX Report", "Microsoft Word document report", "docx", DOCX_AVAILABLE),
        ]

        for name, desc, fmt, available in formats:
            card = ctk.CTkFrame(scroll, corner_radius=10,
                                 fg_color=COLORS["bg_card"],
                                 border_width=1, border_color=COLORS["border"])
            card.pack(fill="x", padx=4, pady=4)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=16, pady=14)

            text_frame = ctk.CTkFrame(inner, fg_color="transparent")
            text_frame.pack(side="left", fill="x", expand=True)

            ctk.CTkLabel(text_frame, text=name,
                         font=(FONT_FAMILY, 14, "bold"),
                         text_color=COLORS["text_primary"]).pack(anchor="w")
            ctk.CTkLabel(text_frame, text=desc,
                         font=(FONT_FAMILY, 11),
                         text_color=COLORS["text_secondary"]).pack(anchor="w")
            if not available:
                ctk.CTkLabel(text_frame, text="(Install optional dependency to enable)",
                             font=(FONT_FAMILY, 10),
                             text_color=COLORS["text_muted"]).pack(anchor="w")

            ctk.CTkButton(
                inner, text="Export", width=100, height=36,
                font=(FONT_FAMILY, 12, "bold"),
                fg_color=COLORS["accent"] if available else COLORS["bg_input"],
                hover_color=COLORS["accent_dim"] if available else COLORS["bg_input"],
                text_color="#000000" if available else COLORS["text_muted"],
                state="normal" if available else "disabled",
                command=lambda f=fmt: self._do_export(f)
            ).pack(side="right")

        return frame

    def _do_export(self, fmt):
        """Export analysis results to file."""
        if not self.results:
            messagebox.showinfo("No Data", "Please analyze a file first.")
            return

        ext_map = {"json": "*.json", "csv": "*.csv", "stix": "*.json", "pdf": "*.pdf", "docx": "*.docx"}
        filepath = filedialog.asksaveasfilename(
            title=f"Save {fmt.upper()} Report",
            defaultextension=ext_map.get(fmt, "*.json"),
            filetypes=[(f"{fmt.upper()} files", ext_map.get(fmt, "*.*"))],
            initialfile=f"threatscope_report.{fmt if fmt != 'stix' else 'json'}"
        )
        if not filepath:
            return

        try:
            if fmt == "json":
                export_json(self.results, filepath)
            elif fmt == "csv":
                export_csv(self.results, filepath)
            elif fmt == "stix":
                export_stix(self.results, filepath)
            elif fmt == "pdf" and PDF_AVAILABLE:
                export_pdf(self.results, filepath)
            elif fmt == "docx" and DOCX_AVAILABLE:
                export_docx(self.results, filepath)

            messagebox.showinfo("Export Complete",
                                f"Report saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{e}")

    # ============================================================
    # Refresh
    # ============================================================
    def _refresh_page(self, page_name):
        """Refresh page content (called when switching pages with data)."""
        pass  # Pages rebuild from self.results on creation


# ============================================================
# Entry Point
# ============================================================
def main():
    """Launch ThreatScope GUI."""
    app = ThreatScopeGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
