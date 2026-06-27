from __future__ import annotations

import ctypes
import os
import sys

def hide_console():
    if sys.platform == "win32" and getattr(sys, "frozen", False):
        kernel32 = ctypes.WinDLL("kernel32")
        user32 = ctypes.WinDLL("user32")
        hWnd = kernel32.GetConsoleWindow()
        if hWnd != 0:
            user32.ShowWindow(hWnd, 0)  # SW_HIDE = 0

hide_console()

import csv
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from dashboard import (
    APP_ROOT,
    BASE_DIR,
    DEFAULT_CONFIG_PATH,
    ALERT_CATEGORY_OPTIONS,
    MONITORING_SETTINGS_PATH,
    NOTIFICATION_HISTORY_PATH,
    OUTPUT_DIR,
    build_disk_treemap_rows,
    build_disabled_categories,
    build_drive_usage_cards,
    build_project_hierarchy,
    build_project_tools_index,
    build_removal_scenario,
    build_runtime_family_report,
    build_runtime_family_test_steps,
    build_version_family_summary,
    build_search_index,
    collect_project_tools,
    enabled_categories_from_preferences,
    load_notification_center_settings,
    normalize_windows_path,
    resolve_runtime_config_path,
    runtime_family_key_from_label,
    save_notification_center_settings,
    safe_float,
)
from src.analyzers.cleanup_planner import build_cleanup_simulation, write_cleanup_simulation
from src.monitoring.notification_service import send_notification
from src.monitoring.tray_service import DesktopTrayController, TrayCallbacks
from src.monitoring.scheduler_service import get_next_scan_date
from src.analyzers.refresh_planner import build_refresh_plan, estimate_plan_duration, format_eta
from src.analyzers.manual_review import evaluate_manual_review, load_manual_review_overrides, save_manual_review_override
from src.analyzers.runtime_advisor import build_runtime_inventory
from src.presentation.view_models import build_program_view_rows
from src.windows_software_inventory_analyzer.config import load_config
from src.main import main as main_func

if Path.cwd().resolve() != APP_ROOT.resolve():
    os.chdir(APP_ROOT)

def load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def safe_int(value: str) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


class DesktopAnalyzerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Windows Software Inventory Analyzer - Desktop GUI")
        self.root.geometry("1520x980")
        self.root.minsize(1260, 820)

        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.status_var = tk.StringVar(value="Hazir")
        self.step_var = tk.StringVar(value="Bekliyor")
        self.progress_var = tk.DoubleVar(value=0)
        self.refresh_mode_var = tk.StringVar(value="quick")

        self.recommendations: list[dict[str, str]] = []
        self.risk_scores: list[dict[str, str]] = []
        self.projects: list[dict[str, str]] = []
        self.disk_usage: list[dict[str, str]] = []
        self.disk_zone_report: list[dict[str, str]] = []
        self.disk_cleanup_scenarios: list[dict[str, str]] = []
        self.installed_programs: list[dict[str, str]] = []
        self.mappings: list[dict[str, str]] = []
        self.dotnet_sdk_report: list[dict[str, str]] = []
        self.sdk_validation_report: list[dict[str, str]] = []
        self.validation_status: list[dict[str, str]] = []
        self.removal_decisions: list[dict[str, str]] = []
        self.system_tools_report: list[dict[str, str]] = []
        self.system_tool_impact_report: list[dict[str, str]] = []
        self.alerts: list[dict[str, str]] = []
        self.event_log_summary: list[dict[str, str]] = []
        self.program_view_rows: list[dict[str, str]] = []
        self.search_rows: list[dict[str, str]] = []
        self.project_tools_index: dict[str, list[dict[str, str]]] = {}
        self.root_projects: list[dict[str, str]] = []
        self.child_projects_index: dict[str, list[dict[str, str]]] = {}
        self.project_size_report: list[dict[str, str]] = []
        self.project_storage_breakdown: list[dict[str, str]] = []
        self.runtime_family_summaries: list[dict[str, str]] = []
        self.runtime_family_details: dict[str, list[dict[str, str]]] = {}
        self.manual_review_overrides: dict[str, dict[str, str]] = {}
        self.selected_program: dict[str, str] = {}
        self.selected_runtime_family: str = ""
        self.selected_disk_zone_path: str = ""
        self.notification_preferences, self.monitoring_settings = load_notification_center_settings()
        self.is_hidden_to_tray = False
        self.tray_runtime_status = "Tray icon henuz denenmedi"
        self.tray_controller = DesktopTrayController(
            "Windows Software Inventory Analyzer",
            TrayCallbacks(
                on_show=lambda: self.root.after(0, self.show_window_from_tray),
                on_exit=lambda: self.root.after(0, self.exit_from_tray),
            ),
        )

        self.root.protocol("WM_DELETE_WINDOW", self.on_close_request)
        self.build_layout()
        self.refresh_views()
        self.sync_tray_icon()
        self.send_desktop_notification(
            title="Windows Software Inventory Analyzer",
            message="Desktop GUI acildi. Uyari Merkezi ve bildirim ayarlari hazir.",
            notification_id="welcome_desktop gui",
            honor_open_pref=True,
        )

    def build_layout(self) -> None:
        toolbar = ttk.Frame(self.root, padding=10)
        toolbar.pack(fill=tk.X)

        ttk.Button(toolbar, text="Verileri Yenile", command=self.run_refresh_all).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(toolbar, text="Projeleri Yenile", command=self.run_refresh_projects).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(toolbar, text="Ekrani Yenile", command=self.refresh_views).pack(side=tk.LEFT)
        ttk.Label(toolbar, text="Mod").pack(side=tk.LEFT, padx=(12, 4))
        ttk.Radiobutton(toolbar, text="Hizli", variable=self.refresh_mode_var, value="quick").pack(side=tk.LEFT)
        ttk.Radiobutton(toolbar, text="Derin", variable=self.refresh_mode_var, value="full").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(toolbar, textvariable=self.status_var).pack(side=tk.RIGHT)

        progress_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        progress_frame.pack(fill=tk.X)
        ttk.Label(progress_frame, textvariable=self.step_var).pack(anchor="w")
        ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100).pack(fill=tk.X, pady=(4, 0))

        self.log_text = tk.Text(self.root, height=6, wrap="word")
        self.log_text.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.make_text_readonly(self.log_text)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.tabs: dict[str, ttk.Frame] = {}
        tab_names = {
            "overview": "Genel Bakis",
            "mapping": "Program ve Proje Eslestirmeleri",
            "program_detail": "Program Karar Detayi",
            "removal": "Kaldirma Oncesi Rehber",
            "runtime": "Sistem Araclari Raporu",
            "project_detail": "Proje Detayi",
            "large": "En Cok Yer Kaplayanlar",
            "uncertain": "En Belirsiz Programlar",
            "cleanup": "Yuksek Temizlik Onceligi",
            "alerts": "Uyari Merkezi",
            "settings": "Bildirim Ayarlari",
        }
        for key, title in tab_names.items():
            frame = ttk.Frame(self.notebook, padding=10)
            self.tabs[key] = frame
            self.notebook.add(frame, text=title)

        self.build_overview_tab()
        self.build_mapping_tab()
        self.build_program_detail_tab()
        self.build_removal_tab()
        self.build_runtime_tab()
        self.build_project_detail_tab()
        self.build_large_tab()
        self.build_uncertain_tab()
        self.build_cleanup_tab()
        self.build_alerts_tab()
        self.build_settings_tab()

    def build_overview_tab(self) -> None:
        self.drive_cards_frame = ttk.LabelFrame(self.tabs["overview"], text="Disk Doluluk Oranlari", padding=10)
        self.drive_cards_frame.pack(fill=tk.X, pady=(0, 10))
        self.disk_canvas = tk.Canvas(self.tabs["overview"], height=200, bg="#f6f3ee", highlightthickness=0)
        self.disk_canvas.pack(fill=tk.X, pady=(0, 10))
        self.disk_canvas.bind("<Button-1>", self.on_disk_canvas_click)
        self.overview_text = tk.Text(self.tabs["overview"], height=18, wrap="word")
        self.overview_text.pack(fill=tk.BOTH, expand=True)
        self.make_text_readonly(self.overview_text)

    def build_mapping_tab(self) -> None:
        top = ttk.Frame(self.tabs["mapping"])
        top.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(top, text="Arama").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=(8, 8))
        search_entry.bind("<KeyRelease>", lambda _event: self.render_mapping_table())
        ttk.Label(top, text="Kategori").pack(side=tk.LEFT, padx=(12, 4))
        self.category_filter_var = tk.StringVar(value="Tum Kategoriler")
        self.category_filter_combo = ttk.Combobox(top, textvariable=self.category_filter_var, state="readonly", width=22)
        self.category_filter_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.category_filter_combo.bind("<<ComboboxSelected>>", lambda _event: self.render_mapping_table())
        ttk.Label(top, text="Karar").pack(side=tk.LEFT, padx=(4, 4))
        self.decision_filter_var = tk.StringVar(value="Tum Kararlar")
        self.decision_filter_combo = ttk.Combobox(top, textvariable=self.decision_filter_var, state="readonly", width=20)
        self.decision_filter_combo.pack(side=tk.LEFT)
        self.decision_filter_combo.bind("<<ComboboxSelected>>", lambda _event: self.render_mapping_table())
        self.mapping_tree = self.build_tree(
            self.tabs["mapping"],
            ("software_name", "decision", "risk_score", "cleanup_priority_score", "matched_projects"),
            ("Program", "Karar", "Risk", "Temizlik", "Projeler"),
        )
        self.mapping_tree.bind("<<TreeviewSelect>>", self.on_mapping_select)

    def build_program_detail_tab(self) -> None:
        self.program_detail_text = tk.Text(self.tabs["program_detail"], wrap="word")
        self.program_detail_text.pack(fill=tk.BOTH, expand=True)
        self.make_text_readonly(self.program_detail_text)

        info_frame = ttk.LabelFrame(self.tabs["program_detail"], text="Hizli Karar Sihirbazi", padding=8)
        info_frame.pack(fill=tk.X, pady=(8, 0))
        self.review_knows_var = tk.StringVar(value="unknown")
        self.review_recent_var = tk.StringVar(value="unknown")
        self.review_project_var = tk.StringVar(value="unknown")
        self.review_alt_var = tk.StringVar(value="unknown")
        self.review_system_var = tk.StringVar(value="unknown")

        ttk.Label(info_frame, text="Bu programi taniyor musun?").grid(row=0, column=0, sticky="w")
        ttk.Combobox(info_frame, textvariable=self.review_knows_var, values=("unknown", "yes", "no"), state="readonly", width=14).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(info_frame, text="Son aylarda kullandin mi?").grid(row=0, column=2, sticky="w")
        ttk.Combobox(info_frame, textvariable=self.review_recent_var, values=("unknown", "yes", "no"), state="readonly", width=14).grid(row=0, column=3, sticky="w", padx=6)
        ttk.Label(info_frame, text="Bir proje icin gerekli mi?").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Combobox(info_frame, textvariable=self.review_project_var, values=("unknown", "yes", "no"), state="readonly", width=14).grid(row=1, column=1, sticky="w", padx=6, pady=(6, 0))
        ttk.Label(info_frame, text="Daha yeni bir alternatifi var mi?").grid(row=1, column=2, sticky="w", pady=(6, 0))
        ttk.Combobox(info_frame, textvariable=self.review_alt_var, values=("unknown", "yes", "no"), state="readonly", width=14).grid(row=1, column=3, sticky="w", padx=6, pady=(6, 0))
        ttk.Label(info_frame, text="Bu sistem icin kritik bir arac mi?").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Combobox(info_frame, textvariable=self.review_system_var, values=("unknown", "yes", "no"), state="readonly", width=14).grid(row=2, column=1, sticky="w", padx=6, pady=(6, 0))
        ttk.Button(info_frame, text="Karari Hesapla", command=self.calculate_manual_review).grid(row=2, column=2, sticky="w", pady=(6, 0))
        ttk.Button(info_frame, text="Karari Kaydet", command=self.save_manual_review).grid(row=2, column=3, sticky="w", padx=6, pady=(6, 0))
        self.review_result_text = tk.Text(info_frame, height=5, wrap="word")
        self.review_result_text.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self.make_text_readonly(self.review_result_text)

    def build_removal_tab(self) -> None:
        actions = ttk.Frame(self.tabs["removal"])
        actions.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(actions, text="Secili Arac Icin Test Et", command=self.run_selected_program_test).pack(side=tk.LEFT)
        self.removal_text = tk.Text(self.tabs["removal"], wrap="word")
        self.removal_text.pack(fill=tk.BOTH, expand=True)
        self.make_text_readonly(self.removal_text)

    def build_runtime_tab(self) -> None:
        actions = ttk.Frame(self.tabs["runtime"])
        actions.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(actions, text="Secili Sistem Aracini Test Et", command=self.run_selected_runtime_test).pack(side=tk.LEFT)
        self.runtime_help_text = tk.Text(self.tabs["runtime"], height=5, wrap="word")
        self.runtime_help_text.pack(fill=tk.X, pady=(0, 8))
        self.make_text_readonly(self.runtime_help_text)
        self.runtime_tree = self.build_tree(
            self.tabs["runtime"],
            ("family", "installed_count", "keep_versions", "older_versions", "advice"),
            ("Arac Grubu", "Sayi", "Once Tut", "Eski Surum Adayi", "Aciklama"),
            height=8,
        )
        self.runtime_tree.bind("<<TreeviewSelect>>", self.on_runtime_select)
        self.runtime_validation_tree = self.build_tree(
            self.tabs["runtime"],
            ("project_name", "selected_sdk", "build_status", "notes"),
            ("Proje", "Kullanilan Surum", "Test Sonucu", "Kisa Not"),
            height=7,
        )
        self.runtime_report_tree = self.build_tree(
            self.tabs["runtime"],
            ("kind", "item", "group", "suggestion", "result"),
            ("Kayit", "Oge", "Hat / Surum", "Oneri", "Test Yorumu"),
            height=10,
        )

    def build_project_detail_tab(self) -> None:
        selector = ttk.Frame(self.tabs["project_detail"])
        selector.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(selector, text="Proje").pack(side=tk.LEFT)
        self.project_combo = ttk.Combobox(selector, state="readonly")
        self.project_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        self.project_combo.bind("<<ComboboxSelected>>", lambda _event: self.render_project_detail())

        self.project_detail_text = tk.Text(self.tabs["project_detail"], height=16, wrap="word")
        self.project_detail_text.pack(fill=tk.X, pady=(0, 8))
        self.make_text_readonly(self.project_detail_text)
        self.project_submodules_tree = self.build_tree(
            self.tabs["project_detail"],
            ("project_name", "path", "total_size_human", "detected_technologies"),
            ("Alt Parca", "Yol", "Boyut", "Teknolojiler"),
        )
        self.project_tools_tree = self.build_tree(
            self.tabs["project_detail"],
            ("software_name", "decision", "risk_score", "cleanup_priority_score"),
            ("Gerekli Arac", "Karar", "Risk", "Temizlik"),
        )

    def build_large_tab(self) -> None:
        self.large_tree = self.build_tree(
            self.tabs["large"],
            ("path", "size_human", "category", "risk"),
            ("Yol", "Boyut", "Tur", "Dikkat"),
        )

    def build_uncertain_tab(self) -> None:
        self.uncertain_tree = self.build_tree(
            self.tabs["uncertain"],
            ("software_name", "decision", "risk_score", "explanation"),
            ("Program", "Karar", "Risk", "Neden Belirsiz"),
        )

    def build_cleanup_tab(self) -> None:
        actions = ttk.Frame(self.tabs["cleanup"])
        actions.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(actions, text="Secili Programlarla Senaryo Hesapla", command=self.run_cleanup_simulation).pack(side=tk.LEFT)
        self.cleanup_tree = self.build_tree(
            self.tabs["cleanup"],
            ("software_name", "cleanup_priority_score", "risk_score", "estimated_size", "decision"),
            ("Program", "Temizlik", "Risk", "Boyut", "Karar"),
            selectmode="extended",
        )

    def build_alerts_tab(self) -> None:
        actions = ttk.Frame(self.tabs["alerts"])
        actions.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(actions, text="Uyarilari Yenile", command=self.run_refresh_alerts).pack(side=tk.LEFT)
        self.alert_tree = self.build_tree(
            self.tabs["alerts"],
            ("severity", "category", "title", "confidence_score"),
            ("Seviye", "Kategori", "Baslik", "Guven"),
            height=10,
        )
        self.alert_tree.bind("<<TreeviewSelect>>", self.on_alert_select)
        self.alert_detail_text = tk.Text(self.tabs["alerts"], height=12, wrap="word")
        self.alert_detail_text.pack(fill=tk.BOTH, expand=True)
        self.make_text_readonly(self.alert_detail_text)

    def build_settings_tab(self) -> None:
        frame = self.tabs["settings"]
        settings_form = ttk.LabelFrame(frame, text="Bildirim Merkezi Ayarlari", padding=10)
        settings_form.pack(fill=tk.X, pady=(0, 10))

        self.enable_notifications_var = tk.BooleanVar(value=bool(self.notification_preferences.get("enable_notifications", True)))
        self.show_welcome_var = tk.BooleanVar(value=bool(self.notification_preferences.get("show_welcome_notification", True)))
        self.notify_on_app_open_var = tk.BooleanVar(value=bool(self.notification_preferences.get("notify_on_app_open", True)))
        self.notify_on_app_close_var = tk.BooleanVar(value=bool(self.notification_preferences.get("notify_on_app_close", True)))
        self.enable_tray_icon_var = tk.BooleanVar(value=bool(self.notification_preferences.get("enable_tray_icon", True)))
        self.only_critical_var = tk.BooleanVar(value=bool(self.notification_preferences.get("only_critical_alerts", False)))
        self.scan_interval_var = tk.StringVar(value=str(self.monitoring_settings.get("scan_interval", "weekly")))
        self.quiet_start_var = tk.StringVar(value=str(self.notification_preferences.get("quiet_hours_start", "23:00")))
        self.quiet_end_var = tk.StringVar(value=str(self.notification_preferences.get("quiet_hours_end", "08:00")))

        ttk.Checkbutton(settings_form, text="Windows bildirimlerini ac", variable=self.enable_notifications_var).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(settings_form, text="Acilista hos geldiniz bildirimi goster", variable=self.show_welcome_var).grid(row=0, column=1, sticky="w", padx=10)
        ttk.Checkbutton(settings_form, text="Sadece kritik uyarilar", variable=self.only_critical_var).grid(row=0, column=2, sticky="w")
        ttk.Checkbutton(settings_form, text="Uygulama acilisinda bildirim goster", variable=self.notify_on_app_open_var).grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Checkbutton(settings_form, text="Uygulama kapanisinda bildirim goster", variable=self.notify_on_app_close_var).grid(row=1, column=1, sticky="w", padx=10, pady=(8, 0))
        ttk.Checkbutton(settings_form, text="Bildirim alanina tray icon ekle", variable=self.enable_tray_icon_var).grid(row=1, column=2, sticky="w", pady=(8, 0))

        ttk.Label(settings_form, text="Tarama sikligi").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Combobox(settings_form, textvariable=self.scan_interval_var, values=("daily", "weekly", "monthly"), state="readonly", width=14).grid(row=2, column=1, sticky="w", pady=(8, 0))
        ttk.Label(settings_form, text="Sessiz saat baslangici").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(settings_form, textvariable=self.quiet_start_var, width=10).grid(row=3, column=1, sticky="w", pady=(8, 0))
        ttk.Label(settings_form, text="Sessiz saat bitisi").grid(row=3, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(settings_form, textvariable=self.quiet_end_var, width=10).grid(row=3, column=3, sticky="w", pady=(8, 0))

        categories_frame = ttk.LabelFrame(frame, text="Bildirim Alinacak Kategoriler", padding=10)
        categories_frame.pack(fill=tk.X, pady=(0, 10))
        self.category_check_vars: dict[str, tk.BooleanVar] = {}
        enabled_categories = set(enabled_categories_from_preferences(self.notification_preferences))
        for index, category in enumerate(ALERT_CATEGORY_OPTIONS):
            var = tk.BooleanVar(value=category in enabled_categories)
            self.category_check_vars[category] = var
            ttk.Checkbutton(categories_frame, text=category, variable=var).grid(row=0, column=index, sticky="w", padx=(0, 12))

        actions = ttk.Frame(frame)
        actions.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(actions, text="Ayarlari Kaydet", command=self.save_notification_settings).pack(side=tk.LEFT)
        ttk.Button(actions, text="Test Bildirimi Gonder", command=self.send_test_notification).pack(side=tk.LEFT, padx=(8, 0))

        self.settings_text = tk.Text(frame, height=10, wrap="word")
        self.settings_text.pack(fill=tk.BOTH, expand=True)
        self.make_text_readonly(self.settings_text)

    def build_tree(self, parent: ttk.Frame, columns: tuple[str, ...], headings: tuple[str, ...], height: int = 12, selectmode: str = "browse") -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=height, selectmode=selectmode)
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading)
            tree.column(column, width=180, stretch=True)
        y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        x_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        return tree

    def refresh_views(self) -> None:
        self.recommendations = load_csv_rows(OUTPUT_DIR / "recommendations.csv")
        self.risk_scores = load_csv_rows(OUTPUT_DIR / "program_risk_scores.csv")
        self.projects = load_csv_rows(OUTPUT_DIR / "project_tech_stack.csv")
        self.disk_usage = load_csv_rows(OUTPUT_DIR / "disk_usage.csv")
        self.disk_zone_report = load_csv_rows(OUTPUT_DIR / "disk_zone_report.csv")
        self.disk_cleanup_scenarios = load_csv_rows(OUTPUT_DIR / "disk_cleanup_scenarios.csv")
        self.installed_programs = load_csv_rows(OUTPUT_DIR / "installed_programs.csv")
        self.mappings = load_csv_rows(OUTPUT_DIR / "software_project_mapping.csv")
        self.project_size_report = load_csv_rows(OUTPUT_DIR / "project_size_report.csv")
        self.project_storage_breakdown = load_csv_rows(OUTPUT_DIR / "project_storage_breakdown.csv")
        self.dotnet_sdk_report = load_csv_rows(OUTPUT_DIR / "dotnet_sdk_decision_report.csv")
        self.sdk_validation_report = load_csv_rows(OUTPUT_DIR / "sdk_validation_report.csv")
        self.validation_status = load_csv_rows(OUTPUT_DIR / "validation_status.csv")
        self.removal_decisions = load_csv_rows(OUTPUT_DIR / "removal_decisions.csv")
        self.system_tools_report = load_csv_rows(OUTPUT_DIR / "system_tools_report.csv")
        self.system_tool_impact_report = load_csv_rows(OUTPUT_DIR / "system_tool_impact_report.csv")
        self.alerts = load_csv_rows(OUTPUT_DIR / "alerts.csv")
        self.event_log_summary = load_csv_rows(OUTPUT_DIR / "event_log_summary.csv")
        self.notification_preferences, self.monitoring_settings = load_notification_center_settings()
        self.manual_review_overrides = load_manual_review_overrides(BASE_DIR / "manual_review_overrides.csv")
        self.search_rows = build_search_index(self.recommendations, self.mappings, self.projects)
        self.program_view_rows = build_program_view_rows(self.search_rows, self.removal_decisions, self.validation_status)
        self.project_tools_index = build_project_tools_index(self.search_rows)
        self.root_projects, self.child_projects_index = build_project_hierarchy(self.projects)
        self.runtime_family_summaries, self.runtime_family_details = build_runtime_inventory(
            self.recommendations,
            self.installed_programs,
            self.projects,
        )
        categories = ["Tum Kategoriler"] + sorted(
            {row.get("category", "") for row in self.search_rows if row.get("category", "")},
            key=str.casefold,
        )
        decisions = ["Tum Kararlar"] + sorted(
            {self.simplify_decision(row.get("decision", "")) for row in self.search_rows if row.get("decision", "")},
            key=str.casefold,
        )
        self.category_filter_combo["values"] = categories
        self.decision_filter_combo["values"] = decisions
        if self.category_filter_var.get() not in categories:
            self.category_filter_var.set("Tum Kategoriler")
        if self.decision_filter_var.get() not in decisions:
            self.decision_filter_var.set("Tum Kararlar")

        self.render_overview()
        self.render_mapping_table()
        self.render_runtime_tab()
        self.render_large_tab()
        self.render_uncertain_tab()
        self.render_cleanup_tab()
        self.render_alerts_tab()
        self.render_settings_tab()
        self.render_project_selector()
        self.status_var.set("Tum ekranlar yenilendi")

    def render_overview(self) -> None:
        for widget in self.drive_cards_frame.winfo_children():
            widget.destroy()

        cards = build_drive_usage_cards(self.disk_usage)
        for index, card in enumerate(cards):
            card_frame = ttk.Frame(self.drive_cards_frame, padding=8)
            card_frame.grid(row=0, column=index, sticky="nsew", padx=5)
            ttk.Label(card_frame, text=f"{card['drive']} Diski", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            ttk.Progressbar(card_frame, maximum=100, value=safe_float(card["used_pct"]), length=220).pack(fill=tk.X, pady=6)
            ttk.Label(card_frame, text=f"Toplam doluluk: %{card['used_pct']}").pack(anchor="w")
            ttk.Label(card_frame, text=f"Analiz edilen kisim: %{card['analyzed_pct']}").pack(anchor="w")
            ttk.Label(card_frame, text=f"Kullanilan alan: {card['used_human']}").pack(anchor="w")
            ttk.Label(card_frame, text=f"Bos alan: {card['free_human']}").pack(anchor="w")

        self.disk_canvas.delete("all")
        rows = build_disk_treemap_rows(self.disk_usage)
        zone_index = {normalize_windows_path(row.get("path", "")): row for row in self.disk_zone_report if row.get("path", "").strip()}
        scenario_index = {normalize_windows_path(row.get("path", "")): row for row in self.disk_cleanup_scenarios if row.get("path", "").strip()}
        self.disk_canvas_regions: list[tuple[int, int, str]] = []
        total = sum(max(1, safe_int(row.get("size_bytes", "0"))) for row in rows) or 1
        x_offset = 12
        colors = ["#0f766e", "#2563eb", "#d97706", "#7c3aed", "#be123c", "#15803d", "#b45309", "#0ea5e9"]
        width = max(self.disk_canvas.winfo_width(), 1200)
        for index, row in enumerate(rows):
            block_width = max(90, int((safe_int(row.get("size_bytes", "0")) / total) * (width - 24)))
            self.disk_canvas.create_rectangle(x_offset, 18, x_offset + block_width, 150, fill=colors[index % len(colors)], outline="")
            self.disk_canvas.create_text(x_offset + 8, 32, text=row.get("path", "")[:38], anchor="w", fill="white", font=("Segoe UI", 9, "bold"))
            self.disk_canvas.create_text(x_offset + 8, 56, text=row.get("size_human", ""), anchor="w", fill="white", font=("Segoe UI", 9))
            self.disk_canvas_regions.append((x_offset, x_offset + block_width, row.get("path", "")))
            x_offset += block_width + 8

        selected_zone = {}
        selected_scenario = {}
        if self.selected_disk_zone_path:
            selected_zone = zone_index.get(normalize_windows_path(self.selected_disk_zone_path), {})
            selected_scenario = scenario_index.get(normalize_windows_path(self.selected_disk_zone_path), {})

        summary_lines = ["Bu ekrandaki basit ozet:", ""]
        if selected_zone:
            summary_lines.extend(
                [
                    f"Secili alan: {selected_zone.get('path', '')}",
                    f"Boyut: {selected_zone.get('size_human', '')}",
                    f"Kategori: {selected_zone.get('category', '')}",
                    f"Risk: {selected_zone.get('risk', '')}",
                    f"Yaklasik acilacak alan: {selected_zone.get('recoverable_space_human', '')}",
                    f"Yeniden uretilebilirlik: {selected_zone.get('rebuildability', '')}",
                    f"Proje ile ilgili: {selected_zone.get('active_project_related', '')}",
                    "",
                    "En buyuk alt yollar:",
                ]
            )
            subpaths = [item.strip() for item in selected_zone.get("top_subpaths", "").split(",") if item.strip()]
            for subpath in subpaths[:5]:
                summary_lines.append(f"- {subpath}")
            summary_lines.extend(
                [
                    "",
                    "Silme / temizleme senaryosu:",
                    selected_zone.get("cleanup_summary", "") or selected_scenario.get("explanation", "") or "Senaryo yok.",
                    "",
                    f"Onerilen aksiyon: {selected_zone.get('recommended_action', '') or selected_scenario.get('recommended_action', '')}",
                ]
            )
        else:
            top_cleanup = sorted(self.risk_scores, key=lambda row: safe_float(row.get("cleanup_priority_score", "0")), reverse=True)[:8]
            for row in top_cleanup:
                summary_lines.append(
                    f"- {row.get('software_name', '')}: temizlik onceligi {row.get('cleanup_priority_score', '')}, "
                    f"risk {row.get('risk_score', '')}, boyut {row.get('estimated_size', '')}"
                )
        self.set_text(self.overview_text, "\n".join(summary_lines))

    def on_disk_canvas_click(self, event: tk.Event[tk.Misc]) -> None:
        for start_x, end_x, path in getattr(self, "disk_canvas_regions", []):
            if start_x <= event.x <= end_x:
                self.selected_disk_zone_path = path
                self.render_overview()
                break

    def render_mapping_table(self) -> None:
        query = self.search_var.get().casefold().strip()
        selected_category = self.category_filter_var.get()
        selected_decision = self.decision_filter_var.get()
        self.clear_tree(self.mapping_tree)
        filtered_rows = [
            row for row in self.search_rows
            if (not query or query in row.get("search_text", ""))
            and (selected_category == "Tum Kategoriler" or row.get("category", "") == selected_category)
            and (selected_decision == "Tum Kararlar" or self.simplify_decision(row.get("decision", "")) == selected_decision)
        ]
        for row in filtered_rows[:500]:
            self.mapping_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("software_name", ""),
                    self.simplify_decision(row.get("decision", "")),
                    row.get("risk_score", ""),
                    row.get("cleanup_priority_score", ""),
                    f"{row.get('matched_projects', '') or 'Yok'} | Son: {row.get('last_used_at', '') or 'Bilinmiyor'} | Iz: {row.get('usage_signal_count', '') or '0'}",
                ),
            )

    def on_mapping_select(self, _event: object) -> None:
        selected = self.mapping_tree.selection()
        if not selected:
            return
        software_name = self.mapping_tree.item(selected[0], "values")[0]
        program = next((row for row in self.search_rows if row.get("software_name", "") == software_name), {})
        if not program:
            return
        self.selected_program = program
        self.load_manual_review_into_form(program)
        self.render_program_detail(program)
        self.render_removal_detail(program)
        self.notebook.select(self.tabs["program_detail"])

    def render_program_detail(self, program: dict[str, str]) -> None:
        removal_row = next((row for row in self.removal_decisions if row.get("software_name", "") == program.get("software_name", "")), {})
        lines = [
            f"Program: {program.get('software_name', '')}",
            f"Ne yapalim?: {self.simplify_decision(program.get('decision', ''))}",
            f"Risk puani: {program.get('risk_score', '')} / 100",
            f"Temizlik onceligi: {program.get('cleanup_priority_score', '')} / 100",
            f"Dogrulama seviyesi: {program.get('validation_level', '') or 'STATIC_ONLY'}",
            f"Kapladigi alan: {program.get('estimated_size', '') or 'Bilinmiyor'}",
            f"Bagli projeler: {program.get('matched_projects', '') or 'Yok'}",
            f"Son kullanim izi: {program.get('last_used_at', '') or 'Bilinmiyor'}",
            f"Kullanim izi sayisi: {program.get('usage_signal_count', '') or '0'}",
            f"Kullanim kaynagi: {program.get('usage_sources', '') or 'Bilinmiyor'}",
            "",
            "Neden boyle deniyor?",
            program.get("explanation", ""),
            "",
            "Bu program ne ise yarar?",
            program.get("purpose", "") or "Acilama yok.",
            "",
            "Genelde nerede kullanilir?",
            program.get("typical_usage", "") or "Bilgi yok.",
            "",
            "Hangi teknolojilerle ilgilidir?",
            program.get("related_technologies", "") or "Bilgi yok.",
            "",
            "Kaldirma riski ozetle ne diyor?",
            program.get("removal_risk_summary", "") or "Ozet yok.",
        ]
        if removal_row:
            lines.extend(
                [
                    "",
                    "Yeni kaldirma motoru ne diyor?",
                    f"Karar etiketi: {removal_row.get('decision_label', '')}",
                    f"Silme riski: {removal_row.get('removal_risk_score', '')} / 100",
                    f"Alan kazanma degeri: {removal_row.get('cleanup_value_score', '')} / 100",
                    f"Etki alani: {removal_row.get('impact_scope', '')}",
                    f"Yaklasik acilacak alan: {removal_row.get('if_removed_frees_space_human', '')}",
                    f"Yeniden uretilebilirlik: {removal_row.get('recoverability_score', '')} / 100",
                    f"Sonraki adim: {removal_row.get('recommended_next_action', '')}",
                    removal_row.get("plain_language_explanation", ""),
                ]
            )
        self.set_text(self.program_detail_text, "\n".join(lines))

    def render_removal_detail(self, program: dict[str, str]) -> None:
        scenario = build_removal_scenario(program, self.recommendations, self.dotnet_sdk_report, self.sdk_validation_report)
        family_summary = build_version_family_summary(
            program,
            self.recommendations,
            self.dotnet_sdk_report,
            self.sdk_validation_report,
        )
        removal_row = next((row for row in self.removal_decisions if row.get("software_name", "") == program.get("software_name", "")), {})
        lines = [
            f"Genel sonuc: {self.simplify_scenario_label(str(scenario.get('final_label', '')))}",
            str(scenario.get("final_reason", "")),
            "",
            "Adim adim bakis:",
        ]
        for step in scenario.get("steps", []):
            step_name = step.get("step", "")
            detail = step.get("detail", "")
            lines.append(f"- {step_name}: {detail}")
        if scenario.get("project_names"):
            lines.extend(["", "Bagli projeler:"])
            for name in scenario.get("project_names", []):
                lines.append(f"- {name}")
        lines.extend(["", "Ayni uygulama ailesi icin ozet:", str(family_summary.get("summary_message", ""))])
        keepers = family_summary.get("keepers", [])
        if keepers:
            lines.append("")
            lines.append("Kalmasi daha guvenli gorunenler:")
            for row in keepers[:6]:
                lines.append(f"- {row.get('software_name', '')}")
        candidates = family_summary.get("candidates", [])
        if candidates:
            lines.append("")
            lines.append("Ilk kaldirma adaylari:")
            for row in candidates[:8]:
                lines.append(f"- {row.get('software_name', '')}")
        notes = family_summary.get("notes", [])
        if notes:
            lines.append("")
            lines.append("Kisa notlar:")
            for note in notes[:4]:
                lines.append(f"- {note}")
        if removal_row:
            lines.extend(
                [
                    "",
                    "Yeni karar motoru ozeti:",
                    f"- Karar etiketi: {removal_row.get('decision_label', '')}",
                    f"- Silme riski: {removal_row.get('removal_risk_score', '')} / 100",
                    f"- Alan kazanma degeri: {removal_row.get('cleanup_value_score', '')} / 100",
                    f"- Etki alani: {removal_row.get('impact_scope', '')}",
                    f"- Yaklasik acilacak alan: {removal_row.get('if_removed_frees_space_human', '')}",
                    f"- Yeniden uretilebilirlik: {removal_row.get('recoverability_score', '')} / 100",
                    f"- Sonraki adim: {removal_row.get('recommended_next_action', '')}",
                    f"- Teknik not: {removal_row.get('technical_explanation', '')}",
                ]
            )
        if program.get("category", "") == "Runtime/System":
            runtime_family_key = runtime_family_key_from_label(program.get("software_name", "")) or ""
            classified_family = runtime_family_key
            if not classified_family:
                lowered_name = program.get("software_name", "").casefold()
                if ".net sdk" in lowered_name:
                    classified_family = "dotnet_sdk"
                elif "asp.net" in lowered_name:
                    classified_family = "aspnet_runtime"
                elif ".net runtime" in lowered_name:
                    classified_family = "dotnet_runtime"
                elif "windows sdk" in lowered_name:
                    classified_family = "windows_sdk"
                elif "visual c++" in lowered_name or "redistributable" in lowered_name:
                    classified_family = "visual_cpp"
                elif any(token in lowered_name for token in ("nvidia", "radeon", "driver", "chipset", "realtek")):
                    classified_family = "gpu_driver"
                elif ".net native" in lowered_name:
                    classified_family = "dotnet_native"
            if classified_family:
                runtime_report = build_runtime_family_report(
                    classified_family,
                    self.runtime_family_details,
                    self.dotnet_sdk_report,
                    self.sdk_validation_report,
                )
                lines.extend(["", "Bilgisayar muhendisi gibi bakarsan:"])
                for note in runtime_report.get("notes", [])[:4]:
                    lines.append(f"- {note}")
        self.set_text(self.removal_text, "\n".join(lines))

    def render_runtime_tab(self) -> None:
        self.clear_tree(self.runtime_tree)
        self.clear_tree(self.runtime_validation_tree)
        self.clear_tree(self.runtime_report_tree)
        for row in self.runtime_family_summaries:
            self.runtime_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("family", ""),
                    row.get("installed_count", ""),
                    row.get("keep_versions", ""),
                    row.get("older_versions", ""),
                    row.get("advice", ""),
                ),
            )
        for row in self.system_tools_report:
            self.runtime_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("family_label", row.get("family", "")),
                    row.get("installed_count", ""),
                    row.get("keep_versions", ""),
                    row.get("candidate_versions", ""),
                    row.get("advice", ""),
                ),
            )
        help_lines = [
            "Bu bolum sistem araci ailelerini tek tek test etmek icindir.",
            "",
            "Kisa akil:",
            "- .NET SDK / Runtime / Windows SDK: proje ve build kontrolu daha onemlidir.",
            "- Visual C++: genelde toplu kaldirilmaz.",
            "- GPU / Driver: kaldirma yerine resmi guncelleme yolu tercih edilir.",
            "- .NET Native Runtime: Store uygulamalari etkilenebilir.",
        ]
        self.set_text(self.runtime_help_text, "\n".join(help_lines))
        if self.runtime_family_summaries:
            if not self.selected_runtime_family:
                self.selected_runtime_family = self.runtime_family_summaries[0].get("family", "")
            self.render_runtime_report()

    def on_runtime_select(self, _event: object) -> None:
        selected = self.runtime_tree.selection()
        if not selected:
            return
        self.selected_runtime_family = self.runtime_tree.item(selected[0], "values")[0]
        self.render_runtime_report()

    def render_runtime_report(self) -> None:
        self.clear_tree(self.runtime_report_tree)
        family_key = runtime_family_key_from_label(self.selected_runtime_family)
        if not family_key:
            return
        report = build_runtime_family_report(
            family_key,
            self.runtime_family_details,
            self.dotnet_sdk_report,
            self.sdk_validation_report,
        )
        self.clear_tree(self.runtime_validation_tree)
        if family_key == "dotnet_sdk":
            for row in self.sdk_validation_report:
                self.runtime_validation_tree.insert(
                    "",
                    tk.END,
                    values=(
                        row.get("project_name", ""),
                        row.get("selected_sdk", ""),
                        self.simplify_build_status(row.get("build_status", "")),
                        row.get("notes", "")[:220],
                    ),
                )
        for row in report.get("rows", []):
            suggestion = row.get("suggestion", "")
            if row.get("kind", "") == "Build Testi":
                suggestion = self.simplify_build_status(suggestion)
            elif family_key == "dotnet_sdk":
                suggestion = self.simplify_sdk_status(suggestion)
            else:
                suggestion = self.simplify_runtime_action(suggestion)
            self.runtime_report_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("kind", ""),
                    row.get("item", ""),
                    row.get("group", ""),
                    suggestion,
                    row.get("result", ""),
                ),
            )
        if self.system_tool_impact_report:
            for row in self.system_tool_impact_report:
                if row.get("family", "") != family_key:
                    continue
                self.runtime_report_tree.insert(
                    "",
                    tk.END,
                    values=(
                        "Etki",
                        row.get("software_name", ""),
                        row.get("validation_level", ""),
                        row.get("decision_label", ""),
                        row.get("next_action", ""),
                    ),
                )
        note_lines = [
            f"Secili aile: {report.get('family_label', '')}",
            "",
            "Bu aile icin test notlari:",
        ]
        for note in report.get("notes", []):
            note_lines.append(f"- {note}")
        self.set_text(self.runtime_help_text, "\n".join(note_lines))

    def render_project_selector(self) -> None:
        labels = []
        for project in self.root_projects:
            child_projects = self.child_projects_index.get(normalize_windows_path(project.get("path", "")), [])
            label = project.get("project_name", "")
            if child_projects:
                label += f" ({len(child_projects)} alt parca)"
            labels.append(label)
        self.project_combo["values"] = labels
        if labels:
            self.project_combo.current(0)
            self.render_project_detail()

    def render_project_detail(self) -> None:
        selected_label = self.project_combo.get().split(" (")[0].strip()
        project = next((row for row in self.root_projects if row.get("project_name", "") == selected_label), {})
        if not project:
            return
        child_projects = self.child_projects_index.get(normalize_windows_path(project.get("path", "")), [])
        tools = collect_project_tools(project, child_projects, self.project_tools_index)
        size_row = next((row for row in self.project_size_report if row.get("project_name", "") == project.get("project_name", "")), {})
        breakdown_rows = [row for row in self.project_storage_breakdown if row.get("project_name", "") == project.get("project_name", "")]

        lines = [
            f"Proje: {project.get('project_name', '')}",
            f"Yol: {project.get('path', '')}",
            f"Teknolojiler: {project.get('detected_technologies', '') or 'Yok'}",
            f"Koddan gorulen kutuphaneler: {project.get('detected_libraries', '') or 'Yok'}",
            f"Ek sinyaller: {project.get('framework_signals', '') or 'Yok'}",
            f"Aciklama: {project.get('repo_description', '') or 'Yok'}",
            f"Notlar: {project.get('user_notes', '') or 'Yok'}",
        ]
        if size_row:
            lines.extend(
                [
                    f"Toplam boyut: {size_row.get('total_size_human', '')}",
                    f"Yeniden uretilebilir alan: {size_row.get('generated_artifact_size_human', '')}",
                    f"Kaynak cekirdek alani: {size_row.get('source_core_size_human', '')}",
                    f"Yeniden uretilebilir oran: %{size_row.get('recoverable_ratio', '')}",
                    f"Buyuk proje riski: {size_row.get('active_project_risk', '')}",
                ]
            )
        lines.extend(
            [
                "",
                "En buyuk proje bolumleri:",
            ]
        )
        for row in breakdown_rows[:8]:
            lines.append(f"- {row.get('segment_name', '')}: {row.get('size_human', '')} | {row.get('segment_type', '')}")
        lines.extend(
            [
                "",
                "Bu projede gozlenen kod ipuclari:",
                project.get("code_evidence", "") or "Kod ipucu yok.",
            ]
        )
        self.set_text(self.project_detail_text, "\n".join(lines))

        self.clear_tree(self.project_submodules_tree)
        for child in child_projects:
            child_size = next((row for row in self.project_size_report if row.get("project_name", "") == child.get("project_name", "")), {})
            self.project_submodules_tree.insert(
                "",
                tk.END,
                values=(
                    child.get("project_name", ""),
                    child.get("path", ""),
                    child_size.get("total_size_human", ""),
                    child.get("detected_technologies", ""),
                ),
            )

        self.clear_tree(self.project_tools_tree)
        for tool in tools[:30]:
            self.project_tools_tree.insert(
                "",
                tk.END,
                values=(
                    tool.get("software_name", ""),
                    self.simplify_decision(tool.get("decision", "")),
                    tool.get("risk_score", ""),
                    tool.get("cleanup_priority_score", ""),
                ),
            )

    def render_large_tab(self) -> None:
        self.clear_tree(self.large_tree)
        for row in sorted(self.disk_usage, key=lambda item: safe_int(item.get("size_bytes", "0")), reverse=True)[:200]:
            self.large_tree.insert("", tk.END, values=(row.get("path", ""), row.get("size_human", ""), row.get("category", ""), row.get("risk", "")))

    def render_uncertain_tab(self) -> None:
        self.clear_tree(self.uncertain_tree)
        rows = [row for row in self.recommendations if row.get("decision", "") in {"UNSURE", "MANUAL_REVIEW"}][:200]
        for row in rows:
            self.uncertain_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("software_name", ""),
                    self.simplify_decision(row.get("decision", "")),
                    row.get("risk_score", ""),
                    row.get("explanation", "")[:220],
                ),
            )

    def render_cleanup_tab(self) -> None:
        self.clear_tree(self.cleanup_tree)
        rows = sorted(self.recommendations, key=lambda row: safe_float(row.get("cleanup_priority_score", "0")), reverse=True)[:200]
        for row in rows:
            self.cleanup_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("software_name", ""),
                    row.get("cleanup_priority_score", ""),
                    row.get("risk_score", ""),
                    row.get("estimated_size", ""),
                    self.simplify_decision(row.get("decision", "")),
                ),
            )

    def render_alerts_tab(self) -> None:
        self.clear_tree(self.alert_tree)
        for row in self.alerts[:200]:
            self.alert_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("severity", ""),
                    row.get("category", ""),
                    row.get("title", ""),
                    row.get("confidence_score", ""),
                ),
            )
        if self.alerts:
            summary_lines = [
                f"Toplam uyari: {len(self.alerts)}",
                f"Kritik: {sum(1 for row in self.alerts if row.get('severity', '') == 'critical')}",
                f"Yuksek: {sum(1 for row in self.alerts if row.get('severity', '') == 'high')}",
                "",
                "Event log ozetleri:",
            ]
            for row in self.event_log_summary[:6]:
                summary_lines.append(
                    f"- {row.get('category', '')}: {row.get('event_count', '')} | {row.get('sample_message', '')}"
                )
            self.set_text(self.alert_detail_text, "\n".join(summary_lines))
        else:
            self.set_text(self.alert_detail_text, "Heniz alert raporu bulunamadi. 'Uyarilari Yenile' butonu ile olustur.")

    def render_settings_tab(self) -> None:
        if hasattr(self, "enable_notifications_var"):
            self.enable_notifications_var.set(bool(self.notification_preferences.get("enable_notifications", True)))
            self.show_welcome_var.set(bool(self.notification_preferences.get("show_welcome_notification", True)))
            self.notify_on_app_open_var.set(bool(self.notification_preferences.get("notify_on_app_open", True)))
            self.notify_on_app_close_var.set(bool(self.notification_preferences.get("notify_on_app_close", True)))
            self.enable_tray_icon_var.set(bool(self.notification_preferences.get("enable_tray_icon", True)))
            self.only_critical_var.set(bool(self.notification_preferences.get("only_critical_alerts", False)))
            self.scan_interval_var.set(str(self.monitoring_settings.get("scan_interval", "weekly")))
            self.quiet_start_var.set(str(self.notification_preferences.get("quiet_hours_start", "23:00")))
            self.quiet_end_var.set(str(self.notification_preferences.get("quiet_hours_end", "08:00")))
            enabled_categories = set(enabled_categories_from_preferences(self.notification_preferences))
            for category, var in self.category_check_vars.items():
                var.set(category in enabled_categories)
        next_scan = get_next_scan_date(
            interval=str(self.monitoring_settings.get("scan_interval", "weekly")),
            settings_path=MONITORING_SETTINGS_PATH,
        )
        lines = [
            "Bildirim merkezi ayarlari bu ekrandan ve Streamlit tarafindan ortak yonetilir.",
            "",
            f"Windows bildirimleri: {'acik' if self.notification_preferences.get('enable_notifications', True) else 'kapali'}",
            f"Hos geldiniz bildirimi: {'acik' if self.notification_preferences.get('show_welcome_notification', True) else 'kapali'}",
            f"Uygulama acilis bildirimi: {'acik' if self.notification_preferences.get('notify_on_app_open', True) else 'kapali'}",
            f"Uygulama kapanis bildirimi: {'acik' if self.notification_preferences.get('notify_on_app_close', True) else 'kapali'}",
            f"Tray icon: {'acik' if self.notification_preferences.get('enable_tray_icon', True) else 'kapali'}",
            f"Tray durum: {self.tray_runtime_status}",
            f"Sadece kritik uyari: {'evet' if self.notification_preferences.get('only_critical_alerts', False) else 'hayir'}",
            f"Tarama sikligi: {self.monitoring_settings.get('scan_interval', 'weekly')}",
            f"Sessiz saatler: {self.notification_preferences.get('quiet_hours_start', '23:00')} - {self.notification_preferences.get('quiet_hours_end', '08:00')}",
            f"Bir sonraki planli kontrol: {next_scan.isoformat(timespec='seconds')}",
            "",
            f"Aktif kategoriler: {', '.join(enabled_categories_from_preferences(self.notification_preferences))}",
        ]
        self.set_text(self.settings_text, "\n".join(lines))

    def clear_tree(self, tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)

    def make_text_readonly(self, widget: tk.Text) -> None:
        widget.configure(state="disabled")

    def set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def simplify_decision(self, decision: str) -> str:
        return {
            "KEEP": "Kalsin",
            "CAN_REMOVE": "Silinebilir olabilir",
            "UNSURE": "Tam emin degilim",
            "MANUAL_REVIEW": "Once kontrol et",
        }.get(decision, decision)

    def simplify_scenario_label(self, label: str) -> str:
        return {
            "LOWER_RISK_CANDIDATE": "Dusuk riskli aday",
            "VERIFY_USAGE_FIRST": "Once kullanimini kontrol et",
            "TEST_FIRST": "Once test et",
            "DO_NOT_REMOVE_YET": "Simdilik kaldirma",
        }.get(label, label)

    def simplify_runtime_action(self, action: str) -> str:
        return {
            "KEEP_CANDIDATE": "Simdilik kalsin",
            "OLDER_VERSION": "Eski surum olabilir",
            "MANUAL_REVIEW": "Elle bakmak gerekir",
            "DO_NOT_REMOVE": "Kaldirma",
            "IDE_DEPENDENT": "Editor buna bakiyor olabilir",
            "KEEP_LATEST": "En yeni surum, kalsin",
            "SAFE_OLDER_PATCH": "Eski yama olabilir",
        }.get(action, action)

    def simplify_sdk_status(self, status: str) -> str:
        return {
            "DO_NOT_REMOVE": "Kaldirma",
            "IDE_DEPENDENT": "Editor buna bakiyor olabilir",
            "KEEP_LATEST": "En yeni surum, kalsin",
            "SAFE_OLDER_PATCH": "Eski yama olabilir",
            "MANUAL_REVIEW": "Test etmeden karar verme",
        }.get(status, status)

    def simplify_build_status(self, status: str) -> str:
        return {
            "BUILD_PASSED": "Test gecti",
            "BUILD_FAILED": "Test gecmedi",
            "DISCOVERED_ONLY": "Sadece bulundu",
            "VALIDATION_FAILED": "Test baslatilamadi",
        }.get(status, status)

    def build_family_test_message(self, program: dict[str, str]) -> str:
        summary = build_version_family_summary(
            program,
            self.recommendations,
            self.dotnet_sdk_report,
            self.sdk_validation_report,
        )
        keepers = summary.get("keepers", [])
        candidates = summary.get("candidates", [])
        lines = [str(summary.get("summary_message", ""))]

        if keepers:
            lines.extend(["", "Simdilik kalmasi daha guvenli olanlar:"])
            for row in keepers[:6]:
                note = row.get("sdk_recommendation", "") or row.get("decision", "") or "Kalsin"
                lines.append(f"- {row.get('software_name', '')}: {note}")

        if candidates:
            lines.extend(["", "Ilk kaldirma adaylari:"])
            for row in candidates[:8]:
                note = row.get("sdk_recommendation", "") or row.get("decision", "") or "Aday"
                lines.append(f"- {row.get('software_name', '')}: {note}")
        else:
            lines.extend(["", "Su an net kaldirma adayi cikmadi."])

        notes = summary.get("notes", [])
        if notes:
            lines.extend(["", "Kisa notlar:"])
            for note in notes[:4]:
                lines.append(f"- {note}")
        return "\n".join(lines)

    def load_manual_review_into_form(self, program: dict[str, str]) -> None:
        override = self.manual_review_overrides.get(program.get("software_name", "").casefold(), {})
        self.review_knows_var.set(override.get("user_knows_program", "unknown"))
        self.review_recent_var.set(override.get("used_recently", "unknown"))
        self.review_project_var.set(override.get("project_required", "unknown"))
        self.review_alt_var.set(override.get("has_newer_alternative", "unknown"))
        self.review_system_var.set(override.get("is_system_component", "unknown"))
        self.set_text(self.review_result_text, "Sihirbaz sonucu burada gorunecek.")

    def calculate_manual_review(self) -> None:
        if not self.selected_program:
            messagebox.showinfo("Bilgi", "Once bir program sec.")
            return
        result = evaluate_manual_review(
            software_name=self.selected_program.get("software_name", ""),
            category=self.selected_program.get("category", ""),
            original_decision=self.selected_program.get("decision", ""),
            user_knows_program=self.review_knows_var.get(),
            used_recently=self.review_recent_var.get(),
            project_required=self.review_project_var.get(),
            has_newer_alternative=self.review_alt_var.get(),
            is_system_component=self.review_system_var.get(),
            review_notes="GUI review",
        )
        text = (
            f"Yeni onerilen karar: {self.simplify_decision(result.get('reviewed_decision', ''))}\n\n"
            f"Neden: {result.get('reviewed_explanation', '')}"
        )
        self.set_text(self.review_result_text, text)
        messagebox.showinfo("Hizli Karar Sonucu", text)

    def save_manual_review(self) -> None:
        if not self.selected_program:
            messagebox.showinfo("Bilgi", "Once bir program sec.")
            return
        result = evaluate_manual_review(
            software_name=self.selected_program.get("software_name", ""),
            category=self.selected_program.get("category", ""),
            original_decision=self.selected_program.get("decision", ""),
            user_knows_program=self.review_knows_var.get(),
            used_recently=self.review_recent_var.get(),
            project_required=self.review_project_var.get(),
            has_newer_alternative=self.review_alt_var.get(),
            is_system_component=self.review_system_var.get(),
            review_notes="GUI review",
        )
        save_manual_review_override(BASE_DIR / "manual_review_overrides.csv", result)
        self.manual_review_overrides = load_manual_review_overrides(BASE_DIR / "manual_review_overrides.csv")
        self.set_text(self.review_result_text, f"Kaydedildi.\n\n{result.get('reviewed_explanation', '')}")
        self.status_var.set("Elle karar kaydedildi")
        messagebox.showinfo("Karar Kaydedildi", "Secimin kaydedildi. Sonraki analizlerde bu bilgi kullanilacak.")

    def run_selected_program_test(self) -> None:
        if not self.selected_program:
            messagebox.showinfo("Bilgi", "Once bir program sec.")
            return
        self.notebook.select(self.tabs["removal"])
        steps = [("scan-projects", "Proje baglari tekrar okunuyor")]
        family_text = f"{self.selected_program.get('software_name', '')} {self.selected_program.get('category', '')}".casefold()
        if ".net" in family_text or "sdk" in family_text or "visual studio" in family_text or "windows sdk" in family_text:
            steps.extend(
                [
                    ("validate-dotnet-sdks", "Secili araca bagli .NET testleri calisiyor"),
                    ("validate-projects", "Proje dogrulama seviyesi guncelleniyor"),
                    ("build-removal-decisions", "Kaldirma karari yeniden hesaplaniyor"),
                    ("build-system-tools-report", "Sistem araci raporu guncelleniyor"),
                ]
            )
        else:
            steps.extend(
                [
                    ("collect-usage", "Son kullanim izleri tekrar okunuyor"),
                    ("score-risk", "Risk puani tekrar hesaplaniyor"),
                    ("recommend", "Karar ekrani guncelleniyor"),
                    ("validate-projects", "Proje dogrulama seviyesi guncelleniyor"),
                    ("build-removal-decisions", "Kaldirma karari yeniden hesaplaniyor"),
                    ("build-system-tools-report", "Sistem araci raporu guncelleniyor"),
                ]
            )
        self.run_background_steps(steps, completion_callback=self.show_selected_program_test_result)

    def run_refresh_all(self) -> None:
        config_path = resolve_runtime_config_path()
        config = load_config(config_path) if config_path is not None else None
        if config is None:
            messagebox.showinfo("Bilgi", "Config bulunamadi.")
            return
        refresh_mode = self.refresh_mode_var.get() or "quick"
        plan = build_refresh_plan(config, OUTPUT_DIR, mode=refresh_mode)
        eta_text = format_eta(estimate_plan_duration(plan))
        steps = []
        for step in plan:
            if not step.should_run:
                continue
            extra_args = ["--refresh-mode", refresh_mode] if step.command in {"scan-disk", "scan-projects", "analyze-dotnet-sdk", "validate-dotnet-sdks"} else []
            steps.append((step.command, step.label, extra_args, step.estimated_seconds))
        steps.append(("validate-projects", "Proje dogrulama seviyesi guncelleniyor", [], 20))
        steps.append(("build-system-tools-report", "Sistem araci raporu guncelleniyor", [], 8))
        mode_label = "Hizli" if refresh_mode == "quick" else "Derin"
        self.set_text(self.log_text, f"{mode_label} yenileme plani hazir. Tahmini sure: {eta_text}\n")
        self.run_background_steps(steps)

    def run_refresh_projects(self) -> None:
        config_path = resolve_runtime_config_path()
        config = load_config(config_path) if config_path is not None else None
        if config is None:
            messagebox.showinfo("Bilgi", "Config bulunamadi.")
            return
        
        # Explicitly rescan and re-map projects bypass refresh plan checks
        steps = [
            ("scan-projects", "Projeler yeniden taraniyor", ["--refresh-mode", "full"], 45),
            ("map-software", "Program eslesmeleri guncelleniyor", [], 10),
            ("score-risk", "Risk puanlari tekrar hesaplaniyor", [], 8),
            ("recommend", "Program onerileri tekrar uretiliyor", [], 12),
            ("validate-projects", "Proje dogrulama seviyesi guncelleniyor", [], 20),
            ("build-removal-decisions", "Kaldirma karar detaylari uretiliyor", [], 10),
            ("build-system-tools-report", "Sistem araci raporu guncelleniyor", [], 8),
        ]
        self.set_text(self.log_text, "Projeleri Yenile islemi baslatiliyor...\n")
        self.run_background_steps(steps)

    def run_selected_runtime_test(self) -> None:
        if not self.selected_runtime_family:
            messagebox.showinfo("Bilgi", "Once bir sistem araci ailesi sec.")
            return
        family_key = runtime_family_key_from_label(self.selected_runtime_family)
        steps = build_runtime_family_test_steps(family_key)
        self.run_background_steps(steps, completion_callback=self.show_selected_runtime_test_result)

    def run_cleanup_simulation(self) -> None:
        selected_items = self.cleanup_tree.selection()
        if not selected_items:
            messagebox.showinfo("Bilgi", "Once bir veya daha fazla program sec.")
            return
        selected_names = [self.cleanup_tree.item(item, "values")[0] for item in selected_items]
        simulation = build_cleanup_simulation(selected_names, self.removal_decisions)
        write_cleanup_simulation(simulation, OUTPUT_DIR)
        messagebox.showinfo("Coklu Senaryo Sonucu", simulation.summary)

    def run_refresh_alerts(self) -> None:
        steps = [
            ("monitor-alerts", "Event log ve akilli uyari kurallari calisiyor", [], 10),
            ("generate-weekly-report", "Haftalik rapor guncelleniyor", [], 4),
        ]
        self.run_background_steps(steps)

    def save_notification_settings(self) -> None:
        selected_categories = [category for category, var in self.category_check_vars.items() if var.get()]
        updated_preferences = dict(self.notification_preferences)
        updated_preferences["enable_notifications"] = self.enable_notifications_var.get()
        updated_preferences["show_welcome_notification"] = self.show_welcome_var.get()
        updated_preferences["notify_on_app_open"] = self.notify_on_app_open_var.get()
        updated_preferences["notify_on_app_close"] = self.notify_on_app_close_var.get()
        updated_preferences["enable_tray_icon"] = self.enable_tray_icon_var.get()
        updated_preferences["only_critical_alerts"] = self.only_critical_var.get()
        updated_preferences["quiet_hours_start"] = self.quiet_start_var.get().strip() or "23:00"
        updated_preferences["quiet_hours_end"] = self.quiet_end_var.get().strip() or "08:00"
        updated_preferences["disabled_categories"] = build_disabled_categories(selected_categories)
        save_notification_center_settings(updated_preferences, self.scan_interval_var.get())
        self.notification_preferences, self.monitoring_settings = load_notification_center_settings()
        self.sync_tray_icon()
        self.render_settings_tab()
        self.status_var.set("Bildirim ayarlari kaydedildi")
        messagebox.showinfo("Ayarlar", "Bildirim merkezi ayarlari kaydedildi.")

    def send_test_notification(self) -> None:
        result = self.send_desktop_notification(
            title="Windows Software Inventory Analyzer",
            message="Hos geldiniz. Bildirim merkezi ayarlari su an etkin.",
            notification_id="desktop_settings_test",
            dedupe_hours=0,
        )
        self.status_var.set(f"Test bildirimi: {result}")
        messagebox.showinfo("Test Bildirimi", f"Bildirim gonderim sonucu: {result}")

    def sync_tray_icon(self) -> None:
        if bool(self.notification_preferences.get("enable_tray_icon", True)):
            started = self.tray_controller.start()
            if not started:
                self.tray_runtime_status = "Baslatilamadi: pystray/pillow yok veya tray desteklenmiyor"
                self.status_var.set("Tray icon baslatilamadi; bildirim fallback kullaniliyor")
            else:
                self.tray_runtime_status = "Etkin. Windows gizli simgeler panelinde gorunebilir"
        else:
            self.tray_controller.stop()
            self.tray_runtime_status = "Kullanici tarafindan kapatildi"

    def show_window_from_tray(self) -> None:
        self.is_hidden_to_tray = False
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.status_var.set("Pencere tray icon uzerinden acildi")

    def exit_from_tray(self) -> None:
        self.on_close_request(force_exit=True)

    def on_close_request(self, force_exit: bool = False) -> None:
        if bool(self.notification_preferences.get("notify_on_app_close", True)):
            self.send_desktop_notification(
                title="Windows Software Inventory Analyzer",
                message="Desktop GUI kapaniyor. Bildirim ayarlari kaydedildi.",
                notification_id="close_desktop gui",
                dedupe_hours=0,
            )
        self.tray_controller.stop()
        self.root.destroy()

    def send_desktop_notification(
        self,
        *,
        title: str,
        message: str,
        notification_id: str,
        dedupe_hours: int = 1,
        honor_open_pref: bool = False,
    ) -> str:
        if not bool(self.notification_preferences.get("enable_notifications", True)):
            return "notifications_disabled"
        if honor_open_pref and not bool(self.notification_preferences.get("notify_on_app_open", True)):
            return "open_disabled"
        if honor_open_pref and not bool(self.notification_preferences.get("show_welcome_notification", True)):
            return "welcome_disabled"
        if self.tray_controller.notify(title, message):
            return "sent"
        return send_notification(
            title=title,
            message=message,
            severity="low",
            history_path=NOTIFICATION_HISTORY_PATH,
            notification_id=notification_id,
            dedupe_hours=dedupe_hours,
        )

    def show_selected_runtime_test_result(self) -> None:
        if not self.selected_runtime_family:
            return
        family_key = runtime_family_key_from_label(self.selected_runtime_family)
        report = build_runtime_family_report(
            family_key,
            self.runtime_family_details,
            self.dotnet_sdk_report,
            self.sdk_validation_report,
        )
        self.render_runtime_report()
        lines = [f"{report.get('family_label', '')} icin test ozeti hazir."]
        for note in report.get("notes", [])[:4]:
            lines.append(f"- {note}")
        messagebox.showinfo("Sistem Araci Test Sonucu", "\n".join(lines))

    def show_selected_program_test_result(self) -> None:
        if not self.selected_program:
            return
        message = self.build_family_test_message(self.selected_program)
        existing_text = self.removal_text.get("1.0", tk.END).strip()
        combined = existing_text + ("\n\n" if existing_text else "") + "Test Sonucu:\n" + message
        self.set_text(self.removal_text, combined)
        messagebox.showinfo("Test Sonucu", message)

    def run_background_steps(self, steps: list[tuple], completion_callback: object | None = None) -> None:
        self.progress_var.set(0)
        self.set_text(self.log_text, "")

        def worker() -> None:
            total = max(len(steps), 1)
            total_estimated = sum(int(step[3]) for step in steps if len(step) >= 4)
            elapsed_estimated = 0
            logs: list[str] = []
            for index, step in enumerate(steps, start=1):
                if len(step) == 2:
                    command_name, label = step
                    extra_args: list[str] = []
                    estimated_seconds = 0
                elif len(step) == 3:
                    command_name, label, extra_args = step
                    estimated_seconds = 0
                else:
                    command_name, label, extra_args, estimated_seconds = step
                remaining = max(0, total_estimated - elapsed_estimated) if total_estimated else 0
                step_label = f"{label} | Tahmini kalan: {format_eta(remaining)}" if remaining else label
                self.root.after(0, lambda text=step_label: self.step_var.set(text))
                self.root.after(0, lambda value=((index - 1) / total) * 100: self.progress_var.set(value))
                args = [command_name]
                config_path = resolve_runtime_config_path()
                if config_path is not None:
                    args.extend(["--config", str(config_path)])
                if extra_args:
                    args.extend(extra_args)
                
                import io
                import contextlib
                import sys

                stdout_buf = io.StringIO()
                stderr_buf = io.StringIO()
                orig_argv = sys.argv
                sys.argv = [sys.executable] + args

                returncode = 0
                try:
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        returncode = main_func()
                except Exception as error:
                    import traceback
                    stderr_buf.write(f"\nBeklenmeyen hata: {error}\n{traceback.format_exc()}")
                    returncode = 1
                finally:
                    sys.argv = orig_argv

                stdout_output = stdout_buf.getvalue()
                stderr_output = stderr_buf.getvalue()
                output = "\n".join(part.strip() for part in (stdout_output, stderr_output) if part.strip()).strip()

                logs.append(f"{label}\n{output or 'Tamamlandi'}")
                self.root.after(0, lambda text="\n\n".join(logs)[-5000:]: self.set_text(self.log_text, text))
                if returncode != 0:
                    self.root.after(0, lambda: messagebox.showerror("Islem Durdu", output or "Komut basarisiz oldu."))
                    self.root.after(0, lambda: self.status_var.set("Islem yarida kaldi"))
                    return
                elapsed_estimated += int(estimated_seconds or 0)

            self.root.after(0, lambda: self.progress_var.set(100))
            self.root.after(0, lambda: self.step_var.set("Tamamlandi"))
            self.root.after(0, self.refresh_views)
            self.root.after(0, self.refresh_selected_views)
            self.root.after(0, lambda: self.status_var.set("Tum adimlar tamamlandi"))
            if callable(completion_callback):
                self.root.after(0, completion_callback)

        threading.Thread(target=worker, daemon=True).start()

    def refresh_selected_views(self) -> None:
        if not self.selected_program:
            return
        updated = next(
            (row for row in build_search_index(self.recommendations, self.mappings, self.projects) if row.get("software_name", "") == self.selected_program.get("software_name", "")),
            {},
        )
        if updated:
            self.selected_program = updated
            self.render_program_detail(updated)
            self.render_removal_detail(updated)

    def on_alert_select(self, _event: object) -> None:
        selection = self.alert_tree.selection()
        if not selection:
            return
        values = self.alert_tree.item(selection[0], "values")
        if not values:
            return
        title = values[2]
        selected = next((row for row in self.alerts if row.get("title", "") == title), {})
        if not selected:
            return
        lines = [
            f"Baslik: {selected.get('title', '')}",
            f"Seviye: {selected.get('severity', '')}",
            f"Kategori: {selected.get('category', '')}",
            f"Guven: {selected.get('confidence_score', '')}",
            "",
            f"Aciklama: {selected.get('description', '')}",
            "",
            f"Onerilen islem: {selected.get('recommended_action', '')}",
            "",
            selected.get("explanation", "") or "Detayli aciklama yok.",
        ]
        self.set_text(self.alert_detail_text, "\n".join(lines))


def main() -> int:
    root = tk.Tk()
    DesktopAnalyzerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
