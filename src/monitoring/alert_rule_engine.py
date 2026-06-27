from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
ALERT_HEADERS = [
    "id",
    "title",
    "description",
    "severity",
    "category",
    "recommended_action",
    "confidence_score",
    "source",
    "created_at",
    "explanation",
]


def _safe_float(value: object) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _size_to_gb(value: str) -> float:
    parts = str(value).strip().split()
    if len(parts) != 2:
        return 0.0
    amount = _safe_float(parts[0])
    unit = parts[1].upper()
    factor = {
        "B": 1 / (1024**3),
        "KB": 1 / (1024**2),
        "MB": 1 / 1024,
        "GB": 1,
        "TB": 1024,
    }.get(unit, 0)
    return amount * factor


def _normalize_pair(left: datetime, right: datetime) -> tuple[datetime, datetime]:
    if (left.tzinfo is None) != (right.tzinfo is None):
        return left.replace(tzinfo=None), right.replace(tzinfo=None)
    return left, right


def _make_alert(
    alert_id: str,
    title: str,
    description: str,
    severity: str,
    category: str,
    recommended_action: str,
    confidence_score: float,
    source: str,
    created_at: str,
) -> dict[str, str]:
    return {
        "id": alert_id,
        "title": title,
        "description": description,
        "severity": severity,
        "category": category,
        "recommended_action": recommended_action,
        "confidence_score": f"{max(0.0, min(confidence_score, 1.0)):.2f}",
        "source": source,
        "created_at": created_at,
        "explanation": "",
    }


def _event_summary_by_category(event_log_summary: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {row.get("category", ""): row for row in event_log_summary if row.get("category", "").strip()}


def generate_alerts(
    installed_apps: list[dict[str, str]],
    disk_usage_data: list[dict[str, str]],
    event_log_summary: list[dict[str, str]],
    sdk_inventory: list[dict[str, str]],
    last_used_app_data: list[dict[str, str]],
    now: datetime | None = None,
) -> list[dict[str, str]]:
    created_at = (now or datetime.now()).isoformat(timespec="seconds")
    alerts: dict[str, dict[str, str]] = {}
    usage_by_name = {row.get("software_name", "").casefold(): row for row in last_used_app_data if row.get("software_name", "").strip()}
    summary_by_category = _event_summary_by_category(event_log_summary)

    for row in disk_usage_data:
        drive = row.get("drive", "") or row.get("scan_root", "") or row.get("path", "")
        usage_percent = _safe_float(row.get("usage_percent", row.get("used_pct", row.get("drive_usage_percent", "0"))))
        if usage_percent >= 95:
            alerts[f"disk_critical_{drive.casefold()}"] = _make_alert(
                f"disk_critical_{drive.casefold()}",
                f"{drive} diski kritik dolulukta",
                f"{drive} icin doluluk %{usage_percent:.0f} seviyesine cikti.",
                "critical",
                "disk",
                "Buyuk klasorleri ve yeniden uretilebilir cache alanlarini once inceleyin.",
                0.98,
                "disk_analyzer",
                created_at,
            )
        elif usage_percent >= 85:
            alerts[f"disk_high_{drive.casefold()}"] = _make_alert(
                f"disk_high_{drive.casefold()}",
                f"{drive} diski yuksek dolulukta",
                f"{drive} icin doluluk %{usage_percent:.0f} seviyesinde.",
                "high",
                "disk",
                "Disk zone raporundaki buyuk ve recoverable alanlari kontrol edin.",
                0.92,
                "disk_analyzer",
                created_at,
            )

    reference_now = now or datetime.now()
    for app in installed_apps:
        software_name = app.get("software_name") or app.get("name", "")
        if not software_name:
            continue
        usage_row = usage_by_name.get(software_name.casefold(), {})
        last_used = _parse_date(usage_row.get("last_used_at", ""))
        if last_used is None:
            continue
        reference_now_value, last_used_value = _normalize_pair(reference_now, last_used)
        age_days = (reference_now_value - last_used_value).days
        size_gb = max(
            _size_to_gb(app.get("estimated_size", "")),
            _size_to_gb(app.get("size_human", "")),
        )
        if age_days >= 90 and size_gb >= 1:
            alerts[f"unused_app_{software_name.casefold()}"] = _make_alert(
                f"unused_app_{software_name.casefold()}",
                f"{software_name} uzun suredir kullanilmiyor",
                f"{software_name} son {age_days} gundur kullanilmamis gorunuyor ve yaklasik {size_gb:.1f} GB alan kapliyor.",
                "medium",
                "app_usage",
                "Kaldirmadan once proje baglarini ve son kullanim ihtimalini manuel kontrol edin.",
                0.81,
                "usage_signals",
                created_at,
            )

    crash_summary = summary_by_category.get("application_crash", {})
    crash_count = int(crash_summary.get("event_count", "0") or "0")
    if crash_count >= 5:
        alerts["event_application_crash"] = _make_alert(
            "event_application_crash",
            "Uygulama cokme kayitlari artmis",
            f"Son izleme araliginda {crash_count} uygulama cokme kaydi bulundu.",
            "high",
            "event_log",
            "Cokme kayitlarinin geldigi uygulamalari guncelleme veya yeniden kurulum acisindan inceleyin.",
            0.88,
            "event_log_reader",
            created_at,
        )

    disk_warning_summary = summary_by_category.get("disk_warning", {})
    disk_warning_count = int(disk_warning_summary.get("event_count", "0") or "0")
    if disk_warning_count > 0:
        alerts["event_disk_warning"] = _make_alert(
            "event_disk_warning",
            "Disk ile ilgili uyari loglari bulundu",
            f"Son izleme araliginda {disk_warning_count} disk uyarisi tespit edildi.",
            "high",
            "event_log",
            "SMART, NTFS ve fiziksel disk sagligi icin ek kontrol yapin.",
            0.9,
            "event_log_reader",
            created_at,
        )

    installer_summary = summary_by_category.get("installer_failure", {})
    installer_count = int(installer_summary.get("event_count", "0") or "0")
    if installer_count > 0:
        alerts["event_installer_failure"] = _make_alert(
            "event_installer_failure",
            "Basarisiz kurulum veya kaldirma kayitlari bulundu",
            f"Son izleme araliginda {installer_count} installer/uninstaller hatasi bulundu.",
            "medium",
            "event_log",
            "Yarim kalmis kurulum veya uninstall girdilerini kontrol edin.",
            0.84,
            "event_log_reader",
            created_at,
        )

    for row in sdk_inventory:
        status = f"{row.get('status', '')} {row.get('recommendation', '')}".casefold()
        sdk_version = row.get("sdk_version", "") or row.get("software_name", "")
        if not sdk_version:
            continue
        if any(flag in status for flag in ("older", "manual_review", "safe_older_patch")):
            alerts[f"sdk_review_{sdk_version.casefold()}"] = _make_alert(
                f"sdk_review_{sdk_version.casefold()}",
                f"Eski SDK surumu gozden gecirilmeli: {sdk_version}",
                f"{sdk_version} icin rapor manuel test veya eski surum sinyali veriyor.",
                "medium",
                "sdk",
                "Kaldirmadan once ilgili projelerde build veya validation raporunu calistirin.",
                0.76,
                "sdk_analyzer",
                created_at,
            )

    return sort_alerts(list(alerts.values()))


def sort_alerts(alerts: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        alerts,
        key=lambda item: (
            -SEVERITY_ORDER.get(item.get("severity", "low"), 0),
            -_safe_float(item.get("confidence_score", "0")),
            item.get("title", "").casefold(),
        ),
    )


def write_alert_reports(alerts: list[dict[str, str]], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "alerts.csv"
    json_path = output_dir / "alerts.json"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=ALERT_HEADERS)
        writer.writeheader()
        writer.writerows(alerts)
    json_path.write_text(json.dumps(alerts, ensure_ascii=True, indent=2), encoding="utf-8")
    return csv_path, json_path
