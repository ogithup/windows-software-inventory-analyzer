from __future__ import annotations

import json
from pathlib import Path


def _safe_float(value: object) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0


def generate_weekly_report(
    alerts: list[dict[str, str]],
    disk_usage_history: list[dict[str, str]],
    app_inventory: list[dict[str, str]],
    event_log_summary: list[dict[str, str]],
    user_actions_history: list[dict[str, str]],
) -> dict[str, object]:
    critical_count = sum(1 for alert in alerts if alert.get("severity", "") == "critical")
    high_count = sum(1 for alert in alerts if alert.get("severity", "") == "high")
    medium_count = sum(1 for alert in alerts if alert.get("severity", "") == "medium")
    system_health_score = max(0, 100 - critical_count * 20 - high_count * 10 - medium_count * 4)

    cleanup_candidates = [
        {
            "software_name": row.get("software_name", "") or row.get("name", ""),
            "estimated_size": row.get("estimated_size", ""),
        }
        for row in app_inventory
        if row.get("software_name", "") or row.get("name", "")
    ][:10]
    crash_rows = [row for row in event_log_summary if row.get("category", "") == "application_crash"]
    old_sdks = [alert for alert in alerts if alert.get("category", "") == "sdk"]
    ignored_alerts = [row for row in user_actions_history if row.get("action", "") == "ignored"]
    recommended_steps = [alert.get("recommended_action", "") for alert in alerts[:5] if alert.get("recommended_action", "").strip()]

    highest_disk = max(disk_usage_history, key=lambda row: _safe_float(row.get("usage_percent", row.get("used_pct", "0"))), default={})

    return {
        "system_health_score": system_health_score,
        "disk_status": {
            "highest_usage_target": highest_disk.get("drive", "") or highest_disk.get("scan_root", "") or highest_disk.get("path", ""),
            "highest_usage_percent": highest_disk.get("usage_percent", "") or highest_disk.get("used_pct", ""),
        },
        "cleanup_candidates": cleanup_candidates,
        "repeated_crash_apps": crash_rows,
        "old_sdk_versions": old_sdks,
        "ignored_alerts": ignored_alerts,
        "recommended_next_steps": recommended_steps,
    }


def export_report_to_markdown(report: dict[str, object], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Haftalik Sistem Sagligi Raporu",
        "",
        f"- Sistem sagligi skoru: {report.get('system_health_score', 0)}",
        f"- En yuksek disk doluluk hedefi: {report.get('disk_status', {}).get('highest_usage_target', '')}",
        f"- En yuksek disk doluluk yuzdesi: {report.get('disk_status', {}).get('highest_usage_percent', '')}",
        "",
        "## Onerilen Sonraki Adimlar",
    ]
    for step in report.get("recommended_next_steps", []):
        lines.append(f"- {step}")
    lines.extend(["", "## Eski SDK Surumleri"])
    for alert in report.get("old_sdk_versions", []):
        lines.append(f"- {alert.get('title', '')}: manual test required")
    lines.extend(["", "## Yok Sayilan Uyarilar"])
    for row in report.get("ignored_alerts", []):
        lines.append(f"- {row.get('alert_id', '')}")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    output_path.with_suffix(".json").write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
    return output_path
