from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from src.monitoring.alert_rule_engine import generate_alerts
from src.monitoring.notification_preferences import (
    ignore_alert,
    is_quiet_time,
    should_show_alert,
    snooze_alert,
)
from src.monitoring.scheduler_service import (
    get_next_scan_date,
    should_run_scan,
    update_last_scan_time,
)
from src.monitoring.weekly_report_generator import generate_weekly_report


def test_scheduler_runs_when_missing_and_respects_saved_scan_time(tmp_path: Path) -> None:
    settings_path = tmp_path / "monitoring_settings.json"
    now = datetime(2026, 6, 27, 12, 0, 0)

    assert should_run_scan(settings_path=settings_path, now=now) is True

    update_last_scan_time(settings_path, interval="weekly", scan_time=now)
    assert should_run_scan(settings_path=settings_path, now=now + timedelta(days=3)) is False
    assert should_run_scan(settings_path=settings_path, now=now + timedelta(days=8)) is True
    assert get_next_scan_date(settings_path=settings_path, now=now) == now + timedelta(days=7)


def test_alert_rule_engine_generates_disk_crash_and_unused_app_alerts() -> None:
    alerts = generate_alerts(
        installed_apps=[
            {
                "software_name": "Old Tool",
                "estimated_size": "2.5 GB",
            }
        ],
        disk_usage_data=[
            {
                "drive": "C:",
                "usage_percent": "96",
            }
        ],
        event_log_summary=[
            {
                "category": "application_crash",
                "event_count": "6",
            }
        ],
        sdk_inventory=[],
        last_used_app_data=[
            {
                "software_name": "Old Tool",
                "last_used_at": "2026-01-01T00:00:00",
            }
        ],
        now=datetime(2026, 6, 27, 12, 0, 0),
    )

    alert_ids = {alert["id"] for alert in alerts}
    assert "disk_critical_c:" in alert_ids
    assert "event_application_crash" in alert_ids
    assert "unused_app_old tool" in alert_ids


def test_notification_preferences_honor_quiet_hours_snooze_and_ignore() -> None:
    prefs = {
        "enable_notifications": True,
        "only_critical_alerts": False,
        "quiet_hours_start": "22:00",
        "quiet_hours_end": "07:00",
        "disabled_categories": [],
        "snoozed_alerts": {},
        "ignored_alerts": [],
    }
    alert = {"id": "disk1", "severity": "medium", "category": "disk"}

    assert is_quiet_time(prefs, now=datetime(2026, 6, 27, 23, 0, 0)) is True
    assert should_show_alert(alert, prefs, now=datetime(2026, 6, 27, 23, 0, 0)) is False

    prefs = snooze_alert("disk1", datetime(2026, 6, 28, 10, 0, 0), prefs)
    assert should_show_alert(alert, prefs, now=datetime(2026, 6, 28, 9, 0, 0)) is False

    prefs["snoozed_alerts"] = {}
    prefs = ignore_alert("disk1", prefs)
    assert should_show_alert(alert, prefs, now=datetime(2026, 6, 28, 12, 0, 0)) is False


def test_weekly_report_contains_expected_sections() -> None:
    report = generate_weekly_report(
        alerts=[
            {"severity": "critical", "category": "disk", "recommended_action": "Diski kontrol et.", "title": "Disk dolu"}
        ],
        disk_usage_history=[{"drive": "C:", "usage_percent": "91"}],
        app_inventory=[{"software_name": "Example App", "estimated_size": "1 GB"}],
        event_log_summary=[{"category": "application_crash", "event_count": "3"}],
        user_actions_history=[{"action": "ignored", "alert_id": "disk1"}],
    )

    assert "system_health_score" in report
    assert "disk_status" in report
    assert "cleanup_candidates" in report
    assert "recommended_next_steps" in report
