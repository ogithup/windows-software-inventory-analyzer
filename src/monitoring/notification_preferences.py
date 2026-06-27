from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def default_preferences() -> dict[str, object]:
    return {
        "enable_notifications": True,
        "show_welcome_notification": True,
        "notify_on_app_open": True,
        "notify_on_app_close": True,
        "enable_tray_icon": True,
        "only_critical_alerts": False,
        "quiet_hours_start": "23:00",
        "quiet_hours_end": "08:00",
        "disabled_categories": [],
        "snoozed_alerts": {},
        "ignored_alerts": [],
    }


def load_preferences(path: Path) -> dict[str, object]:
    if not path.exists():
        return default_preferences()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_preferences()
    preferences = default_preferences()
    preferences.update(raw if isinstance(raw, dict) else {})
    return preferences


def save_preferences(path: Path, preferences: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(preferences, ensure_ascii=True, indent=2), encoding="utf-8")


def is_category_enabled(category: str, preferences: dict[str, object] | None = None) -> bool:
    prefs = preferences or default_preferences()
    disabled = {str(item) for item in prefs.get("disabled_categories", [])}
    return category not in disabled


def _parse_clock(value: str) -> tuple[int, int]:
    try:
        hour, minute = value.split(":", 1)
        return int(hour), int(minute)
    except (ValueError, AttributeError):
        return 0, 0


def is_quiet_time(preferences: dict[str, object] | None = None, now: datetime | None = None) -> bool:
    prefs = preferences or default_preferences()
    reference_now = now or datetime.now()
    start_hour, start_minute = _parse_clock(str(prefs.get("quiet_hours_start", "23:00")))
    end_hour, end_minute = _parse_clock(str(prefs.get("quiet_hours_end", "08:00")))
    current_minutes = reference_now.hour * 60 + reference_now.minute
    start_minutes = start_hour * 60 + start_minute
    end_minutes = end_hour * 60 + end_minute
    if start_minutes == end_minutes:
        return False
    if start_minutes < end_minutes:
        return start_minutes <= current_minutes < end_minutes
    return current_minutes >= start_minutes or current_minutes < end_minutes


def should_show_alert(alert: dict[str, str], preferences: dict[str, object] | None = None, now: datetime | None = None) -> bool:
    prefs = preferences or default_preferences()
    if not bool(prefs.get("enable_notifications", True)):
        return False
    if bool(prefs.get("only_critical_alerts", False)) and alert.get("severity", "") != "critical":
        return False
    if not is_category_enabled(alert.get("category", ""), prefs):
        return False
    if alert.get("id", "") in {str(item) for item in prefs.get("ignored_alerts", [])}:
        return False
    snoozed = prefs.get("snoozed_alerts", {})
    if isinstance(snoozed, dict):
        until_raw = str(snoozed.get(alert.get("id", ""), ""))
        if until_raw:
            try:
                if (now or datetime.now()) < datetime.fromisoformat(until_raw):
                    return False
            except ValueError:
                pass
    if alert.get("severity", "") in {"low", "medium"} and is_quiet_time(prefs, now=now):
        return False
    return True


def snooze_alert(alert_id: str, until_datetime: datetime, preferences: dict[str, object] | None = None) -> dict[str, object]:
    prefs = preferences or default_preferences()
    snoozed = dict(prefs.get("snoozed_alerts", {}))
    snoozed[alert_id] = until_datetime.isoformat(timespec="seconds")
    prefs["snoozed_alerts"] = snoozed
    return prefs


def ignore_alert(alert_id: str, preferences: dict[str, object] | None = None) -> dict[str, object]:
    prefs = preferences or default_preferences()
    ignored = {str(item) for item in prefs.get("ignored_alerts", [])}
    ignored.add(alert_id)
    prefs["ignored_alerts"] = sorted(ignored)
    return prefs
