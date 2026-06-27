from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path


DEFAULT_INTERVAL = "weekly"
VALID_INTERVALS = {"daily", "weekly", "monthly"}


def _default_settings(interval: str = DEFAULT_INTERVAL) -> dict[str, str]:
    return {
        "scan_interval": interval if interval in VALID_INTERVALS else DEFAULT_INTERVAL,
        "last_scan_time": "",
    }


def load_scheduler_settings(settings_path: Path) -> dict[str, str]:
    if not settings_path.exists():
        return _default_settings()
    try:
        raw = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default_settings()
    settings = _default_settings(str(raw.get("scan_interval", DEFAULT_INTERVAL)))
    settings["last_scan_time"] = str(raw.get("last_scan_time", "")).strip()
    return settings


def save_scheduler_settings(settings_path: Path, settings: dict[str, str]) -> None:
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "scan_interval": settings.get("scan_interval", DEFAULT_INTERVAL),
        "last_scan_time": settings.get("last_scan_time", ""),
    }
    settings_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _interval_delta(interval: str) -> timedelta:
    if interval == "daily":
        return timedelta(days=1)
    if interval == "monthly":
        return timedelta(days=30)
    return timedelta(days=7)


def should_run_scan(
    interval: str = DEFAULT_INTERVAL,
    settings_path: Path | None = None,
    now: datetime | None = None,
) -> bool:
    reference_now = now or datetime.now()
    if settings_path is None:
        return True
    settings = load_scheduler_settings(settings_path)
    effective_interval = interval if interval in VALID_INTERVALS else settings.get("scan_interval", DEFAULT_INTERVAL)
    last_scan = _parse_datetime(settings.get("last_scan_time", ""))
    if last_scan is None:
        return True
    return reference_now >= last_scan + _interval_delta(effective_interval)


def update_last_scan_time(
    settings_path: Path,
    interval: str = DEFAULT_INTERVAL,
    scan_time: datetime | None = None,
) -> dict[str, str]:
    effective_time = scan_time or datetime.now()
    settings = load_scheduler_settings(settings_path)
    settings["scan_interval"] = interval if interval in VALID_INTERVALS else settings.get("scan_interval", DEFAULT_INTERVAL)
    settings["last_scan_time"] = effective_time.isoformat(timespec="seconds")
    save_scheduler_settings(settings_path, settings)
    return settings


def get_next_scan_date(
    interval: str = DEFAULT_INTERVAL,
    settings_path: Path | None = None,
    now: datetime | None = None,
) -> datetime:
    reference_now = now or datetime.now()
    if settings_path is None:
        return reference_now + _interval_delta(interval)
    settings = load_scheduler_settings(settings_path)
    effective_interval = interval if interval in VALID_INTERVALS else settings.get("scan_interval", DEFAULT_INTERVAL)
    last_scan = _parse_datetime(settings.get("last_scan_time", ""))
    if last_scan is None:
        return reference_now
    return last_scan + _interval_delta(effective_interval)


if __name__ == "__main__":
    settings_file = Path("data/output/monitoring_settings.json")
    print("Should run:", should_run_scan(settings_path=settings_file))
    print("Next run:", get_next_scan_date(settings_path=settings_file).isoformat(timespec="seconds"))
    print("Updating last scan time...")
    update_last_scan_time(settings_file)

