from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path


def _load_history(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _save_history(path: Path, history: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history, ensure_ascii=True, indent=2), encoding="utf-8")


def _escape_powershell_text(value: str) -> str:
    return value.replace("'", "''")


def _send_windows_balloon_notification(title: str, message: str, silent: bool) -> bool:
    if sys.platform != "win32":
        return False
    ps_title = _escape_powershell_text(title)
    ps_message = _escape_powershell_text(message)
    timeout = 4000 if silent else 7000
    script = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "Add-Type -AssemblyName System.Drawing; "
        "$notify = New-Object System.Windows.Forms.NotifyIcon; "
        "$notify.Icon = [System.Drawing.SystemIcons]::Information; "
        "$notify.BalloonTipTitle = '{title}'; "
        "$notify.BalloonTipText = '{message}'; "
        "$notify.Visible = $true; "
        "$notify.ShowBalloonTip({timeout}); "
        "Start-Sleep -Milliseconds {sleep_ms}; "
        "$notify.Dispose();"
    ).format(title=ps_title, message=ps_message, timeout=timeout, sleep_ms=timeout + 1200)
    try:
        subprocess.Popen(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def should_notify(alert: dict[str, str], history_path: Path, now: datetime | None = None) -> bool:
    reference_now = now or datetime.now()
    history = _load_history(history_path)
    sent_at = history.get(alert.get("id", ""))
    if not sent_at:
        return True
    try:
        notified_at = datetime.fromisoformat(sent_at)
    except ValueError:
        return True
    return reference_now - notified_at >= timedelta(hours=24)


def mark_as_notified(alert: dict[str, str], history_path: Path, now: datetime | None = None) -> None:
    history = _load_history(history_path)
    history[alert.get("id", "")] = (now or datetime.now()).isoformat(timespec="seconds")
    _save_history(history_path, history)


def send_notification(
    *,
    title: str,
    message: str,
    severity: str = "low",
    history_path: Path | None = None,
    notification_id: str | None = None,
    dedupe_hours: int | None = 24,
    now: datetime | None = None,
) -> str:
    if history_path is not None and notification_id and dedupe_hours is not None:
        reference_now = now or datetime.now()
        history = _load_history(history_path)
        sent_at = history.get(notification_id)
        if sent_at:
            try:
                notified_at = datetime.fromisoformat(sent_at)
                if reference_now - notified_at < timedelta(hours=dedupe_hours):
                    return "duplicate_skipped"
            except ValueError:
                pass

    silent = severity == "low"
    delivered = False
    try:
        from winotify import Notification  # type: ignore

        toast = Notification(app_id="WSIA", title=title, msg=message, duration="short")
        if silent:
            toast.set_audio(None, loop=False)
        toast.show()
        delivered = True
    except Exception:
        try:
            from plyer import notification  # type: ignore

            notification.notify(
                title=title,
                message=message,
                app_name="WSIA",
                timeout=8 if not silent else 4,
            )
            delivered = True
        except Exception:
            delivered = _send_windows_balloon_notification(title, message, silent)
            if not delivered:
                print(f"[notification:{severity}] {title} - {message}")

    if history_path is not None and notification_id:
        history = _load_history(history_path)
        history[notification_id] = (now or datetime.now()).isoformat(timespec="seconds")
        _save_history(history_path, history)
    return "sent" if delivered else "console_fallback"


def send_alert_notification(alert: dict[str, str], history_path: Path, now: datetime | None = None) -> str:
    if not should_notify(alert, history_path=history_path, now=now):
        return "duplicate_skipped"
    return send_notification(
        title=alert.get("title", "Windows Software Inventory Analyzer"),
        message=alert.get("description", ""),
        severity=alert.get("severity", "low"),
        history_path=history_path,
        notification_id=alert.get("id", ""),
        dedupe_hours=24,
        now=now,
    )
