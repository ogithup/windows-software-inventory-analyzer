from __future__ import annotations

import csv
from datetime import datetime, timedelta
from pathlib import Path


EVENT_HEADERS = [
    "source",
    "event_id",
    "level",
    "timestamp",
    "message_summary",
    "category",
]

SUMMARY_HEADERS = [
    "category",
    "event_count",
    "sources",
    "latest_timestamp",
    "sample_message",
]


def _detect_category(source: str, event_id: int, message: str, log_name: str) -> str:
    text = f"{source} {message} {log_name}".casefold()
    if "crash" in text or "faulting" in text or event_id in {1000, 1001, 1002}:
        return "application_crash"
    if "disk" in text or "ntfs" in text or event_id in {7, 51, 55, 98, 129, 153}:
        return "disk_warning"
    if "msi" in text or "install" in text or "uninstall" in text or event_id in {1033, 1034, 11707, 11708, 11724}:
        return "installer_failure"
    if "error" in text or "warning" in text:
        return "system_warning"
    return "general_warning"


def _safe_summary(message: str) -> str:
    single_line = " ".join(message.split())
    return single_line[:240]


def read_windows_event_logs(days: int = 7, log_names: tuple[str, ...] = ("Application", "System")) -> tuple[list[dict[str, str]], str | None]:
    try:
        import win32evtlog  # type: ignore
        import win32evtlogutil  # type: ignore
    except ImportError:
        return [], "pywin32 kurulu degil; Windows Event Viewer loglari okunamadi."

    cutoff = datetime.now() - timedelta(days=max(days, 1))
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    warning_types = {
        win32evtlog.EVENTLOG_WARNING_TYPE: "warning",
        win32evtlog.EVENTLOG_ERROR_TYPE: "error",
    }
    events: list[dict[str, str]] = []
    status_messages: list[str] = []

    for log_name in log_names:
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
        except Exception as error:
            status_messages.append(f"{log_name} loguna erisilemedi: {error}")
            continue
        try:
            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for record in records:
                    event_time = record.TimeGenerated.Format()
                    try:
                        timestamp = datetime.strptime(event_time, "%a %b %d %H:%M:%S %Y")
                    except ValueError:
                        timestamp = datetime.now()
                    if timestamp < cutoff:
                        continue
                    level = warning_types.get(record.EventType)
                    if not level:
                        continue
                    source = str(getattr(record, "SourceName", "") or log_name)
                    event_id = int(record.EventID & 0xFFFF)
                    try:
                        message = win32evtlogutil.SafeFormatMessage(record, log_name)
                    except Exception:
                        message = ""
                    events.append(
                        {
                            "source": source,
                            "event_id": str(event_id),
                            "level": level,
                            "timestamp": timestamp.isoformat(timespec="seconds"),
                            "message_summary": _safe_summary(message),
                            "category": _detect_category(source, event_id, message, log_name),
                        }
                    )
        except Exception as error:
            status_messages.append(f"{log_name} okunurken hata: {error}")
        finally:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass

    return events, " | ".join(status_messages) if status_messages else None


def summarize_events(events: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[str, dict[str, object]] = {}
    for event in events:
        category = event.get("category", "general_warning")
        group = grouped.setdefault(
            category,
            {
                "category": category,
                "event_count": 0,
                "sources": set(),
                "latest_timestamp": "",
                "sample_message": "",
            },
        )
        group["event_count"] = int(group["event_count"]) + 1
        if event.get("source", "").strip():
            group["sources"].add(event["source"])  # type: ignore[index]
        if event.get("timestamp", "") >= str(group["latest_timestamp"]):
            group["latest_timestamp"] = event.get("timestamp", "")
            group["sample_message"] = event.get("message_summary", "")
    summary_rows: list[dict[str, str]] = []
    for group in grouped.values():
        summary_rows.append(
            {
                "category": str(group["category"]),
                "event_count": str(group["event_count"]),
                "sources": ", ".join(sorted(group["sources"])),  # type: ignore[arg-type]
                "latest_timestamp": str(group["latest_timestamp"]),
                "sample_message": str(group["sample_message"]),
            }
        )
    summary_rows.sort(key=lambda item: (-int(item.get("event_count", "0")), item.get("category", "")))
    return summary_rows


def write_event_log_reports(
    events: list[dict[str, str]],
    summary_rows: list[dict[str, str]],
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    events_path = output_dir / "event_log_events.csv"
    summary_path = output_dir / "event_log_summary.csv"
    with events_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=EVENT_HEADERS)
        writer.writeheader()
        writer.writerows(events)
    with summary_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=SUMMARY_HEADERS)
        writer.writeheader()
        writer.writerows(summary_rows)
    return events_path, summary_path

