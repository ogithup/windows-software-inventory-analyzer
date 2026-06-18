from __future__ import annotations

import csv
import json
import logging
import os
import re
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from src.windows_software_inventory_analyzer.models import InstalledApplication, ProgramUsageSignalEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.collectors.usage_signals")

USAGE_SIGNAL_HEADERS = (
    "software_name",
    "last_used_at",
    "usage_signal_count",
    "usage_sources",
    "matched_executables",
    "usage_status",
)

SIGNAL_SOURCE_ROOTS = {
    "recent": Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent",
    "start_menu_user": Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu",
    "start_menu_common": Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows" / "Start Menu",
    "jump_lists_auto": Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations",
    "jump_lists_custom": Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "CustomDestinations",
    "prefetch": Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch",
}

LINK_SIGNAL_SOURCES = {"recent", "start_menu_user", "start_menu_common"}
APP_MATCH_STOPWORDS = {
    "microsoft",
    "corporation",
    "program",
    "package",
    "runtime",
    "sdk",
    "desktop",
    "app",
    "application",
    "tools",
    "tool",
    "update",
    "assistant",
    "core",
    "framework",
    "support",
    "library",
    "libraries",
    "standard",
    "documentation",
    "bootstrap",
    "shared",
    "host",
    "bundle",
    "version",
    "x64",
    "x86",
    "arm64",
    "browser",
    "server",
    "studio",
    "installer",
    "client",
    "service",
}
GENERIC_EXECUTABLE_NAMES = {
    "uninstall.exe",
    "unins000.exe",
    "setup.exe",
    "msiexec.exe",
    "update.exe",
    "launcher.exe",
    "landingpage.exe",
    "cmd.exe",
    "powershell.exe",
}


def collect_program_usage_signals(installed_programs: list[InstalledApplication]) -> list[ProgramUsageSignalEntry]:
    raw_signals = collect_raw_usage_signals()
    if not raw_signals:
        LOGGER.info("No usage signals were collected from Windows sources.")

    results: list[ProgramUsageSignalEntry] = []
    for program in installed_programs:
        matches = match_usage_signals(program, raw_signals)
        if not matches:
            results.append(
                ProgramUsageSignalEntry(
                    software_name=program.name,
                    last_used_at="",
                    usage_signal_count=0,
                    usage_sources="",
                    matched_executables="",
                    usage_status="unknown_usage",
                )
            )
            continue

        last_used_at = max(match["last_seen"] for match in matches if match.get("last_seen")) if matches else ""
        sources = unique_join(match["source"] for match in matches)
        executables = unique_join(match["target_name"] for match in matches)
        results.append(
            ProgramUsageSignalEntry(
                software_name=program.name,
                last_used_at=last_used_at,
                usage_signal_count=len(matches),
                usage_sources=sources,
                matched_executables=executables,
                usage_status="usage_detected",
            )
        )

    results.sort(key=lambda item: (item.software_name.casefold(), item.last_used_at), reverse=False)
    return results


def collect_raw_usage_signals() -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []

    for source_name, root in SIGNAL_SOURCE_ROOTS.items():
        if not root.exists():
            LOGGER.debug("Usage signal root does not exist: %s", root)
            continue
        if source_name in LINK_SIGNAL_SOURCES:
            signals.extend(collect_link_signals(root, source_name))
        elif source_name.startswith("jump_lists"):
            signals.extend(collect_jump_list_signals(root, source_name))
        elif source_name == "prefetch":
            signals.extend(collect_prefetch_signals(root, source_name))

    return deduplicate_raw_signals(signals)


def collect_link_signals(root: Path, source_name: str) -> list[dict[str, str]]:
    command = build_link_inspection_command(root)
    completed = run_powershell_command(command)
    if completed is None or completed.returncode != 0:
        return []

    payload = parse_json_output(completed.stdout)
    if not isinstance(payload, list):
        return []

    signals: list[dict[str, str]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        target_path = str(item.get("TargetPath", "")).strip()
        link_path = str(item.get("FullName", "")).strip()
        last_seen = normalize_datetime(item.get("LastWriteTimeUtc", ""))
        if not link_path or not last_seen:
            continue
        target_name = Path(target_path).name if target_path else Path(link_path).stem
        signals.append(
            {
                "source": source_name,
                "target_path": target_path,
                "target_name": target_name,
                "last_seen": last_seen,
                "signal_path": link_path,
            }
        )
    return signals


def collect_jump_list_signals(root: Path, source_name: str) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    try:
        iterator = root.glob("*")
    except OSError as error:
        LOGGER.debug("Could not scan Jump List root %s: %s", root, error)
        return signals

    for path in iterator:
        try:
            if not path.is_file():
                continue
            stat = path.stat()
        except OSError:
            continue
        signals.append(
            {
                "source": source_name,
                "target_path": "",
                "target_name": path.stem,
                "last_seen": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "signal_path": str(path),
            }
        )
    return signals


def collect_prefetch_signals(root: Path, source_name: str) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    try:
        iterator = root.glob("*.pf")
    except OSError as error:
        LOGGER.debug("Could not scan Prefetch root %s: %s", root, error)
        return signals

    for path in iterator:
        try:
            stat = path.stat()
        except OSError:
            continue
        executable_name = path.stem.split("-")[0].strip()
        if not executable_name:
            continue
        signals.append(
            {
                "source": source_name,
                "target_path": "",
                "target_name": executable_name,
                "last_seen": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "signal_path": str(path),
            }
        )
    return signals


def build_link_inspection_command(root: Path) -> str:
    root_text = str(root).replace("'", "''")
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$root='{root_text}';"
        "if (-not (Test-Path -LiteralPath $root)) { '[]'; exit 0 };"
        "$shell = New-Object -ComObject WScript.Shell;"
        "$items = Get-ChildItem -LiteralPath $root -Recurse -Filter *.lnk -ErrorAction SilentlyContinue |"
        " ForEach-Object {"
        "   $shortcut = $shell.CreateShortcut($_.FullName);"
        "   [pscustomobject]@{"
        "     FullName = $_.FullName;"
        "     TargetPath = $shortcut.TargetPath;"
        "     LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString('o')"
        "   }"
        " };"
        "$items | ConvertTo-Json -Compress"
    )


def run_powershell_command(command: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        LOGGER.debug("PowerShell usage signal command failed: %s", error)
        return None


def parse_json_output(text: str) -> list[dict[str, str]] | dict[str, str] | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        LOGGER.debug("Could not decode usage signal JSON output.")
        return None


def match_usage_signals(program: InstalledApplication, signals: list[dict[str, str]]) -> list[dict[str, str]]:
    name_tokens = tokenize_program_name(program.name)
    install_path = normalize_path_text(program.install_location)
    uninstall_text = normalize_path_text(program.uninstall_string)
    executable_hints = extract_executable_hints(program)
    matches: list[dict[str, str]] = []

    for signal in signals:
        target_name = normalize_path_text(signal.get("target_name", ""))
        target_path = normalize_path_text(signal.get("target_path", ""))
        signal_path = normalize_path_text(signal.get("signal_path", ""))
        target_basename = Path(target_name).name if target_name else ""

        score = 0
        if executable_hints and any(hint in target_name or hint in target_path for hint in executable_hints):
            score += 3
        if install_path and target_path and install_path in target_path:
            score += 3
        if uninstall_text and target_path and any(hint in target_path for hint in executable_hints):
            score += 1
        token_hits = sum(1 for token in name_tokens if token in target_name or token in target_path)
        if token_hits >= 2:
            score += min(token_hits, 3)
        elif token_hits == 1 and len(name_tokens) == 1:
            score += 1

        if target_basename in GENERIC_EXECUTABLE_NAMES and score < 4:
            continue
        if score >= 3:
            matches.append(signal)

    matches.sort(key=lambda item: item.get("last_seen", ""), reverse=True)
    return matches[:20]


def extract_executable_hints(program: InstalledApplication) -> set[str]:
    hints: set[str] = set()
    for value in (program.install_location, program.uninstall_string):
        lowered = normalize_path_text(value)
        for match in re.findall(r"([a-z0-9._-]+\.exe)", lowered):
            if match not in GENERIC_EXECUTABLE_NAMES:
                hints.add(match)
    hints.update(
        f"{token}.exe"
        for token in tokenize_program_name(program.name)
        if len(token) >= 4 and f"{token}.exe" not in GENERIC_EXECUTABLE_NAMES
    )
    return hints


def tokenize_program_name(name: str) -> set[str]:
    tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", name.casefold())
        if len(token) >= 3 and token not in APP_MATCH_STOPWORDS and not token.isdigit()
    }
    return tokens


def normalize_path_text(value: str) -> str:
    return value.strip().replace("/", "\\").casefold()


def normalize_datetime(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def deduplicate_raw_signals(signals: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: dict[tuple[str, str, str], dict[str, str]] = {}
    for signal in signals:
        key = (
            signal.get("source", ""),
            normalize_path_text(signal.get("target_path", "")),
            normalize_path_text(signal.get("signal_path", "")),
        )
        current = deduped.get(key)
        if current is None or signal.get("last_seen", "") > current.get("last_seen", ""):
            deduped[key] = signal
    return list(deduped.values())


def unique_join(values) -> str:
    unique_values: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if normalized and normalized not in unique_values:
            unique_values.append(normalized)
    return ",".join(unique_values)


def write_program_usage_report(entries: list[ProgramUsageSignalEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "program_usage_signals.csv"
    with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=USAGE_SIGNAL_HEADERS)
        writer.writeheader()
        for entry in entries:
            writer.writerow(asdict(entry))
    return output_path
