from __future__ import annotations

import csv
import json
import logging
import re
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Iterator

try:
    import winreg
except ModuleNotFoundError:  # pragma: no cover - non-Windows fallback
    winreg = None

from src.windows_software_inventory_analyzer.models import InstalledApplication


LOGGER = logging.getLogger("windows_software_inventory_analyzer.collectors.installed_apps")

REGISTRY_UNINSTALL_PATHS = (
    (
        getattr(winreg, "HKEY_LOCAL_MACHINE", None),
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        getattr(winreg, "KEY_READ", 0) | getattr(winreg, "KEY_WOW64_64KEY", 0),
    ),
    (
        getattr(winreg, "HKEY_LOCAL_MACHINE", None),
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        getattr(winreg, "KEY_READ", 0) | getattr(winreg, "KEY_WOW64_32KEY", 0),
    ),
    (
        getattr(winreg, "HKEY_CURRENT_USER", None),
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        getattr(winreg, "KEY_READ", 0),
    ),
)

CSV_HEADERS = (
    "name",
    "version",
    "publisher",
    "install_location",
    "uninstall_string",
    "source",
)


def collect_installed_applications() -> list[InstalledApplication]:
    winget_apps = collect_from_winget()
    if winget_apps:
        LOGGER.info("Collected %s installed applications from winget.", len(winget_apps))
    else:
        LOGGER.warning("Winget collection returned no records. Falling back to registry only.")

    registry_apps = collect_from_registry()
    LOGGER.info("Collected %s installed applications from registry.", len(registry_apps))

    combined = deduplicate_applications([*winget_apps, *registry_apps])
    LOGGER.info("Normalized down to %s unique installed applications.", len(combined))
    return combined


def collect_from_winget() -> list[InstalledApplication]:
    winget_executable = shutil.which("winget")
    if winget_executable is None:
        LOGGER.warning("winget executable was not found on PATH.")
        return []

    commands = (
        [winget_executable, "list", "--disable-interactivity", "--accept-source-agreements", "--source", "winget"],
        [winget_executable, "list", "--disable-interactivity", "--accept-source-agreements"],
    )

    results: list[InstalledApplication] = []
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as error:
            LOGGER.warning("winget command could not be executed: %s", error)
            return []

        if completed.returncode != 0:
            LOGGER.warning("winget command failed (%s): %s", completed.returncode, completed.stderr.strip())
            continue

        parsed = parse_winget_output(completed.stdout)
        if parsed:
            results.extend(parsed)

    return deduplicate_applications(results)


def parse_winget_output(output: str) -> list[InstalledApplication]:
    lines = [line.rstrip("\n") for line in output.splitlines() if line.strip()]
    header_index = find_header_index(lines)
    if header_index is None or header_index + 1 >= len(lines):
        return []

    header_line = lines[header_index]
    divider_line = lines[header_index + 1]
    if not set(divider_line.strip()).issubset({"-", " "}):
        return []

    columns = extract_header_columns(header_line)
    parsed: list[InstalledApplication] = []

    for raw_line in lines[header_index + 2 :]:
        if set(raw_line.strip()).issubset({"-", " "}):
            continue

        values = slice_row_by_columns(raw_line, columns)
        if (
            not values.get("version", "").strip()
            or not values.get("source", "").strip()
            or " " in values.get("version", "").strip()
        ):
            values = fallback_parse_winget_row(raw_line, values)
        name = normalize_text(values.get("name", ""))
        version = normalize_text(values.get("version", ""))
        source = normalize_text(values.get("source", "")) or "winget"
        if not name:
            continue

        parsed.append(
            InstalledApplication(
                name=name,
                version=version,
                publisher="",
                install_location="",
                uninstall_string="",
                source=source,
            )
        )

    return parsed


def find_header_index(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        lowered = line.lower()
        if "name" in lowered and "version" in lowered:
            return index
    return None


def extract_header_columns(header_line: str) -> list[tuple[str, int, int | None]]:
    matches = list(re.finditer(r"\S(?:.*?\S)?(?=\s{2,}|$)", header_line))
    columns: list[tuple[str, int, int | None]] = []
    for position, match in enumerate(matches):
        title = match.group(0).strip().lower().replace(" ", "_")
        start = match.start()
        end = matches[position + 1].start() if position + 1 < len(matches) else None
        columns.append((title, start, end))
    return columns


def slice_row_by_columns(row: str, columns: list[tuple[str, int, int | None]]) -> dict[str, str]:
    values: dict[str, str] = {}
    for title, start, end in columns:
        values[title] = row[start:end].strip() if end is not None else row[start:].strip()
    return values


def fallback_parse_winget_row(row: str, values: dict[str, str]) -> dict[str, str]:
    tokens = row.split()
    if len(tokens) < 4:
        return values

    fallback = dict(values)
    fallback["source"] = tokens[-1]
    fallback["version"] = tokens[-2]
    fallback["id"] = tokens[-3]
    fallback["name"] = " ".join(tokens[:-3])
    return fallback


def collect_from_registry() -> list[InstalledApplication]:
    if winreg is None:
        LOGGER.info("Registry collection is not available outside Windows.")
        return []

    applications: list[InstalledApplication] = []
    for hive, uninstall_path, access in REGISTRY_UNINSTALL_PATHS:
        if hive is None:
            continue
        applications.extend(iter_registry_applications(hive, uninstall_path, access))
    return deduplicate_applications(applications)


def iter_registry_applications(hive: int, uninstall_path: str, access: int) -> Iterator[InstalledApplication]:
    try:
        with winreg.OpenKey(hive, uninstall_path, 0, access) as root_key:
            subkey_count, _, _ = winreg.QueryInfoKey(root_key)
            for index in range(subkey_count):
                subkey_name = winreg.EnumKey(root_key, index)
                with open_registry_subkey(root_key, subkey_name, access) as app_key:
                    if app_key is None:
                        continue

                    name = normalize_text(read_registry_value(app_key, "DisplayName"))
                    if not name:
                        continue

                    uninstall_string = normalize_text(
                        read_registry_value(app_key, "QuietUninstallString")
                        or read_registry_value(app_key, "UninstallString")
                    )

                    yield InstalledApplication(
                        name=name,
                        version=normalize_text(read_registry_value(app_key, "DisplayVersion")),
                        publisher=normalize_text(read_registry_value(app_key, "Publisher")),
                        install_location=normalize_text(read_registry_value(app_key, "InstallLocation")),
                        uninstall_string=uninstall_string,
                        source="registry",
                    )
    except FileNotFoundError:
        LOGGER.info("Registry uninstall path not available for this view: %s", uninstall_path)
    except OSError as error:
        LOGGER.warning("Failed reading registry uninstall path %s: %s", uninstall_path, error)


class open_registry_subkey:
    def __init__(self, root_key: winreg.HKEYType, subkey_name: str, access: int) -> None:
        self.root_key = root_key
        self.subkey_name = subkey_name
        self.access = access
        self.handle: winreg.HKEYType | None = None

    def __enter__(self) -> winreg.HKEYType | None:
        try:
            self.handle = winreg.OpenKey(self.root_key, self.subkey_name, 0, self.access)
        except OSError as error:
            LOGGER.debug("Skipping registry subkey %s: %s", self.subkey_name, error)
            self.handle = None
        return self.handle

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handle is not None:
            winreg.CloseKey(self.handle)


def read_registry_value(app_key: winreg.HKEYType, value_name: str) -> str:
    try:
        value, _ = winreg.QueryValueEx(app_key, value_name)
    except FileNotFoundError:
        return ""
    except OSError as error:
        LOGGER.debug("Failed reading registry value %s: %s", value_name, error)
        return ""
    return str(value)


def normalize_text(value: str) -> str:
    return " ".join(value.strip().split())


def deduplicate_applications(applications: Iterable[InstalledApplication]) -> list[InstalledApplication]:
    deduplicated: dict[tuple[str, str, str], InstalledApplication] = {}

    for application in applications:
        normalized = normalize_application(application)
        if not normalized.name:
            continue

        key = (
            normalized.name.casefold(),
            normalized.version.casefold(),
            normalized.publisher.casefold(),
        )
        if key not in deduplicated:
            deduplicated[key] = normalized
            continue

        deduplicated[key] = merge_applications(deduplicated[key], normalized)

    return sorted(deduplicated.values(), key=lambda item: (item.name.casefold(), item.version.casefold()))


def normalize_application(application: InstalledApplication) -> InstalledApplication:
    return InstalledApplication(
        name=normalize_text(application.name),
        version=normalize_text(application.version),
        publisher=normalize_text(application.publisher),
        install_location=normalize_text(application.install_location),
        uninstall_string=normalize_text(application.uninstall_string),
        source=normalize_text(application.source),
    )


def merge_applications(left: InstalledApplication, right: InstalledApplication) -> InstalledApplication:
    return InstalledApplication(
        name=left.name or right.name,
        version=pick_preferred_value(left.version, right.version),
        publisher=pick_preferred_value(left.publisher, right.publisher),
        install_location=pick_preferred_value(left.install_location, right.install_location),
        uninstall_string=pick_preferred_value(left.uninstall_string, right.uninstall_string),
        source=merge_sources(left.source, right.source),
    )


def pick_preferred_value(left: str, right: str) -> str:
    if left and not right:
        return left
    if right and not left:
        return right
    if len(right) > len(left):
        return right
    return left


def merge_sources(left: str, right: str) -> str:
    parts = []
    for source in (left, right):
        for item in source.split(","):
            normalized = normalize_text(item)
            if normalized and normalized not in parts:
                parts.append(normalized)
    return ",".join(parts)


def write_installed_application_reports(applications: list[InstalledApplication], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "installed_programs.json"
    csv_path = output_dir / "installed_programs.csv"

    json_payload = [asdict(application) for application in applications]
    json_path.write_text(
        json.dumps(json_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    with csv_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for application in applications:
            writer.writerow(asdict(application))

    return json_path, csv_path
