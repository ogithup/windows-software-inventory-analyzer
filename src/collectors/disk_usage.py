from __future__ import annotations

import csv
import logging
import os
import stat
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from src.windows_software_inventory_analyzer.models import DeveloperCacheEntry, DiskUsageEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.collectors.disk_usage")

DISK_USAGE_HEADERS = (
    "path",
    "scan_root",
    "depth",
    "size_bytes",
    "size_human",
    "category",
    "risk",
)

DEVELOPER_CACHE_HEADERS = (
    "path",
    "scan_root",
    "depth",
    "size_bytes",
    "size_human",
    "cache_type",
    "risk",
)

DEVELOPER_CACHE_MARKERS = {
    "node_modules": "node_modules",
    ".venv": "python_virtualenv",
    "venv": "python_virtualenv",
    "env": "python_virtualenv",
    "__pycache__": "python_bytecode_cache",
    ".gradle": "gradle_cache",
    ".m2": "maven_cache",
    ".npm": "npm_cache",
    "npm-cache": "npm_cache",
    ".docker": "docker_cache",
}

SYSTEM_RISK_PREFIXES = (
    Path(r"C:\Windows"),
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),
    Path(r"C:\ProgramData"),
)


def collect_disk_usage(
    roots: Iterable[Path],
    exclude_paths: Iterable[Path],
    max_depth: int,
) -> tuple[list[DiskUsageEntry], list[DeveloperCacheEntry]]:
    normalized_excludes = {normalize_path(path) for path in exclude_paths}
    normalized_roots = normalize_scan_roots(roots)
    disk_entries: list[DiskUsageEntry] = []
    cache_entries: list[DeveloperCacheEntry] = []

    for normalized_root in normalized_roots:
        if not normalized_root.exists():
            LOGGER.info("Disk usage root does not exist, skipping: %s", normalized_root)
            continue

        LOGGER.info("Scanning disk usage root: %s", normalized_root)
        scan_directory(
            path=normalized_root,
            scan_root=normalized_root,
            depth=0,
            max_depth=max_depth,
            exclude_paths=normalized_excludes,
            disk_entries=disk_entries,
            cache_entries=cache_entries,
        )

    disk_entries.sort(key=lambda item: item.size_bytes, reverse=True)
    cache_entries.sort(key=lambda item: item.size_bytes, reverse=True)
    return disk_entries, deduplicate_caches(cache_entries)


def normalize_scan_roots(roots: Iterable[Path]) -> list[Path]:
    unique_roots: list[Path] = []
    for root in sorted((normalize_path(root) for root in roots), key=lambda item: len(str(item))):
        lower_root = str(root).casefold()
        if any(lower_root == str(existing).casefold() or lower_root.startswith(f"{str(existing).casefold()}\\") for existing in unique_roots):
            LOGGER.info("Skipping nested disk usage root because parent root is already included: %s", root)
            continue
        unique_roots.append(root)
    return unique_roots


def scan_directory(
    path: Path,
    scan_root: Path,
    depth: int,
    max_depth: int,
    exclude_paths: set[Path],
    disk_entries: list[DiskUsageEntry],
    cache_entries: list[DeveloperCacheEntry],
) -> int:
    normalized_path = normalize_path(path)
    if should_skip_path(normalized_path, exclude_paths):
        LOGGER.debug("Skipping excluded path: %s", normalized_path)
        return 0

    total_size = 0
    child_directories: list[Path] = []

    try:
        with os.scandir(normalized_path) as iterator:
            for entry in iterator:
                entry_path = Path(entry.path)

                try:
                    if is_reparse_point(entry):
                        continue

                    if entry.is_file(follow_symlinks=False):
                        total_size += entry.stat(follow_symlinks=False).st_size
                        continue

                    if entry.is_dir(follow_symlinks=False):
                        child_directories.append(entry_path)
                except OSError as error:
                    LOGGER.debug("Skipping entry %s: %s", entry_path, error)
    except OSError as error:
        LOGGER.debug("Unable to scan directory %s: %s", normalized_path, error)
        return 0

    for child_path in child_directories:
        total_size += scan_directory(
            path=child_path,
            scan_root=scan_root,
            depth=depth + 1,
            max_depth=max_depth,
            exclude_paths=exclude_paths,
            disk_entries=disk_entries,
            cache_entries=cache_entries,
        )

    if depth <= max_depth:
        disk_entries.append(
            DiskUsageEntry(
                path=str(normalized_path),
                scan_root=str(scan_root),
                depth=depth,
                size_bytes=total_size,
                size_human=format_size(total_size),
                category=categorize_path(normalized_path),
                risk=assess_risk(normalized_path),
            )
        )

    cache_type = detect_developer_cache(normalized_path)
    if cache_type:
        cache_entries.append(
            DeveloperCacheEntry(
                path=str(normalized_path),
                scan_root=str(scan_root),
                depth=depth,
                size_bytes=total_size,
                size_human=format_size(total_size),
                cache_type=cache_type,
                risk=assess_risk(normalized_path),
            )
        )

    return total_size


def normalize_path(path: Path) -> Path:
    expanded = Path(os.path.expandvars(str(path))).expanduser()
    try:
        return expanded.resolve(strict=False)
    except OSError:
        return expanded


def should_skip_path(path: Path, exclude_paths: set[Path]) -> bool:
    lower_path = str(path).casefold()
    return any(lower_path == str(excluded).casefold() or lower_path.startswith(f"{str(excluded).casefold()}\\") for excluded in exclude_paths)


def detect_developer_cache(path: Path) -> str:
    folder_name = path.name.casefold()
    if folder_name in DEVELOPER_CACHE_MARKERS:
        return DEVELOPER_CACHE_MARKERS[folder_name]

    full_path = str(path).casefold()
    if "\\pip\\cache" in full_path:
        return "pip_cache"
    if "\\docker\\windowsfilter" in full_path or "\\docker\\wsl" in full_path:
        return "docker_cache"
    if "\\.gradle\\caches" in full_path or "\\.android\\cache" in full_path:
        return "android_gradle_cache"
    return ""


def categorize_path(path: Path) -> str:
    folder_name = path.name.casefold()
    if detect_developer_cache(path):
        return "developer_cache"
    if "users" in {part.casefold() for part in path.parts}:
        return "user_data"
    if folder_name in {"program files", "program files (x86)"}:
        return "installed_programs"
    if folder_name == "appdata":
        return "application_data"
    return "directory"


def assess_risk(path: Path) -> str:
    normalized = normalize_path(path)
    lower_path = str(normalized).casefold()
    for prefix in SYSTEM_RISK_PREFIXES:
        prefix_text = str(prefix).casefold()
        if lower_path == prefix_text or lower_path.startswith(f"{prefix_text}\\"):
            return "manual_review"
    return "review"


def is_reparse_point(entry: os.DirEntry[str]) -> bool:
    try:
        attributes = entry.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def format_size(size_bytes: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(size_bytes)
    unit = units[0]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024
    if unit == "B":
        return f"{int(size)} {unit}"
    return f"{size:.2f} {unit}"


def deduplicate_caches(entries: list[DeveloperCacheEntry]) -> list[DeveloperCacheEntry]:
    unique: dict[str, DeveloperCacheEntry] = {}
    for entry in entries:
        unique[entry.path.casefold()] = entry
    return sorted(unique.values(), key=lambda item: item.size_bytes, reverse=True)


def write_disk_usage_reports(
    disk_entries: list[DiskUsageEntry],
    cache_entries: list[DeveloperCacheEntry],
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    disk_usage_path = output_dir / "disk_usage.csv"
    developer_caches_path = output_dir / "developer_caches.csv"

    with disk_usage_path.open("w", encoding="utf-8-sig", newline="") as disk_usage_file:
        writer = csv.DictWriter(disk_usage_file, fieldnames=DISK_USAGE_HEADERS)
        writer.writeheader()
        for entry in disk_entries:
            writer.writerow(asdict(entry))

    with developer_caches_path.open("w", encoding="utf-8-sig", newline="") as developer_caches_file:
        writer = csv.DictWriter(developer_caches_file, fieldnames=DEVELOPER_CACHE_HEADERS)
        writer.writeheader()
        for entry in cache_entries:
            writer.writerow(asdict(entry))

    return disk_usage_path, developer_caches_path
