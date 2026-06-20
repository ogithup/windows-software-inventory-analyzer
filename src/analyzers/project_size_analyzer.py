from __future__ import annotations

import csv
import os
from dataclasses import asdict
from pathlib import Path

from src.windows_software_inventory_analyzer.models import ProjectSizeReportEntry, ProjectStorageBreakdownEntry


GENERATED_DIR_MARKERS = {
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".gradle",
    "dist",
    "build",
    "bin",
    "obj",
    ".next",
    ".nuxt",
    ".mypy_cache",
    ".pytest_cache",
}


def analyze_project_sizes(project_rows: list[dict[str, str]]) -> tuple[list[ProjectSizeReportEntry], list[ProjectStorageBreakdownEntry]]:
    reports: list[ProjectSizeReportEntry] = []
    breakdowns: list[ProjectStorageBreakdownEntry] = []

    for row in project_rows:
        path_text = row.get("path", "").strip()
        project_name = row.get("project_name", "").strip()
        if not path_text or not project_name:
            continue
        project_path = Path(path_text)
        if not project_path.exists():
            continue
        total_size, breakdown_map = scan_project_storage(project_path)
        generated_size = sum(size for key, size in breakdown_map.items() if key in GENERATED_DIR_MARKERS)
        source_core_size = max(0, total_size - generated_size)
        recoverable_ratio = round((generated_size / total_size) * 100, 2) if total_size else 0.0
        active_project_risk = infer_project_risk(row, total_size, recoverable_ratio)

        reports.append(
            ProjectSizeReportEntry(
                project_name=project_name,
                path=path_text,
                total_size_bytes=total_size,
                total_size_human=format_size(total_size),
                generated_artifact_size_bytes=generated_size,
                generated_artifact_size_human=format_size(generated_size),
                source_core_size_bytes=source_core_size,
                source_core_size_human=format_size(source_core_size),
                recoverable_ratio=recoverable_ratio,
                active_project_risk=active_project_risk,
            )
        )

        for segment_name, size_bytes in sorted(breakdown_map.items(), key=lambda item: item[1], reverse=True)[:20]:
            segment_type = "generated_artifact" if segment_name in GENERATED_DIR_MARKERS else "project_segment"
            breakdowns.append(
                ProjectStorageBreakdownEntry(
                    project_name=project_name,
                    path=path_text,
                    segment_name=segment_name,
                    segment_type=segment_type,
                    size_bytes=size_bytes,
                    size_human=format_size(size_bytes),
                    recoverable="yes" if segment_type == "generated_artifact" else "no",
                )
            )

    reports.sort(key=lambda item: item.total_size_bytes, reverse=True)
    breakdowns.sort(key=lambda item: (item.project_name.casefold(), -item.size_bytes))
    return reports, breakdowns


def scan_project_storage(project_path: Path) -> tuple[int, dict[str, int]]:
    total_size = 0
    breakdown_map: dict[str, int] = {}
    try:
        with os.scandir(project_path) as iterator:
            for entry in iterator:
                entry_path = Path(entry.path)
                size_bytes = calculate_path_size(entry_path)
                total_size += size_bytes
                breakdown_map[entry.name] = size_bytes
    except OSError:
        return 0, {}
    return total_size, breakdown_map


def calculate_path_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0

    total_size = 0
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                entry_path = Path(entry.path)
                if entry.is_file(follow_symlinks=False):
                    try:
                        total_size += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
                elif entry.is_dir(follow_symlinks=False):
                    total_size += calculate_path_size(entry_path)
    except OSError:
        return total_size
    return total_size


def infer_project_risk(project_row: dict[str, str], total_size: int, recoverable_ratio: float) -> str:
    technologies = project_row.get("detected_technologies", "").casefold()
    if ".net" in technologies or "python" in technologies or "docker" in technologies:
        if total_size >= 5 * 1024**3:
            return "high"
        if recoverable_ratio >= 40:
            return "medium"
    return "low"


def write_project_size_reports(
    reports: list[ProjectSizeReportEntry],
    breakdowns: list[ProjectStorageBreakdownEntry],
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "project_size_report.csv"
    breakdown_path = output_dir / "project_storage_breakdown.csv"

    with report_path.open("w", encoding="utf-8-sig", newline="") as report_file:
        writer = csv.DictWriter(
            report_file,
            fieldnames=(
                "project_name",
                "path",
                "total_size_bytes",
                "total_size_human",
                "generated_artifact_size_bytes",
                "generated_artifact_size_human",
                "source_core_size_bytes",
                "source_core_size_human",
                "recoverable_ratio",
                "active_project_risk",
            ),
        )
        writer.writeheader()
        for entry in reports:
            writer.writerow(asdict(entry))

    with breakdown_path.open("w", encoding="utf-8-sig", newline="") as breakdown_file:
        writer = csv.DictWriter(
            breakdown_file,
            fieldnames=(
                "project_name",
                "path",
                "segment_name",
                "segment_type",
                "size_bytes",
                "size_human",
                "recoverable",
            ),
        )
        writer.writeheader()
        for entry in breakdowns:
            writer.writerow(asdict(entry))

    return report_path, breakdown_path


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
