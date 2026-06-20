from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path

from src.windows_software_inventory_analyzer.models import SystemToolImpactEntry, SystemToolReportEntry


SYSTEM_TOOL_REPORT_HEADERS = (
    "family",
    "family_label",
    "installed_count",
    "keep_versions",
    "candidate_versions",
    "duplicate_status",
    "ide_dependency_status",
    "build_status",
    "validation_level",
    "affected_projects",
    "advice",
)

SYSTEM_TOOL_IMPACT_HEADERS = (
    "family",
    "software_name",
    "installed_version",
    "decision_label",
    "validation_level",
    "duplicate_summary",
    "build_status",
    "ide_dependency_status",
    "affected_projects",
    "impact_scope",
    "next_action",
)


def build_system_tools_reports(
    runtime_family_summaries: list[dict[str, str]],
    runtime_family_details: dict[str, list[dict[str, str]]],
    removal_decisions: list[dict[str, str]],
    validation_rows: list[dict[str, str]],
    sdk_validation_rows: list[dict[str, str]],
) -> tuple[list[SystemToolReportEntry], list[SystemToolImpactEntry]]:
    validation_index = build_validation_index(validation_rows)
    family_validation_levels = build_family_validation_levels(validation_rows)
    build_statuses = {row.get("build_status", "") for row in sdk_validation_rows if row.get("build_status", "")}
    family_reports: list[SystemToolReportEntry] = []
    impact_rows: list[SystemToolImpactEntry] = []

    for summary in runtime_family_summaries:
        family_label = summary.get("family", "")
        family_key = family_key_from_label(family_label)
        detail_rows = runtime_family_details.get(family_key, [])
        family_removals = [row for row in removal_decisions if row.get("family_type", "") == family_key]
        affected_projects = sorted({row.get("matched_projects", "") for row in family_removals if row.get("matched_projects", "")})
        validation_levels = sorted(
            {family_validation_levels.get(family_to_validation_family(family_key), "")} - {""}
        )
        duplicate_status = "duplicate_variants_found" if any(row.get("suggestion", "") == "OLDER_VERSION" for row in detail_rows) else "no_clear_duplicate"
        ide_dependency_status = "ide_signals_present" if family_key in {"dotnet_sdk", "windows_sdk"} and affected_projects else "no_strong_ide_signal"
        build_status = ", ".join(sorted(build_statuses)) if family_key == "dotnet_sdk" and build_statuses else "static_only"
        family_reports.append(
            SystemToolReportEntry(
                family=family_key,
                family_label=family_label,
                installed_count=safe_int(summary.get("installed_count", "0")),
                keep_versions=summary.get("keep_versions", ""),
                candidate_versions=summary.get("older_versions", ""),
                duplicate_status=duplicate_status,
                ide_dependency_status=ide_dependency_status,
                build_status=build_status,
                validation_level=", ".join(validation_levels) or "STATIC_ONLY",
                affected_projects=" | ".join(affected_projects[:10]) or "-",
                advice=summary.get("advice", ""),
            )
        )

    for row in removal_decisions:
        family_key = row.get("family_type", "")
        if family_key not in {"dotnet_sdk", "dotnet_runtime", "aspnet_runtime", "windows_sdk", "visual_cpp", "gpu_driver", "dotnet_native", "runtime_system"}:
            continue
        validation = validation_index.get(row.get("software_name", "").casefold(), {})
        impact_rows.append(
            SystemToolImpactEntry(
                family=family_key,
                software_name=row.get("software_name", ""),
                installed_version=row.get("installed_version", ""),
                decision_label=row.get("decision_label", ""),
                validation_level=family_validation_levels.get(family_to_validation_family(family_key), validation.get("validation_level", "STATIC_ONLY")),
                duplicate_summary=row.get("duplicate_summary", ""),
                build_status=validation.get("validation_status", row.get("test_summary", "")),
                ide_dependency_status="ide_related" if row.get("affected_projects_count", "0") not in {"", "0"} else "no_project_signal",
                affected_projects=row.get("matched_projects", "") or "-",
                impact_scope=row.get("impact_scope", ""),
                next_action=row.get("recommended_next_action", ""),
            )
        )

    family_reports.sort(key=lambda item: item.family_label.casefold())
    impact_rows.sort(key=lambda item: (item.family.casefold(), item.software_name.casefold()))
    return family_reports, impact_rows


def write_system_tools_reports(
    family_reports: list[SystemToolReportEntry],
    impact_rows: list[SystemToolImpactEntry],
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "system_tools_report.csv"
    impact_path = output_dir / "system_tool_impact_report.csv"

    with report_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=SYSTEM_TOOL_REPORT_HEADERS)
        writer.writeheader()
        for entry in family_reports:
            writer.writerow(asdict(entry))

    with impact_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=SYSTEM_TOOL_IMPACT_HEADERS)
        writer.writeheader()
        for entry in impact_rows:
            writer.writerow(asdict(entry))

    return report_path, impact_path


def build_validation_index(validation_rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in validation_rows:
        project_name = row.get("project_name", "").strip()
        family = row.get("technology_family", "").strip()
        if not project_name or not family:
            continue
        index.setdefault(project_name.casefold(), row)
    return index


def build_family_validation_levels(validation_rows: list[dict[str, str]]) -> dict[str, str]:
    rank = {"STATIC_ONLY": 1, "BUILD_VERIFIED": 2, "ISOLATED_REINSTALL_VERIFIED": 3}
    levels: dict[str, str] = {}
    for row in validation_rows:
        family = row.get("technology_family", "").strip()
        level = row.get("validation_level", "").strip() or "STATIC_ONLY"
        if not family:
            continue
        current = levels.get(family, "STATIC_ONLY")
        if rank.get(level, 0) >= rank.get(current, 0):
            levels[family] = level
    return levels


def family_to_validation_family(family_key: str) -> str:
    if family_key in {"dotnet_sdk", "dotnet_runtime", "aspnet_runtime", "windows_sdk", "dotnet_native"}:
        return "dotnet"
    return family_key


def family_key_from_label(label: str) -> str:
    lowered = label.casefold()
    if ".net sdk" in lowered:
        return "dotnet_sdk"
    if "asp.net" in lowered:
        return "aspnet_runtime"
    if ".net runtime" in lowered:
        return "dotnet_runtime"
    if "windows sdk" in lowered:
        return "windows_sdk"
    if "visual c++" in lowered:
        return "visual_cpp"
    if "gpu" in lowered or "driver" in lowered:
        return "gpu_driver"
    if ".net native" in lowered:
        return "dotnet_native"
    return "runtime_system"


def safe_int(value: str) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0
