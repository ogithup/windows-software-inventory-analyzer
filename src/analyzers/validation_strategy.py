from __future__ import annotations

from pathlib import Path

from src.analyzers.project_rebuild_validator import (
    validate_java_project,
    validate_node_project,
    validate_python_project,
    write_validation_status_report,
)
from src.windows_software_inventory_analyzer.models import ValidationStatusEntry


def build_validation_status(
    project_rows: list[dict[str, str]],
    sdk_validation_rows: list[dict[str, str]],
    artifacts_root: Path,
    dry_run: bool = False,
) -> list[ValidationStatusEntry]:
    entries: list[ValidationStatusEntry] = []
    seen_project_family: set[tuple[str, str]] = set()

    for row in sdk_validation_rows:
        project_name = row.get("project_name", "")
        if not project_name:
            continue
        status = row.get("build_status", "")
        validation_level = "BUILD_VERIFIED" if status == "BUILD_PASSED" else "STATIC_ONLY"
        confidence_boost = 14.0 if status == "BUILD_PASSED" else 0.0
        entries.append(
            ValidationStatusEntry(
                project_name=project_name,
                project_path=row.get("target_path", ""),
                technology_family="dotnet",
                validation_level=validation_level,
                validation_status=status or "DISCOVERED_ONLY",
                command_used=row.get("validation_mode", ""),
                validation_target=row.get("target_path", ""),
                confidence_boost=confidence_boost,
                notes=row.get("notes", ""),
            )
        )
        seen_project_family.add((project_name.casefold(), "dotnet"))

    for project_row in project_rows:
        project_name = project_row.get("project_name", "")
        technologies = {item.strip().casefold() for item in project_row.get("detected_technologies", "").split(",") if item.strip()}
        important_files = {item.strip().casefold() for item in project_row.get("important_files", "").split(",") if item.strip()}
        validators: list[str] = []
        if "python" in technologies or {"requirements.txt", "pyproject.toml", "environment.yml"} & important_files:
            validators.append("python")
        if "nodejs" in technologies or "package.json" in important_files:
            validators.append("node")
        if {"java-maven", "java-gradle"} & technologies or {"pom.xml", "build.gradle", "build.gradle.kts"} & important_files:
            validators.append("java")
        for family in validators:
            identity = (project_name.casefold(), family)
            if identity in seen_project_family:
                continue
            seen_project_family.add(identity)
            if family == "python":
                entries.append(validate_python_project(project_row, artifacts_root, dry_run=dry_run))
            elif family == "node":
                entries.append(validate_node_project(project_row, artifacts_root, dry_run=dry_run))
            elif family == "java":
                entries.append(validate_java_project(project_row, artifacts_root, dry_run=dry_run))

    entries.sort(key=lambda item: (item.project_name.casefold(), item.technology_family))
    return entries


__all__ = ["build_validation_status", "write_validation_status_report"]
