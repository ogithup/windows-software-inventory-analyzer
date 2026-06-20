from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path

from src.windows_software_inventory_analyzer.models import CleanupSimulationEntry


CLEANUP_SIMULATION_HEADERS = (
    "simulation_name",
    "selected_software",
    "total_reclaim_bytes",
    "total_reclaim_human",
    "affected_projects_count",
    "affected_projects",
    "affected_system_families",
    "risk_tier",
    "summary",
)


def build_cleanup_simulation(
    selected_names: list[str],
    removal_decisions: list[dict[str, str]],
    simulation_name: str = "manual-selection",
) -> CleanupSimulationEntry:
    selected_keys = {name.strip().casefold() for name in selected_names if name.strip()}
    selected_rows = [row for row in removal_decisions if row.get("software_name", "").strip().casefold() in selected_keys]
    reclaim_bytes = sum(safe_int(row.get("if_removed_frees_space_bytes", "0")) for row in selected_rows)
    affected_projects = sorted(
        {
            project.strip()
            for row in selected_rows
            for project in row.get("matched_projects", "").split(",")
            if project.strip()
        },
        key=str.casefold,
    )
    affected_families = sorted({row.get("family_type", "") for row in selected_rows if row.get("family_type", "")}, key=str.casefold)
    highest_risk = max((safe_float(row.get("removal_risk_score", "0")) for row in selected_rows), default=0.0)
    risk_tier = derive_risk_tier(highest_risk, affected_projects_count=len(affected_projects), family_count=len(affected_families))
    summary = build_summary(selected_rows, reclaim_bytes, affected_projects, affected_families, risk_tier)
    return CleanupSimulationEntry(
        simulation_name=simulation_name,
        selected_software=", ".join(row.get("software_name", "") for row in selected_rows),
        total_reclaim_bytes=reclaim_bytes,
        total_reclaim_human=format_size(reclaim_bytes),
        affected_projects_count=len(affected_projects),
        affected_projects=", ".join(affected_projects) or "-",
        affected_system_families=", ".join(affected_families) or "-",
        risk_tier=risk_tier,
        summary=summary,
    )


def write_cleanup_simulation(entry: CleanupSimulationEntry, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "cleanup_simulation.csv"
    with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CLEANUP_SIMULATION_HEADERS)
        writer.writeheader()
        writer.writerow(asdict(entry))
    return output_path


def derive_risk_tier(highest_risk: float, affected_projects_count: int, family_count: int) -> str:
    if highest_risk >= 85 or affected_projects_count >= 4:
        return "CRITICAL"
    if highest_risk >= 70 or affected_projects_count >= 2 or family_count >= 3:
        return "HIGH"
    if highest_risk >= 45 or affected_projects_count >= 1:
        return "MEDIUM"
    return "LOW"


def build_summary(
    selected_rows: list[dict[str, str]],
    reclaim_bytes: int,
    affected_projects: list[str],
    affected_families: list[str],
    risk_tier: str,
) -> str:
    software_count = len(selected_rows)
    if not selected_rows:
        return "Secili program bulunamadi."
    return (
        f"{software_count} arac secildi. Yaklasik {format_size(reclaim_bytes)} alan kazanilabilir. "
        f"Etkilenebilecek proje sayisi: {len(affected_projects)}. Sistem aileleri: {', '.join(affected_families) or '-'}. "
        f"Genel risk seviyesi: {risk_tier}."
    )


def safe_int(value: str) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


def safe_float(value: str) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0


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
