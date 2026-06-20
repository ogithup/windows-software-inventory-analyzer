from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path

from src.windows_software_inventory_analyzer.models import (
    DeveloperCacheEntry,
    DiskCleanupScenarioEntry,
    DiskUsageEntry,
    DiskZoneReportEntry,
)


DISK_ZONE_HEADERS = (
    "path",
    "scan_root",
    "category",
    "risk",
    "size_bytes",
    "size_human",
    "recoverable_space_bytes",
    "recoverable_space_human",
    "rebuildability",
    "active_project_related",
    "top_subpaths",
    "recommended_action",
    "cleanup_summary",
)

DISK_SCENARIO_HEADERS = (
    "path",
    "scenario_type",
    "estimated_reclaim_bytes",
    "estimated_reclaim_human",
    "risk_level",
    "recommended_action",
    "explanation",
)


def analyze_disk_zones(
    disk_entries: list[DiskUsageEntry],
    cache_entries: list[DeveloperCacheEntry],
    project_rows: list[dict[str, str]],
) -> tuple[list[DiskZoneReportEntry], list[DiskCleanupScenarioEntry]]:
    project_paths = {normalize_path(row.get("path", "")) for row in project_rows if row.get("path", "").strip()}
    cache_by_path = {normalize_path(entry.path): entry for entry in cache_entries}
    children_map = build_children_map(disk_entries)

    zone_entries: list[DiskZoneReportEntry] = []
    scenario_entries: list[DiskCleanupScenarioEntry] = []

    for entry in sorted(disk_entries, key=lambda item: item.size_bytes, reverse=True):
        if entry.depth > 1:
            continue
        normalized = normalize_path(entry.path)
        zone_category = classify_zone(entry.path, entry.category)
        active_project_related = "yes" if is_project_related(normalized, project_paths) else "no"
        rebuildability = infer_rebuildability(zone_category)
        recoverable_space = estimate_recoverable_space(entry, zone_category, cache_by_path)
        top_subpaths = ",".join(child.path for child in children_map.get(normalized, [])[:5])
        recommended_action, cleanup_summary = build_zone_guidance(
            zone_category=zone_category,
            recoverable_space_bytes=recoverable_space,
            active_project_related=active_project_related == "yes",
            risk=entry.risk,
            path=entry.path,
        )

        zone_entries.append(
            DiskZoneReportEntry(
                path=entry.path,
                scan_root=entry.scan_root,
                category=zone_category,
                risk=entry.risk,
                size_bytes=entry.size_bytes,
                size_human=entry.size_human,
                recoverable_space_bytes=recoverable_space,
                recoverable_space_human=format_size(recoverable_space),
                rebuildability=rebuildability,
                active_project_related=active_project_related,
                top_subpaths=top_subpaths,
                recommended_action=recommended_action,
                cleanup_summary=cleanup_summary,
            )
        )
        scenario_entries.append(
            DiskCleanupScenarioEntry(
                path=entry.path,
                scenario_type=zone_category,
                estimated_reclaim_bytes=recoverable_space,
                estimated_reclaim_human=format_size(recoverable_space),
                risk_level=entry.risk,
                recommended_action=recommended_action,
                explanation=cleanup_summary,
            )
        )

    return zone_entries, scenario_entries


def build_children_map(disk_entries: list[DiskUsageEntry]) -> dict[str, list[DiskUsageEntry]]:
    entries = sorted(disk_entries, key=lambda item: (normalize_path(item.path), item.depth))
    children_map: dict[str, list[DiskUsageEntry]] = {}
    for entry in entries:
        normalized = normalize_path(entry.path)
        parent = str(Path(normalized).parent).casefold()
        children_map.setdefault(parent, []).append(entry)
    for key in children_map:
        children_map[key].sort(key=lambda item: item.size_bytes, reverse=True)
    return children_map


def classify_zone(path_text: str, category: str) -> str:
    lowered = normalize_path(path_text)
    if "\\windows" in lowered or lowered.endswith(":\\windows"):
        return "system_protected"
    if "epic games" in lowered or "steam" in lowered or "riot games" in lowered:
        return "game_library"
    if any(token in lowered for token in ("node_modules", ".venv", "__pycache__", ".gradle", ".m2", ".npm", "\\docker\\")):
        return "developer_cache"
    if "\\users\\" in lowered and any(token in lowered for token in ("source\\repos", "\\github", "\\projects", "\\workspace")):
        return "project_workspace"
    if "\\program files" in lowered:
        return "toolchain_storage"
    if category == "developer_cache":
        return "developer_cache"
    if "\\users\\" in lowered:
        return "user_storage"
    return "toolchain_storage"


def is_project_related(path_text: str, project_paths: set[str]) -> bool:
    return any(project_path and (path_text.startswith(project_path) or project_path.startswith(path_text)) for project_path in project_paths)


def infer_rebuildability(zone_category: str) -> str:
    return {
        "system_protected": "low",
        "developer_cache": "high",
        "project_workspace": "medium",
        "game_library": "medium",
        "user_storage": "low",
        "toolchain_storage": "medium",
    }.get(zone_category, "low")


def estimate_recoverable_space(
    entry: DiskUsageEntry,
    zone_category: str,
    cache_by_path: dict[str, DeveloperCacheEntry],
) -> int:
    normalized = normalize_path(entry.path)
    if zone_category == "developer_cache":
        return entry.size_bytes
    if zone_category == "project_workspace":
        return int(entry.size_bytes * 0.35)
    if zone_category == "game_library":
        return int(entry.size_bytes * 0.9)
    if zone_category == "toolchain_storage":
        if normalized in cache_by_path:
            return cache_by_path[normalized].size_bytes
        return int(entry.size_bytes * 0.12)
    if zone_category == "user_storage":
        return int(entry.size_bytes * 0.18)
    return 0


def build_zone_guidance(
    zone_category: str,
    recoverable_space_bytes: int,
    active_project_related: bool,
    risk: str,
    path: str,
) -> tuple[str, str]:
    reclaim_human = format_size(recoverable_space_bytes)
    if zone_category == "system_protected":
        return (
            "Koruma",
            f"{path} sistem klasoru gibi gorunuyor. Dogrudan silme senaryosu verme. Ancak icindeki log/temp klasorleri elle incelenebilir.",
        )
    if zone_category == "developer_cache":
        return (
            "Cache temizligi",
            f"Bu alan yeniden uretilebilir cache gibi duruyor. Yaklasik {reclaim_human} alan kazanilabilir.",
        )
    if zone_category == "project_workspace":
        if active_project_related:
            return (
                "Proje ici temizlik",
                f"Bu alan aktif projelerle ilgili gorunuyor. Tam silmek yerine build/cache klasorlerinden yaklasik {reclaim_human} alan acilabilir.",
            )
        return (
            "Eski proje inceleme",
            f"Bu proje alaninin bir kismi yeniden uretilebilir olabilir. Yaklasik {reclaim_human} alan kontrollu temizlikle acilabilir.",
        )
    if zone_category == "game_library":
        return (
            "Oyun kutuphanesi",
            f"Bu klasor oyun kutuphanesi gibi duruyor. Kullanmadigin oyunlar kaldirilirsa yaklasik {reclaim_human} alan acilabilir.",
        )
    if zone_category == "toolchain_storage":
        return (
            "Arac zinciri inceleme",
            f"Bu alan gelistirme araclari veya kurulu uygulamalarla ilgili olabilir. Duplicate surum ve bagimlilik testinden sonra yaklasik {reclaim_human} alan acilabilir.",
        )
    return (
        "Elle inceleme",
        f"Bu alan icin dogrudan silme karari guvenli degil. Once icerik ve kullanim ihtiyaci kontrol edilmeli. Muhtemel acilacak alan: {reclaim_human}.",
    )


def write_disk_zone_reports(
    zone_entries: list[DiskZoneReportEntry],
    scenario_entries: list[DiskCleanupScenarioEntry],
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    zone_path = output_dir / "disk_zone_report.csv"
    scenario_path = output_dir / "disk_cleanup_scenarios.csv"

    with zone_path.open("w", encoding="utf-8-sig", newline="") as zone_file:
        writer = csv.DictWriter(zone_file, fieldnames=DISK_ZONE_HEADERS)
        writer.writeheader()
        for entry in zone_entries:
            writer.writerow(asdict(entry))

    with scenario_path.open("w", encoding="utf-8-sig", newline="") as scenario_file:
        writer = csv.DictWriter(scenario_file, fieldnames=DISK_SCENARIO_HEADERS)
        writer.writeheader()
        for entry in scenario_entries:
            writer.writerow(asdict(entry))

    return zone_path, scenario_path


def normalize_path(path_text: str) -> str:
    return str(Path(path_text)).replace("/", "\\").rstrip("\\").casefold()


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
