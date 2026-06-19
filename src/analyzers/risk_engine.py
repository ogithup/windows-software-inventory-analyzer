from __future__ import annotations

import csv
import logging
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from src.windows_software_inventory_analyzer.models import ProgramRiskScoreEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.analyzers.risk_engine")

RISK_HEADERS = (
    "software_name",
    "category",
    "publisher",
    "decision",
    "estimated_size",
    "project_count",
    "last_used_at",
    "risk_score",
    "cleanup_priority_score",
    "hard_protection",
    "score_breakdown",
    "rationale",
)

CATEGORY_RISK_WEIGHTS = {
    "Runtime/System": 42,
    "Database": 28,
    "Network": 24,
    "Virtualization": 26,
    "Backend": 18,
    "Frontend": 14,
    "AI/ML": 22,
    "Computer Vision": 22,
    "Game Development": 20,
    "Office": 16,
    "Unknown": 20,
}

TRUSTED_PUBLISHERS = (
    "microsoft",
    "nvidia",
    "intel",
    "amd",
    "google",
    "docker",
    "jetbrains",
    "oracle",
    "postgresql",
)

PROTECTED_KEYWORDS = (
    "redistributable",
    "runtime",
    "windows sdk",
    ".net sdk",
    ".net runtime",
    "asp.net",
    "driver",
    "nvidia",
    "chipset",
    "visual studio",
    "windowsappruntime",
    "winappruntime",
)


def build_program_risk_scores(
    installed_programs: list[dict[str, str]],
    mapping_rows: list[dict[str, str]],
    recommendation_rows: list[dict[str, str]],
    usage_rows: list[dict[str, str]],
) -> list[ProgramRiskScoreEntry]:
    installed_index = {row.get("name", "").strip().casefold(): row for row in installed_programs if row.get("name", "").strip()}
    mapping_index = {row.get("software_name", "").strip().casefold(): row for row in mapping_rows if row.get("software_name", "").strip()}
    usage_index = {row.get("software_name", "").strip().casefold(): row for row in usage_rows if row.get("software_name", "").strip()}

    entries: list[ProgramRiskScoreEntry] = []
    for recommendation in recommendation_rows:
        software_name = recommendation.get("software_name", "").strip()
        if not software_name:
            continue
        installed = installed_index.get(software_name.casefold(), {})
        mapping = mapping_index.get(software_name.casefold(), {})
        usage = usage_index.get(software_name.casefold(), {})
        entry = compute_risk_score(installed, mapping, recommendation, usage)
        entries.append(entry)

    entries.sort(key=lambda item: (-item.cleanup_priority_score, item.software_name.casefold()))
    return entries


def compute_risk_score(
    installed_row: dict[str, str],
    mapping_row: dict[str, str],
    recommendation_row: dict[str, str],
    usage_row: dict[str, str],
) -> ProgramRiskScoreEntry:
    software_name = recommendation_row.get("software_name", "").strip()
    category = recommendation_row.get("category", "").strip() or "Unknown"
    publisher = installed_row.get("publisher", "").strip()
    decision = recommendation_row.get("decision", "").strip()
    estimated_size = recommendation_row.get("estimated_size", "").strip()
    project_count = safe_int(recommendation_row.get("project_count", "0"))
    last_used_at = usage_row.get("last_used_at", "").strip() or recommendation_row.get("last_used_at", "").strip()
    usage_signal_count = safe_int(usage_row.get("usage_signal_count", recommendation_row.get("usage_signal_count", "0")))
    confidence_score = safe_float(recommendation_row.get("confidence_score", "0"))

    hard_protection = "yes" if is_hard_protected(software_name, category, publisher) else "no"
    category_weight = CATEGORY_RISK_WEIGHTS.get(category, CATEGORY_RISK_WEIGHTS["Unknown"])
    project_weight = min(project_count * 14, 30)
    usage_weight = compute_usage_weight(last_used_at, usage_signal_count)
    publisher_weight = compute_publisher_weight(publisher)
    size_weight = compute_size_weight(estimated_size)
    decision_weight = {"KEEP": 18, "MANUAL_REVIEW": 12, "UNSURE": 6, "CAN_REMOVE": -8}.get(decision, 0)
    mapping_weight = min(int(round(confidence_score * 10)), 10)

    base_risk = category_weight + project_weight + usage_weight + publisher_weight + decision_weight + mapping_weight
    if hard_protection == "yes":
        base_risk = max(base_risk, 82)
    risk_score = max(0, min(100, base_risk))

    cleanup_priority = 55 + size_weight - project_weight - usage_weight - max(category_weight - 18, 0) - publisher_weight
    cleanup_priority += {"CAN_REMOVE": 16, "UNSURE": 6, "MANUAL_REVIEW": -4, "KEEP": -12}.get(decision, 0)
    if hard_protection == "yes":
        cleanup_priority = min(cleanup_priority, 12)
    cleanup_priority_score = max(0, min(100, cleanup_priority))

    breakdown = (
        f"category={category_weight}; project={project_weight}; usage={usage_weight}; "
        f"publisher={publisher_weight}; size={size_weight}; decision={decision_weight}; "
        f"mapping={mapping_weight}; hard_protection={hard_protection}"
    )
    rationale = build_rationale(
        software_name=software_name,
        category=category,
        hard_protection=hard_protection,
        project_count=project_count,
        last_used_at=last_used_at,
        estimated_size=estimated_size,
        risk_score=risk_score,
        cleanup_priority_score=cleanup_priority_score,
    )
    return ProgramRiskScoreEntry(
        software_name=software_name,
        category=category,
        publisher=publisher,
        decision=decision,
        estimated_size=estimated_size,
        project_count=project_count,
        last_used_at=last_used_at,
        risk_score=float(risk_score),
        cleanup_priority_score=float(cleanup_priority_score),
        hard_protection=hard_protection,
        score_breakdown=breakdown,
        rationale=rationale,
    )


def compute_usage_weight(last_used_at: str, usage_signal_count: int) -> int:
    parsed = parse_iso_datetime(last_used_at)
    if parsed is None:
        return 3 if usage_signal_count == 0 else 8
    days = max(0, int((datetime.now(timezone.utc) - parsed).total_seconds() // 86400))
    if days <= 30:
        return 24
    if days <= 180:
        return 16
    if days <= 365:
        return 8
    return 2


def compute_publisher_weight(publisher: str) -> int:
    lowered = publisher.casefold()
    if not lowered:
        return 0
    if any(keyword in lowered for keyword in TRUSTED_PUBLISHERS):
        return 10
    return 2


def compute_size_weight(size_human: str) -> int:
    match = re.match(r"([0-9]+(?:\.[0-9]+)?)\s*(TB|GB|MB|KB)", size_human.strip(), flags=re.IGNORECASE)
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2).upper()
    if unit == "TB":
        value *= 1024
        unit = "GB"
    if unit == "GB":
        if value >= 10:
            return 24
        if value >= 3:
            return 16
        if value >= 1:
            return 8
        return 4
    if unit == "MB":
        if value >= 900:
            return 6
        if value >= 500:
            return 4
    return 1


def is_hard_protected(software_name: str, category: str, publisher: str) -> bool:
    haystack = f"{software_name} {category} {publisher}".casefold()
    if category == "Runtime/System":
        return True
    return any(keyword in haystack for keyword in PROTECTED_KEYWORDS)


def build_rationale(
    software_name: str,
    category: str,
    hard_protection: str,
    project_count: int,
    last_used_at: str,
    estimated_size: str,
    risk_score: int,
    cleanup_priority_score: int,
) -> str:
    parts = [f"{software_name} icin removal riski {risk_score}/100"]
    if hard_protection == "yes":
        parts.append("korumali runtime/system veya toolchain sinyali bulundu")
    if project_count > 0:
        parts.append(f"{project_count} proje eslesmesi var")
    if last_used_at:
        parts.append(f"son kullanim izi {last_used_at}")
    if estimated_size:
        parts.append(f"kapladigi alan {estimated_size}")
    parts.append(f"temizlik onceligi {cleanup_priority_score}/100")
    parts.append(f"kategori {category}")
    return ". ".join(parts) + "."


def write_program_risk_scores(entries: list[ProgramRiskScoreEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "program_risk_scores.csv"
    with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=RISK_HEADERS)
        writer.writeheader()
        for entry in entries:
            row = asdict(entry)
            row["risk_score"] = f"{entry.risk_score:.2f}"
            row["cleanup_priority_score"] = f"{entry.cleanup_priority_score:.2f}"
            writer.writerow(row)
    return output_path


def parse_iso_datetime(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def safe_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def safe_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
