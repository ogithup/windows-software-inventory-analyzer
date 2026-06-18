from __future__ import annotations

import csv
import logging
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from src.analyzers.manual_review import apply_manual_review_override, load_manual_review_overrides
from src.windows_software_inventory_analyzer.models import RecommendationEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.analyzers.recommender")
MANUAL_REVIEW_OVERRIDES_PATH = Path("manual_review_overrides.csv")

RECOMMENDATION_HEADERS = (
    "software_name",
    "category",
    "decision",
    "matched_projects",
    "project_links",
    "project_context",
    "project_count",
    "install_location",
    "estimated_size",
    "last_related_project_activity",
    "last_used_at",
    "usage_signal_count",
    "usage_sources",
    "usage_status",
    "confidence_score",
    "explanation",
    "review_status",
    "review_notes",
)


def load_category_rules(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        raise FileNotFoundError(f"Category rules file not found: {path}")

    rules: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    current_list_key: str | None = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- "):
            if line.startswith("- "):
                if current is not None:
                    rules.append(current)
                current = {}
                current_list_key = None
                stripped = stripped[2:]
                if stripped:
                    key, _, value = stripped.partition(":")
                    current[key.strip()] = parse_scalar(value.strip())
                continue

            if current is None or current_list_key is None:
                raise ValueError(f"Invalid rules structure near line: {raw_line}")
            items = current.setdefault(current_list_key, [])
            if not isinstance(items, list):
                raise ValueError(f"Expected list for {current_list_key}")
            items.append(parse_scalar(stripped[2:].strip()))
            continue

        if current is None:
            continue

        key, _, value = stripped.partition(":")
        if value.strip():
            current[key.strip()] = parse_scalar(value.strip())
            current_list_key = None
        else:
            current[key.strip()] = []
            current_list_key = key.strip()

    if current is not None:
        rules.append(current)

    return rules


def parse_scalar(value: str) -> str | float:
    normalized = value.strip()
    if normalized.startswith('"') and normalized.endswith('"'):
        return normalized[1:-1]
    if normalized.startswith("'") and normalized.endswith("'"):
        return normalized[1:-1]
    if re.fullmatch(r"\d+(?:\.\d+)?", normalized):
        return float(normalized)
    return normalized


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        LOGGER.warning("CSV input not found for recommender: %s", path)
        return []

    with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def build_recommendations(
    installed_programs: list[dict[str, str]],
    disk_usage_rows: list[dict[str, str]],
    mapping_rows: list[dict[str, str]],
    category_rules: list[dict[str, object]],
    project_rows: list[dict[str, str]] | None = None,
    usage_rows: list[dict[str, str]] | None = None,
    manual_review_overrides: dict[str, dict[str, str]] | None = None,
) -> list[RecommendationEntry]:
    mapping_by_name = {row.get("software_name", "").casefold(): row for row in mapping_rows}
    project_index = build_project_index(project_rows or [])
    usage_index = {row.get("software_name", "").strip().casefold(): row for row in (usage_rows or []) if row.get("software_name", "").strip()}
    overrides = manual_review_overrides if manual_review_overrides is not None else load_manual_review_overrides(MANUAL_REVIEW_OVERRIDES_PATH)

    recommendations: list[RecommendationEntry] = []
    for program in installed_programs:
        software_name = program.get("name", "").strip()
        if not software_name:
            continue

        mapping = mapping_by_name.get(software_name.casefold())
        usage = usage_index.get(software_name.casefold(), {})
        matched_projects = mapping.get("matched_projects", "") if mapping else ""
        project_links = mapping.get("matched_project_links", "") if mapping else ""
        project_context = mapping.get("project_context", "") if mapping else ""
        project_count = safe_int(mapping.get("project_count", "0") if mapping else "0")
        mapping_confidence = safe_float(mapping.get("confidence_score", "0") if mapping else "0")
        last_used_at = usage.get("last_used_at", "")
        usage_signal_count = safe_int(usage.get("usage_signal_count", "0"))
        usage_sources = usage.get("usage_sources", "")
        usage_status = usage.get("usage_status", "unknown_usage") or "unknown_usage"

        category, protection_reason = categorize_program(program, mapping, category_rules)
        install_location = program.get("install_location", "").strip()
        estimated_size = estimate_program_size(install_location, disk_usage_rows)
        last_related_project_activity = derive_last_related_project_activity(matched_projects, project_index)

        decision, confidence_score, explanation = decide_recommendation(
            program=program,
            category=category,
            protection_reason=protection_reason,
            matched_projects=matched_projects,
            project_context=project_context,
            project_count=project_count,
            mapping_confidence=mapping_confidence,
            estimated_size=estimated_size,
            last_related_project_activity=last_related_project_activity,
            last_used_at=last_used_at,
            usage_signal_count=usage_signal_count,
            usage_sources=usage_sources,
            usage_status=usage_status,
        )
        review_status = ""
        review_notes = ""
        override = overrides.get(software_name.casefold())
        decision, explanation, review_status, review_notes = apply_manual_review_override(
            decision=decision,
            explanation=explanation,
            review_status=review_status,
            review_notes=review_notes,
            override=override,
        )

        recommendations.append(
            RecommendationEntry(
                software_name=software_name,
                category=category,
                decision=decision,
                matched_projects=matched_projects,
                project_links=project_links,
                project_context=project_context,
                project_count=project_count,
                install_location=install_location,
                estimated_size=estimated_size,
                last_related_project_activity=last_related_project_activity,
                last_used_at=last_used_at,
                usage_signal_count=usage_signal_count,
                usage_sources=usage_sources,
                usage_status=usage_status,
                confidence_score=round(confidence_score, 2),
                explanation=explanation,
                review_status=review_status,
                review_notes=review_notes,
            )
        )

    recommendations.sort(
        key=lambda item: (
            decision_rank(item.decision),
            -item.project_count,
            item.software_name.casefold(),
        )
    )
    return recommendations


def categorize_program(
    program: dict[str, str],
    mapping: dict[str, str] | None,
    category_rules: list[dict[str, object]],
) -> tuple[str, str]:
    haystack = " ".join(
        [
            program.get("name", ""),
            program.get("publisher", ""),
            program.get("install_location", ""),
            program.get("uninstall_string", ""),
        ]
    ).casefold()

    for rule in category_rules:
        patterns = [str(item).casefold() for item in rule.get("patterns", []) if str(item).strip()]
        if any(pattern in haystack for pattern in patterns):
            return str(rule.get("category", "Unknown")), str(rule.get("protection_reason", ""))

    if mapping:
        mapped_category = normalize_mapping_category(mapping.get("category", ""))
        if mapped_category:
            return mapped_category, ""

    return "Unknown", ""


def normalize_mapping_category(value: str) -> str:
    normalized = value.strip().casefold()
    mapping = {
        "language_runtime": "Backend",
        "javascript_runtime": "Frontend",
        "containerization": "Virtualization",
        "database": "Database",
        "network_analysis": "Network",
        "mobile_development": "Game Development",
        "uncategorized": "Unknown",
    }
    return mapping.get(normalized, "")


def estimate_program_size(install_location: str, disk_usage_rows: list[dict[str, str]]) -> str:
    if not install_location:
        return ""

    normalized_install = install_location.casefold().rstrip("\\")
    best_row: dict[str, str] | None = None
    best_length = -1

    for row in disk_usage_rows:
        path = row.get("path", "").casefold().rstrip("\\")
        if not path:
            continue
        if normalized_install == path or normalized_install.startswith(f"{path}\\") or path.startswith(f"{normalized_install}\\"):
            if len(path) > best_length:
                best_row = row
                best_length = len(path)

    return best_row.get("size_human", "") if best_row else ""


def derive_last_related_project_activity(matched_projects: str, project_index: dict[str, dict[str, str]]) -> str:
    if not matched_projects:
        return ""

    timestamps = [project_index.get(project.strip().casefold(), {}).get("last_modified", "") for project in matched_projects.split(",")]
    timestamps = [value for value in timestamps if value]
    return max(timestamps) if timestamps else ""


def build_project_index(project_rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in project_rows:
        project_name = row.get("project_name", "").strip().casefold()
        if project_name:
            index[project_name] = row
    return index


def decide_recommendation(
    program: dict[str, str],
    category: str,
    protection_reason: str,
    matched_projects: str,
    project_context: str,
    project_count: int,
    mapping_confidence: float,
    estimated_size: str,
    last_related_project_activity: str,
    last_used_at: str,
    usage_signal_count: int,
    usage_sources: str,
    usage_status: str,
) -> tuple[str, float, str]:
    software_name = program.get("name", "").strip()
    publisher = program.get("publisher", "").strip()
    name_haystack = f"{software_name} {publisher}".casefold()

    if protection_reason:
        explanation = (
            f"{software_name} korumali bir bilesen gibi gorunuyor ({protection_reason}). "
            "Bu tip runtime, surucu veya sistem araclarina otomatik silme onerisi verilmedi."
        )
        return "MANUAL_REVIEW", 0.95, explanation

    if category == "Unknown":
        explanation = (
            f"{software_name} icin guvenilir bir kategori veya proje eslesmesi bulunamadi. "
            "Bu nedenle Unknown olarak isaretlenip manuel incelemeye birakildi."
        )
        return "MANUAL_REVIEW", 0.55, explanation

    if project_count > 0 and mapping_confidence >= 0.7:
        explanation = (
            f"{software_name} {project_count} projeyle iliskili bulundu. "
            f"Eslestirme guveni {mapping_confidence:.2f} seviyesinde."
        )
        if last_used_at:
            explanation += f" Son kullanim izi {last_used_at} tarihinde goruldu."
        if last_related_project_activity:
            explanation += f" Ilgili proje aktivitesi en son {last_related_project_activity} tarihinde goruluyor."
        if project_context:
            explanation += f" Proje baglami: {shorten_context(project_context)}."
        if estimated_size:
            explanation += f" Tahmini kapladigi alan {estimated_size}."
        return "KEEP", min(0.65 + mapping_confidence * 0.3, 0.98), explanation

    if category in {"Office", "Database", "Network", "Virtualization", "Game Development", "AI/ML", "Computer Vision", "Backend", "Frontend"}:
        if estimated_size and is_large_size(estimated_size):
            explanation = (
                f"{software_name} {category} kategorisinde ama aktif proje eslesmesi bulunamadi. "
                f"Tahmini boyutu {estimated_size} oldugu icin silmeden once emin olmak gerekir."
            )
            if last_used_at:
                explanation += f" Son kullanim izi {last_used_at} tarihinde goruldu."
            if project_context:
                explanation += f" Kayitli proje notu/aciklamasi: {shorten_context(project_context)}."
            return "UNSURE", 0.66, explanation

        explanation = (
            f"{software_name} {category} kategorisinde, ancak aktif proje iliskisi tespit edilmedi. "
            "Daha once gecici kullandiysan kaldirilabilir olabilir ama otomatik guven dusuk."
        )
        if usage_status == "usage_detected" and last_used_at:
            explanation += f" Sistem son kullanim izini {last_used_at} tarihinde gordu."
        if project_context:
            explanation += f" Kayitli proje notu/aciklamasi: {shorten_context(project_context)}."
        return "UNSURE", 0.60, explanation

    if any(token in name_haystack for token in ("tool", "sdk", "library", "redistributable", "runtime")):
        explanation = (
            f"{software_name} yardimci bilesen veya runtime gibi gorunuyor. "
            "Dogrudan kaldirma yerine once bagimli araclar kontrol edilmeli."
        )
        return "MANUAL_REVIEW", 0.82, explanation

    explanation = (
        f"{software_name} icin proje iliskisi bulunamadi ve koruma listesinde yer almiyor. "
        "Eger artik kullanmiyorsan kaldirilabilir olabilir."
    )
    if usage_status == "usage_detected" and last_used_at:
        explanation += f" Ancak sistem son kullanim izini {last_used_at} tarihinde gordu."
    if estimated_size:
        explanation += f" Tahmini boyutu {estimated_size}."
    return "CAN_REMOVE", 0.58, explanation


def shorten_context(project_context: str) -> str:
    compact = " ".join(project_context.split())
    return compact[:220]


def is_large_size(size_human: str) -> bool:
    match = re.match(r"([0-9]+(?:\.[0-9]+)?)\s*(GB|MB)", size_human.strip(), flags=re.IGNORECASE)
    if not match:
        return False
    value = float(match.group(1))
    unit = match.group(2).upper()
    if unit == "GB":
        return value >= 1.0
    return value >= 700.0


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


def decision_rank(decision: str) -> int:
    order = {
        "KEEP": 0,
        "UNSURE": 1,
        "MANUAL_REVIEW": 2,
        "CAN_REMOVE": 3,
    }
    return order.get(decision, 4)


def search_recommendations(entries: Iterable[RecommendationEntry], keyword: str) -> list[RecommendationEntry]:
    lowered = keyword.casefold().strip()
    if not lowered:
        return []
    return [
        entry
        for entry in entries
        if lowered in entry.software_name.casefold()
        or lowered in entry.category.casefold()
        or lowered in entry.decision.casefold()
        or lowered in entry.explanation.casefold()
        or lowered in entry.matched_projects.casefold()
    ]


def write_recommendations(entries: list[RecommendationEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    recommendations_path = output_dir / "recommendations.csv"
    with recommendations_path.open("w", encoding="utf-8-sig", newline="") as recommendations_file:
        writer = csv.DictWriter(recommendations_file, fieldnames=RECOMMENDATION_HEADERS)
        writer.writeheader()
        for entry in entries:
            row = asdict(entry)
            row["confidence_score"] = f"{entry.confidence_score:.2f}"
            writer.writerow(row)
    return recommendations_path
