from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path


MANUAL_REVIEW_HEADERS = (
    "software_name",
    "category_snapshot",
    "original_decision",
    "user_knows_program",
    "used_recently",
    "project_required",
    "has_newer_alternative",
    "is_system_component",
    "review_notes",
    "reviewed_decision",
    "reviewed_explanation",
    "last_reviewed_at",
)


def load_manual_review_overrides(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))
    return {
        row.get("software_name", "").strip().casefold(): row
        for row in rows
        if row.get("software_name", "").strip()
    }


def save_manual_review_override(path: Path, row: dict[str, str]) -> None:
    existing = load_manual_review_overrides(path)
    key = row.get("software_name", "").strip().casefold()
    if not key:
        raise ValueError("software_name is required for manual review override")
    existing[key] = row

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=MANUAL_REVIEW_HEADERS)
        writer.writeheader()
        for override in sorted(existing.values(), key=lambda item: item.get("software_name", "").casefold()):
            writer.writerow({header: override.get(header, "") for header in MANUAL_REVIEW_HEADERS})


def evaluate_manual_review(
    software_name: str,
    category: str,
    original_decision: str,
    user_knows_program: str,
    used_recently: str,
    project_required: str,
    has_newer_alternative: str,
    is_system_component: str,
    review_notes: str,
) -> dict[str, str]:
    normalized = {
        "user_knows_program": normalize_choice(user_knows_program),
        "used_recently": normalize_choice(used_recently),
        "project_required": normalize_choice(project_required),
        "has_newer_alternative": normalize_choice(has_newer_alternative),
        "is_system_component": normalize_choice(is_system_component),
    }
    explanation_parts: list[str] = []

    if normalized["is_system_component"] == "yes":
        decision = "KEEP"
        explanation_parts.append("Kullanici bunu sistem/runtime bileseni olarak isaretledi.")
    elif normalized["project_required"] == "yes":
        decision = "KEEP"
        explanation_parts.append("Kullanici bunu aktif bir proje icin gerekli olarak isaretledi.")
    elif normalized["used_recently"] == "yes":
        decision = "KEEP"
        explanation_parts.append("Kullanici son donemde kullandigini belirtti.")
    elif normalized["has_newer_alternative"] == "yes" and normalized["project_required"] != "yes":
        decision = "CAN_REMOVE"
        explanation_parts.append("Kullanici ayni islev icin daha yeni veya alternatif bir surum oldugunu belirtti.")
    elif normalized["user_knows_program"] == "no" and category == "Runtime/System":
        decision = "MANUAL_REVIEW"
        explanation_parts.append("Program Runtime/System kategorisinde ve kullanici ne ise yaradigindan emin degil.")
    elif normalized["user_knows_program"] == "yes" and normalized["used_recently"] == "no":
        decision = "CAN_REMOVE"
        explanation_parts.append("Kullanici programi taniyor ancak yakin zamanda kullanmadigini belirtti.")
    else:
        decision = "UNSURE"
        explanation_parts.append("Verilen cevaplar kaldirma veya tutma karari icin hala tam net degil.")

    if review_notes.strip():
        explanation_parts.append(f"Kullanici notu: {review_notes.strip()[:220]}")

    return {
        "software_name": software_name,
        "category_snapshot": category,
        "original_decision": original_decision,
        "user_knows_program": normalized["user_knows_program"],
        "used_recently": normalized["used_recently"],
        "project_required": normalized["project_required"],
        "has_newer_alternative": normalized["has_newer_alternative"],
        "is_system_component": normalized["is_system_component"],
        "review_notes": review_notes.strip(),
        "reviewed_decision": decision,
        "reviewed_explanation": " ".join(explanation_parts),
        "last_reviewed_at": datetime.now(timezone.utc).isoformat(),
    }


def apply_manual_review_override(
    decision: str,
    explanation: str,
    review_status: str,
    review_notes: str,
    override: dict[str, str] | None,
) -> tuple[str, str, str, str]:
    if not override:
        return decision, explanation, review_status, review_notes

    reviewed_decision = override.get("reviewed_decision", "").strip() or decision
    reviewed_explanation = override.get("reviewed_explanation", "").strip() or explanation
    reviewed_at = override.get("last_reviewed_at", "").strip()
    notes = override.get("review_notes", "").strip()
    status = f"USER_REVIEWED {reviewed_at}" if reviewed_at else "USER_REVIEWED"
    if notes:
        reviewed_explanation = f"{reviewed_explanation} Not: {notes[:220]}"
    return reviewed_decision, reviewed_explanation, status, notes


def normalize_choice(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized in {"yes", "evet"}:
        return "yes"
    if normalized in {"no", "hayir", "hayır"}:
        return "no"
    return "unknown"
