from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path

from src.analyzers.decision_context import build_decision_contexts
from src.analyzers.decision_explainer import build_plain_language_explanation, build_technical_explanation
from src.analyzers.family_evaluators import evaluate_context
from src.windows_software_inventory_analyzer.models import RemovalDecisionEntry


REMOVAL_DECISION_HEADERS = (
    "software_name",
    "normalized_family",
    "family_type",
    "category",
    "publisher",
    "installed_version",
    "decision_label",
    "removal_risk_score",
    "cleanup_value_score",
    "recommended_next_action",
    "plain_language_explanation",
    "technical_explanation",
    "evidence",
    "matched_projects",
    "project_count",
    "last_used_at",
    "usage_signal_count",
    "estimated_size",
    "duplicate_summary",
    "test_summary",
)


def build_removal_decisions(
    installed_programs: list[dict[str, str]],
    recommendation_rows: list[dict[str, str]],
    mapping_rows: list[dict[str, str]],
    usage_rows: list[dict[str, str]],
    risk_rows: list[dict[str, str]],
    dotnet_sdk_rows: list[dict[str, str]],
    sdk_validation_rows: list[dict[str, str]],
    runtime_family_rows: dict[str, list[dict[str, str]]],
) -> list[RemovalDecisionEntry]:
    contexts = build_decision_contexts(
        installed_programs=installed_programs,
        recommendation_rows=recommendation_rows,
        mapping_rows=mapping_rows,
        usage_rows=usage_rows,
        risk_rows=risk_rows,
        dotnet_sdk_rows=dotnet_sdk_rows,
        sdk_validation_rows=sdk_validation_rows,
        runtime_family_rows=runtime_family_rows,
    )

    entries: list[RemovalDecisionEntry] = []
    for context in contexts:
        decision_label, removal_risk_score, cleanup_value_score, next_action, reasons, duplicate_summary, test_summary = evaluate_context(context)
        plain_language_explanation = build_plain_language_explanation(context, decision_label, reasons)
        technical_explanation = build_technical_explanation(
            context,
            decision_label,
            removal_risk_score,
            cleanup_value_score,
            reasons,
        )
        evidence_parts = [
            f"family={context.family_type}",
            f"project_count={context.project_count}",
            f"usage_status={context.usage_status}",
            f"last_used_at={context.last_used_at or '-'}",
            f"hard_protection={'yes' if context.hard_protection else 'no'}",
        ]
        if context.ide_signals:
            evidence_parts.append(f"ide_signals={'; '.join(context.ide_signals[:4])}")
        if context.project_signals:
            evidence_parts.append(f"project_signals={'; '.join(context.project_signals[:4])}")

        entries.append(
            RemovalDecisionEntry(
                software_name=context.software_name,
                normalized_family=context.normalized_family,
                family_type=context.family_type,
                category=context.category,
                publisher=context.publisher,
                installed_version=context.installed_version,
                decision_label=decision_label,
                removal_risk_score=removal_risk_score,
                cleanup_value_score=cleanup_value_score,
                recommended_next_action=next_action,
                plain_language_explanation=plain_language_explanation,
                technical_explanation=technical_explanation,
                evidence=" | ".join(evidence_parts),
                matched_projects=context.matched_projects,
                project_count=context.project_count,
                last_used_at=context.last_used_at,
                usage_signal_count=context.usage_signal_count,
                estimated_size=context.estimated_size,
                duplicate_summary=duplicate_summary,
                test_summary=test_summary,
            )
        )

    entries.sort(key=lambda item: (-item.cleanup_value_score, -item.removal_risk_score, item.software_name.casefold()))
    return entries


def write_removal_decisions(entries: list[RemovalDecisionEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "removal_decisions.csv"
    with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=REMOVAL_DECISION_HEADERS)
        writer.writeheader()
        for entry in entries:
            row = asdict(entry)
            row["removal_risk_score"] = f"{entry.removal_risk_score:.2f}"
            row["cleanup_value_score"] = f"{entry.cleanup_value_score:.2f}"
            writer.writerow(row)
    return output_path
