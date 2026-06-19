from __future__ import annotations

from src.analyzers.family_classifier import classify_family, normalize_family_name
from src.windows_software_inventory_analyzer.models import ProgramDecisionContext, ProgramVersionCandidate


PROTECTED_FAMILIES = {
    "dotnet_sdk",
    "dotnet_runtime",
    "aspnet_runtime",
    "windows_sdk",
    "visual_cpp",
    "gpu_driver",
    "dotnet_native",
    "runtime_system",
}


def build_decision_contexts(
    installed_programs: list[dict[str, str]],
    recommendation_rows: list[dict[str, str]],
    mapping_rows: list[dict[str, str]],
    usage_rows: list[dict[str, str]],
    risk_rows: list[dict[str, str]],
    dotnet_sdk_rows: list[dict[str, str]],
    sdk_validation_rows: list[dict[str, str]],
    runtime_family_rows: dict[str, list[dict[str, str]]],
) -> list[ProgramDecisionContext]:
    recommendation_index = {row.get("software_name", "").strip().casefold(): row for row in recommendation_rows if row.get("software_name", "").strip()}
    mapping_index = {row.get("software_name", "").strip().casefold(): row for row in mapping_rows if row.get("software_name", "").strip()}
    usage_index = {row.get("software_name", "").strip().casefold(): row for row in usage_rows if row.get("software_name", "").strip()}
    risk_index = {row.get("software_name", "").strip().casefold(): row for row in risk_rows if row.get("software_name", "").strip()}

    family_candidates: dict[str, list[ProgramVersionCandidate]] = {}
    for recommendation in recommendation_rows:
        software_name = recommendation.get("software_name", "").strip()
        if not software_name:
            continue
        family_name = normalize_family_name(software_name)
        family_candidates.setdefault(family_name, []).append(
            ProgramVersionCandidate(
                software_name=software_name,
                normalized_family=family_name,
                version=recommendation.get("installed_version", "") or recommendation.get("display_version", "") or "",
                category=recommendation.get("category", ""),
                estimated_size=recommendation.get("estimated_size", ""),
                last_used_at=recommendation.get("last_used_at", ""),
                project_count=safe_int(recommendation.get("project_count", "0")),
                decision=recommendation.get("decision", ""),
            )
        )

    contexts: list[ProgramDecisionContext] = []
    for installed in installed_programs:
        software_name = installed.get("name", "").strip()
        if not software_name:
            continue
        recommendation = recommendation_index.get(software_name.casefold(), {})
        mapping = mapping_index.get(software_name.casefold(), {})
        usage = usage_index.get(software_name.casefold(), {})
        risk = risk_index.get(software_name.casefold(), {})

        category = recommendation.get("category", "") or "Unknown"
        family_type = classify_family(software_name, category, installed.get("install_location", ""))
        normalized_family = normalize_family_name(software_name)
        matched_projects = recommendation.get("matched_projects", "") or mapping.get("matched_projects", "")
        project_context = recommendation.get("project_context", "") or mapping.get("project_context", "")
        dotnet_rows = [row for row in dotnet_sdk_rows if row.get("sdk_version", "") and row.get("sdk_version", "") in software_name]
        validation_rows = [row for row in sdk_validation_rows if row.get("selected_sdk", "") and row.get("selected_sdk", "") in software_name]
        runtime_rows = runtime_family_rows.get(family_type, [])

        project_signals = []
        if matched_projects:
            project_signals.append(matched_projects)
        if project_context:
            project_signals.append(project_context)

        ide_signals = []
        for row in dotnet_rows:
            for key in ("ide_context", "project_context", "global_json_matches"):
                value = row.get(key, "").strip()
                if value:
                    ide_signals.append(value)

        contexts.append(
            ProgramDecisionContext(
                software_name=software_name,
                normalized_family=normalized_family,
                family_type=family_type,
                category=category,
                publisher=installed.get("publisher", "").strip(),
                installed_version=installed.get("version", "").strip(),
                install_location=installed.get("install_location", "").strip(),
                estimated_size=recommendation.get("estimated_size", "").strip(),
                project_count=safe_int(recommendation.get("project_count", "0") or mapping.get("project_count", "0")),
                matched_projects=matched_projects,
                project_context=project_context,
                last_used_at=usage.get("last_used_at", "").strip() or recommendation.get("last_used_at", "").strip(),
                usage_signal_count=safe_int(usage.get("usage_signal_count", recommendation.get("usage_signal_count", "0"))),
                usage_sources=usage.get("usage_sources", "").strip() or recommendation.get("usage_sources", "").strip(),
                usage_status=usage.get("usage_status", "").strip() or recommendation.get("usage_status", "").strip() or "unknown_usage",
                risk_score=safe_float(risk.get("risk_score", recommendation.get("risk_score", "0"))),
                cleanup_priority_score=safe_float(risk.get("cleanup_priority_score", recommendation.get("cleanup_priority_score", "0"))),
                confidence_score=safe_float(recommendation.get("confidence_score", "0")),
                existing_decision=recommendation.get("decision", "").strip(),
                existing_explanation=recommendation.get("explanation", "").strip(),
                hard_protection=family_type in PROTECTED_FAMILIES or risk.get("hard_protection", "").strip().casefold() == "yes",
                duplicate_versions=[candidate for candidate in family_candidates.get(normalized_family, []) if candidate.software_name != software_name],
                dotnet_sdk_rows=dotnet_rows,
                sdk_validation_rows=validation_rows,
                runtime_family_rows=runtime_rows,
                project_signals=project_signals,
                ide_signals=ide_signals,
            )
        )

    return contexts


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
