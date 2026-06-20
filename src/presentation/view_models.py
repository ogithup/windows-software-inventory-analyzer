from __future__ import annotations


def build_program_view_rows(
    search_rows: list[dict[str, str]],
    removal_rows: list[dict[str, str]],
    validation_rows: list[dict[str, str]],
) -> list[dict[str, str]]:
    removal_index = {row.get("software_name", "").casefold(): row for row in removal_rows if row.get("software_name", "").strip()}
    validation_index = build_validation_family_index(validation_rows)
    rows: list[dict[str, str]] = []
    for row in search_rows:
        software_name = row.get("software_name", "")
        removal = removal_index.get(software_name.casefold(), {})
        family_type = removal.get("family_type", "")
        validation_level = validation_index.get(family_type, "STATIC_ONLY")
        merged = dict(row)
        merged["family_type"] = family_type
        merged["validation_level"] = validation_level
        merged["impact_scope"] = removal.get("impact_scope", "")
        merged["if_removed_frees_space_human"] = removal.get("if_removed_frees_space_human", "")
        merged["recoverability_score"] = removal.get("recoverability_score", "")
        merged["decision_label"] = removal.get("decision_label", "")
        rows.append(merged)
    return rows


def filter_program_view_rows(
    rows: list[dict[str, str]],
    query: str = "",
    categories: set[str] | None = None,
    decisions: set[str] | None = None,
    validation_levels: set[str] | None = None,
    family_types: set[str] | None = None,
) -> list[dict[str, str]]:
    categories = categories or set()
    decisions = decisions or set()
    validation_levels = validation_levels or set()
    family_types = family_types or set()
    lowered_query = query.casefold().strip()
    filtered: list[dict[str, str]] = []
    for row in rows:
        if categories and row.get("category", "") not in categories:
            continue
        if decisions and row.get("decision", "") not in decisions and row.get("decision_label", "") not in decisions:
            continue
        if validation_levels and row.get("validation_level", "") not in validation_levels:
            continue
        if family_types and row.get("family_type", "") not in family_types:
            continue
        haystack = " ".join(str(row.get(key, "")) for key in ("software_name", "category", "decision", "decision_label", "family_type", "matched_projects", "project_context", "impact_scope", "validation_level")).casefold()
        if lowered_query and lowered_query not in haystack:
            continue
        filtered.append(row)
    return filtered


def build_validation_family_index(validation_rows: list[dict[str, str]]) -> dict[str, str]:
    rank = {"STATIC_ONLY": 1, "BUILD_VERIFIED": 2, "ISOLATED_REINSTALL_VERIFIED": 3}
    index: dict[str, str] = {}
    for row in validation_rows:
        family = row.get("technology_family", "").strip()
        level = row.get("validation_level", "").strip() or "STATIC_ONLY"
        if not family:
            continue
        current = index.get(family, "STATIC_ONLY")
        if rank.get(level, 0) >= rank.get(current, 0):
            index[family] = level
    return index
