from __future__ import annotations

import csv
import logging
import re
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from src.windows_software_inventory_analyzer.models import SoftwareProjectMappingEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.analyzers.mapper")

MAPPING_HEADERS = (
    "software_name",
    "category",
    "matched_projects",
    "matched_project_links",
    "project_context",
    "project_count",
    "evidence",
    "confidence_score",
)


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        LOGGER.warning("CSV input not found for mapping: %s", path)
        return []

    with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def load_technology_rules(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        raise FileNotFoundError(f"Technology rules file not found: {path}")

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


def map_software_to_projects(
    installed_programs: list[dict[str, str]],
    project_entries: list[dict[str, str]],
    file_index_entries: list[dict[str, str]],
    rules: list[dict[str, object]],
) -> list[SoftwareProjectMappingEntry]:
    mappings: list[SoftwareProjectMappingEntry] = []

    for program in installed_programs:
        software_name = program.get("name", "").strip()
        if not software_name:
            continue

        matched_projects: set[str] = set()
        matched_project_links: set[str] = set()
        project_contexts: list[str] = []
        evidence_parts: list[str] = []
        category = "uncategorized"
        confidence = 0.0

        for rule in rules:
            if not software_matches_rule(program, rule):
                continue

            category = str(rule.get("category", category))
            rule_projects, rule_links, rule_contexts, rule_evidence, rule_confidence = find_projects_for_rule(
                project_entries=project_entries,
                file_index_entries=file_index_entries,
                rule=rule,
            )
            if not rule_projects:
                continue

            matched_projects.update(rule_projects)
            matched_project_links.update(rule_links)
            project_contexts.extend(rule_contexts)
            evidence_parts.extend(f"{software_name}: {entry}" for entry in rule_evidence)
            confidence = max(confidence, rule_confidence)

        if not matched_projects:
            continue

        mappings.append(
            SoftwareProjectMappingEntry(
                software_name=software_name,
                category=category,
                matched_projects=",".join(sorted(matched_projects, key=str.casefold)),
                matched_project_links=",".join(sorted(matched_project_links, key=str.casefold)),
                project_context=" | ".join(unique_strings(project_contexts)),
                project_count=len(matched_projects),
                evidence=" | ".join(unique_strings(evidence_parts)),
                confidence_score=round(confidence, 2),
            )
        )

    mappings.sort(key=lambda item: (-item.project_count, -item.confidence_score, item.software_name.casefold()))
    return mappings


def software_matches_rule(program: dict[str, str], rule: dict[str, object]) -> bool:
    haystack = " ".join(
        [
            program.get("name", ""),
            program.get("publisher", ""),
            program.get("install_location", ""),
            program.get("uninstall_string", ""),
        ]
    ).casefold()

    patterns = [str(item).casefold() for item in rule.get("software_patterns", []) if str(item).strip()]
    return any(pattern in haystack for pattern in patterns)


def find_projects_for_rule(
    project_entries: list[dict[str, str]],
    file_index_entries: list[dict[str, str]],
    rule: dict[str, object],
) -> tuple[set[str], set[str], list[str], list[str], float]:
    technologies = [str(item).casefold() for item in rule.get("tech_keywords", []) if str(item).strip()]
    dependency_keywords = [str(item).casefold() for item in rule.get("dependency_keywords", []) if str(item).strip()]
    base_confidence = float(rule.get("base_confidence", 0.55))

    matched_projects: set[str] = set()
    matched_links: set[str] = set()
    project_contexts: list[str] = []
    evidence_parts: list[str] = []
    best_confidence = 0.0

    for project in project_entries:
        project_name = project.get("project_name", "").strip()
        if not project_name:
            continue

        project_technologies = split_csv_like_field(
            ",".join(
                [
                    project.get("detected_technologies", ""),
                    project.get("detected_libraries", ""),
                    project.get("framework_signals", ""),
                ]
            )
        )
        project_dependencies = split_dependency_summary(project.get("dependencies_summary", ""))
        project_evidence = " ".join(
            [
                project.get("code_evidence", ""),
                project.get("repo_description", ""),
                project.get("user_notes", ""),
            ]
        ).casefold()

        tech_matches = [tech for tech in technologies if tech in project_technologies]
        dependency_matches = [dep for dep in dependency_keywords if contains_token(project_dependencies, dep)]
        evidence_matches = [keyword for keyword in dependency_keywords if keyword in project_evidence]

        if not tech_matches and not dependency_matches and not evidence_matches:
            continue

        matched_projects.add(project_name)
        github_url = project.get("github_url", "").strip()
        if github_url:
            matched_links.add(github_url)
        context_text = build_project_context(project)
        if context_text:
            project_contexts.append(f"{project_name}: {context_text}")
        evidence = []
        if tech_matches:
            evidence.append(f"tech={','.join(sorted(tech_matches))}")
        if dependency_matches:
            evidence.append(f"deps={','.join(sorted(dependency_matches))}")
        if evidence_matches:
            evidence.append(f"code={','.join(sorted(evidence_matches))}")
        evidence_parts.append(f"{project_name} ({'; '.join(evidence)})")

        confidence = base_confidence
        if tech_matches:
            confidence += 0.2
        if dependency_matches:
            confidence += 0.2
        if evidence_matches:
            confidence += 0.15
        if len(tech_matches) + len(dependency_matches) + len(evidence_matches) > 1:
            confidence += 0.1
        best_confidence = max(best_confidence, min(confidence, 0.99))

    if dependency_keywords:
        for file_entry in file_index_entries:
            project_name = file_entry.get("project_name", "").strip()
            searchable_text = file_entry.get("searchable_text", "").casefold()
            file_name = file_entry.get("file_name", "")
            file_matches = [keyword for keyword in dependency_keywords if keyword in searchable_text]
            if not file_matches:
                continue
            matched_projects.add(project_name)
            github_url = file_entry.get("github_url", "").strip()
            if github_url:
                matched_links.add(github_url)
            context_text = build_project_context(file_entry)
            if context_text:
                project_contexts.append(f"{project_name}: {context_text}")
            evidence_parts.append(f"{project_name} ({file_name}: {','.join(sorted(file_matches))})")
            best_confidence = max(best_confidence, min(base_confidence + 0.25, 0.99))

    return matched_projects, matched_links, unique_strings(project_contexts), unique_strings(evidence_parts), best_confidence


def split_csv_like_field(value: str) -> set[str]:
    return {item.strip().casefold() for item in value.split(",") if item.strip()}


def split_dependency_summary(value: str) -> set[str]:
    tokens: set[str] = set()
    for fragment in value.split(";"):
        for part in fragment.split(","):
            stripped = part.strip()
            if stripped:
                tokens.add(stripped.casefold())
    return tokens


def contains_token(tokens: set[str], keyword: str) -> bool:
    lowered = keyword.casefold()
    return any(lowered in token for token in tokens)


def unique_strings(items: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        normalized = item.strip()
        if normalized and normalized not in seen:
            seen.append(normalized)
    return seen


def build_project_context(project_row: dict[str, str]) -> str:
    description = project_row.get("repo_description", "").strip()
    user_notes = project_row.get("user_notes", "").strip()
    parts = [part for part in (description, user_notes) if part]
    return " ".join(parts)[:500]


def search_mappings(entries: Iterable[SoftwareProjectMappingEntry], keyword: str) -> list[SoftwareProjectMappingEntry]:
    lowered = keyword.casefold().strip()
    if not lowered:
        return []
    return [
        entry
        for entry in entries
        if lowered in entry.software_name.casefold()
        or lowered in entry.category.casefold()
        or lowered in entry.matched_projects.casefold()
        or lowered in entry.evidence.casefold()
    ]


def write_mapping_report(entries: list[SoftwareProjectMappingEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    mapping_path = output_dir / "software_project_mapping.csv"
    with mapping_path.open("w", encoding="utf-8-sig", newline="") as mapping_file:
        writer = csv.DictWriter(mapping_file, fieldnames=MAPPING_HEADERS)
        writer.writeheader()
        for entry in entries:
            row = asdict(entry)
            row["confidence_score"] = f"{entry.confidence_score:.2f}"
            writer.writerow(row)
    return mapping_path
