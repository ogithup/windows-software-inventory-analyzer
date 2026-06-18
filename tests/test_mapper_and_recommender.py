from __future__ import annotations

from pathlib import Path

from src.analyzers.mapper import load_csv_rows as load_mapping_csv_rows
from src.analyzers.mapper import load_technology_rules, map_software_to_projects
from src.analyzers.recommender import (
    build_recommendations,
    load_category_rules,
    load_csv_rows as load_recommender_csv_rows,
)


def test_mapper_matches_python_and_docker(fixtures_dir: Path) -> None:
    installed_programs = load_mapping_csv_rows(fixtures_dir / "installed_programs.csv")
    project_entries = load_mapping_csv_rows(fixtures_dir / "project_tech_stack.csv")
    file_index_entries = load_mapping_csv_rows(fixtures_dir / "project_files_index.csv")
    rules = load_technology_rules(Path("technology_rules.yaml"))

    mappings = map_software_to_projects(installed_programs, project_entries, file_index_entries, rules)
    names = {entry.software_name for entry in mappings}

    assert "Python 3.11" in names
    assert "Docker Desktop" in names


def test_recommender_protects_runtime_and_marks_unknown_manual_review(fixtures_dir: Path) -> None:
    installed_programs = load_recommender_csv_rows(fixtures_dir / "installed_programs.csv")
    disk_usage_rows = load_recommender_csv_rows(fixtures_dir / "disk_usage.csv")
    mapping_rows = load_recommender_csv_rows(fixtures_dir / "software_project_mapping.csv")
    project_rows = load_recommender_csv_rows(fixtures_dir / "project_tech_stack.csv")
    category_rules = load_category_rules(Path("category_rules.yaml"))

    recommendations = build_recommendations(
        installed_programs=installed_programs,
        disk_usage_rows=disk_usage_rows,
        mapping_rows=mapping_rows,
        category_rules=category_rules,
        project_rows=project_rows,
    )
    by_name = {entry.software_name: entry for entry in recommendations}

    assert by_name["Python 3.11"].decision == "KEEP"
    assert by_name["Docker Desktop"].decision in {"KEEP", "UNSURE"}
    assert by_name["Microsoft Visual C++ 2015-2022 Redistributable"].decision == "MANUAL_REVIEW"
    assert by_name["Mystery Tool"].category == "Unknown"
    assert by_name["Mystery Tool"].decision == "MANUAL_REVIEW"


def test_load_csv_rows_returns_empty_for_missing_file(tmp_path: Path) -> None:
    assert load_recommender_csv_rows(tmp_path / "missing.csv") == []
