from __future__ import annotations

from pathlib import Path

from src.analyzers.project_scanner import (
    analyze_signature_file,
    scan_projects,
    search_project_index,
)


def test_analyze_signature_file_falls_back_on_invalid_package_json(tmp_path: Path) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text("{ invalid json", encoding="utf-8")

    technologies, dependencies, keywords = analyze_signature_file(package_json)

    assert "nodejs" in technologies
    assert dependencies
    assert keywords == []


def test_scan_projects_handles_empty_root(tmp_path: Path) -> None:
    projects, file_index = scan_projects([tmp_path], [])

    assert projects == []
    assert file_index == []


def test_search_project_index_matches_dependency(fixtures_dir: Path) -> None:
    _, file_index_entries = scan_projects([], [])
    assert file_index_entries == []

    rows = [
        {
            "project_name": "vision-app",
            "repo_name": "vision-app",
            "project_path": "D:/Projects/vision-app",
            "file_path": "D:/Projects/vision-app/requirements.txt",
            "file_name": "requirements.txt",
            "detected_technology": "python",
            "dependencies_summary": "opencv-python; fastapi",
            "matched_keywords": "opencv,fastapi",
            "last_modified": "2026-06-10T10:00:00+00:00",
            "searchable_text": "requirements.txt python opencv-python fastapi opencv",
        }
    ]

    results = search_project_index(
        [type("Entry", (), row)() for row in rows],  # simple object with attributes
        "opencv",
    )

    assert len(results) == 1
