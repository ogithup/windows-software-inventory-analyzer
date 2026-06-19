from __future__ import annotations

import csv
import logging
import re
from dataclasses import asdict
from pathlib import Path

from src.windows_software_inventory_analyzer.models import ProjectCodeSignalEntry, ProjectTechStackEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.analyzers.repo_deep_scanner")

PROJECT_CODE_SIGNAL_HEADERS = (
    "project_name",
    "repo_name",
    "project_path",
    "github_url",
    "detected_libraries",
    "framework_signals",
    "code_evidence",
    "source_files_scanned",
    "last_modified",
)

SUPPORTED_SOURCE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".cs",
    ".md",
    ".yml",
    ".yaml",
}

IGNORED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".vs",
    ".vscode",
    ".idea",
    ".cursor",
    "node_modules",
    "bin",
    "obj",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    "coverage",
}

LIBRARY_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "opencv": [
        re.compile(r"\bimport\s+cv2\b"),
        re.compile(r"\bfrom\s+cv2\b"),
    ],
    "mediapipe": [
        re.compile(r"\bimport\s+mediapipe\b"),
        re.compile(r"\bfrom\s+mediapipe\b"),
    ],
    "pyshark": [
        re.compile(r"\bimport\s+pyshark\b"),
        re.compile(r"\bfrom\s+pyshark\b"),
    ],
    "torch": [
        re.compile(r"\bimport\s+torch\b"),
        re.compile(r"\bfrom\s+torch\b"),
    ],
    "tensorflow": [
        re.compile(r"\bimport\s+tensorflow\b"),
        re.compile(r"\bfrom\s+tensorflow\b"),
    ],
    "react": [
        re.compile(r"\bfrom\s+['\"]react['\"]"),
        re.compile(r"\brequire\(['\"]react['\"]\)"),
    ],
    "nextjs": [
        re.compile(r"\bfrom\s+['\"]next/"),
        re.compile(r"\bnext\.config\."),
    ],
    "spring": [
        re.compile(r"\borg\.springframework\b"),
        re.compile(r"\bimport\s+org\.springframework"),
    ],
    "aspnet": [
        re.compile(r"\busing\s+Microsoft\.AspNetCore"),
        re.compile(r"\bWebApplication\.CreateBuilder\b"),
    ],
    "entityframework": [
        re.compile(r"\busing\s+Microsoft\.EntityFrameworkCore"),
    ],
    "docker": [
        re.compile(r"^\s*FROM\s+[^\n]+$", re.IGNORECASE | re.MULTILINE),
        re.compile(r"^\s*image:\s*", re.IGNORECASE | re.MULTILINE),
    ],
    "github_actions": [
        re.compile(r"^\s*uses:\s*actions/", re.IGNORECASE | re.MULTILINE),
        re.compile(r"^\s*on:\s*", re.IGNORECASE | re.MULTILINE),
    ],
}

FRAMEWORK_LIBRARY_MAP = {
    "opencv": "computer_vision",
    "mediapipe": "computer_vision",
    "torch": "ai_ml",
    "tensorflow": "ai_ml",
    "react": "frontend",
    "nextjs": "frontend",
    "spring": "backend",
    "aspnet": "backend",
    "entityframework": "database",
    "pyshark": "network",
    "docker": "virtualization",
    "github_actions": "ci_cd",
}


def scan_project_code_signals(project_entries: list[ProjectTechStackEntry]) -> list[ProjectCodeSignalEntry]:
    results: list[ProjectCodeSignalEntry] = []

    for project in project_entries:
        project_path = Path(project.path)
        libraries: list[str] = []
        framework_signals: list[str] = []
        evidence_parts: list[str] = []
        scanned_files = 0

        if not project_path.exists():
            LOGGER.debug("Project path does not exist for deep scan: %s", project_path)
            results.append(
                ProjectCodeSignalEntry(
                    project_name=project.project_name,
                    repo_name=project.repo_name,
                    project_path=project.path,
                    github_url=project.github_url,
                    detected_libraries="",
                    framework_signals="",
                    code_evidence="",
                    source_files_scanned=0,
                    last_modified=project.last_modified,
                )
            )
            continue

        for file_path in iter_source_files(project_path):
            scanned_files += 1
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                LOGGER.debug("Could not read source file %s: %s", file_path, error)
                continue

            relative_path = file_path.relative_to(project_path)
            file_libraries, file_frameworks, file_evidence = analyze_source_content(relative_path, content)
            libraries.extend(file_libraries)
            framework_signals.extend(file_frameworks)
            evidence_parts.extend(file_evidence)

        results.append(
            ProjectCodeSignalEntry(
                project_name=project.project_name,
                repo_name=project.repo_name,
                project_path=project.path,
                github_url=project.github_url,
                detected_libraries=",".join(unique_sorted(libraries)),
                framework_signals=",".join(unique_sorted(framework_signals)),
                code_evidence=" | ".join(unique_sorted(evidence_parts))[:2000],
                source_files_scanned=scanned_files,
                last_modified=project.last_modified,
            )
        )

    results.sort(key=lambda item: item.project_name.casefold())
    return results


def iter_source_files(project_path: Path):
    for current_root, directory_names, file_names in __import__("os").walk(project_path):
        directory_names[:] = [name for name in directory_names if name.casefold() not in IGNORED_DIR_NAMES]
        root_path = Path(current_root)
        for file_name in file_names:
            file_path = root_path / file_name
            lowered_name = file_name.casefold()
            if lowered_name == "dockerfile":
                yield file_path
                continue
            if lowered_name in {"readme.md", "readme.txt", "readme.rst"}:
                yield file_path
                continue
            if lowered_name.endswith((".yml", ".yaml")) and ".github\\workflows" in str(file_path).replace("/", "\\").casefold():
                yield file_path
                continue
            if file_path.suffix.casefold() in SUPPORTED_SOURCE_SUFFIXES:
                yield file_path


def analyze_source_content(relative_path: Path, content: str) -> tuple[list[str], list[str], list[str]]:
    libraries: list[str] = []
    framework_signals: list[str] = []
    evidence_parts: list[str] = []
    compact_content = content[:120000]
    lowered_path = str(relative_path).replace("/", "\\").casefold()
    suffix = relative_path.suffix.casefold()
    is_docker_file = relative_path.name.casefold() == "dockerfile" or suffix in {".yml", ".yaml"} or "docker-compose" in lowered_path
    is_python = suffix == ".py"
    is_js = suffix in {".js", ".jsx", ".ts", ".tsx"}
    is_java = suffix == ".java"
    is_csharp = suffix == ".cs"
    is_github_workflow = ".github\\workflows\\" in lowered_path and suffix in {".yml", ".yaml"}

    for library, patterns in LIBRARY_PATTERNS.items():
        if library in {"opencv", "mediapipe", "pyshark", "torch", "tensorflow"} and not is_python:
            continue
        if library in {"react", "nextjs"} and not is_js:
            continue
        if library == "spring" and not is_java:
            continue
        if library in {"aspnet", "entityframework"} and not is_csharp:
            continue
        if library == "docker" and not is_docker_file:
            continue
        if library == "github_actions" and not is_github_workflow:
            continue
        for pattern in patterns:
            match = pattern.search(compact_content)
            if not match:
                continue
            libraries.append(library)
            framework = FRAMEWORK_LIBRARY_MAP.get(library)
            if framework:
                framework_signals.append(framework)
            snippet = compact_content[max(0, match.start() - 20) : min(len(compact_content), match.end() + 60)]
            snippet = " ".join(snippet.split())[:180]
            evidence_parts.append(f"{relative_path}: {library} -> {snippet}")
            break

    return unique_sorted(libraries), unique_sorted(framework_signals), unique_sorted(evidence_parts)


def merge_code_signals_into_projects(
    project_entries: list[ProjectTechStackEntry],
    code_signal_entries: list[ProjectCodeSignalEntry],
) -> list[ProjectTechStackEntry]:
    signals_by_name = {entry.project_name.casefold(): entry for entry in code_signal_entries}
    merged_entries: list[ProjectTechStackEntry] = []

    for project in project_entries:
        signal = signals_by_name.get(project.project_name.casefold())
        merged_entries.append(
            ProjectTechStackEntry(
                project_name=project.project_name,
                repo_name=project.repo_name,
                path=project.path,
                github_url=project.github_url,
                repo_description=project.repo_description,
                user_notes=project.user_notes,
                detected_technologies=merge_csv_fields(project.detected_technologies, signal.detected_libraries if signal else "", signal.framework_signals if signal else ""),
                dependencies_summary=project.dependencies_summary,
                detected_libraries=signal.detected_libraries if signal else "",
                framework_signals=signal.framework_signals if signal else "",
                code_evidence=signal.code_evidence if signal else "",
                last_modified=project.last_modified,
                file_count=project.file_count,
                important_files=project.important_files,
            )
        )

    return merged_entries


def write_project_code_signals(entries: list[ProjectCodeSignalEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "project_code_signals.csv"
    with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=PROJECT_CODE_SIGNAL_HEADERS)
        writer.writeheader()
        for entry in entries:
            writer.writerow(asdict(entry))
    return output_path


def merge_csv_fields(*values: str) -> str:
    items: list[str] = []
    for value in values:
        for item in value.split(","):
            normalized = item.strip()
            if normalized and normalized not in items:
                items.append(normalized)
    return ",".join(items)


def unique_sorted(items: list[str]) -> list[str]:
    return sorted({item.strip() for item in items if item and item.strip()}, key=str.casefold)
