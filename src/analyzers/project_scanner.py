from __future__ import annotations

import csv
import json
import logging
import os
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
import xml.etree.ElementTree as ET

from src.windows_software_inventory_analyzer.models import ProjectFileIndexEntry, ProjectTechStackEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.analyzers.project_scanner")

PROJECT_TECH_HEADERS = (
    "project_name",
    "repo_name",
    "path",
    "detected_technologies",
    "dependencies_summary",
    "last_modified",
    "file_count",
    "important_files",
)

PROJECT_FILE_INDEX_HEADERS = (
    "project_name",
    "repo_name",
    "project_path",
    "file_path",
    "file_name",
    "detected_technology",
    "dependencies_summary",
    "matched_keywords",
    "last_modified",
    "searchable_text",
)

SIGNATURES: dict[str, str] = {
    "package.json": "nodejs",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "environment.yml": "python",
    "dockerfile": "docker",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "build.gradle.kts": "java-gradle",
    ".sln": ".net",
    ".csproj": ".net",
}

EXTRA_KEYWORD_TECH = {
    "react": "react",
    "next": "nextjs",
    "vue": "vue",
    "angular": "angular",
    "express": "express",
    "nestjs": "nestjs",
    "flask": "flask",
    "fastapi": "fastapi",
    "django": "django",
    "spring": "spring",
    "kotlin": "kotlin",
    "android": "android",
    "docker": "docker",
    "postgres": "postgresql",
    "mysql": "mysql",
    "mongodb": "mongodb",
}


def scan_projects(project_roots: Iterable[Path], exclude_paths: Iterable[Path]) -> tuple[list[ProjectTechStackEntry], list[ProjectFileIndexEntry]]:
    project_entries: list[ProjectTechStackEntry] = []
    file_index_entries: list[ProjectFileIndexEntry] = []
    normalized_excludes = {normalize_path(path) for path in exclude_paths}

    for root in project_roots:
        normalized_root = normalize_path(root)
        if not normalized_root.exists():
            LOGGER.info("Project root does not exist, skipping: %s", normalized_root)
            continue

        LOGGER.info("Scanning project root: %s", normalized_root)
        for project_path in find_project_directories(normalized_root, normalized_excludes):
            project_entry, project_files = analyze_project(project_path)
            if project_entry is None:
                continue
            project_entries.append(project_entry)
            file_index_entries.extend(project_files)

    project_entries.sort(key=lambda entry: entry.last_modified, reverse=True)
    file_index_entries.sort(key=lambda entry: (entry.project_name.casefold(), entry.file_path.casefold()))
    return project_entries, file_index_entries


def find_project_directories(root: Path, exclude_paths: set[Path]) -> list[Path]:
    projects: set[Path] = set()
    for current_root, directory_names, file_names in os.walk(root):
        current_path = normalize_path(Path(current_root))
        if should_skip_path(current_path, exclude_paths):
            directory_names[:] = []
            continue

        filtered_directories: list[str] = []
        for directory_name in directory_names:
            candidate = current_path / directory_name
            if should_skip_path(candidate, exclude_paths):
                continue
            filtered_directories.append(directory_name)
        directory_names[:] = filtered_directories

        for file_name in file_names:
            lower_name = file_name.casefold()
            if file_name in SIGNATURES or lower_name in SIGNATURES:
                projects.add(current_path)

    return sorted(projects)


def analyze_project(project_path: Path) -> tuple[ProjectTechStackEntry | None, list[ProjectFileIndexEntry]]:
    try:
        important_files = sorted(
            path for path in project_path.iterdir() if path.is_file() and is_signature_file(path.name)
        )
    except OSError as error:
        LOGGER.warning("Could not inspect project directory %s: %s", project_path, error)
        return None, []

    if not important_files:
        return None, []

    detected_technologies: list[str] = []
    dependency_fragments: list[str] = []
    index_entries: list[ProjectFileIndexEntry] = []
    last_modified = get_last_modified(project_path)
    file_count = count_files(project_path)
    repo_name = detect_repo_name(project_path)

    for file_path in important_files:
        technology, dependencies, keywords = analyze_signature_file(file_path)
        detected_technologies.extend(technology)
        dependency_fragments.extend(dependencies)

        index_entries.append(
            ProjectFileIndexEntry(
                project_name=project_path.name,
                repo_name=repo_name,
                project_path=str(project_path),
                file_path=str(file_path),
                file_name=file_path.name,
                detected_technology=",".join(unique_sorted(technology)),
                dependencies_summary="; ".join(unique_sorted(dependencies)),
                matched_keywords=",".join(unique_sorted(keywords)),
                last_modified=last_modified,
                searchable_text=build_searchable_text(file_path.name, technology, dependencies, keywords),
            )
        )

    project_entry = ProjectTechStackEntry(
        project_name=project_path.name,
        repo_name=repo_name,
        path=str(project_path),
        detected_technologies=",".join(unique_sorted(detected_technologies)),
        dependencies_summary="; ".join(unique_sorted(dependency_fragments)),
        last_modified=last_modified,
        file_count=file_count,
        important_files=",".join(path.name for path in important_files),
    )
    return project_entry, index_entries


def analyze_signature_file(file_path: Path) -> tuple[list[str], list[str], list[str]]:
    lower_name = file_path.name.casefold()
    base_tech = [SIGNATURES[lower_name] if lower_name in SIGNATURES else SIGNATURES.get(file_path.name, "")]
    technologies = [item for item in base_tech if item]
    dependencies: list[str] = []
    keywords: list[str] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        LOGGER.warning("Could not read project file %s: %s", file_path, error)
        return technologies, dependencies, keywords

    if lower_name == "package.json":
        deps = parse_package_json(content)
        dependencies.extend(deps)
    elif lower_name == "requirements.txt":
        deps = parse_requirements_txt(content)
        dependencies.extend(deps)
    elif lower_name == "pyproject.toml":
        deps = parse_pyproject_toml(content)
        dependencies.extend(deps)
    elif lower_name == "environment.yml":
        deps = parse_environment_yml(content)
        dependencies.extend(deps)
    elif lower_name in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
        deps = parse_docker_content(content)
        dependencies.extend(deps)
    elif lower_name == "pom.xml":
        deps = parse_pom_xml(content)
        dependencies.extend(deps)
    elif lower_name in {"build.gradle", "build.gradle.kts"}:
        deps = parse_gradle_file(content)
        dependencies.extend(deps)
    elif lower_name == ".sln":
        deps = parse_solution_file(content)
        dependencies.extend(deps)
    elif lower_name == ".csproj":
        deps = parse_csproj_file(content)
        dependencies.extend(deps)

    keywords.extend(match_keywords(file_path.name))
    for dependency in dependencies:
        keywords.extend(match_keywords(dependency))
        technologies.extend(match_technologies(dependency))

    return unique_sorted(technologies), unique_sorted(dependencies), unique_sorted(keywords)


def parse_package_json(content: str) -> list[str]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as error:
        LOGGER.warning("Invalid package.json content encountered: %s", error)
        return fallback_tokens(content)

    dependencies: list[str] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = payload.get(key, {})
        if isinstance(values, dict):
            dependencies.extend(str(name) for name in values.keys())
    return dependencies


def parse_requirements_txt(content: str) -> list[str]:
    dependencies: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        token = re.split(r"[<>=!~\[]", stripped, maxsplit=1)[0].strip()
        if token:
            dependencies.append(token)
    return dependencies


def parse_pyproject_toml(content: str) -> list[str]:
    matches = re.findall(r'["\']([A-Za-z0-9_.\-]+)[<>=!~ ]', content)
    return matches or fallback_tokens(content)


def parse_environment_yml(content: str) -> list[str]:
    dependencies = []
    for line in content.splitlines():
        stripped = line.strip().lstrip("-").strip()
        if not stripped or ":" in stripped and not stripped.startswith("python"):
            continue
        token = re.split(r"[<>=!~ ]", stripped, maxsplit=1)[0].strip()
        if token and token not in {"dependencies", "channels", "name"}:
            dependencies.append(token)
    return dependencies


def parse_docker_content(content: str) -> list[str]:
    dependencies = re.findall(r"FROM\s+([^\s]+)", content, flags=re.IGNORECASE)
    dependencies.extend(re.findall(r"image:\s*([^\s]+)", content, flags=re.IGNORECASE))
    return dependencies


def parse_pom_xml(content: str) -> list[str]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        LOGGER.warning("Invalid pom.xml content encountered: %s", error)
        return fallback_tokens(content)

    namespaces = {"m": root.tag.partition("}")[0].strip("{")} if "}" in root.tag else {}
    dependency_tags = root.findall(".//m:dependency", namespaces) if namespaces else root.findall(".//dependency")
    dependencies = []
    for dependency in dependency_tags:
        group_id = find_xml_text(dependency, "groupId", namespaces)
        artifact_id = find_xml_text(dependency, "artifactId", namespaces)
        combined = ":".join(part for part in (group_id, artifact_id) if part)
        if combined:
            dependencies.append(combined)
    return dependencies


def parse_gradle_file(content: str) -> list[str]:
    matches = re.findall(r'["\']([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+(?::[A-Za-z0-9_.\-]+)?)["\']', content)
    return matches or fallback_tokens(content)


def parse_solution_file(content: str) -> list[str]:
    return re.findall(r'Project\(".*?"\)\s*=\s*".*?",\s*"(.*?)"', content)


def parse_csproj_file(content: str) -> list[str]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        LOGGER.warning("Invalid .csproj content encountered: %s", error)
        return fallback_tokens(content)

    package_refs = root.findall(".//PackageReference")
    project_refs = root.findall(".//ProjectReference")
    dependencies = []
    for node in [*package_refs, *project_refs]:
        include = node.attrib.get("Include", "")
        if include:
            dependencies.append(include)
    return dependencies


def find_xml_text(node: ET.Element, tag_name: str, namespaces: dict[str, str]) -> str:
    element = node.find(f"m:{tag_name}", namespaces) if namespaces else node.find(tag_name)
    return element.text.strip() if element is not None and element.text else ""


def fallback_tokens(content: str) -> list[str]:
    return re.findall(r"[A-Za-z][A-Za-z0-9_.\-]{2,}", content)[:25]


def match_keywords(value: str) -> list[str]:
    lowered = value.casefold()
    return [keyword for keyword in EXTRA_KEYWORD_TECH if keyword in lowered]


def match_technologies(value: str) -> list[str]:
    lowered = value.casefold()
    return [technology for keyword, technology in EXTRA_KEYWORD_TECH.items() if keyword in lowered]


def build_searchable_text(file_name: str, technologies: list[str], dependencies: list[str], keywords: list[str]) -> str:
    parts = [file_name, *technologies, *dependencies, *keywords]
    return " ".join(unique_sorted(parts))


def search_project_index(entries: Iterable[ProjectFileIndexEntry], keyword: str) -> list[ProjectFileIndexEntry]:
    lowered = keyword.casefold().strip()
    if not lowered:
        return []
    return [
        entry
        for entry in entries
        if lowered in entry.file_name.casefold()
        or lowered in entry.dependencies_summary.casefold()
        or lowered in entry.searchable_text.casefold()
    ]


def unique_sorted(items: Iterable[str]) -> list[str]:
    return sorted({item.strip() for item in items if item and item.strip()}, key=str.casefold)


def is_signature_file(file_name: str) -> bool:
    lower_name = file_name.casefold()
    return file_name in SIGNATURES or lower_name in SIGNATURES


def normalize_path(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except OSError:
        return path.expanduser()


def should_skip_path(path: Path, exclude_paths: set[Path]) -> bool:
    lower_path = str(normalize_path(path)).casefold()
    return any(lower_path == str(excluded).casefold() or lower_path.startswith(f"{str(excluded).casefold()}\\") for excluded in exclude_paths)


def count_files(project_path: Path) -> int:
    count = 0
    try:
        iterator = project_path.rglob("*")
    except OSError:
        return 0

    for file_path in iterator:
        try:
            if file_path.is_file():
                count += 1
        except OSError:
            continue
    return count


def get_last_modified(project_path: Path) -> str:
    try:
        latest_timestamp = project_path.stat().st_mtime
    except OSError:
        latest_timestamp = datetime.now(timezone.utc).timestamp()

    try:
        iterator = project_path.rglob("*")
    except OSError:
        return datetime.fromtimestamp(latest_timestamp, tz=timezone.utc).isoformat()

    for file_path in iterator:
        try:
            latest_timestamp = max(latest_timestamp, file_path.stat().st_mtime)
        except OSError:
            continue
    return datetime.fromtimestamp(latest_timestamp, tz=timezone.utc).isoformat()


def detect_repo_name(project_path: Path) -> str:
    git_config = project_path / ".git" / "config"
    if git_config.exists():
        try:
            content = git_config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return project_path.name
        match = re.search(r"url\s*=\s*.*?/([^/\s]+?)(?:\.git)?\s*$", content, flags=re.MULTILINE)
        if match:
            return match.group(1)
    return project_path.name


def write_project_reports(
    project_entries: list[ProjectTechStackEntry],
    file_index_entries: list[ProjectFileIndexEntry],
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    project_stack_path = output_dir / "project_tech_stack.csv"
    project_index_path = output_dir / "project_files_index.csv"

    with project_stack_path.open("w", encoding="utf-8-sig", newline="") as project_stack_file:
        writer = csv.DictWriter(project_stack_file, fieldnames=PROJECT_TECH_HEADERS)
        writer.writeheader()
        for entry in project_entries:
            writer.writerow(asdict(entry))

    with project_index_path.open("w", encoding="utf-8-sig", newline="") as project_index_file:
        writer = csv.DictWriter(project_index_file, fieldnames=PROJECT_FILE_INDEX_HEADERS)
        writer.writeheader()
        for entry in file_index_entries:
            writer.writerow(asdict(entry))

    return project_stack_path, project_index_path
