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
    "github_url",
    "repo_description",
    "user_notes",
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
    "github_url",
    "repo_description",
    "user_notes",
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

PROJECT_NOTES_PATH = Path("project_notes.csv")
PROJECT_ROOT_MARKERS = (".git", ".gitignore")
README_MARKERS = ("README.md", "README.txt", "README.rst")
PROJECT_STRUCTURE_MARKERS = {
    "src",
    "app",
    "apps",
    "public",
    "server",
    "client",
    "backend",
    "frontend",
    "api",
    "tests",
    "docs",
}
PROJECT_FILE_MARKERS = {
    "app.py",
    "manage.py",
    "main.py",
    "index.js",
    "index.ts",
    "index.tsx",
    "index.jsx",
    "app.js",
    "app.ts",
    "app.tsx",
    "app.jsx",
    "vite.config.js",
    "vite.config.ts",
    "next.config.js",
    "next.config.mjs",
}
IGNORED_PROJECT_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".vscode",
    ".idea",
    ".vs",
    ".cursor",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "site-packages",
    "dist-packages",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".next",
    ".nuxt",
    "vendor",
    "coverage",
    "dist",
    "build",
}
IGNORED_PATH_FRAGMENTS = (
    "\\.vscode\\",
    "\\.vscode\\extensions\\",
    "\\.cursor\\",
    "\\.cursor\\extensions\\",
    "\\.antigravity\\",
    "\\.antigravity-ide\\",
    "\\.p2\\",
    "\\.codex\\",
    "\\appdata\\local\\programs\\microsoft vs code\\resources\\app\\extensions\\",
    "\\appdata\\local\\programs\\cursor\\resources\\app\\extensions\\",
    "\\appdata\\roaming\\npm\\node_modules\\",
    "\\.nuget\\packages\\",
    "\\.cargo\\registry\\",
    "\\.cargo\\git\\",
    "\\go\\pkg\\mod\\",
)


def scan_projects(project_roots: Iterable[Path], exclude_paths: Iterable[Path]) -> tuple[list[ProjectTechStackEntry], list[ProjectFileIndexEntry]]:
    project_entries: list[ProjectTechStackEntry] = []
    file_index_entries: list[ProjectFileIndexEntry] = []
    normalized_excludes = {normalize_path(path) for path in exclude_paths}
    project_notes = load_project_notes(PROJECT_NOTES_PATH)

    for root in project_roots:
        normalized_root = normalize_path(root)
        if not normalized_root.exists():
            LOGGER.info("Project root does not exist, skipping: %s", normalized_root)
            continue

        LOGGER.info("Scanning project root: %s", normalized_root)
        for project_path in find_project_directories(normalized_root, normalized_excludes):
            project_entry, project_files = analyze_project(project_path, project_notes)
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
            if directory_name.casefold() in IGNORED_PROJECT_DIR_NAMES:
                continue
            if should_skip_path(candidate, exclude_paths):
                continue
            filtered_directories.append(directory_name)
        directory_names[:] = filtered_directories

        for file_name in file_names:
            lower_name = file_name.casefold()
            if file_name in SIGNATURES or lower_name in SIGNATURES:
                project_root = infer_project_root(current_path, root)
                if project_root is not None:
                    projects.add(project_root)

    return sorted(projects)


def analyze_project(
    project_path: Path,
    project_notes: dict[str, dict[str, str]] | None = None,
) -> tuple[ProjectTechStackEntry | None, list[ProjectFileIndexEntry]]:
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
    notes = resolve_project_notes(project_path, repo_name, project_notes or {})
    github_url = notes.get("github_url_override", "") or detect_github_url(project_path)
    repo_description = notes.get("repo_description_override", "") or detect_repo_description(project_path)
    user_notes = notes.get("user_notes", "")

    for file_path in important_files:
        technology, dependencies, keywords = analyze_signature_file(file_path)
        detected_technologies.extend(technology)
        dependency_fragments.extend(dependencies)

        index_entries.append(
            ProjectFileIndexEntry(
                project_name=project_path.name,
                repo_name=repo_name,
                project_path=str(project_path),
                github_url=github_url,
                repo_description=repo_description,
                user_notes=user_notes,
                file_path=str(file_path),
                file_name=file_path.name,
                detected_technology=",".join(unique_sorted(technology)),
                dependencies_summary="; ".join(unique_sorted(dependencies)),
                matched_keywords=",".join(unique_sorted(keywords)),
                last_modified=last_modified,
                searchable_text=build_searchable_text(
                    file_path.name,
                    technology,
                    dependencies,
                    keywords,
                    repo_description,
                    user_notes,
                    github_url,
                ),
            )
        )

    project_entry = ProjectTechStackEntry(
        project_name=project_path.name,
        repo_name=repo_name,
        path=str(project_path),
        github_url=github_url,
        repo_description=repo_description,
        user_notes=user_notes,
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
        deps = parse_package_json(content, file_path)
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


def parse_package_json(content: str, file_path: Path | None = None) -> list[str]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as error:
        if file_path is not None:
            LOGGER.warning("Invalid package.json content encountered at %s: %s", file_path, error)
        else:
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


def build_searchable_text(
    file_name: str,
    technologies: list[str],
    dependencies: list[str],
    keywords: list[str],
    repo_description: str = "",
    user_notes: str = "",
    github_url: str = "",
) -> str:
    parts = [file_name, *technologies, *dependencies, *keywords, repo_description, user_notes, github_url]
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


def infer_project_root(current_path: Path, scan_root: Path) -> Path | None:
    normalized_current = normalize_path(current_path)
    normalized_scan_root = normalize_path(scan_root)
    candidate = normalized_current

    while True:
        if is_real_project_root(candidate):
            return candidate
        if candidate == normalized_scan_root:
            break
        if candidate.parent == candidate:
            break
        candidate = candidate.parent

    return None


def has_project_root_marker(path: Path) -> bool:
    for marker in PROJECT_ROOT_MARKERS:
        try:
            if (path / marker).exists():
                return True
        except OSError:
            continue
    return False


def has_real_project_pattern(path: Path) -> bool:
    try:
        child_names = {child.name.casefold() for child in path.iterdir()}
    except OSError:
        return False

    has_readme = any(marker.casefold() in child_names for marker in README_MARKERS)
    has_structure_dir = any(marker.casefold() in child_names for marker in PROJECT_STRUCTURE_MARKERS)
    has_file_marker = any(marker.casefold() in child_names for marker in PROJECT_FILE_MARKERS)
    has_signature = directory_has_signature(child_names)

    patterns = (
        has_readme and has_structure_dir,
        has_readme and has_signature,
        "package.json" in child_names and has_structure_dir,
        "requirements.txt" in child_names and ("app.py" in child_names or "main.py" in child_names or has_structure_dir),
        "pyproject.toml" in child_names and has_structure_dir,
        "environment.yml" in child_names and has_structure_dir,
        "dockerfile" in child_names and has_structure_dir,
        any(name.endswith(".sln") for name in child_names) and has_structure_dir,
        any(name.endswith(".csproj") for name in child_names) and has_structure_dir,
        has_signature and has_file_marker,
    )
    return any(patterns)


def is_real_project_root(path: Path) -> bool:
    try:
        child_names = {child.name.casefold() for child in path.iterdir()}
    except OSError:
        return False

    has_marker = any(marker.casefold() in child_names for marker in PROJECT_ROOT_MARKERS)
    has_readme = any(marker.casefold() in child_names for marker in README_MARKERS)
    has_structure_dir = any(marker.casefold() in child_names for marker in PROJECT_STRUCTURE_MARKERS)
    has_file_marker = any(marker.casefold() in child_names for marker in PROJECT_FILE_MARKERS)
    has_signature = directory_has_signature(child_names)

    if has_real_project_pattern(path):
        return True

    marker_supported_patterns = (
        has_marker and has_readme and has_structure_dir,
        has_marker and has_signature and has_structure_dir,
        has_marker and has_signature and has_file_marker,
        has_marker and has_readme and has_file_marker,
    )
    return any(marker_supported_patterns)


def directory_has_signature(child_names: set[str]) -> bool:
    exact_signatures = {name.casefold() for name in SIGNATURES if not name.startswith(".")}
    extension_signatures = tuple(name.casefold() for name in SIGNATURES if name.startswith("."))
    if any(name in child_names for name in exact_signatures):
        return True
    return any(any(child_name.endswith(extension) for extension in extension_signatures) for child_name in child_names)


def should_skip_path(path: Path, exclude_paths: set[Path]) -> bool:
    lower_path = str(normalize_path(path)).casefold()
    if any(fragment in lower_path for fragment in IGNORED_PATH_FRAGMENTS):
        return True
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


def detect_github_url(project_path: Path) -> str:
    git_config = project_path / ".git" / "config"
    if not git_config.exists():
        return ""
    try:
        content = git_config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    match = re.search(r"url\s*=\s*(.+)$", content, flags=re.MULTILINE)
    if not match:
        return ""
    raw_url = match.group(1).strip()
    if raw_url.startswith("git@github.com:"):
        repo_path = raw_url.split(":", maxsplit=1)[1]
        if repo_path.endswith(".git"):
            repo_path = repo_path[:-4]
        return f"https://github.com/{repo_path}"
    if raw_url.startswith("https://github.com/") or raw_url.startswith("http://github.com/"):
        return raw_url[:-4] if raw_url.endswith(".git") else raw_url
    return raw_url


def detect_repo_description(project_path: Path) -> str:
    for candidate_name in ("README.md", "README.txt", "README.rst"):
        readme_path = project_path / candidate_name
        if not readme_path.exists():
            continue
        try:
            content = readme_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        description = extract_readme_description(content)
        if description:
            return description
    return ""


def extract_readme_description(content: str) -> str:
    cleaned_lines = [line.replace("\ufeff", "").strip() for line in content.splitlines()]
    paragraph_lines: list[str] = []
    for line in cleaned_lines:
        if not line:
            if paragraph_lines:
                break
            continue
        if line.startswith("#"):
            continue
        paragraph_lines.append(line)
    return " ".join(paragraph_lines)[:400]


def load_project_notes(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    notes: dict[str, dict[str, str]] = {}
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                project_name = row.get("project_name", "").strip().casefold()
                repo_name = row.get("repo_name", "").strip().casefold()
                path_contains = row.get("path_contains", "").strip().casefold()
                if project_name:
                    notes[f"project:{project_name}"] = row
                if repo_name:
                    notes[f"repo:{repo_name}"] = row
                if path_contains:
                    notes[f"path:{path_contains}"] = row
    except OSError as error:
        LOGGER.warning("Could not read project notes file %s: %s", path, error)
    return notes


def resolve_project_notes(
    project_path: Path,
    repo_name: str,
    project_notes: dict[str, dict[str, str]],
) -> dict[str, str]:
    project_key = f"project:{project_path.name.casefold()}"
    repo_key = f"repo:{repo_name.casefold()}"
    path_text = str(project_path).casefold()

    if project_key in project_notes:
        return project_notes[project_key]
    if repo_key in project_notes:
        return project_notes[repo_key]
    for key, value in project_notes.items():
        if key.startswith("path:") and key[5:] in path_text:
            return value
    return {}


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
