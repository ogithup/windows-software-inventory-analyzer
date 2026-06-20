from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path

from src.windows_software_inventory_analyzer.models import DotnetSdkValidationEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.analyzers.dotnet_sdk_validator")

VALIDATION_HEADERS = (
    "project_name",
    "target_path",
    "target_type",
    "selected_sdk",
    "selected_feature_band",
    "global_json_version",
    "required_frameworks",
    "build_status",
    "build_exit_code",
    "validation_mode",
    "notes",
)

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
    "packages",
    ".venv",
    "venv",
    "env",
    "__pycache__",
}


def validate_dotnet_sdks(
    project_roots: list[Path],
    exclude_paths: list[Path],
    artifacts_root: Path,
    project_rows: list[dict[str, str]] | None = None,
    quick: bool = False,
    dry_run: bool = False,
) -> list[DotnetSdkValidationEntry]:
    targets = discover_dotnet_targets(project_roots, exclude_paths, project_rows=project_rows or [], quick=quick)
    if not targets:
        LOGGER.info("No .NET build targets found for validation.")
        return []

    results: list[DotnetSdkValidationEntry] = []
    artifacts_root.mkdir(parents=True, exist_ok=True)

    for target in targets:
        selected_sdk = detect_selected_sdk(target.parent)
        global_json_version = find_nearest_global_json_version(target.parent)
        required_frameworks = ",".join(infer_required_frameworks(target))
        selected_band = feature_band(selected_sdk)
        notes = build_validation_notes(selected_sdk, global_json_version, required_frameworks, dry_run)

        if dry_run:
            results.append(
                DotnetSdkValidationEntry(
                    project_name=target.stem,
                    target_path=str(target),
                    target_type=target.suffix.lstrip("."),
                    selected_sdk=selected_sdk,
                    selected_feature_band=selected_band,
                    global_json_version=global_json_version,
                    required_frameworks=required_frameworks,
                    build_status="DISCOVERED_ONLY",
                    build_exit_code=0,
                    validation_mode="dotnet --version only (dry-run)",
                    notes=notes,
                )
            )
            continue

        build_status, exit_code, build_notes = run_dotnet_build_validation(target, artifacts_root)
        combined_notes = " | ".join(part for part in (notes, build_notes) if part)
        results.append(
            DotnetSdkValidationEntry(
                project_name=target.stem,
                target_path=str(target),
                target_type=target.suffix.lstrip("."),
                selected_sdk=selected_sdk,
                selected_feature_band=selected_band,
                global_json_version=global_json_version,
                required_frameworks=required_frameworks,
                build_status=build_status,
                build_exit_code=exit_code,
                validation_mode="dotnet --version + dotnet build",
                notes=combined_notes,
            )
        )

    return results


def discover_dotnet_targets(
    project_roots: list[Path],
    exclude_paths: list[Path],
    project_rows: list[dict[str, str]] | None = None,
    quick: bool = False,
) -> list[Path]:
    if quick and project_rows:
        return discover_dotnet_targets_from_project_rows(project_rows)

    normalized_excludes = {normalize_path(path) for path in exclude_paths}
    targets: list[Path] = []
    seen: set[str] = set()

    for root in project_roots:
        normalized_root = normalize_path(root)
        if not normalized_root.exists():
            continue

        for current_root, directory_names, file_names in walk_project_tree(normalized_root, normalized_excludes):
            current_path = normalize_path(Path(current_root))
            for file_name in file_names:
                lower_name = file_name.casefold()
                if not (lower_name.endswith(".sln") or lower_name.endswith(".csproj")):
                    continue
                target = normalize_path(current_path / file_name)
                if lower_name.endswith(".sln") and not solution_contains_managed_project(target):
                    continue
                key = str(target).casefold()
                if key in seen:
                    continue
                seen.add(key)
                targets.append(target)

    targets.sort(key=lambda item: (item.suffix != ".sln", str(item).casefold()))
    return targets


def discover_dotnet_targets_from_project_rows(project_rows: list[dict[str, str]]) -> list[Path]:
    targets: list[Path] = []
    seen: set[str] = set()
    for row in project_rows:
        technologies = {item.strip().casefold() for item in row.get("detected_technologies", "").split(",") if item.strip()}
        important_files = [item.strip() for item in row.get("important_files", "").split(",") if item.strip()]
        if ".net" not in technologies and not any(Path(name).suffix.casefold() in {".sln", ".csproj"} for name in important_files):
            continue
        project_path = normalize_path(Path(row.get("path", "")))
        for name in important_files:
            candidate = normalize_path(project_path / name)
            if not candidate.exists() or not candidate.is_file():
                continue
            lower_name = candidate.name.casefold()
            if not (lower_name.endswith(".sln") or lower_name.endswith(".csproj")):
                continue
            if lower_name.endswith(".sln") and not solution_contains_managed_project(candidate):
                continue
            key = str(candidate).casefold()
            if key in seen:
                continue
            seen.add(key)
            targets.append(candidate)
    targets.sort(key=lambda item: (item.suffix != ".sln", str(item).casefold()))
    return targets


def walk_project_tree(root: Path, exclude_paths: set[Path]):
    import os

    for current_root, directory_names, file_names in os.walk(root):
        current_path = normalize_path(Path(current_root))
        if should_skip_path(current_path, exclude_paths):
            directory_names[:] = []
            continue

        directory_names[:] = [
            name
            for name in directory_names
            if name.casefold() not in IGNORED_DIR_NAMES
            and not should_skip_path(current_path / name, exclude_paths)
        ]
        yield current_root, directory_names, file_names


def detect_selected_sdk(cwd: Path) -> str:
    completed = run_command(["dotnet", "--version"], cwd=cwd, timeout_seconds=30)
    if completed is None or completed.returncode != 0:
        return ""
    return completed.stdout.strip().splitlines()[0].strip() if completed.stdout.strip() else ""


def find_nearest_global_json_version(start_dir: Path) -> str:
    current = normalize_path(start_dir)
    while True:
        candidate = current / "global.json"
        if candidate.exists():
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                return ""
            sdk = payload.get("sdk", {})
            if isinstance(sdk, dict):
                return str(sdk.get("version", "")).strip()
            return ""
        if current.parent == current:
            break
        current = current.parent
    return ""


def infer_required_frameworks(target: Path) -> list[str]:
    if target.suffix.casefold() == ".csproj":
        return parse_csproj_frameworks(target)
    if target.suffix.casefold() == ".sln":
        frameworks: set[str] = set()
        solution_dir = target.parent
        try:
            iterator = solution_dir.rglob("*.csproj")
        except OSError:
            return []
        for csproj_path in iterator:
            for framework in parse_csproj_frameworks(csproj_path):
                frameworks.add(framework)
        return sorted(frameworks, key=str.casefold)
    return []


def solution_contains_managed_project(path: Path) -> bool:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return ".csproj" in content.casefold()


def parse_csproj_frameworks(path: Path) -> list[str]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ET.ParseError):
        return []

    frameworks: list[str] = []
    for tag_name in ("TargetFramework", "TargetFrameworks"):
        for node in root.findall(f".//{tag_name}"):
            if node.text:
                frameworks.extend(part.strip() for part in node.text.split(";") if part.strip())
    return sorted(set(frameworks), key=str.casefold)


def build_validation_notes(selected_sdk: str, global_json_version: str, required_frameworks: str, dry_run: bool) -> str:
    notes: list[str] = []
    if selected_sdk:
        notes.append(f"selected_sdk={selected_sdk}")
    if global_json_version:
        notes.append(f"global_json={global_json_version}")
        if selected_sdk and selected_sdk != global_json_version:
            notes.append("selected SDK global.json ile birebir ayni degil")
    if required_frameworks:
        notes.append(f"frameworks={required_frameworks}")
    if dry_run:
        notes.append("build calistirilmadi")
    return " | ".join(notes)


def run_dotnet_build_validation(target: Path, artifacts_root: Path) -> tuple[str, int, str]:
    artifact_dir = artifacts_root / build_target_slug(target)
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir, ignore_errors=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    obj_dir = artifact_dir / "obj"
    bin_dir = artifact_dir / "bin"
    packages_dir = artifact_dir / "packages"

    command = [
        "dotnet",
        "build",
        str(target),
        "-nologo",
        "-clp:ErrorsOnly",
        "--disable-build-servers",
        f"-p:BaseIntermediateOutputPath={ensure_trailing_sep(obj_dir)}",
        f"-p:MSBuildProjectExtensionsPath={ensure_trailing_sep(obj_dir)}",
        f"-p:OutputPath={ensure_trailing_sep(bin_dir)}",
        f"-p:RestorePackagesPath={ensure_trailing_sep(packages_dir)}",
    ]
    completed = run_command(command, cwd=target.parent, timeout_seconds=240)
    if completed is None:
        return "VALIDATION_FAILED", 1, "dotnet build baslatilamadi"

    if completed.returncode == 0:
        return "BUILD_PASSED", 0, "Build dogrulamasi basarili"

    output_text = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip()).strip()
    compact_output = " ".join(output_text.split())[:400]
    return "BUILD_FAILED", completed.returncode, compact_output or "dotnet build basarisiz oldu"


def write_dotnet_sdk_validation_report(entries: list[DotnetSdkValidationEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "sdk_validation_report.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=VALIDATION_HEADERS)
        writer.writeheader()
        for entry in entries:
            writer.writerow(asdict(entry))
    return path


def build_target_slug(target: Path) -> str:
    digest = hashlib.sha1(str(target).encode("utf-8", errors="replace")).hexdigest()[:10]
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", target.stem)[:40].strip("-") or "dotnet-target"
    return f"{safe_name}-{digest}"


def feature_band(version: str) -> str:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return ""
    major, minor, patch = match.groups()
    band = int(patch) // 100
    return f"{major}.{minor}.{band}xx"


def ensure_trailing_sep(path: Path) -> str:
    return f"{path}{os.sep}"


def run_command(command: list[str], cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        LOGGER.info("Command failed: %s | %s", " ".join(command), error)
        return None


def normalize_path(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except OSError:
        return path.expanduser()


def should_skip_path(path: Path, exclude_paths: set[Path]) -> bool:
    lower_path = str(path).casefold()
    return any(lower_path == str(excluded).casefold() or lower_path.startswith(f"{str(excluded).casefold()}\\") for excluded in exclude_paths)
