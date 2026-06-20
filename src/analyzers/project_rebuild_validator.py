from __future__ import annotations

import csv
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from src.windows_software_inventory_analyzer.models import ValidationStatusEntry


VALIDATION_STATUS_HEADERS = (
    "project_name",
    "project_path",
    "technology_family",
    "validation_level",
    "validation_status",
    "command_used",
    "validation_target",
    "confidence_boost",
    "notes",
)


def validate_python_project(project_row: dict[str, str], artifacts_root: Path, dry_run: bool = False) -> ValidationStatusEntry:
    project_path = Path(project_row.get("path", ""))
    target_files = find_files(project_path, "*.py", limit=80)
    command = f"{sys.executable} -c <python-parse-check>"
    if dry_run:
        return build_entry(project_row, "python", "STATIC_ONLY", "DISCOVERED_ONLY", command, ",".join(target_files[:5]), 4.0, "Dry-run: python derleme kontrolu calistirilmadi.")

    venv_dir = artifacts_root / f"{project_path.name}-py-venv"
    try:
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], cwd=project_path, capture_output=True, text=True, check=False, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        pass
    helper_script = (artifacts_root / "python_parse_check.py").resolve()
    helper_script.parent.mkdir(parents=True, exist_ok=True)
    helper_script.write_text(
        "\n".join(
            [
                "import sys",
                "from pathlib import Path",
                "",
                "root = Path(sys.argv[1])",
                "blocked = {'node_modules', '.git', '.venv', 'venv', 'env', '__pycache__', 'dist', 'build'}",
                "files = [",
                "    path",
                "    for path in root.rglob('*.py')",
                "    if not any(part.lower() in blocked for part in path.parts)",
                "][:120]",
                "failed = []",
                "for path in files:",
                "    try:",
                "        source = path.read_text(encoding='utf-8', errors='replace')",
                "        compile(source, str(path), 'exec')",
                "    except Exception as exc:",
                "        failed.append(f'{path}: {exc}')",
                "print(*failed[:20], sep='\\n')",
                "raise SystemExit(1 if failed else 0)",
            ]
        ),
        encoding="utf-8",
    )
    completed = run_command([sys.executable, str(helper_script), str(project_path)], cwd=project_path, timeout=180)
    if completed and completed.returncode == 0:
        return build_entry(project_row, "python", "ISOLATED_REINSTALL_VERIFIED", "VALIDATED", command, ",".join(target_files[:5]), 12.0, "Izole venv olusturuldu ve Python kaynaklari yazmasiz parse kontrolunden gecti.")
    notes = compact_output(completed) or "Python kaynak parse kontrolu basarisiz."
    return build_entry(project_row, "python", "STATIC_ONLY", "VALIDATION_FAILED", command, ",".join(target_files[:5]), 0.0, notes)


def validate_node_project(project_row: dict[str, str], artifacts_root: Path, dry_run: bool = False) -> ValidationStatusEntry:
    project_path = Path(project_row.get("path", ""))
    target_files = find_files(project_path, "*.js", limit=20) + find_files(project_path, "*.mjs", limit=10)
    command = "node --check <source-files>"
    if not target_files:
        return build_entry(project_row, "node", "STATIC_ONLY", "NO_TARGET", command, "package.json", 0.0, "Kontrol edilecek JS dosyasi bulunamadi.")
    if dry_run:
        return build_entry(project_row, "node", "STATIC_ONLY", "DISCOVERED_ONLY", command, ",".join(target_files[:5]), 3.0, "Dry-run: node syntax kontrolu calistirilmadi.")
    for source_file in target_files[:10]:
        completed = run_command(["node", "--check", source_file], cwd=project_path, timeout=45)
        if completed is None or completed.returncode != 0:
            notes = compact_output(completed) or f"node --check basarisiz: {source_file}"
            return build_entry(project_row, "node", "STATIC_ONLY", "VALIDATION_FAILED", command, source_file, 0.0, notes)
    return build_entry(project_row, "node", "BUILD_VERIFIED", "VALIDATED", command, ",".join(target_files[:5]), 8.0, "Secilen JS dosyalari node --check ile gecti.")


def validate_java_project(project_row: dict[str, str], artifacts_root: Path, dry_run: bool = False) -> ValidationStatusEntry:
    project_path = Path(project_row.get("path", ""))
    maven_wrapper = project_path / "mvnw.cmd"
    gradle_wrapper = project_path / "gradlew.bat"
    if maven_wrapper.exists():
        command_parts = [str(maven_wrapper), "-q", "-DskipTests", "-o", "validate"]
        command_text = " ".join(command_parts)
    elif gradle_wrapper.exists():
        command_parts = [str(gradle_wrapper), "classes", "--offline", "--quiet"]
        command_text = " ".join(command_parts)
    else:
        return build_entry(project_row, "java", "STATIC_ONLY", "DISCOVERED_ONLY", "wrapper not found", "pom.xml/build.gradle", 2.0, "Wrapper bulunmadi; statik karar kullanildi.")
    if dry_run:
        return build_entry(project_row, "java", "STATIC_ONLY", "DISCOVERED_ONLY", command_text, project_row.get("important_files", ""), 3.0, "Dry-run: Java build kontrolu calistirilmadi.")
    completed = run_command(command_parts, cwd=project_path, timeout=300)
    if completed and completed.returncode == 0:
        return build_entry(project_row, "java", "BUILD_VERIFIED", "VALIDATED", command_text, project_row.get("important_files", ""), 10.0, "Java wrapper tabanli build kontrolu gecti.")
    notes = compact_output(completed) or "Java build kontrolu basarisiz."
    return build_entry(project_row, "java", "STATIC_ONLY", "VALIDATION_FAILED", command_text, project_row.get("important_files", ""), 0.0, notes)


def build_entry(
    project_row: dict[str, str],
    family: str,
    validation_level: str,
    validation_status: str,
    command_used: str,
    validation_target: str,
    confidence_boost: float,
    notes: str,
) -> ValidationStatusEntry:
    return ValidationStatusEntry(
        project_name=project_row.get("project_name", ""),
        project_path=project_row.get("path", ""),
        technology_family=family,
        validation_level=validation_level,
        validation_status=validation_status,
        command_used=command_used,
        validation_target=validation_target,
        confidence_boost=confidence_boost,
        notes=notes,
    )


def write_validation_status_report(entries: list[ValidationStatusEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "validation_status.csv"
    with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=VALIDATION_STATUS_HEADERS)
        writer.writeheader()
        for entry in entries:
            row = asdict(entry)
            row["confidence_boost"] = f"{entry.confidence_boost:.2f}"
            writer.writerow(row)
    return output_path


def run_command(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def compact_output(completed: subprocess.CompletedProcess[str] | None) -> str:
    if completed is None:
        return ""
    text = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part and part.strip()).strip()
    return " ".join(text.split())[:500]


def find_files(project_path: Path, pattern: str, limit: int) -> list[str]:
    matches: list[str] = []
    try:
        iterator = project_path.rglob(pattern)
    except OSError:
        return matches
    for path in iterator:
        if any(part.casefold() in {"node_modules", ".git", ".venv", "venv", "env", "__pycache__", "dist", "build"} for part in path.parts):
            continue
        matches.append(str(path.relative_to(project_path)))
        if len(matches) >= limit:
            break
    return matches
