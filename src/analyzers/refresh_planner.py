from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from src.windows_software_inventory_analyzer.models import AppConfig


REFRESH_STATE_PATH = Path("refresh_state.json")


@dataclass(slots=True)
class RefreshPlanStep:
    command: str
    label: str
    should_run: bool
    reason: str
    estimated_seconds: int


STEP_METADATA: dict[str, dict[str, object]] = {
    "collect-programs": {
        "label": "Kurulu programlar okunuyor",
        "outputs": ["installed_programs.csv", "installed_programs.json"],
        "estimate": 12,
        "cooldown_seconds": 2 * 3600,
        "fingerprint_kind": "time_only",
    },
    "collect-usage": {
        "label": "Kullanim izleri okunuyor",
        "outputs": ["program_usage_signals.csv"],
        "estimate": 18,
        "cooldown_seconds": 2 * 3600,
        "fingerprint_kind": "time_only",
    },
    "scan-projects": {
        "label": "Projeler taraniyor",
        "outputs": [
            "project_tech_stack.csv",
            "project_files_index.csv",
            "project_code_signals.csv",
            "project_size_report.csv",
            "project_storage_breakdown.csv",
        ],
        "estimate": 45,
        "quick_estimate": 18,
        "fingerprint_kind": "project_roots",
    },
    "scan-disk": {
        "label": "Disk doluluk verisi hazirlaniyor",
        "outputs": [
            "disk_usage.csv",
            "developer_caches.csv",
            "disk_zone_report.csv",
            "disk_cleanup_scenarios.csv",
        ],
        "estimate": 50,
        "quick_estimate": 20,
        "fingerprint_kind": "disk_roots",
    },
    "map-software": {
        "label": "Programlar projelerle baglaniyor",
        "outputs": ["software_project_mapping.csv"],
        "estimate": 10,
        "fingerprint_kind": "derived",
        "dependencies": ["installed_programs.csv", "project_tech_stack.csv", "project_files_index.csv"],
    },
    "score-risk": {
        "label": "Risk puanlari hesaplaniyor",
        "outputs": ["program_risk_scores.csv"],
        "estimate": 8,
        "fingerprint_kind": "derived",
        "dependencies": ["installed_programs.csv", "software_project_mapping.csv", "program_usage_signals.csv"],
    },
    "recommend": {
        "label": "Oneriler yaziliyor",
        "outputs": ["recommendations.csv", "software_descriptions.json"],
        "estimate": 12,
        "fingerprint_kind": "derived",
        "dependencies": [
            "installed_programs.csv",
            "disk_usage.csv",
            "software_project_mapping.csv",
            "program_usage_signals.csv",
            "program_risk_scores.csv",
        ],
    },
    "analyze-dotnet-sdk": {
        "label": ".NET raporu guncelleniyor",
        "outputs": ["dotnet_sdk_decision_report.csv"],
        "estimate": 16,
        "fingerprint_kind": "project_roots",
    },
    "validate-dotnet-sdks": {
        "label": "Build testi calisiyor",
        "outputs": ["sdk_validation_report.csv"],
        "estimate": 60,
        "quick_estimate": 24,
        "fingerprint_kind": "project_roots",
        "dependencies": ["project_tech_stack.csv", "dotnet_sdk_decision_report.csv"],
    },
    "build-removal-decisions": {
        "label": "Kaldirma senaryosu kararlari uretiliyor",
        "outputs": ["removal_decisions.csv"],
        "estimate": 10,
        "fingerprint_kind": "derived",
        "dependencies": [
            "installed_programs.csv",
            "recommendations.csv",
            "software_project_mapping.csv",
            "program_usage_signals.csv",
            "program_risk_scores.csv",
            "dotnet_sdk_decision_report.csv",
            "sdk_validation_report.csv",
            "project_size_report.csv",
            "disk_zone_report.csv",
            "disk_cleanup_scenarios.csv",
        ],
    },
}


def build_refresh_plan(config: AppConfig, output_dir: Path, mode: str = "quick") -> list[RefreshPlanStep]:
    state = load_refresh_state()
    ordered_commands = [
        "collect-programs",
        "collect-usage",
        "scan-projects",
        "scan-disk",
        "map-software",
        "score-risk",
        "recommend",
        "analyze-dotnet-sdk",
        "validate-dotnet-sdks",
        "build-removal-decisions",
    ]
    plan: list[RefreshPlanStep] = []
    changed_outputs: set[str] = set()
    for command in ordered_commands:
        metadata = STEP_METADATA[command]
        should_run, reason = evaluate_step(
            command=command,
            metadata=metadata,
            config=config,
            output_dir=output_dir,
            mode=mode,
            state=state,
            changed_outputs=changed_outputs,
        )
        outputs = set(str(name) for name in metadata.get("outputs", []))
        if should_run:
            changed_outputs.update(outputs)
        plan.append(
            RefreshPlanStep(
                command=command,
                label=str(metadata.get("label", command)),
                should_run=should_run,
                reason=reason,
                estimated_seconds=int(metadata.get("quick_estimate" if mode == "quick" else "estimate", metadata.get("estimate", 10))),
            )
        )
    return plan


def evaluate_step(
    command: str,
    metadata: dict[str, object],
    config: AppConfig,
    output_dir: Path,
    mode: str,
    state: dict[str, object],
    changed_outputs: set[str],
) -> tuple[bool, str]:
    outputs = [output_dir / str(name) for name in metadata.get("outputs", [])]
    if not outputs or any(not path.exists() for path in outputs):
        return True, "Cikti dosyasi eksik"

    dependency_files = [str(name) for name in metadata.get("dependencies", [])]
    if changed_outputs.intersection(dependency_files):
        return True, "Bagimli veri degisti"

    step_state = state.get(command, {}) if isinstance(state, dict) else {}
    current_fingerprint = compute_fingerprint(command, config, output_dir, metadata)
    previous_fingerprint = step_state.get("fingerprint", "")
    if current_fingerprint != previous_fingerprint:
        return True, "Kaynak klasorlerde degisiklik algilandi"

    cooldown_seconds = int(metadata.get("cooldown_seconds", 0) or 0)
    if cooldown_seconds:
        newest_output = max(path.stat().st_mtime for path in outputs)
        age_seconds = seconds_since(newest_output)
        if age_seconds < cooldown_seconds and mode == "quick":
            return False, f"Veri yeni; yaklasik {age_seconds // 60} dk once guncellendi"
        return True, "Sure esigi doldu"

    if mode == "full" and command in {"scan-projects", "scan-disk", "validate-dotnet-sdks"}:
        return True, "Derin yenileme modu"
    return False, "Kaynak degismedi, adim atlandi"


def compute_fingerprint(command: str, config: AppConfig, output_dir: Path, metadata: dict[str, object]) -> str:
    kind = str(metadata.get("fingerprint_kind", "derived"))
    if kind == "project_roots":
        return fingerprint_project_roots(config.scan.project_roots, config.scan.exclude_paths)
    if kind == "disk_roots":
        return fingerprint_disk_roots(config.scan.disk_usage_roots, config.scan.exclude_paths)
    if kind == "derived":
        return fingerprint_output_dependencies(output_dir, [str(name) for name in metadata.get("dependencies", [])])
    return fingerprint_time_only(output_dir, [str(name) for name in metadata.get("outputs", [])])


def fingerprint_project_roots(project_roots: Iterable[Path], exclude_paths: Iterable[Path]) -> str:
    exclude_keys = {normalize_path(path) for path in exclude_paths}
    parts: list[str] = []
    signature_names = {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "environment.yml",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        ".sln",
        ".csproj",
        "global.json",
        "readme.md",
    }
    for root in project_roots:
        normalized_root = normalize_path(root)
        if not normalized_root.exists():
            parts.append(f"{normalized_root}|missing")
            continue
        latest = normalized_root.stat().st_mtime
        marker_count = 0
        try:
            children = list(normalized_root.iterdir())
        except OSError:
            children = []
        for child in children:
            try:
                normalized_child = normalize_path(child)
                if should_skip(normalized_child, exclude_keys):
                    continue
                child_stat = child.stat()
                latest = max(latest, child_stat.st_mtime)
                if child.is_file() and child.name.casefold() in signature_names:
                    marker_count += 1
                    continue
                if not child.is_dir():
                    continue
                direct_entries = list(child.iterdir())
                for entry in direct_entries:
                    normalized_entry = normalize_path(entry)
                    if should_skip(normalized_entry, exclude_keys):
                        continue
                    entry_stat = entry.stat()
                    latest = max(latest, entry_stat.st_mtime)
                    if entry.is_file() and entry.name.casefold() in signature_names:
                        marker_count += 1
            except OSError:
                continue
        parts.append(f"{normalized_root}|{int(latest)}|{marker_count}")
    return ";".join(parts)


def fingerprint_disk_roots(disk_roots: Iterable[Path], exclude_paths: Iterable[Path]) -> str:
    exclude_keys = {normalize_path(path) for path in exclude_paths}
    parts: list[str] = []
    for root in disk_roots:
        normalized_root = normalize_path(root)
        if not normalized_root.exists():
            parts.append(f"{normalized_root}|missing")
            continue
        latest = normalized_root.stat().st_mtime
        child_count = 0
        try:
            for child in normalized_root.iterdir():
                normalized_child = normalize_path(child)
                if should_skip(normalized_child, exclude_keys):
                    continue
                stat = child.stat()
                latest = max(latest, stat.st_mtime)
                child_count += 1
        except OSError:
            pass
        parts.append(f"{normalized_root}|{int(latest)}|{child_count}")
    return ";".join(parts)


def fingerprint_output_dependencies(output_dir: Path, names: Iterable[str]) -> str:
    parts: list[str] = []
    for name in names:
        path = output_dir / name
        if not path.exists():
            parts.append(f"{name}|missing")
            continue
        stat = path.stat()
        parts.append(f"{name}|{int(stat.st_mtime)}|{stat.st_size}")
    return ";".join(parts)


def fingerprint_time_only(output_dir: Path, names: Iterable[str]) -> str:
    return fingerprint_output_dependencies(output_dir, names)


def load_refresh_state() -> dict[str, object]:
    if not REFRESH_STATE_PATH.exists():
        return {}
    try:
        return json.loads(REFRESH_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def write_refresh_state(command: str, config: AppConfig, output_dir: Path) -> None:
    state = load_refresh_state()
    metadata = STEP_METADATA.get(command, {})
    state[command] = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "fingerprint": compute_fingerprint(command, config, output_dir, metadata),
        "outputs": list(metadata.get("outputs", [])),
    }
    REFRESH_STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=True), encoding="utf-8")


def estimate_plan_duration(plan: Iterable[RefreshPlanStep]) -> int:
    return sum(step.estimated_seconds for step in plan if step.should_run)


def plan_to_rows(plan: Iterable[RefreshPlanStep]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for step in plan:
        rows.append(
            {
                "command": step.command,
                "label": step.label,
                "run_state": "RUN" if step.should_run else "SKIP",
                "reason": step.reason,
                "estimated_seconds": str(step.estimated_seconds),
            }
        )
    return rows


def seconds_since(epoch_seconds: float) -> int:
    return max(0, int(datetime.now(timezone.utc).timestamp() - epoch_seconds))


def normalize_path(path: Path | str) -> Path:
    return Path(path).resolve()


def should_skip(path: Path, exclude_keys: set[Path]) -> bool:
    path_key = normalize_path(path)
    return any(path_key == exclude or exclude in path_key.parents for exclude in exclude_keys)


def format_eta(seconds: int) -> str:
    if seconds <= 0:
        return "0 sn"
    minutes, remaining = divmod(seconds, 60)
    if minutes <= 0:
        return f"{remaining} sn"
    return f"{minutes} dk {remaining} sn"
