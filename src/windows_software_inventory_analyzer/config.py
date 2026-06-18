from __future__ import annotations

import os
from pathlib import Path

from .models import AppConfig, BehaviorConfig, LoggingConfig, ReportConfig, ScanConfig


DEFAULT_CONFIG_PATH = Path("config.example.yaml")


def _expand_path(value: str) -> Path:
    return Path(os.path.expandvars(value)).expanduser()


def _parse_scalar(value: str) -> str | bool:
    normalized = value.strip()
    if normalized.lower() == "true":
        return True
    if normalized.lower() == "false":
        return False
    if normalized.startswith('"') and normalized.endswith('"'):
        return normalized[1:-1]
    return normalized


def _parse_simple_yaml(path: Path) -> dict:
    root: dict = {}
    current_section: dict | None = None
    current_list_key: str | None = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        if not line.startswith(" "):
            key, _, remainder = stripped.partition(":")
            value = remainder.strip()
            if value:
                root[key] = _parse_scalar(value)
                current_section = None
                current_list_key = None
            else:
                root[key] = {}
                current_section = root[key]
                current_list_key = None
            continue

        if current_section is None:
            raise ValueError(f"Invalid YAML structure in {path}: {raw_line}")

        indented = stripped
        if indented.startswith("- "):
            if current_list_key is None:
                raise ValueError(f"List item without key in {path}: {raw_line}")
            current_section[current_list_key].append(_parse_scalar(indented[2:]))
            continue

        key, _, remainder = indented.partition(":")
        value = remainder.strip()
        if value:
            current_section[key] = _parse_scalar(value)
            current_list_key = None
        else:
            current_section[key] = []
            current_list_key = key

    return root


def load_config(config_path: Path | None = None) -> AppConfig:
    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw_config = _parse_simple_yaml(path)
    scan = raw_config.get("scan", {})
    report = raw_config.get("report", {})
    logging = raw_config.get("logging", {})
    behavior = raw_config.get("behavior", {})

    return AppConfig(
        scan=ScanConfig(
            disks=list(scan.get("disks", [])),
            project_roots=[_expand_path(item) for item in scan.get("project_roots", [])],
            exclude_paths=[_expand_path(item) for item in scan.get("exclude_paths", [])],
            disk_usage_roots=[_expand_path(item) for item in scan.get("disk_usage_roots", [])],
            max_depth=int(scan.get("max_depth", 3)),
        ),
        report=ReportConfig(
            output_dir=_expand_path(report.get("output_dir", "./data/output")),
            formats=list(report.get("formats", ["json"])),
        ),
        logging=LoggingConfig(
            level=str(logging.get("level", "INFO")).upper(),
            log_to_file=bool(logging.get("log_to_file", False)),
            log_dir=_expand_path(logging.get("log_dir", "./data/output/logs")),
        ),
        behavior=BehaviorConfig(
            read_only=bool(behavior.get("read_only", True)),
            allow_delete=bool(behavior.get("allow_delete", False)),
            allow_uninstall=bool(behavior.get("allow_uninstall", False)),
        ),
    )
