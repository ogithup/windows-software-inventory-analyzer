from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ScanConfig:
    disks: list[str] = field(default_factory=list)
    project_roots: list[Path] = field(default_factory=list)
    exclude_paths: list[Path] = field(default_factory=list)


@dataclass(slots=True)
class ReportConfig:
    output_dir: Path
    formats: list[str] = field(default_factory=lambda: ["json"])


@dataclass(slots=True)
class LoggingConfig:
    level: str = "INFO"
    log_to_file: bool = False
    log_dir: Path = Path("./data/output/logs")


@dataclass(slots=True)
class BehaviorConfig:
    read_only: bool = True
    allow_delete: bool = False
    allow_uninstall: bool = False


@dataclass(slots=True)
class AppConfig:
    scan: ScanConfig
    report: ReportConfig
    logging: LoggingConfig
    behavior: BehaviorConfig
