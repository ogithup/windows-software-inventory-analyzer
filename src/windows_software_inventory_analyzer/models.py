from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ScanConfig:
    disks: list[str] = field(default_factory=list)
    project_roots: list[Path] = field(default_factory=list)
    exclude_paths: list[Path] = field(default_factory=list)
    disk_usage_roots: list[Path] = field(default_factory=list)
    max_depth: int = 3


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


@dataclass(slots=True)
class InstalledApplication:
    name: str
    version: str = ""
    publisher: str = ""
    install_location: str = ""
    uninstall_string: str = ""
    source: str = ""


@dataclass(slots=True)
class DiskUsageEntry:
    path: str
    scan_root: str
    depth: int
    size_bytes: int
    size_human: str
    category: str
    risk: str


@dataclass(slots=True)
class DeveloperCacheEntry:
    path: str
    scan_root: str
    depth: int
    size_bytes: int
    size_human: str
    cache_type: str
    risk: str


@dataclass(slots=True)
class ProjectTechStackEntry:
    project_name: str
    repo_name: str
    path: str
    detected_technologies: str
    dependencies_summary: str
    last_modified: str
    file_count: int
    important_files: str


@dataclass(slots=True)
class ProjectFileIndexEntry:
    project_name: str
    repo_name: str
    project_path: str
    file_path: str
    file_name: str
    detected_technology: str
    dependencies_summary: str
    matched_keywords: str
    last_modified: str
    searchable_text: str


@dataclass(slots=True)
class SoftwareProjectMappingEntry:
    software_name: str
    category: str
    matched_projects: str
    project_count: int
    evidence: str
    confidence_score: float


@dataclass(slots=True)
class RecommendationEntry:
    software_name: str
    category: str
    decision: str
    matched_projects: str
    project_count: int
    install_location: str
    estimated_size: str
    last_related_project_activity: str
    confidence_score: float
    explanation: str
