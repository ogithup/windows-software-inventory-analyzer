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
    github_url: str
    repo_description: str
    user_notes: str
    detected_technologies: str
    dependencies_summary: str
    detected_libraries: str
    framework_signals: str
    code_evidence: str
    last_modified: str
    file_count: int
    important_files: str


@dataclass(slots=True)
class ProjectFileIndexEntry:
    project_name: str
    repo_name: str
    project_path: str
    github_url: str
    repo_description: str
    user_notes: str
    file_path: str
    file_name: str
    detected_technology: str
    dependencies_summary: str
    matched_keywords: str
    last_modified: str
    searchable_text: str


@dataclass(slots=True)
class ProjectCodeSignalEntry:
    project_name: str
    repo_name: str
    project_path: str
    github_url: str
    detected_libraries: str
    framework_signals: str
    code_evidence: str
    source_files_scanned: int
    last_modified: str


@dataclass(slots=True)
class SoftwareProjectMappingEntry:
    software_name: str
    category: str
    matched_projects: str
    matched_project_links: str
    project_context: str
    project_count: int
    evidence: str
    confidence_score: float


@dataclass(slots=True)
class RecommendationEntry:
    software_name: str
    category: str
    decision: str
    matched_projects: str
    project_links: str
    project_context: str
    project_count: int
    install_location: str
    estimated_size: str
    last_related_project_activity: str
    risk_score: float
    cleanup_priority_score: float
    confidence_score: float
    explanation: str
    purpose: str = ""
    typical_usage: str = ""
    related_technologies: str = ""
    removal_risk_summary: str = ""
    last_used_at: str = ""
    usage_signal_count: int = 0
    usage_sources: str = ""
    usage_status: str = ""
    review_status: str = ""
    review_notes: str = ""


@dataclass(slots=True)
class ProgramUsageSignalEntry:
    software_name: str
    last_used_at: str
    usage_signal_count: int
    usage_sources: str
    matched_executables: str
    usage_status: str


@dataclass(slots=True)
class ProgramRiskScoreEntry:
    software_name: str
    category: str
    publisher: str
    decision: str
    estimated_size: str
    project_count: int
    last_used_at: str
    risk_score: float
    cleanup_priority_score: float
    hard_protection: str
    score_breakdown: str
    rationale: str


@dataclass(slots=True)
class DotnetSdkDecisionEntry:
    sdk_version: str
    feature_band: str
    status: str
    used_by: str
    ide_context: str
    workload_context: str
    project_context: str
    global_json_matches: str
    csproj_signals: str
    recommendation: str


@dataclass(slots=True)
class DotnetSdkValidationEntry:
    project_name: str
    target_path: str
    target_type: str
    selected_sdk: str
    selected_feature_band: str
    global_json_version: str
    required_frameworks: str
    build_status: str
    build_exit_code: int
    validation_mode: str
    notes: str


@dataclass(slots=True)
class ProgramVersionCandidate:
    software_name: str
    normalized_family: str
    version: str
    category: str
    estimated_size: str = ""
    last_used_at: str = ""
    project_count: int = 0
    decision: str = ""


@dataclass(slots=True)
class ProgramDecisionContext:
    software_name: str
    normalized_family: str
    family_type: str
    category: str
    publisher: str
    installed_version: str
    install_location: str
    estimated_size: str
    project_count: int
    matched_projects: str
    project_context: str
    last_used_at: str
    usage_signal_count: int
    usage_sources: str
    usage_status: str
    risk_score: float
    cleanup_priority_score: float
    confidence_score: float
    existing_decision: str
    existing_explanation: str
    hard_protection: bool
    duplicate_versions: list[ProgramVersionCandidate] = field(default_factory=list)
    dotnet_sdk_rows: list[dict[str, str]] = field(default_factory=list)
    sdk_validation_rows: list[dict[str, str]] = field(default_factory=list)
    runtime_family_rows: list[dict[str, str]] = field(default_factory=list)
    project_signals: list[str] = field(default_factory=list)
    ide_signals: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RemovalDecisionEntry:
    software_name: str
    normalized_family: str
    family_type: str
    category: str
    publisher: str
    installed_version: str
    decision_label: str
    removal_risk_score: float
    cleanup_value_score: float
    recommended_next_action: str
    plain_language_explanation: str
    technical_explanation: str
    evidence: str
    matched_projects: str
    project_count: int
    last_used_at: str
    usage_signal_count: int
    estimated_size: str
    duplicate_summary: str
    test_summary: str
