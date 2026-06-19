from __future__ import annotations

from dataclasses import asdict
import logging
from pathlib import Path

from src.analyzers.mapper import (
    load_csv_rows as load_mapping_csv_rows,
    load_technology_rules,
    map_software_to_projects,
    write_mapping_report,
)
from src.analyzers.dotnet_sdk_advisor import (
    analyze_dotnet_sdk_dependencies,
    write_dotnet_sdk_decision_report,
)
from src.analyzers.dotnet_sdk_validator import (
    validate_dotnet_sdks,
    write_dotnet_sdk_validation_report,
)
from src.analyzers.repo_deep_scanner import (
    merge_code_signals_into_projects,
    scan_project_code_signals,
    write_project_code_signals,
)
from src.analyzers.project_scanner import scan_projects, write_project_reports
from src.analyzers.removal_engine import build_removal_decisions, write_removal_decisions
from src.analyzers.risk_engine import build_program_risk_scores, write_program_risk_scores
from src.analyzers.recommender import (
    build_recommendations,
    enrich_recommendations,
    load_category_rules,
    write_recommendations,
)
from src.analyzers.runtime_advisor import build_runtime_inventory
from src.analyzers.software_explainer import load_software_catalog, write_software_descriptions
from src.collectors.disk_usage import collect_disk_usage, write_disk_usage_reports
from src.collectors.installed_apps import (
    collect_installed_applications,
    write_installed_application_reports,
)
from src.collectors.usage_signals import (
    collect_program_usage_signals,
    write_program_usage_report,
)

from .config import load_config
from .logging_config import configure_logging
from .models import AppConfig


LOGGER = logging.getLogger("windows_software_inventory_analyzer.pipeline")


def prepare_config(config_path: Path | None = None, verbose: bool = False) -> AppConfig:
    config = load_config(config_path)
    if verbose:
        config.logging.level = "DEBUG"
    configure_logging(config.logging)
    return config


def enforce_read_only(config: AppConfig) -> None:
    if not config.behavior.read_only:
        raise ValueError("Read-only mode must remain enabled in this version.")
    if config.behavior.allow_delete:
        raise ValueError("Deletion is not supported in this version.")
    if config.behavior.allow_uninstall:
        raise ValueError("Uninstall actions are not supported in this version.")


def run_collect_programs(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    applications = collect_installed_applications()
    if dry_run:
        LOGGER.info("Dry-run: installed program raporu yazilmadi. Kayit sayisi=%s", len(applications))
        return {"applications": applications, "json_path": None, "csv_path": None}
    json_path, csv_path = write_installed_application_reports(applications, config.report.output_dir)
    return {"applications": applications, "json_path": json_path, "csv_path": csv_path}


def run_collect_usage_signals(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=False)
    entries = collect_program_usage_signals(collect_result["applications"])
    if dry_run:
        LOGGER.info("Dry-run: usage signal raporu yazilmadi. entries=%s", len(entries))
        return {"usage_signal_entries": entries, "usage_signal_report_path": None}
    report_path = write_program_usage_report(entries, config.report.output_dir)
    return {"usage_signal_entries": entries, "usage_signal_report_path": report_path}


def run_scan_disk(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    disk_entries, cache_entries = collect_disk_usage(
        roots=config.scan.disk_usage_roots,
        exclude_paths=config.scan.exclude_paths,
        max_depth=config.scan.max_depth,
    )
    if dry_run:
        LOGGER.info(
            "Dry-run: disk raporlari yazilmadi. disk_entries=%s cache_entries=%s",
            len(disk_entries),
            len(cache_entries),
        )
        return {"disk_entries": disk_entries, "cache_entries": cache_entries, "disk_usage_path": None, "developer_caches_path": None}
    disk_usage_path, developer_caches_path = write_disk_usage_reports(
        disk_entries,
        cache_entries,
        config.report.output_dir,
    )
    return {
        "disk_entries": disk_entries,
        "cache_entries": cache_entries,
        "disk_usage_path": disk_usage_path,
        "developer_caches_path": developer_caches_path,
    }


def run_scan_projects(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    project_entries, file_index_entries = scan_projects(
        project_roots=config.scan.project_roots,
        exclude_paths=config.scan.exclude_paths,
    )
    code_signal_entries = scan_project_code_signals(project_entries)
    merged_project_entries = merge_code_signals_into_projects(project_entries, code_signal_entries)
    if dry_run:
        LOGGER.info(
            "Dry-run: proje raporlari yazilmadi. projects=%s indexed_files=%s code_signals=%s",
            len(merged_project_entries),
            len(file_index_entries),
            len(code_signal_entries),
        )
        return {
            "project_entries": merged_project_entries,
            "file_index_entries": file_index_entries,
            "code_signal_entries": code_signal_entries,
            "project_stack_path": None,
            "project_index_path": None,
            "project_code_signals_path": None,
        }
    project_stack_path, project_index_path = write_project_reports(
        merged_project_entries,
        file_index_entries,
        config.report.output_dir,
    )
    project_code_signals_path = write_project_code_signals(code_signal_entries, config.report.output_dir)
    return {
        "project_entries": merged_project_entries,
        "file_index_entries": file_index_entries,
        "code_signal_entries": code_signal_entries,
        "project_stack_path": project_stack_path,
        "project_index_path": project_index_path,
        "project_code_signals_path": project_code_signals_path,
    }


def run_map_software(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=False)
    project_result = run_scan_projects(config, dry_run=False)
    mapping_entries = map_software_to_projects(
        installed_programs=load_mapping_csv_rows(collect_result["csv_path"]),
        project_entries=load_mapping_csv_rows(project_result["project_stack_path"]),
        file_index_entries=load_mapping_csv_rows(project_result["project_index_path"]),
        rules=load_technology_rules(Path("technology_rules.yaml")),
    )
    if dry_run:
        LOGGER.info("Dry-run: software mapping raporu yazilmadi. mappings=%s", len(mapping_entries))
        return {"mapping_entries": mapping_entries, "mapping_path": None}
    mapping_path = write_mapping_report(mapping_entries, config.report.output_dir)
    return {"mapping_entries": mapping_entries, "mapping_path": mapping_path}


def run_recommend(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=False)
    usage_result = run_collect_usage_signals(config, dry_run=False)
    disk_result = run_scan_disk(config, dry_run=False)
    project_result = run_scan_projects(config, dry_run=False)
    mapping_result = run_map_software(config, dry_run=False)
    recommendation_entries = build_recommendations(
        installed_programs=load_mapping_csv_rows(collect_result["csv_path"]),
        disk_usage_rows=load_mapping_csv_rows(disk_result["disk_usage_path"]),
        mapping_rows=load_mapping_csv_rows(mapping_result["mapping_path"]),
        category_rules=load_category_rules(Path("category_rules.yaml")),
        project_rows=load_mapping_csv_rows(project_result["project_stack_path"]),
        usage_rows=load_mapping_csv_rows(usage_result["usage_signal_report_path"]),
    )
    risk_entries = build_program_risk_scores(
        installed_programs=load_mapping_csv_rows(collect_result["csv_path"]),
        mapping_rows=load_mapping_csv_rows(mapping_result["mapping_path"]),
        recommendation_rows=[asdict(entry) for entry in recommendation_entries],
        usage_rows=load_mapping_csv_rows(usage_result["usage_signal_report_path"]),
    )
    risk_report_path = None
    if not dry_run:
        risk_report_path = write_program_risk_scores(risk_entries, config.report.output_dir)
    risk_rows = [asdict(entry) for entry in risk_entries]
    recommendation_entries = enrich_recommendations(
        recommendation_entries,
        risk_rows=risk_rows,
        catalog=load_software_catalog(),
    )
    software_descriptions_path = None
    if not dry_run:
        software_descriptions_path = write_software_descriptions(
            [
                {
                    "software_name": entry.software_name,
                    "category": entry.category,
                    "purpose": entry.purpose,
                    "typical_usage": entry.typical_usage,
                    "related_technologies": entry.related_technologies,
                    "removal_risk_summary": entry.removal_risk_summary,
                }
                for entry in recommendation_entries
            ],
            config.report.output_dir,
        )
    if dry_run:
        LOGGER.info("Dry-run: recommendations raporu yazilmadi. recommendations=%s", len(recommendation_entries))
        return {
            "recommendation_entries": recommendation_entries,
            "recommendations_path": None,
            "risk_entries": risk_entries,
            "risk_report_path": None,
            "software_descriptions_path": None,
        }
    recommendations_path = write_recommendations(recommendation_entries, config.report.output_dir)
    return {
        "recommendation_entries": recommendation_entries,
        "recommendations_path": recommendations_path,
        "risk_entries": risk_entries,
        "risk_report_path": risk_report_path,
        "software_descriptions_path": software_descriptions_path,
    }


def run_score_risk(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=False)
    usage_result = run_collect_usage_signals(config, dry_run=False)
    disk_result = run_scan_disk(config, dry_run=False)
    project_result = run_scan_projects(config, dry_run=False)
    mapping_result = run_map_software(config, dry_run=False)
    recommendation_entries = build_recommendations(
        installed_programs=load_mapping_csv_rows(collect_result["csv_path"]),
        disk_usage_rows=load_mapping_csv_rows(disk_result["disk_usage_path"]),
        mapping_rows=load_mapping_csv_rows(mapping_result["mapping_path"]),
        category_rules=load_category_rules(Path("category_rules.yaml")),
        project_rows=load_mapping_csv_rows(project_result["project_stack_path"]),
        usage_rows=load_mapping_csv_rows(usage_result["usage_signal_report_path"]),
    )
    risk_entries = build_program_risk_scores(
        installed_programs=load_mapping_csv_rows(collect_result["csv_path"]),
        mapping_rows=load_mapping_csv_rows(mapping_result["mapping_path"]),
        recommendation_rows=[asdict(entry) for entry in recommendation_entries],
        usage_rows=load_mapping_csv_rows(usage_result["usage_signal_report_path"]),
    )
    if dry_run:
        LOGGER.info("Dry-run: risk report yazilmadi. entries=%s", len(risk_entries))
        return {"risk_entries": risk_entries, "risk_report_path": None}
    risk_report_path = write_program_risk_scores(risk_entries, config.report.output_dir)
    return {"risk_entries": risk_entries, "risk_report_path": risk_report_path}


def run_analyze_dotnet_sdk(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    entries = analyze_dotnet_sdk_dependencies(
        project_roots=config.scan.project_roots,
        exclude_paths=config.scan.exclude_paths,
    )
    if dry_run:
        LOGGER.info("Dry-run: dotnet sdk decision report yazilmadi. entries=%s", len(entries))
        return {"dotnet_sdk_entries": entries, "dotnet_sdk_report_path": None}
    report_path = write_dotnet_sdk_decision_report(entries, config.report.output_dir)
    return {"dotnet_sdk_entries": entries, "dotnet_sdk_report_path": report_path}


def run_validate_dotnet_sdks(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    artifacts_root = config.report.output_dir / "sdk_validation_artifacts"
    entries = validate_dotnet_sdks(
        project_roots=config.scan.project_roots,
        exclude_paths=config.scan.exclude_paths,
        artifacts_root=artifacts_root,
        dry_run=dry_run,
    )
    if dry_run:
        LOGGER.info("Dry-run: sdk validation report yazilmadi. entries=%s", len(entries))
        return {"dotnet_sdk_validation_entries": entries, "sdk_validation_report_path": None}
    report_path = write_dotnet_sdk_validation_report(entries, config.report.output_dir)
    return {"dotnet_sdk_validation_entries": entries, "sdk_validation_report_path": report_path}


def run_build_removal_decisions(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=False)
    usage_result = run_collect_usage_signals(config, dry_run=False)
    project_result = run_scan_projects(config, dry_run=False)
    mapping_result = run_map_software(config, dry_run=False)
    recommendation_result = run_recommend(config, dry_run=False)
    dotnet_result = run_analyze_dotnet_sdk(config, dry_run=False)
    dotnet_validation_result = run_validate_dotnet_sdks(config, dry_run=False)

    installed_rows = load_mapping_csv_rows(collect_result["csv_path"])
    recommendation_rows = load_mapping_csv_rows(recommendation_result["recommendations_path"])
    mapping_rows = load_mapping_csv_rows(mapping_result["mapping_path"])
    usage_rows = load_mapping_csv_rows(usage_result["usage_signal_report_path"])
    risk_rows = load_mapping_csv_rows(recommendation_result["risk_report_path"]) if recommendation_result.get("risk_report_path") else []
    project_rows = load_mapping_csv_rows(project_result["project_stack_path"])
    dotnet_sdk_rows = load_mapping_csv_rows(dotnet_result["dotnet_sdk_report_path"]) if dotnet_result.get("dotnet_sdk_report_path") else []
    sdk_validation_rows = load_mapping_csv_rows(dotnet_validation_result["sdk_validation_report_path"]) if dotnet_validation_result.get("sdk_validation_report_path") else []
    _, runtime_family_details = build_runtime_inventory(recommendation_rows, installed_rows, project_rows)

    entries = build_removal_decisions(
        installed_programs=installed_rows,
        recommendation_rows=recommendation_rows,
        mapping_rows=mapping_rows,
        usage_rows=usage_rows,
        risk_rows=risk_rows,
        dotnet_sdk_rows=dotnet_sdk_rows,
        sdk_validation_rows=sdk_validation_rows,
        runtime_family_rows=runtime_family_details,
    )
    if dry_run:
        LOGGER.info("Dry-run: removal decisions report yazilmadi. entries=%s", len(entries))
        return {"removal_decision_entries": entries, "removal_decisions_path": None}
    report_path = write_removal_decisions(entries, config.report.output_dir)
    return {"removal_decision_entries": entries, "removal_decisions_path": report_path}


def run_full_pipeline(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=dry_run)
    usage_result = run_collect_usage_signals(config, dry_run=dry_run)
    disk_result = run_scan_disk(config, dry_run=dry_run)
    project_result = run_scan_projects(config, dry_run=dry_run)
    dotnet_result = run_analyze_dotnet_sdk(config, dry_run=dry_run)
    dotnet_validation_result = run_validate_dotnet_sdks(config, dry_run=dry_run)

    if dry_run:
        mapping_entries = map_software_to_projects(
            installed_programs=[asdict(application) for application in collect_result["applications"]],
            project_entries=[asdict(entry) for entry in project_result["project_entries"]],
            file_index_entries=[asdict(entry) for entry in project_result["file_index_entries"]],
            rules=load_technology_rules(Path("technology_rules.yaml")),
        )
        recommendation_entries = build_recommendations(
            installed_programs=[asdict(application) for application in collect_result["applications"]],
            disk_usage_rows=[asdict(entry) for entry in disk_result["disk_entries"]],
            mapping_rows=[asdict(entry) for entry in mapping_entries],
            category_rules=load_category_rules(Path("category_rules.yaml")),
            project_rows=[asdict(entry) for entry in project_result["project_entries"]],
            usage_rows=[asdict(entry) for entry in usage_result["usage_signal_entries"]],
        )
        LOGGER.info(
            "Dry-run tamamlandi. programs=%s disks=%s projects=%s mappings=%s recommendations=%s",
            len(collect_result["applications"]),
            len(disk_result["disk_entries"]),
            len(project_result["project_entries"]),
            len(mapping_entries),
            len(recommendation_entries),
        )
        return {}

    mapping_result = run_map_software(config, dry_run=False)
    recommendation_result = run_recommend(config, dry_run=False)
    removal_decision_result = run_build_removal_decisions(config, dry_run=False)
    return {
        **collect_result,
        **usage_result,
        **disk_result,
        **project_result,
        **dotnet_result,
        **dotnet_validation_result,
        **mapping_result,
        **recommendation_result,
        **removal_decision_result,
    }
