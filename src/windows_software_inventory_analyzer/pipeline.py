from __future__ import annotations

import logging
from pathlib import Path

from src.analyzers.mapper import (
    load_csv_rows as load_mapping_csv_rows,
    load_technology_rules,
    map_software_to_projects,
    write_mapping_report,
)
from src.analyzers.project_scanner import scan_projects, write_project_reports
from src.analyzers.recommender import (
    build_recommendations,
    load_category_rules,
    write_recommendations,
)
from src.collectors.disk_usage import collect_disk_usage, write_disk_usage_reports
from src.collectors.installed_apps import (
    collect_installed_applications,
    write_installed_application_reports,
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
    if dry_run:
        LOGGER.info(
            "Dry-run: proje raporlari yazilmadi. projects=%s indexed_files=%s",
            len(project_entries),
            len(file_index_entries),
        )
        return {"project_entries": project_entries, "file_index_entries": file_index_entries, "project_stack_path": None, "project_index_path": None}
    project_stack_path, project_index_path = write_project_reports(
        project_entries,
        file_index_entries,
        config.report.output_dir,
    )
    return {
        "project_entries": project_entries,
        "file_index_entries": file_index_entries,
        "project_stack_path": project_stack_path,
        "project_index_path": project_index_path,
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
    disk_result = run_scan_disk(config, dry_run=False)
    project_result = run_scan_projects(config, dry_run=False)
    mapping_result = run_map_software(config, dry_run=False)
    recommendation_entries = build_recommendations(
        installed_programs=load_mapping_csv_rows(collect_result["csv_path"]),
        disk_usage_rows=load_mapping_csv_rows(disk_result["disk_usage_path"]),
        mapping_rows=load_mapping_csv_rows(mapping_result["mapping_path"]),
        category_rules=load_category_rules(Path("category_rules.yaml")),
        project_rows=load_mapping_csv_rows(project_result["project_stack_path"]),
    )
    if dry_run:
        LOGGER.info("Dry-run: recommendations raporu yazilmadi. recommendations=%s", len(recommendation_entries))
        return {"recommendation_entries": recommendation_entries, "recommendations_path": None}
    recommendations_path = write_recommendations(recommendation_entries, config.report.output_dir)
    return {"recommendation_entries": recommendation_entries, "recommendations_path": recommendations_path}


def run_full_pipeline(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=dry_run)
    disk_result = run_scan_disk(config, dry_run=dry_run)
    project_result = run_scan_projects(config, dry_run=dry_run)

    if dry_run:
        mapping_entries = map_software_to_projects(
            installed_programs=[application.__dict__ for application in collect_result["applications"]],
            project_entries=[entry.__dict__ for entry in project_result["project_entries"]],
            file_index_entries=[entry.__dict__ for entry in project_result["file_index_entries"]],
            rules=load_technology_rules(Path("technology_rules.yaml")),
        )
        recommendation_entries = build_recommendations(
            installed_programs=[application.__dict__ for application in collect_result["applications"]],
            disk_usage_rows=[entry.__dict__ for entry in disk_result["disk_entries"]],
            mapping_rows=[entry.__dict__ for entry in mapping_entries],
            category_rules=load_category_rules(Path("category_rules.yaml")),
            project_rows=[entry.__dict__ for entry in project_result["project_entries"]],
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
    return {
        **collect_result,
        **disk_result,
        **project_result,
        **mapping_result,
        **recommendation_result,
    }
