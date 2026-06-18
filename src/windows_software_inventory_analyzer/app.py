from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.analyzers.mapper import (
    load_csv_rows,
    load_technology_rules,
    map_software_to_projects,
    search_mappings,
    write_mapping_report,
)
from src.analyzers.recommender import (
    build_recommendations,
    load_category_rules,
    search_recommendations,
    write_recommendations,
)
from src.analyzers.project_scanner import scan_projects, write_project_reports
from src.collectors.disk_usage import collect_disk_usage, write_disk_usage_reports
from src.collectors.installed_apps import (
    collect_installed_applications,
    write_installed_application_reports,
)
from src.windows_software_inventory_analyzer.pipeline import enforce_read_only

from .config import load_config
from .logging_config import configure_logging


LOGGER = logging.getLogger("windows_software_inventory_analyzer")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze Windows software inventory in read-only mode."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to a YAML config file. Defaults to config.example.yaml.",
    )
    parser.add_argument(
        "--search",
        type=str,
        default="",
        help="Keyword to search in software-project mapping results.",
    )
    return parser.parse_args()
def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    configure_logging(config.logging)

    enforce_read_only(config)

    LOGGER.info("Application started in read-only mode.")
    LOGGER.info("Configured disks: %s", ", ".join(config.scan.disks) or "None")
    LOGGER.info("Project roots: %s", ", ".join(str(path) for path in config.scan.project_roots) or "None")
    LOGGER.info("Excluded paths: %s", ", ".join(str(path) for path in config.scan.exclude_paths) or "None")
    LOGGER.info("Disk usage roots: %s", ", ".join(str(path) for path in config.scan.disk_usage_roots) or "None")
    LOGGER.info("Maximum scan depth: %s", config.scan.max_depth)
    LOGGER.info("Report output directory: %s", config.report.output_dir)

    applications = collect_installed_applications()
    json_path, csv_path = write_installed_application_reports(applications, config.report.output_dir)
    disk_entries, cache_entries = collect_disk_usage(
        roots=config.scan.disk_usage_roots,
        exclude_paths=config.scan.exclude_paths,
        max_depth=config.scan.max_depth,
    )
    disk_usage_path, developer_caches_path = write_disk_usage_reports(
        disk_entries,
        cache_entries,
        config.report.output_dir,
    )
    project_entries, file_index_entries = scan_projects(
        project_roots=config.scan.project_roots,
        exclude_paths=config.scan.exclude_paths,
    )
    project_stack_path, project_index_path = write_project_reports(
        project_entries,
        file_index_entries,
        config.report.output_dir,
    )
    mapping_entries = map_software_to_projects(
        installed_programs=load_csv_rows(csv_path),
        project_entries=load_csv_rows(project_stack_path),
        file_index_entries=load_csv_rows(project_index_path),
        rules=load_technology_rules(Path("technology_rules.yaml")),
    )
    mapping_path = write_mapping_report(mapping_entries, config.report.output_dir)
    recommendation_entries = build_recommendations(
        installed_programs=load_csv_rows(csv_path),
        disk_usage_rows=load_csv_rows(disk_usage_path),
        mapping_rows=load_csv_rows(mapping_path),
        category_rules=load_category_rules(Path("category_rules.yaml")),
        project_rows=load_csv_rows(project_stack_path),
    )
    recommendations_path = write_recommendations(recommendation_entries, config.report.output_dir)

    LOGGER.info("Installed application inventory exported to: %s", json_path)
    LOGGER.info("Installed application inventory exported to: %s", csv_path)
    LOGGER.info("Disk usage report exported to: %s", disk_usage_path)
    LOGGER.info("Developer caches report exported to: %s", developer_caches_path)
    LOGGER.info("Project tech stack report exported to: %s", project_stack_path)
    LOGGER.info("Project files index report exported to: %s", project_index_path)
    LOGGER.info("Software-project mapping report exported to: %s", mapping_path)
    LOGGER.info("Recommendations report exported to: %s", recommendations_path)
    LOGGER.info("Sprint 1 completed with %s normalized application records.", len(applications))
    LOGGER.info("Sprint 2 completed with %s disk entries and %s developer cache entries.", len(disk_entries), len(cache_entries))
    LOGGER.info("Sprint 3 completed with %s projects and %s indexed project files.", len(project_entries), len(file_index_entries))
    LOGGER.info("Sprint 4 completed with %s software-project mappings.", len(mapping_entries))
    LOGGER.info("Sprint 5 completed with %s recommendations.", len(recommendation_entries))

    if args.search.strip():
        search_results = search_mappings(mapping_entries, args.search)
        LOGGER.info("Search '%s' returned %s mapping results.", args.search, len(search_results))
        for entry in search_results:
            LOGGER.info(
                "Search match | software=%s | category=%s | projects=%s | confidence=%.2f | evidence=%s",
                entry.software_name,
                entry.category,
                entry.matched_projects,
                entry.confidence_score,
                entry.evidence,
            )
        recommendation_search_results = search_recommendations(recommendation_entries, args.search)
        LOGGER.info("Search '%s' returned %s recommendation results.", args.search, len(recommendation_search_results))
        for entry in recommendation_search_results[:20]:
            LOGGER.info(
                "Recommendation match | software=%s | category=%s | decision=%s | confidence=%.2f | explanation=%s",
                entry.software_name,
                entry.category,
                entry.decision,
                entry.confidence_score,
                entry.explanation,
            )

    return 0
