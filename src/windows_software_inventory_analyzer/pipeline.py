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
from src.analyzers.cleanup_planner import build_cleanup_simulation, write_cleanup_simulation
from src.analyzers.refresh_planner import build_refresh_plan, estimate_plan_duration, write_refresh_state
from src.analyzers.repo_deep_scanner import (
    merge_code_signals_into_projects,
    scan_project_code_signals,
    write_project_code_signals,
)
from src.analyzers.project_scanner import scan_projects, write_project_reports
from src.analyzers.project_size_analyzer import analyze_project_sizes, write_project_size_reports
from src.analyzers.removal_engine import build_removal_decisions, write_removal_decisions
from src.analyzers.risk_engine import build_program_risk_scores, write_program_risk_scores
from src.analyzers.system_tools_report import build_system_tools_reports, write_system_tools_reports
from src.analyzers.validation_strategy import build_validation_status, write_validation_status_report
from src.analyzers.recommender import (
    build_recommendations,
    enrich_recommendations,
    load_category_rules,
    write_recommendations,
)
from src.analyzers.runtime_advisor import build_runtime_inventory
from src.analyzers.software_explainer import load_software_catalog, write_software_descriptions
from src.collectors.disk_usage import collect_disk_usage, write_disk_usage_reports
from src.analyzers.disk_zone_analyzer import analyze_disk_zones, write_disk_zone_reports
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
    write_refresh_state("collect-programs", config, config.report.output_dir)
    return {"applications": applications, "json_path": json_path, "csv_path": csv_path}


def run_collect_usage_signals(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=False)
    entries = collect_program_usage_signals(collect_result["applications"])
    if dry_run:
        LOGGER.info("Dry-run: usage signal raporu yazilmadi. entries=%s", len(entries))
        return {"usage_signal_entries": entries, "usage_signal_report_path": None}
    report_path = write_program_usage_report(entries, config.report.output_dir)
    write_refresh_state("collect-usage", config, config.report.output_dir)
    return {"usage_signal_entries": entries, "usage_signal_report_path": report_path}


def run_scan_disk(config: AppConfig, dry_run: bool = False, quick: bool = False) -> dict[str, object]:
    max_depth = min(config.scan.max_depth, 2) if quick else config.scan.max_depth
    disk_entries, cache_entries = collect_disk_usage(
        roots=config.scan.disk_usage_roots,
        exclude_paths=config.scan.exclude_paths,
        max_depth=max_depth,
    )
    project_rows = []
    if config.report.output_dir.joinpath("project_tech_stack.csv").exists():
        project_rows = load_mapping_csv_rows(config.report.output_dir / "project_tech_stack.csv")
    zone_entries, scenario_entries = analyze_disk_zones(
        disk_entries=disk_entries,
        cache_entries=cache_entries,
        project_rows=project_rows,
    )
    if dry_run:
        LOGGER.info(
            "Dry-run: disk raporlari yazilmadi. disk_entries=%s cache_entries=%s zone_entries=%s",
            len(disk_entries),
            len(cache_entries),
            len(zone_entries),
        )
        return {
            "disk_entries": disk_entries,
            "cache_entries": cache_entries,
            "zone_entries": zone_entries,
            "scenario_entries": scenario_entries,
            "disk_usage_path": None,
            "developer_caches_path": None,
            "disk_zone_report_path": None,
            "disk_cleanup_scenarios_path": None,
        }
    disk_usage_path, developer_caches_path = write_disk_usage_reports(
        disk_entries,
        cache_entries,
        config.report.output_dir,
    )
    disk_zone_report_path, disk_cleanup_scenarios_path = write_disk_zone_reports(
        zone_entries,
        scenario_entries,
        config.report.output_dir,
    )
    write_refresh_state("scan-disk", config, config.report.output_dir)
    return {
        "disk_entries": disk_entries,
        "cache_entries": cache_entries,
        "zone_entries": zone_entries,
        "scenario_entries": scenario_entries,
        "disk_usage_path": disk_usage_path,
        "developer_caches_path": developer_caches_path,
        "disk_zone_report_path": disk_zone_report_path,
        "disk_cleanup_scenarios_path": disk_cleanup_scenarios_path,
    }


def run_scan_projects(config: AppConfig, dry_run: bool = False, quick: bool = False) -> dict[str, object]:
    project_entries, file_index_entries = scan_projects(
        project_roots=config.scan.project_roots,
        exclude_paths=config.scan.exclude_paths,
    )
    code_signal_entries = [] if quick else scan_project_code_signals(project_entries)
    merged_project_entries = merge_code_signals_into_projects(project_entries, code_signal_entries)
    project_size_entries, project_storage_breakdowns = analyze_project_sizes([asdict(entry) for entry in merged_project_entries])
    if dry_run:
        LOGGER.info(
            "Dry-run: proje raporlari yazilmadi. projects=%s indexed_files=%s code_signals=%s project_sizes=%s",
            len(merged_project_entries),
            len(file_index_entries),
            len(code_signal_entries),
            len(project_size_entries),
        )
        return {
            "project_entries": merged_project_entries,
            "file_index_entries": file_index_entries,
            "code_signal_entries": code_signal_entries,
            "project_size_entries": project_size_entries,
            "project_storage_breakdowns": project_storage_breakdowns,
            "project_stack_path": None,
            "project_index_path": None,
            "project_code_signals_path": None,
            "project_size_report_path": None,
            "project_storage_breakdown_path": None,
        }
    project_stack_path, project_index_path = write_project_reports(
        merged_project_entries,
        file_index_entries,
        config.report.output_dir,
    )
    project_code_signals_path = write_project_code_signals(code_signal_entries, config.report.output_dir)
    project_size_report_path, project_storage_breakdown_path = write_project_size_reports(
        project_size_entries,
        project_storage_breakdowns,
        config.report.output_dir,
    )
    write_refresh_state("scan-projects", config, config.report.output_dir)
    return {
        "project_entries": merged_project_entries,
        "file_index_entries": file_index_entries,
        "code_signal_entries": code_signal_entries,
        "project_size_entries": project_size_entries,
        "project_storage_breakdowns": project_storage_breakdowns,
        "project_stack_path": project_stack_path,
        "project_index_path": project_index_path,
        "project_code_signals_path": project_code_signals_path,
        "project_size_report_path": project_size_report_path,
        "project_storage_breakdown_path": project_storage_breakdown_path,
    }


def run_map_software(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    output_dir = config.report.output_dir
    installed_path = output_dir / "installed_programs.csv"
    project_stack_path = output_dir / "project_tech_stack.csv"
    project_index_path = output_dir / "project_files_index.csv"
    if not installed_path.exists():
        installed_path = run_collect_programs(config, dry_run=False)["csv_path"]
    if not project_stack_path.exists() or not project_index_path.exists():
        project_result = run_scan_projects(config, dry_run=False)
        project_stack_path = project_result["project_stack_path"]
        project_index_path = project_result["project_index_path"]
    import sys
    tech_rules_path = Path("technology_rules.yaml")
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        bundle_path = Path(sys._MEIPASS) / "technology_rules.yaml"
        if bundle_path.exists():
            tech_rules_path = bundle_path

    mapping_entries = map_software_to_projects(
        installed_programs=load_mapping_csv_rows(installed_path),
        project_entries=load_mapping_csv_rows(project_stack_path),
        file_index_entries=load_mapping_csv_rows(project_index_path),
        rules=load_technology_rules(tech_rules_path),
    )
    if dry_run:
        LOGGER.info("Dry-run: software mapping raporu yazilmadi. mappings=%s", len(mapping_entries))
        return {"mapping_entries": mapping_entries, "mapping_path": None}
    mapping_path = write_mapping_report(mapping_entries, config.report.output_dir)
    write_refresh_state("map-software", config, config.report.output_dir)
    return {"mapping_entries": mapping_entries, "mapping_path": mapping_path}


def run_recommend(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    output_dir = config.report.output_dir
    installed_path = output_dir / "installed_programs.csv"
    usage_path = output_dir / "program_usage_signals.csv"
    disk_usage_path = output_dir / "disk_usage.csv"
    project_stack_path = output_dir / "project_tech_stack.csv"
    mapping_path = output_dir / "software_project_mapping.csv"
    if not installed_path.exists():
        installed_path = run_collect_programs(config, dry_run=False)["csv_path"]
    if not usage_path.exists():
        usage_path = run_collect_usage_signals(config, dry_run=False)["usage_signal_report_path"]
    if not disk_usage_path.exists():
        disk_usage_path = run_scan_disk(config, dry_run=False)["disk_usage_path"]
    if not project_stack_path.exists():
        project_stack_path = run_scan_projects(config, dry_run=False)["project_stack_path"]
    if not mapping_path.exists():
        mapping_path = run_map_software(config, dry_run=False)["mapping_path"]
    import sys
    cat_rules_path = Path("category_rules.yaml")
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        bundle_path = Path(sys._MEIPASS) / "category_rules.yaml"
        if bundle_path.exists():
            cat_rules_path = bundle_path

    recommendation_entries = build_recommendations(
        installed_programs=load_mapping_csv_rows(installed_path),
        disk_usage_rows=load_mapping_csv_rows(disk_usage_path),
        mapping_rows=load_mapping_csv_rows(mapping_path),
        category_rules=load_category_rules(cat_rules_path),
        project_rows=load_mapping_csv_rows(project_stack_path),
        usage_rows=load_mapping_csv_rows(usage_path),
    )
    risk_entries = build_program_risk_scores(
        installed_programs=load_mapping_csv_rows(installed_path),
        mapping_rows=load_mapping_csv_rows(mapping_path),
        recommendation_rows=[asdict(entry) for entry in recommendation_entries],
        usage_rows=load_mapping_csv_rows(usage_path),
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
    write_refresh_state("recommend", config, config.report.output_dir)
    return {
        "recommendation_entries": recommendation_entries,
        "recommendations_path": recommendations_path,
        "risk_entries": risk_entries,
        "risk_report_path": risk_report_path,
        "software_descriptions_path": software_descriptions_path,
    }


def run_score_risk(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    output_dir = config.report.output_dir
    installed_path = output_dir / "installed_programs.csv"
    usage_path = output_dir / "program_usage_signals.csv"
    disk_usage_path = output_dir / "disk_usage.csv"
    project_stack_path = output_dir / "project_tech_stack.csv"
    mapping_path = output_dir / "software_project_mapping.csv"
    if not installed_path.exists():
        installed_path = run_collect_programs(config, dry_run=False)["csv_path"]
    if not usage_path.exists():
        usage_path = run_collect_usage_signals(config, dry_run=False)["usage_signal_report_path"]
    if not disk_usage_path.exists():
        disk_usage_path = run_scan_disk(config, dry_run=False)["disk_usage_path"]
    if not project_stack_path.exists():
        project_stack_path = run_scan_projects(config, dry_run=False)["project_stack_path"]
    if not mapping_path.exists():
        mapping_path = run_map_software(config, dry_run=False)["mapping_path"]
    recommendation_entries = build_recommendations(
        installed_programs=load_mapping_csv_rows(installed_path),
        disk_usage_rows=load_mapping_csv_rows(disk_usage_path),
        mapping_rows=load_mapping_csv_rows(mapping_path),
        category_rules=load_category_rules(Path("category_rules.yaml")),
        project_rows=load_mapping_csv_rows(project_stack_path),
        usage_rows=load_mapping_csv_rows(usage_path),
    )
    risk_entries = build_program_risk_scores(
        installed_programs=load_mapping_csv_rows(installed_path),
        mapping_rows=load_mapping_csv_rows(mapping_path),
        recommendation_rows=[asdict(entry) for entry in recommendation_entries],
        usage_rows=load_mapping_csv_rows(usage_path),
    )
    if dry_run:
        LOGGER.info("Dry-run: risk report yazilmadi. entries=%s", len(risk_entries))
        return {"risk_entries": risk_entries, "risk_report_path": None}
    risk_report_path = write_program_risk_scores(risk_entries, config.report.output_dir)
    write_refresh_state("score-risk", config, config.report.output_dir)
    return {"risk_entries": risk_entries, "risk_report_path": risk_report_path}


def run_analyze_dotnet_sdk(config: AppConfig, dry_run: bool = False, quick: bool = False) -> dict[str, object]:
    project_rows = load_mapping_csv_rows(config.report.output_dir / "project_tech_stack.csv")
    if not project_rows:
        project_result = run_scan_projects(config, dry_run=False, quick=quick)
        project_rows = load_mapping_csv_rows(project_result["project_stack_path"]) if project_result.get("project_stack_path") else []
    entries = analyze_dotnet_sdk_dependencies(
        project_roots=config.scan.project_roots,
        exclude_paths=config.scan.exclude_paths,
        project_rows=project_rows,
        quick=quick,
    )
    if dry_run:
        LOGGER.info("Dry-run: dotnet sdk decision report yazilmadi. entries=%s", len(entries))
        return {"dotnet_sdk_entries": entries, "dotnet_sdk_report_path": None}
    report_path = write_dotnet_sdk_decision_report(entries, config.report.output_dir)
    write_refresh_state("analyze-dotnet-sdk", config, config.report.output_dir)
    return {"dotnet_sdk_entries": entries, "dotnet_sdk_report_path": report_path}


def run_validate_dotnet_sdks(config: AppConfig, dry_run: bool = False, quick: bool = False) -> dict[str, object]:
    artifacts_root = config.report.output_dir / "sdk_validation_artifacts"
    project_rows = load_mapping_csv_rows(config.report.output_dir / "project_tech_stack.csv")
    if not project_rows:
        project_result = run_scan_projects(config, dry_run=False, quick=quick)
        project_rows = load_mapping_csv_rows(project_result["project_stack_path"]) if project_result.get("project_stack_path") else []
    entries = validate_dotnet_sdks(
        project_roots=config.scan.project_roots,
        exclude_paths=config.scan.exclude_paths,
        artifacts_root=artifacts_root,
        project_rows=project_rows,
        quick=quick,
        dry_run=dry_run,
    )
    if dry_run:
        LOGGER.info("Dry-run: sdk validation report yazilmadi. entries=%s", len(entries))
        return {"dotnet_sdk_validation_entries": entries, "sdk_validation_report_path": None}
    report_path = write_dotnet_sdk_validation_report(entries, config.report.output_dir)
    write_refresh_state("validate-dotnet-sdks", config, config.report.output_dir)
    return {"dotnet_sdk_validation_entries": entries, "sdk_validation_report_path": report_path}


def run_validate_projects(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    output_dir = config.report.output_dir
    project_rows = load_mapping_csv_rows(output_dir / "project_tech_stack.csv")
    sdk_validation_rows = load_mapping_csv_rows(output_dir / "sdk_validation_report.csv")
    if not project_rows:
        project_result = run_scan_projects(config, dry_run=False)
        project_rows = load_mapping_csv_rows(project_result["project_stack_path"])
    if not sdk_validation_rows:
        sdk_result = run_validate_dotnet_sdks(config, dry_run=False)
        sdk_validation_rows = (
            load_mapping_csv_rows(sdk_result["sdk_validation_report_path"])
            if sdk_result.get("sdk_validation_report_path")
            else []
        )
    entries = build_validation_status(
        project_rows=project_rows,
        sdk_validation_rows=sdk_validation_rows,
        artifacts_root=output_dir / "validation_artifacts",
        dry_run=dry_run,
    )
    if dry_run:
        LOGGER.info("Dry-run: validation status report yazilmadi. entries=%s", len(entries))
        return {"validation_entries": entries, "validation_status_report_path": None}
    report_path = write_validation_status_report(entries, output_dir)
    write_refresh_state("validate-projects", config, output_dir)
    return {"validation_entries": entries, "validation_status_report_path": report_path}


def run_build_removal_decisions(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    output_dir = config.report.output_dir
    installed_rows = load_mapping_csv_rows(output_dir / "installed_programs.csv")
    recommendation_rows = load_mapping_csv_rows(output_dir / "recommendations.csv")
    mapping_rows = load_mapping_csv_rows(output_dir / "software_project_mapping.csv")
    usage_rows = load_mapping_csv_rows(output_dir / "program_usage_signals.csv")
    risk_rows = load_mapping_csv_rows(output_dir / "program_risk_scores.csv")
    project_rows = load_mapping_csv_rows(output_dir / "project_tech_stack.csv")
    project_size_rows = load_mapping_csv_rows(output_dir / "project_size_report.csv")
    disk_zone_rows = load_mapping_csv_rows(output_dir / "disk_zone_report.csv")
    disk_scenario_rows = load_mapping_csv_rows(output_dir / "disk_cleanup_scenarios.csv")
    dotnet_sdk_rows = load_mapping_csv_rows(output_dir / "dotnet_sdk_decision_report.csv")
    sdk_validation_rows = load_mapping_csv_rows(output_dir / "sdk_validation_report.csv")

    if not installed_rows:
        collect_result = run_collect_programs(config, dry_run=False)
        installed_rows = load_mapping_csv_rows(collect_result["csv_path"])
    if not usage_rows:
        usage_result = run_collect_usage_signals(config, dry_run=False)
        usage_rows = load_mapping_csv_rows(usage_result["usage_signal_report_path"])
    if not project_rows:
        project_result = run_scan_projects(config, dry_run=False)
        project_rows = load_mapping_csv_rows(project_result["project_stack_path"])
        project_size_rows = load_mapping_csv_rows(project_result["project_size_report_path"]) if project_result.get("project_size_report_path") else []
    if not disk_zone_rows or not disk_scenario_rows:
        disk_result = run_scan_disk(config, dry_run=False)
        disk_zone_rows = load_mapping_csv_rows(disk_result["disk_zone_report_path"]) if disk_result.get("disk_zone_report_path") else []
        disk_scenario_rows = load_mapping_csv_rows(disk_result["disk_cleanup_scenarios_path"]) if disk_result.get("disk_cleanup_scenarios_path") else []
    if not mapping_rows:
        mapping_result = run_map_software(config, dry_run=False)
        mapping_rows = load_mapping_csv_rows(mapping_result["mapping_path"])
    if not recommendation_rows or not risk_rows:
        recommendation_result = run_recommend(config, dry_run=False)
        recommendation_rows = load_mapping_csv_rows(recommendation_result["recommendations_path"])
        risk_rows = load_mapping_csv_rows(recommendation_result["risk_report_path"]) if recommendation_result.get("risk_report_path") else []
    if not dotnet_sdk_rows:
        dotnet_result = run_analyze_dotnet_sdk(config, dry_run=False, quick=True)
        dotnet_sdk_rows = load_mapping_csv_rows(dotnet_result["dotnet_sdk_report_path"]) if dotnet_result.get("dotnet_sdk_report_path") else []
    if not sdk_validation_rows:
        dotnet_validation_result = run_validate_dotnet_sdks(config, dry_run=False, quick=True)
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
        project_size_rows=project_size_rows,
        disk_zone_rows=disk_zone_rows,
        disk_scenario_rows=disk_scenario_rows,
    )
    if dry_run:
        LOGGER.info("Dry-run: removal decisions report yazilmadi. entries=%s", len(entries))
        return {"removal_decision_entries": entries, "removal_decisions_path": None}
    report_path = write_removal_decisions(entries, config.report.output_dir)
    write_refresh_state("build-removal-decisions", config, config.report.output_dir)
    return {"removal_decision_entries": entries, "removal_decisions_path": report_path}


def run_build_system_tools_report(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    output_dir = config.report.output_dir
    recommendations = load_mapping_csv_rows(output_dir / "recommendations.csv")
    installed_rows = load_mapping_csv_rows(output_dir / "installed_programs.csv")
    project_rows = load_mapping_csv_rows(output_dir / "project_tech_stack.csv")
    removal_rows = load_mapping_csv_rows(output_dir / "removal_decisions.csv")
    validation_rows = load_mapping_csv_rows(output_dir / "validation_status.csv")
    sdk_validation_rows = load_mapping_csv_rows(output_dir / "sdk_validation_report.csv")

    if not recommendations:
        recommendations = load_mapping_csv_rows(run_recommend(config, dry_run=False)["recommendations_path"])
    if not installed_rows:
        installed_rows = load_mapping_csv_rows(run_collect_programs(config, dry_run=False)["csv_path"])
    if not project_rows:
        project_rows = load_mapping_csv_rows(run_scan_projects(config, dry_run=False)["project_stack_path"])
    if not removal_rows:
        removal_rows = load_mapping_csv_rows(run_build_removal_decisions(config, dry_run=False)["removal_decisions_path"])
    if not validation_rows:
        validation_rows = load_mapping_csv_rows(run_validate_projects(config, dry_run=False)["validation_status_report_path"])

    runtime_family_summaries, runtime_family_details = build_runtime_inventory(
        recommendations,
        installed_rows,
        project_rows,
    )
    family_reports, impact_rows = build_system_tools_reports(
        runtime_family_summaries=runtime_family_summaries,
        runtime_family_details=runtime_family_details,
        removal_decisions=removal_rows,
        validation_rows=validation_rows,
        sdk_validation_rows=sdk_validation_rows,
    )
    if dry_run:
        LOGGER.info("Dry-run: system tools reports yazilmadi. families=%s impacts=%s", len(family_reports), len(impact_rows))
        return {
            "family_reports": family_reports,
            "impact_rows": impact_rows,
            "system_tools_report_path": None,
            "system_tool_impact_report_path": None,
        }
    report_path, impact_path = write_system_tools_reports(family_reports, impact_rows, output_dir)
    write_refresh_state("build-system-tools-report", config, output_dir)
    return {
        "family_reports": family_reports,
        "impact_rows": impact_rows,
        "system_tools_report_path": report_path,
        "system_tool_impact_report_path": impact_path,
    }


def run_plan_cleanup_simulation(config: AppConfig, selected_names: list[str] | None = None, dry_run: bool = False) -> dict[str, object]:
    output_dir = config.report.output_dir
    removal_rows = load_mapping_csv_rows(output_dir / "removal_decisions.csv")
    if not removal_rows:
        removal_rows = load_mapping_csv_rows(run_build_removal_decisions(config, dry_run=False)["removal_decisions_path"])
    if not selected_names:
        selected_names = [
            row.get("software_name", "")
            for row in removal_rows
            if row.get("decision_label", "") in {"LOWER_RISK_CANDIDATE", "CACHE_CLEAN_ONLY"}
        ][:5]
    entry = build_cleanup_simulation(selected_names, removal_rows)
    if dry_run:
        LOGGER.info("Dry-run: cleanup simulation yazilmadi. selected=%s", len(selected_names))
        return {"cleanup_simulation_entry": entry, "cleanup_simulation_path": None}
    report_path = write_cleanup_simulation(entry, output_dir)
    return {"cleanup_simulation_entry": entry, "cleanup_simulation_path": report_path}


def run_incremental_refresh(config: AppConfig, dry_run: bool = False, mode: str = "quick") -> dict[str, object]:
    plan = build_refresh_plan(config, config.report.output_dir, mode=mode)
    LOGGER.info("Refresh plan hazir. mode=%s eta=%s saniye", mode, estimate_plan_duration(plan))
    results: dict[str, object] = {"refresh_plan": plan}
    executed_commands: set[str] = set()
    for step in plan:
        if not step.should_run:
            LOGGER.info("Skipping %s: %s", step.command, step.reason)
            continue
        executed_commands.add(step.command)
        if step.command == "collect-programs":
            results.update(run_collect_programs(config, dry_run=dry_run))
        elif step.command == "collect-usage":
            results.update(run_collect_usage_signals(config, dry_run=dry_run))
        elif step.command == "scan-projects":
            results.update(run_scan_projects(config, dry_run=dry_run, quick=mode == "quick"))
        elif step.command == "scan-disk":
            results.update(run_scan_disk(config, dry_run=dry_run, quick=mode == "quick"))
        elif step.command == "map-software":
            results.update(run_map_software(config, dry_run=dry_run))
        elif step.command == "score-risk":
            results.update(run_score_risk(config, dry_run=dry_run))
        elif step.command == "recommend":
            results.update(run_recommend(config, dry_run=dry_run))
        elif step.command == "analyze-dotnet-sdk":
            results.update(run_analyze_dotnet_sdk(config, dry_run=dry_run, quick=mode == "quick"))
        elif step.command == "validate-dotnet-sdks":
            results.update(run_validate_dotnet_sdks(config, dry_run=dry_run, quick=mode == "quick"))
        elif step.command == "build-removal-decisions":
            results.update(run_build_removal_decisions(config, dry_run=dry_run))
    if not dry_run:
        validation_path = config.report.output_dir / "validation_status.csv"
        system_report_path = config.report.output_dir / "system_tools_report.csv"
        if executed_commands.intersection({"scan-projects", "validate-dotnet-sdks"}) or not validation_path.exists():
            results.update(run_validate_projects(config, dry_run=False))
            executed_commands.add("validate-projects")
        if executed_commands.intersection({"build-removal-decisions", "validate-projects", "recommend"}) or not system_report_path.exists():
            results.update(run_build_system_tools_report(config, dry_run=False))
    return results


def run_full_pipeline(config: AppConfig, dry_run: bool = False) -> dict[str, object]:
    collect_result = run_collect_programs(config, dry_run=dry_run)
    usage_result = run_collect_usage_signals(config, dry_run=dry_run)
    project_result = run_scan_projects(config, dry_run=dry_run)
    disk_result = run_scan_disk(config, dry_run=dry_run)
    dotnet_result = run_analyze_dotnet_sdk(config, dry_run=dry_run, quick=False)
    dotnet_validation_result = run_validate_dotnet_sdks(config, dry_run=dry_run, quick=False)

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
    validation_result = run_validate_projects(config, dry_run=False)
    system_tools_result = run_build_system_tools_report(config, dry_run=False)
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
        **validation_result,
        **system_tools_result,
    }
