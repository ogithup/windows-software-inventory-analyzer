from __future__ import annotations

import argparse
from pathlib import Path

from src.windows_software_inventory_analyzer.pipeline import (
    enforce_read_only,
    prepare_config,
    run_analyze_dotnet_sdk,
    run_build_system_tools_report,
    run_build_removal_decisions,
    run_collect_programs,
    run_collect_usage_signals,
    run_full_pipeline,
    run_incremental_refresh,
    run_map_software,
    run_monitoring_alerts,
    run_plan_cleanup_simulation,
    run_recommend,
    run_scan_disk,
    run_scan_projects,
    run_score_risk,
    run_generate_weekly_report,
    run_validate_projects,
    run_validate_dotnet_sdks,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Windows Software Inventory Analyzer CLI")
    parser.add_argument("--config", type=Path, default=None, help="YAML config yolu")
    parser.add_argument("--dry-run", action="store_true", help="Dosya yazmadan sadece analiz et")
    parser.add_argument("--verbose", action="store_true", help="Detayli log ac")
    parser.add_argument("--refresh-mode", choices=("quick", "full"), default="quick", help="Yenileme modu")

    subparsers = parser.add_subparsers(dest="command", required=False)
    for command in ("collect-programs", "collect-usage", "scan-disk", "scan-projects", "map-software", "score-risk", "recommend", "analyze-dotnet-sdk", "validate-dotnet-sdks", "validate-projects", "build-removal-decisions", "build-system-tools-report", "plan-cleanup-simulation", "monitor-alerts", "generate-weekly-report", "full-run", "refresh-all"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--config", type=Path, default=None, help=argparse.SUPPRESS)
        subparser.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)
        subparser.add_argument("--verbose", action="store_true", help=argparse.SUPPRESS)
        subparser.add_argument("--refresh-mode", choices=("quick", "full"), default="quick", help=argparse.SUPPRESS)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    command = args.command or "refresh-all"

    config = prepare_config(args.config, verbose=args.verbose)
    enforce_read_only(config)

    if command == "collect-programs":
        run_collect_programs(config, dry_run=args.dry_run)
    elif command == "collect-usage":
        run_collect_usage_signals(config, dry_run=args.dry_run)
    elif command == "scan-disk":
        run_scan_disk(config, dry_run=args.dry_run, quick=args.refresh_mode == "quick")
    elif command == "scan-projects":
        run_scan_projects(config, dry_run=args.dry_run, quick=args.refresh_mode == "quick")
    elif command == "map-software":
        run_map_software(config, dry_run=args.dry_run)
    elif command == "score-risk":
        run_score_risk(config, dry_run=args.dry_run)
    elif command == "recommend":
        run_recommend(config, dry_run=args.dry_run)
    elif command == "analyze-dotnet-sdk":
        run_analyze_dotnet_sdk(config, dry_run=args.dry_run, quick=args.refresh_mode == "quick")
    elif command == "validate-dotnet-sdks":
        run_validate_dotnet_sdks(config, dry_run=args.dry_run, quick=args.refresh_mode == "quick")
    elif command == "validate-projects":
        run_validate_projects(config, dry_run=args.dry_run)
    elif command == "build-removal-decisions":
        run_build_removal_decisions(config, dry_run=args.dry_run)
    elif command == "build-system-tools-report":
        run_build_system_tools_report(config, dry_run=args.dry_run)
    elif command == "plan-cleanup-simulation":
        run_plan_cleanup_simulation(config, dry_run=args.dry_run)
    elif command == "monitor-alerts":
        run_monitoring_alerts(config, dry_run=args.dry_run, force=True)
    elif command == "generate-weekly-report":
        run_generate_weekly_report(config, dry_run=args.dry_run)
    elif command == "refresh-all":
        run_incremental_refresh(config, dry_run=args.dry_run, mode=args.refresh_mode)
    else:
        run_full_pipeline(config, dry_run=args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
