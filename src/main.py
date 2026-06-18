from __future__ import annotations

import argparse
from pathlib import Path

from src.windows_software_inventory_analyzer.pipeline import (
    enforce_read_only,
    prepare_config,
    run_analyze_dotnet_sdk,
    run_collect_programs,
    run_full_pipeline,
    run_map_software,
    run_recommend,
    run_scan_disk,
    run_scan_projects,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Windows Software Inventory Analyzer CLI")
    parser.add_argument("--config", type=Path, default=None, help="YAML config yolu")
    parser.add_argument("--dry-run", action="store_true", help="Dosya yazmadan sadece analiz et")
    parser.add_argument("--verbose", action="store_true", help="Detayli log ac")

    subparsers = parser.add_subparsers(dest="command", required=False)
    for command in ("collect-programs", "scan-disk", "scan-projects", "map-software", "recommend", "analyze-dotnet-sdk", "full-run", "refresh-all"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--config", type=Path, default=None, help=argparse.SUPPRESS)
        subparser.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)
        subparser.add_argument("--verbose", action="store_true", help=argparse.SUPPRESS)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    command = args.command or "refresh-all"

    config = prepare_config(args.config, verbose=args.verbose)
    enforce_read_only(config)

    if command == "collect-programs":
        run_collect_programs(config, dry_run=args.dry_run)
    elif command == "scan-disk":
        run_scan_disk(config, dry_run=args.dry_run)
    elif command == "scan-projects":
        run_scan_projects(config, dry_run=args.dry_run)
    elif command == "map-software":
        run_map_software(config, dry_run=args.dry_run)
    elif command == "recommend":
        run_recommend(config, dry_run=args.dry_run)
    elif command == "analyze-dotnet-sdk":
        run_analyze_dotnet_sdk(config, dry_run=args.dry_run)
    else:
        run_full_pipeline(config, dry_run=args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
