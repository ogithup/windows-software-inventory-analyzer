from __future__ import annotations

import argparse
import logging
from pathlib import Path

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
    return parser.parse_args()


def enforce_read_only(read_only: bool, allow_delete: bool, allow_uninstall: bool) -> None:
    if not read_only:
        raise ValueError("Read-only mode must remain enabled in this version.")
    if allow_delete:
        raise ValueError("Deletion is not supported in this version.")
    if allow_uninstall:
        raise ValueError("Uninstall actions are not supported in this version.")


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    configure_logging(config.logging)

    enforce_read_only(
        read_only=config.behavior.read_only,
        allow_delete=config.behavior.allow_delete,
        allow_uninstall=config.behavior.allow_uninstall,
    )

    LOGGER.info("Application started in read-only mode.")
    LOGGER.info("Configured disks: %s", ", ".join(config.scan.disks) or "None")
    LOGGER.info("Project roots: %s", ", ".join(str(path) for path in config.scan.project_roots) or "None")
    LOGGER.info("Excluded paths: %s", ", ".join(str(path) for path in config.scan.exclude_paths) or "None")
    LOGGER.info("Report output directory: %s", config.report.output_dir)
    LOGGER.info("No scan actions are executed in Sprint 0. Initialization only.")

    return 0
