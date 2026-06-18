from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_cli_dry_run_collect_programs() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "src.main", "collect-programs", "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0


def test_dashboard_build_report() -> None:
    completed = subprocess.run(
        [sys.executable, "dashboard.py", "--build-report"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
