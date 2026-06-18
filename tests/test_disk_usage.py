from __future__ import annotations

from pathlib import Path

from src.collectors import disk_usage


def test_scan_directory_handles_permission_error(monkeypatch, tmp_path: Path) -> None:
    def raising_scandir(_path):
        raise PermissionError("denied")

    monkeypatch.setattr(disk_usage.os, "scandir", raising_scandir)
    disk_entries: list = []
    cache_entries: list = []

    total_size = disk_usage.scan_directory(
        path=tmp_path,
        scan_root=tmp_path,
        depth=0,
        max_depth=2,
        exclude_paths=set(),
        disk_entries=disk_entries,
        cache_entries=cache_entries,
    )

    assert total_size == 0
    assert disk_entries == []
    assert cache_entries == []


def test_collect_disk_usage_detects_cache(tmp_path: Path) -> None:
    cache_dir = tmp_path / "project" / ".venv"
    cache_dir.mkdir(parents=True)
    (cache_dir / "python.exe").write_text("binary", encoding="utf-8")

    disk_entries, cache_entries = disk_usage.collect_disk_usage([tmp_path], [], max_depth=3)

    assert disk_entries
    assert any(entry.cache_type == "python_virtualenv" for entry in cache_entries)
