from __future__ import annotations

from src.collectors.installed_apps import collect_from_registry, parse_winget_output


def test_parse_winget_output_parses_basic_table() -> None:
    output = """
Name                           Id                  Version Source
---------------------------------------------------------------
Docker Desktop                 Docker.DockerDesktop 4.54.0 winget
Python 3.11                    Python.Python.3.11   3.11.7 winget
"""

    applications = parse_winget_output(output)

    assert len(applications) == 2
    assert applications[0].name == "Docker Desktop"
    assert applications[1].version == "3.11.7"


def test_collect_from_registry_non_windows_safe() -> None:
    applications = collect_from_registry()

    assert isinstance(applications, list)
