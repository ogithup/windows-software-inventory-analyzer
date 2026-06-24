from __future__ import annotations

import csv
import json
import logging
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path

from src.windows_software_inventory_analyzer.models import DotnetSdkDecisionEntry


LOGGER = logging.getLogger("windows_software_inventory_analyzer.analyzers.dotnet_sdk_advisor")

DOTNET_SDK_HEADERS = (
    "sdk_version",
    "feature_band",
    "status",
    "used_by",
    "ide_context",
    "workload_context",
    "project_context",
    "global_json_matches",
    "csproj_signals",
    "recommendation",
)


def analyze_dotnet_sdk_dependencies(
    project_roots: list[Path],
    exclude_paths: list[Path],
    project_rows: list[dict[str, str]] | None = None,
    quick: bool = False,
) -> list[DotnetSdkDecisionEntry]:
    installed_sdks = collect_installed_sdks()
    if not installed_sdks:
        LOGGER.info("No .NET SDK installations detected.")
        return []

    ide_context = detect_ide_context()
    workload_context = detect_workload_context()
    project_signals = scan_dotnet_projects(project_roots, exclude_paths, project_rows=project_rows or [], quick=quick)

    results: list[DotnetSdkDecisionEntry] = []
    versions_by_band = build_versions_by_feature_band(installed_sdks)
    newest_by_band = {band: sorted(versions, key=version_sort_key, reverse=True)[0] for band, versions in versions_by_band.items()}

    global_versions = {signal["sdk_version"] for signal in project_signals["global_json_signals"] if signal["sdk_version"]}
    global_bands = {feature_band(version) for version in global_versions if version}
    csproj_bands = {band for band in project_signals["required_feature_bands"] if band}

    ide_summary = summarize_ide_context(ide_context)
    workload_summary = summarize_workloads(workload_context)
    project_summary = summarize_project_context(project_signals)

    for sdk_version in sorted(installed_sdks, key=version_sort_key, reverse=True):
        band = feature_band(sdk_version)
        exact_global_matches = [
            signal for signal in project_signals["global_json_signals"] if signal["sdk_version"] == sdk_version
        ]
        band_global_matches = [
            signal for signal in project_signals["global_json_signals"] if feature_band(signal["sdk_version"]) == band
        ]
        band_csproj_signals = [
            signal for signal in project_signals["csproj_signals"] if signal["band"] == band
        ]

        status, used_by, recommendation = decide_sdk_status(
            sdk_version=sdk_version,
            newest_in_band=newest_by_band.get(band, sdk_version),
            exact_global_matches=exact_global_matches,
            band_global_matches=band_global_matches,
            band_csproj_signals=band_csproj_signals,
            ide_context=ide_context,
            workload_context=workload_context,
            project_signals=project_signals,
            global_bands=global_bands,
            csproj_bands=csproj_bands,
        )

        results.append(
            DotnetSdkDecisionEntry(
                sdk_version=sdk_version,
                feature_band=band,
                status=status,
                used_by=used_by,
                ide_context=ide_summary,
                workload_context=workload_summary,
                project_context=project_summary,
                global_json_matches=" | ".join(signal["path"] for signal in exact_global_matches) or "-",
                csproj_signals=" | ".join(signal["path"] for signal in band_csproj_signals[:10]) or "-",
                recommendation=recommendation,
            )
        )

    return results


def collect_installed_sdks() -> list[str]:
    completed = run_command(["dotnet", "--list-sdks"])
    if completed is None or completed.returncode != 0:
        LOGGER.info("dotnet --list-sdks could not be executed.")
        return []

    versions: list[str] = []
    for line in completed.stdout.splitlines():
        match = re.match(r"\s*([0-9]+\.[0-9]+\.[0-9]+)", line)
        if match:
            versions.append(match.group(1))
    return sorted(set(versions), key=version_sort_key)


def detect_ide_context() -> dict[str, object]:
    context: dict[str, object] = {
        "visual_studio_installed": False,
        "visual_studio_products": [],
        "rider_installed": False,
        "vscode_installed": False,
    }

    vswhere_path = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    if vswhere_path.exists():
        completed = run_command([str(vswhere_path), "-all", "-format", "json"])
        if completed and completed.returncode == 0:
            try:
                payload = json.loads(completed.stdout or "[]")
            except json.JSONDecodeError:
                payload = []
            products = [item.get("displayName", "").strip() for item in payload if item.get("displayName", "").strip()]
            if products:
                context["visual_studio_installed"] = True
                context["visual_studio_products"] = products

    rider_candidates = [
        Path(r"C:\Program Files\JetBrains"),
        Path.home() / "AppData" / "Local" / "Programs" / "Rider",
    ]
    context["rider_installed"] = any(candidate.exists() for candidate in rider_candidates)

    vscode_candidates = [
        Path(r"C:\Program Files\Microsoft VS Code"),
        Path.home() / "AppData" / "Local" / "Programs" / "Microsoft VS Code",
        Path.home() / "AppData" / "Local" / "Programs" / "cursor",
    ]
    context["vscode_installed"] = any(candidate.exists() for candidate in vscode_candidates)
    return context


def detect_workload_context() -> dict[str, object]:
    completed = run_command(["dotnet", "workload", "list"])
    if completed is None or completed.returncode != 0:
        return {"installed_workloads": []}

    workloads: list[str] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("Installed Workload Id")
            or stripped.startswith("-")
            or "yüklenecek" in stripped.casefold()
            or "yüklenmiş" in stripped.casefold()
            or "yüklü" in stripped.casefold()
            or "workload" in stripped.casefold() and "version" in stripped.casefold()
        ):
            continue
        workload_id = stripped.split()[0]
        if re.fullmatch(r"[a-z0-9][a-z0-9.\-]*", workload_id):
            workloads.append(workload_id)
    return {"installed_workloads": sorted(set(workloads), key=str.casefold)}


def scan_dotnet_projects(
    project_roots: list[Path],
    exclude_paths: list[Path],
    project_rows: list[dict[str, str]] | None = None,
    quick: bool = False,
) -> dict[str, object]:
    if quick and project_rows:
        return scan_dotnet_projects_from_project_rows(project_rows)

    normalized_excludes = {normalize_path(path) for path in exclude_paths}
    global_json_signals: list[dict[str, str]] = []
    csproj_signals: list[dict[str, str]] = []
    sln_count = 0

    import os
    for root in project_roots:
        normalized_root = normalize_path(root)
        if not normalized_root.exists():
            continue

        for dirpath, dirnames, filenames in os.walk(str(normalized_root), topdown=True):
            # Prune dirnames in-place to avoid scanning excluded directories (e.g. AppData, node_modules)
            valid_dirs = []
            for d in dirnames:
                dir_path = Path(dirpath) / d
                normalized_dir = normalize_path(dir_path)
                if not should_skip_path(normalized_dir, normalized_excludes):
                    valid_dirs.append(d)
            dirnames[:] = valid_dirs

            for f in filenames:
                file_path = Path(dirpath) / f
                normalized_path = normalize_path(file_path)
                if should_skip_path(normalized_path, normalized_excludes):
                    continue

                lower_name = f.casefold()
                if lower_name == "global.json":
                    signal = parse_global_json(normalized_path)
                    if signal:
                        global_json_signals.append(signal)
                elif lower_name.endswith(".csproj"):
                    signal = parse_csproj_signal(normalized_path)
                    if signal:
                        csproj_signals.append(signal)
                elif lower_name.endswith(".sln"):
                    sln_count += 1

    required_feature_bands = sorted({signal["band"] for signal in csproj_signals if signal.get("band")}, key=str.casefold)
    return {
        "global_json_signals": global_json_signals,
        "csproj_signals": csproj_signals,
        "required_feature_bands": required_feature_bands,
        "sln_count": sln_count,
    }


def scan_dotnet_projects_from_project_rows(project_rows: list[dict[str, str]]) -> dict[str, object]:
    global_json_signals: list[dict[str, str]] = []
    csproj_signals: list[dict[str, str]] = []
    sln_count = 0

    for row in project_rows:
        technologies = {item.strip().casefold() for item in row.get("detected_technologies", "").split(",") if item.strip()}
        important_files = {item.strip() for item in row.get("important_files", "").split(",") if item.strip()}
        if ".net" not in technologies and not ({".sln", ".csproj"} & {Path(name).suffix.casefold() for name in important_files}):
            continue
        project_path = normalize_path(Path(row.get("path", "")))
        if not project_path.exists():
            continue
        for name in important_files:
            candidate = project_path / name
            if not candidate.exists() or not candidate.is_file():
                continue
            lower_name = candidate.name.casefold()
            if lower_name == "global.json":
                signal = parse_global_json(candidate)
                if signal:
                    global_json_signals.append(signal)
            elif lower_name.endswith(".csproj"):
                signal = parse_csproj_signal(candidate)
                if signal:
                    csproj_signals.append(signal)
            elif lower_name.endswith(".sln"):
                sln_count += 1
        current = project_path
        for _ in range(3):
            candidate = current / "global.json"
            if candidate.exists():
                signal = parse_global_json(candidate)
                if signal and not any(existing["path"] == signal["path"] for existing in global_json_signals):
                    global_json_signals.append(signal)
                break
            if current.parent == current:
                break
            current = current.parent

    required_feature_bands = sorted({signal["band"] for signal in csproj_signals if signal.get("band")}, key=str.casefold)
    return {
        "global_json_signals": global_json_signals,
        "csproj_signals": csproj_signals,
        "required_feature_bands": required_feature_bands,
        "sln_count": sln_count,
    }


def parse_global_json(path: Path) -> dict[str, str] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None

    sdk = payload.get("sdk", {})
    if not isinstance(sdk, dict):
        return None
    version = str(sdk.get("version", "")).strip()
    if not version:
        return None
    return {"path": str(path), "sdk_version": version}


def parse_csproj_signal(path: Path) -> dict[str, str] | None:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ET.ParseError):
        return None

    frameworks = collect_target_frameworks(root)
    if not frameworks:
        return None

    band = infer_feature_band_from_frameworks(frameworks)
    signal_fragments = frameworks.copy()
    if has_xml_text(root, "UseMaui", "true"):
        signal_fragments.append("maui")
    if has_sdk_attribute(root, "Microsoft.NET.Sdk.Web"):
        signal_fragments.append("aspnet")
    return {
        "path": str(path),
        "frameworks": ",".join(frameworks),
        "band": band,
        "signals": ",".join(signal_fragments),
    }


def collect_target_frameworks(root: ET.Element) -> list[str]:
    values: list[str] = []
    for tag_name in ("TargetFramework", "TargetFrameworks"):
        for node in root.findall(f".//{tag_name}"):
            if node.text:
                values.extend(part.strip() for part in node.text.split(";") if part.strip())
    return sorted(set(values), key=str.casefold)


def has_xml_text(root: ET.Element, tag_name: str, expected_value: str) -> bool:
    for node in root.findall(f".//{tag_name}"):
        if (node.text or "").strip().casefold() == expected_value.casefold():
            return True
    return False


def has_sdk_attribute(root: ET.Element, expected_value: str) -> bool:
    return (root.attrib.get("Sdk", "")).strip().casefold() == expected_value.casefold()


def infer_feature_band_from_frameworks(frameworks: list[str]) -> str:
    for framework in frameworks:
        match = re.search(r"net(\d+)\.(\d+)", framework.casefold())
        if match:
            major, minor = match.groups()
            return f"{major}.{minor}.1xx"
    return ""


def decide_sdk_status(
    sdk_version: str,
    newest_in_band: str,
    exact_global_matches: list[dict[str, str]],
    band_global_matches: list[dict[str, str]],
    band_csproj_signals: list[dict[str, str]],
    ide_context: dict[str, object],
    workload_context: dict[str, object],
    project_signals: dict[str, object],
    global_bands: set[str],
    csproj_bands: set[str],
) -> tuple[str, str, str]:
    band = feature_band(sdk_version)
    has_vs = bool(ide_context.get("visual_studio_installed"))
    workloads = {item.casefold() for item in workload_context.get("installed_workloads", [])}

    if exact_global_matches:
        return (
            "DO_NOT_REMOVE",
            "global.json exact match",
            "Bu SDK surumu en az bir projede global.json ile birebir sabitlenmis. Once bu projelerin sdk kisitini degistirmeden kaldirma.",
        )

    if band in global_bands:
        return (
            "IDE_DEPENDENT",
            "global.json band match",
            "Ayni feature band projelerde isaretlenmis. En yeni patch kalsa bile once proje build testi yap.",
        )

    if band_csproj_signals:
        if sdk_version == newest_in_band:
            return (
                "DO_NOT_REMOVE",
                "project framework match",
                "Bu feature band aktif .NET projeleriyle eslesiyor ve bu bandin en yeni patch'i. Once bunu tut.",
            )
        return (
            "SAFE_OLDER_PATCH",
            "older patch in active band",
            "Ayni feature band icinde daha yeni patch kurulu. global.json exact match yoksa once yeni patch ile build test edip eskiyi aday gorebilirsin.",
        )

    if has_vs and workloads & {"maui", "wasm-tools", "aspire", "android", "ios", "macos", "maccatalyst"}:
        if sdk_version == newest_in_band:
            return (
                "IDE_DEPENDENT",
                "Visual Studio workload context",
                "Visual Studio/.NET workload'lari kurulu. Bu band dogrudan proje izi vermese de IDE tarafinda kullaniliyor olabilir; once workload senaryosunu test et.",
            )
        return (
            "MANUAL_REVIEW",
            "Visual Studio workload context",
            "Visual Studio workload'lari kurulu. Eski patch olabilir ama kaldirmadan once Visual Studio ile build alin.",
        )

    if project_signals.get("sln_count", 0) > 0 and has_vs:
        if sdk_version == newest_in_band:
            return (
                "IDE_DEPENDENT",
                "solution files + Visual Studio",
                "Makinede .sln dosyalari ve Visual Studio var. Bu band dolayli olarak kullaniliyor olabilir.",
            )
        return (
            "MANUAL_REVIEW",
            "solution files + Visual Studio",
            "Eski patch olabilir; once .NET projelerini acip build testi yap.",
        )

    if sdk_version == newest_in_band:
        return (
            "KEEP_LATEST",
            "latest patch in band",
            "Bu feature band icindeki en yeni patch surumu. Eski patch'leri degerlendirmeden once bunu koru.",
        )

    if band not in csproj_bands and band not in global_bands:
        return (
            "SAFE_OLDER_PATCH",
            "no project or global.json evidence",
            "Bu patch surumu icin proje veya global.json kaniti bulunmadi. Ayni bandda daha yeni patch varsa kaldirma adayi olabilir.",
        )

    return (
        "MANUAL_REVIEW",
        "insufficient evidence",
        "Bu SDK icin net bir kullanim kaniti yok ama IDE/proje baglaminda ihtiyac olma ihtimali var. Build testi olmadan karar verme.",
    )


def build_versions_by_feature_band(versions: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for version in versions:
        grouped.setdefault(feature_band(version), []).append(version)
    return grouped


def feature_band(version: str) -> str:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return version
    major, minor, patch = match.groups()
    band = int(patch) // 100
    return f"{major}.{minor}.{band}xx"


def version_sort_key(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts) if parts else (0,)


def summarize_ide_context(ide_context: dict[str, object]) -> str:
    parts: list[str] = []
    if ide_context.get("visual_studio_installed"):
        products = ", ".join(ide_context.get("visual_studio_products", [])[:3])
        parts.append(f"Visual Studio: {products or 'kurulu'}")
    if ide_context.get("rider_installed"):
        parts.append("Rider: kurulu")
    if ide_context.get("vscode_installed"):
        parts.append("VS Code/Cursor: kurulu")
    return " | ".join(parts) or "Belirgin IDE bulunamadi"


def summarize_workloads(workload_context: dict[str, object]) -> str:
    workloads = workload_context.get("installed_workloads", [])
    if not workloads:
        return "dotnet workload list bos veya erisilemedi"
    preview = ", ".join(workloads[:8])
    suffix = "" if len(workloads) <= 8 else f" (+{len(workloads) - 8})"
    return f"{preview}{suffix}"


def summarize_project_context(project_signals: dict[str, object]) -> str:
    return (
        f"global.json={len(project_signals.get('global_json_signals', []))}, "
        f"csproj={len(project_signals.get('csproj_signals', []))}, "
        f"sln={project_signals.get('sln_count', 0)}"
    )


def write_dotnet_sdk_decision_report(entries: list[DotnetSdkDecisionEntry], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "dotnet_sdk_decision_report.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=DOTNET_SDK_HEADERS)
        writer.writeheader()
        for entry in entries:
            writer.writerow(asdict(entry))
    return path


def run_command(command: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        LOGGER.info("Command failed: %s | %s", " ".join(command), error)
        return None


def normalize_path(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except OSError:
        return path.expanduser()


def should_skip_path(path: Path, exclude_paths: set[Path]) -> bool:
    lower_path = str(path).casefold()
    return any(lower_path == str(excluded).casefold() or lower_path.startswith(f"{str(excluded).casefold()}\\") for excluded in exclude_paths)
