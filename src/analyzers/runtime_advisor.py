from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(slots=True)
class RuntimeEntry:
    software_name: str
    family: str
    version: str
    arch: str
    decision: str
    confidence_score: float
    matched_projects: str
    install_location: str


def build_runtime_inventory(
    recommendations: list[dict[str, str]],
    installed_programs: list[dict[str, str]],
    projects: list[dict[str, str]],
) -> tuple[list[dict[str, str]], dict[str, list[dict[str, str]]]]:
    runtime_rows = [row for row in recommendations if row.get("category", "") == "Runtime/System"]
    project_context = build_project_dependency_context(projects)
    installed_index = build_installed_program_index(installed_programs)

    unique_entries: dict[str, RuntimeEntry] = {}
    for row in runtime_rows:
        software_name = row.get("software_name", "").strip()
        if not software_name:
            continue
        family = classify_runtime_family(software_name)
        if family == "other_runtime":
            continue

        installed_row = installed_index.get(software_name.casefold(), {})
        version = normalize_runtime_version(
            family=family,
            software_name=software_name,
            installed_version=installed_row.get("version", "").strip(),
        )
        arch = extract_architecture(software_name)
        identity = build_runtime_identity(family, software_name, version, arch)

        entry = RuntimeEntry(
            software_name=software_name,
            family=family,
            version=version,
            arch=arch,
            decision=row.get("decision", ""),
            confidence_score=safe_float(row.get("confidence_score", "0")),
            matched_projects=row.get("matched_projects", ""),
            install_location=row.get("install_location", ""),
        )
        current = unique_entries.get(identity)
        if current is None or entry.confidence_score >= current.confidence_score:
            unique_entries[identity] = entry

    family_entries: dict[str, list[RuntimeEntry]] = {}
    for entry in unique_entries.values():
        family_entries.setdefault(entry.family, []).append(entry)

    summaries: list[dict[str, str]] = []
    family_detail_rows: dict[str, list[dict[str, str]]] = {}
    for family, entries in sorted(family_entries.items()):
        entries.sort(key=lambda item: version_sort_key(item.version), reverse=True)
        summary, detail_rows = summarize_family(family, entries, project_context)
        summaries.append(summary)
        family_detail_rows[family] = detail_rows

    return summaries, family_detail_rows


def build_installed_program_index(installed_programs: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in installed_programs:
        name = row.get("name", "").strip()
        if not name:
            continue
        key = name.casefold()
        current = index.get(key)
        if current is None or len(row.get("version", "")) > len(current.get("version", "")):
            index[key] = row
    return index


def build_project_dependency_context(projects: list[dict[str, str]]) -> dict[str, int]:
    context = {
        "dotnet_projects": 0,
        "backend_projects": 0,
        "ai_projects": 0,
    }
    for project in projects:
        technologies = {item.strip().casefold() for item in project.get("detected_technologies", "").split(",") if item.strip()}
        important_files = project.get("important_files", "").casefold()
        if ".net" in technologies or ".csproj" in important_files or ".sln" in important_files:
            context["dotnet_projects"] += 1
        if {"python", "java-maven", "java-gradle", "docker", "flask", "django", "fastapi"} & technologies:
            context["backend_projects"] += 1
        if {"opencv", "pytorch", "tensorflow", "python"} & technologies:
            context["ai_projects"] += 1
    return context


def summarize_family(
    family: str,
    entries: list[RuntimeEntry],
    project_context: dict[str, int],
) -> tuple[dict[str, str], list[dict[str, str]]]:
    keep_candidates, remove_candidates, rule_text, dependency_signal = advise_family(family, entries, project_context)
    detail_rows = []
    for entry in entries:
        action = "KEEP_CANDIDATE" if entry.software_name in keep_candidates else "MANUAL_REVIEW"
        if entry.software_name in remove_candidates:
            action = "OLDER_VERSION"
        detail_rows.append(
            {
                "software_name": entry.software_name,
                "version": entry.version or "-",
                "arch": entry.arch or "-",
                "suggestion": action,
                "matched_projects": entry.matched_projects or "-",
            }
        )

    summary = {
        "family": display_family_name(family),
        "installed_count": str(len(entries)),
        "keep_versions": ", ".join(keep_candidates) or "-",
        "older_versions": ", ".join(remove_candidates) or "-",
        "dependency_signal": dependency_signal,
        "advice": rule_text,
    }
    return summary, detail_rows


def advise_family(
    family: str,
    entries: list[RuntimeEntry],
    project_context: dict[str, int],
) -> tuple[list[str], list[str], str, str]:
    dotnet_projects = project_context.get("dotnet_projects", 0)
    if family == "dotnet_sdk":
        grouped: dict[str, list[RuntimeEntry]] = {}
        for entry in entries:
            grouped.setdefault(dotnet_feature_band(entry.version), []).append(entry)

        keep_candidates: list[str] = []
        remove_candidates: list[str] = []
        for band_entries in grouped.values():
            band_entries.sort(key=lambda item: version_sort_key(item.version), reverse=True)
            keep_candidates.append(band_entries[0].software_name)
            remove_candidates.extend(item.software_name for item in band_entries[1:])

        dependency_signal = (
            f"{dotnet_projects} .NET proje izi bulundu"
            if dotnet_projects
            else "Taradigin projelerde belirgin .NET proje izi bulunmadi"
        )
        advice = (
            "Ayni feature band icinde genelde en yuksek patch tutulur. Daha eski patch'ler kaldirma adayi olabilir. "
            "Ancak global.json veya ders/proje gereksinimi yoksa ilerle."
        )
        return keep_candidates, remove_candidates, advice, dependency_signal

    if family in {"dotnet_runtime", "aspnet_runtime"}:
        grouped: dict[str, list[RuntimeEntry]] = {}
        for entry in entries:
            grouped.setdefault(runtime_line(entry.version, entry.arch, entry.software_name), []).append(entry)

        keep_candidates = []
        remove_candidates = []
        for line_entries in grouped.values():
            line_entries.sort(key=lambda item: version_sort_key(item.version), reverse=True)
            keep_candidates.append(line_entries[0].software_name)
            remove_candidates.extend(item.software_name for item in line_entries[1:])

        dependency_signal = (
            f"{dotnet_projects} .NET proje izi bulundu"
            if dotnet_projects
            else "Uygulama bagimliligi olabilir; proje izi tek basina yeterli degil"
        )
        advice = (
            "Runtime tarafinda ayni major.minor ve mimari icin genelde en yeni patch tutulur. "
            "Farkli major/minor surumleri yan yana kalabilir; hepsini tek hamlede silme."
        )
        return keep_candidates, remove_candidates, advice, dependency_signal

    if family == "windows_sdk":
        sorted_entries = sorted(entries, key=lambda item: version_sort_key(item.version), reverse=True)
        keep_candidates = [sorted_entries[0].software_name] if sorted_entries else []
        remove_candidates = [item.software_name for item in sorted_entries[1:]]
        dependency_signal = (
            f"{dotnet_projects} .NET proje izi bulundu"
            if dotnet_projects
            else "Aktif Windows/.NET SDK bagimliligi net degil"
        )
        advice = (
            "Windows SDK'larda en yeni 1 surum genelde yeterlidir. Visual Studio workload kullaniyorsan eski surumleri "
            "silmeden once build testi yap."
        )
        return keep_candidates, remove_candidates, advice, dependency_signal

    if family == "visual_cpp":
        dependency_signal = "Bir cok Windows uygulamasi Visual C++ Redistributable ister"
        advice = "Visual C++ Redistributable surumlerini otomatik temizleme. Farkli major surumler yan yana gerekli olabilir."
        return [entry.software_name for entry in entries], [], advice, dependency_signal

    if family == "gpu_driver":
        dependency_signal = (
            f"{project_context.get('ai_projects', 0)} AI/Computer Vision proje izi bulundu"
            if project_context.get("ai_projects", 0)
            else "GPU suruculeri proje bagimsiz olarak sistem icin kritik olabilir"
        )
        advice = "GPU suruculerini bu aractan kaldirma adayi olarak dusunme. Gerekirse sadece resmi surucu araci ile temizle."
        return [entries[0].software_name], [], advice, dependency_signal

    if family == "dotnet_native":
        dependency_signal = "Store/MSIX uygulamalari bu paketlere bagli olabilir"
        advice = ".NET Native paketleri kaldirma adayi gibi gorunse de Store uygulamalarini bozabilir; manuel inceleme disinda dokunma."
        return [entry.software_name for entry in entries], [], advice, dependency_signal

    dependency_signal = "Genel runtime/system ailesi"
    advice = "Ayni ailede tekrarlayan surumler varsa en yeni surumu once koru, digerlerini ise proje ve uygulama testinden sonra degerlendir."
    return [entries[0].software_name], [entry.software_name for entry in entries[1:]], advice, dependency_signal


def classify_runtime_family(software_name: str) -> str:
    lowered = software_name.casefold()
    if ".net sdk" in lowered:
        return "dotnet_sdk"
    if "asp.net" in lowered:
        return "aspnet_runtime"
    if ".net runtime" in lowered:
        return "dotnet_runtime"
    if ".net native" in lowered:
        return "dotnet_native"
    if "windows sdk" in lowered:
        return "windows_sdk"
    if "visual c++" in lowered or "redistributable" in lowered:
        return "visual_cpp"
    if any(token in lowered for token in ("nvidia", "geforce", "radeon", "intel graphics", "chipset", "realtek", "driver")):
        return "gpu_driver"
    return "other_runtime"


def display_family_name(family: str) -> str:
    names = {
        "dotnet_sdk": ".NET SDK",
        "dotnet_runtime": ".NET Runtime",
        "aspnet_runtime": "ASP.NET Runtime",
        "windows_sdk": "Windows SDK",
        "visual_cpp": "Visual C++ Redistributable",
        "gpu_driver": "GPU / Driver",
        "dotnet_native": ".NET Native Runtime",
        "other_runtime": "Diger Runtime",
    }
    return names.get(family, family)


def build_runtime_identity(family: str, software_name: str, version: str, arch: str) -> str:
    normalized_name = re.sub(r"\s*\((x64|x86|arm64)\)\s*", "", software_name, flags=re.IGNORECASE).strip().casefold()
    return f"{family}|{normalized_name}|{version.casefold()}|{arch.casefold()}"


def dotnet_feature_band(version: str) -> str:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return version or "unknown"
    major, minor, patch = match.groups()
    band = int(patch) // 100
    return f"{major}.{minor}.{band}xx"


def runtime_line(version: str, arch: str, software_name: str = "") -> str:
    match = re.search(r"(\d+)\.(\d+)", version)
    variant = runtime_variant(software_name)
    if not match:
        return f"{version}|{arch}|{variant}"
    major, minor = match.groups()
    return f"{major}.{minor}|{arch}|{variant}"


def extract_architecture(software_name: str) -> str:
    match = re.search(r"\((x64|x86|arm64)\)", software_name, flags=re.IGNORECASE)
    return match.group(1).lower() if match else ""


def extract_version_from_name(software_name: str) -> str:
    match = re.search(r"(\d+\.\d+(?:\.\d+)*)", software_name)
    return match.group(1) if match else ""


def normalize_runtime_version(family: str, software_name: str, installed_version: str) -> str:
    name_version = extract_version_from_name(software_name)
    if family in {"dotnet_sdk", "dotnet_runtime", "aspnet_runtime", "windows_sdk"} and name_version:
        return name_version
    return installed_version or name_version


def runtime_variant(software_name: str) -> str:
    lowered = software_name.casefold()
    if "targeting pack" in lowered:
        return "targeting-pack"
    if "shared framework" in lowered:
        return "shared-framework"
    return "default"


def version_sort_key(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    if not parts:
        return (0,)
    return tuple(int(part) for part in parts)


def safe_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
