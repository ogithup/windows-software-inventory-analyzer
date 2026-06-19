from __future__ import annotations

import re


def normalize_family_name(software_name: str) -> str:
    normalized = software_name.casefold()
    normalized = re.sub(r"\((x64|x86|arm64)\)", " ", normalized)
    normalized = re.sub(r"\b(64-bit|32-bit|x64|x86|arm64)\b", " ", normalized)
    normalized = re.sub(r"\b\d+(?:\.\d+){1,4}\b", " ", normalized)
    normalized = re.sub(r"\b(19|20)\d{2}\b", " ", normalized)
    normalized = re.sub(r"[-_]+", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip(" -_.")
    return normalized


def classify_family(software_name: str, category: str, install_location: str = "") -> str:
    lowered_name = software_name.casefold()
    lowered_category = category.casefold()
    lowered_location = install_location.casefold()

    if ".net sdk" in lowered_name:
        return "dotnet_sdk"
    if "asp.net" in lowered_name:
        return "aspnet_runtime"
    if ".net runtime" in lowered_name:
        return "dotnet_runtime"
    if ".net native" in lowered_name:
        return "dotnet_native"
    if "windows sdk" in lowered_name:
        return "windows_sdk"
    if "visual c++" in lowered_name or "redistributable" in lowered_name:
        return "visual_cpp"
    if any(token in lowered_name for token in ("nvidia", "radeon", "geforce", "driver", "chipset", "realtek", "intel graphics")):
        return "gpu_driver"
    if any(token in lowered_name for token in ("visual studio", "android studio", "rider", "pycharm", "intellij", "webstorm")):
        return "developer_tool"
    if any(token in lowered_name or token in lowered_location for token in ("cache", "node_modules", ".venv", "__pycache__", ".gradle", ".m2", "pip\\cache", "npm-cache")):
        return "cache_artifact"
    if lowered_category == "runtime/system":
        return "runtime_system"
    if lowered_category in {"backend", "frontend", "database", "network", "virtualization", "ai/ml", "computer vision", "game development"}:
        return "general_app"
    return "unknown"
