from __future__ import annotations

import json
from pathlib import Path


CATALOG_PATH = Path("software_catalog.json")


def load_software_catalog(path: Path = CATALOG_PATH) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(key).casefold(): normalize_catalog_entry(value) for key, value in payload.items() if isinstance(value, dict)}


def explain_software(
    software_name: str,
    category: str,
    matched_projects: str,
    catalog: dict[str, dict[str, str]] | None = None,
) -> dict[str, str]:
    catalog = catalog or load_software_catalog()
    lowered_name = software_name.casefold()

    for key, entry in catalog.items():
        if key in lowered_name:
            return entry

    return build_fallback_explanation(software_name, category, matched_projects)


def build_fallback_explanation(software_name: str, category: str, matched_projects: str) -> dict[str, str]:
    project_hint = "Bagli proje sinyali yok." if not matched_projects else f"Bagli projeler: {matched_projects}."
    category_hint = category or "Unknown"
    purpose = (
        f"{software_name} icin curated katalog kaydi bulunamadi. Isim, kategori ve proje baglarina gore bu arac "
        f"{category_hint} alaninda yardimci bir arac olabilir."
    )
    typical_usage = (
        "Bu programin tam amaci kesin degil. Kaldirma oncesi publisher, install path ve proje baglarini kontrol et."
    )
    removal_risk_summary = (
        "Unknown programlarda otomatik kesinlik dusuk tutuldu. Runtime/system sinyali varsa once manual review yap."
    )
    return {
        "category": category_hint,
        "purpose": purpose,
        "typical_usage": typical_usage,
        "related_technologies": matched_projects,
        "removal_risk_summary": f"{removal_risk_summary} {project_hint}".strip(),
    }


def normalize_catalog_entry(entry: dict[str, str]) -> dict[str, str]:
    return {
        "category": str(entry.get("category", "")).strip(),
        "purpose": str(entry.get("purpose", "")).strip(),
        "typical_usage": str(entry.get("typical_usage", "")).strip(),
        "related_technologies": str(entry.get("related_technologies", "")).strip(),
        "removal_risk_summary": str(entry.get("removal_risk_summary", "")).strip(),
    }


def write_software_descriptions(rows: list[dict[str, str]], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "software_descriptions.json"
    output_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path
