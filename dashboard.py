from __future__ import annotations

import csv
import html
import io
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.analyzers.manual_review import evaluate_manual_review, load_manual_review_overrides, save_manual_review_override
from src.analyzers.runtime_advisor import build_runtime_inventory


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "data" / "output"
EXPORTS_DIR = BASE_DIR / "exports"
REPORT_HTML_PATH = BASE_DIR / "report.html"
STREAMLIT_LAUNCH_FLAG = "WSIA_STREAMLIT_LAUNCHED"
DEFAULT_CONFIG_PATH = BASE_DIR / "config.yaml"
MANUAL_REVIEW_OVERRIDES_PATH = BASE_DIR / "manual_review_overrides.csv"


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
        return list(csv.DictReader(csv_file))


def safe_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def safe_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def build_search_index(
    recommendations: list[dict[str, str]],
    mappings: list[dict[str, str]],
    projects: list[dict[str, str]],
) -> list[dict[str, str]]:
    mapping_by_name = {row.get("software_name", "").casefold(): row for row in mappings}
    projects_by_name = {row.get("project_name", "").casefold(): row for row in projects}

    indexed_rows: list[dict[str, str]] = []
    for recommendation in recommendations:
        software_name = recommendation.get("software_name", "")
        mapping = mapping_by_name.get(software_name.casefold(), {})
        matched_projects = recommendation.get("matched_projects", "") or mapping.get("matched_projects", "")
        matched_project_names = [item.strip() for item in matched_projects.split(",") if item.strip()]
        technologies: list[str] = []
        project_links: list[str] = []
        project_contexts: list[str] = []
        for project_name in matched_project_names:
            project = projects_by_name.get(project_name.casefold(), {})
            detected = project.get("detected_technologies", "")
            if detected:
                technologies.extend([item.strip() for item in detected.split(",") if item.strip()])
            github_url = project.get("github_url", "")
            if github_url:
                project_links.append(github_url)
            context = " ".join(
                part for part in (project.get("repo_description", ""), project.get("user_notes", "")) if part
            ).strip()
            if context:
                project_contexts.append(f"{project_name}: {context}")

        indexed_rows.append(
            {
                "software_name": software_name,
                "category": recommendation.get("category", ""),
                "decision": recommendation.get("decision", ""),
                "matched_projects": matched_projects,
                "project_links": recommendation.get("project_links", "") or ",".join(project_links),
                "project_context": recommendation.get("project_context", "") or " | ".join(project_contexts),
                "project_count": recommendation.get("project_count", ""),
                "estimated_size": recommendation.get("estimated_size", ""),
                "last_used_at": recommendation.get("last_used_at", ""),
                "usage_signal_count": recommendation.get("usage_signal_count", ""),
                "usage_sources": recommendation.get("usage_sources", ""),
                "usage_status": recommendation.get("usage_status", ""),
                "review_status": recommendation.get("review_status", ""),
                "review_notes": recommendation.get("review_notes", ""),
                "confidence_score": recommendation.get("confidence_score", "") or mapping.get("confidence_score", ""),
                "explanation": recommendation.get("explanation", ""),
                "evidence": mapping.get("evidence", ""),
                "technologies": ",".join(sorted({item for item in technologies if item}, key=str.casefold)),
                "search_text": " ".join(
                    [
                        software_name,
                        recommendation.get("category", ""),
                        recommendation.get("decision", ""),
                        matched_projects,
                        recommendation.get("project_context", ""),
                        recommendation.get("explanation", ""),
                        mapping.get("evidence", ""),
                        recommendation.get("project_links", ""),
                        recommendation.get("last_used_at", ""),
                        recommendation.get("usage_sources", ""),
                        ",".join(technologies),
                    ]
                ).casefold(),
            }
        )
    return indexed_rows


def filter_search_rows(
    rows: list[dict[str, str]],
    query: str,
    categories: set[str],
    decisions: set[str],
) -> list[dict[str, str]]:
    lowered_query = query.casefold().strip()
    filtered: list[dict[str, str]] = []
    for row in rows:
        if categories and row.get("category", "") not in categories:
            continue
        if decisions and row.get("decision", "") not in decisions:
            continue
        if lowered_query and lowered_query not in row.get("search_text", ""):
            continue
        filtered.append(row)
    return filtered


def format_table_html(rows: list[dict[str, str]], columns: list[str], title: str) -> str:
    header_html = "".join(f"<th>{html.escape(column)}</th>" for column in columns)
    body_parts: list[str] = []
    for row in rows:
        cells = "".join(render_html_cell(row, column) for column in columns)
        body_parts.append(f"<tr>{cells}</tr>")
    body_html = "".join(body_parts) or f"<tr><td colspan='{len(columns)}'>Veri bulunamadi.</td></tr>"
    return (
        f"<section><h2>{html.escape(title)}</h2>"
        f"<div class='table-wrap'><table><thead><tr>{header_html}</tr></thead>"
        f"<tbody>{body_html}</tbody></table></div></section>"
    )


def render_html_cell(row: dict[str, str], column: str) -> str:
    value = str(row.get(column, ""))
    if column in {"project_links", "github_url", "matched_project_links"} and value.strip():
        links = [item.strip() for item in value.split(",") if item.strip()]
        rendered = "<br>".join(
            f'<a href="{html.escape(link)}" target="_blank" rel="noopener noreferrer">{html.escape(link)}</a>'
            for link in links
        )
        return f"<td>{rendered}</td>"
    return f"<td>{html.escape(value)}</td>"


def generate_report_html(
    recommendations: list[dict[str, str]],
    mappings: list[dict[str, str]],
    disk_usage: list[dict[str, str]],
    projects: list[dict[str, str]],
) -> str:
    search_rows = build_search_index(recommendations, mappings, projects)
    top_large_programs = sorted(
        recommendations,
        key=lambda item: size_to_bytes(item.get("estimated_size", "")),
        reverse=True,
    )[:15]
    most_uncertain = sorted(
        [row for row in recommendations if row.get("decision") in {"UNSURE", "MANUAL_REVIEW"}],
        key=lambda item: safe_float(item.get("confidence_score", "0")),
    )[:15]
    large_folders = disk_usage[:15]
    search_preview = search_rows[:20]

    generated_at = datetime.now(timezone.utc).isoformat()
    summary_cards = {
        "Toplam Program": str(len(recommendations)),
        "Eslestirilen Program": str(len(mappings)),
        "Buyuk Klasor": str(len(disk_usage)),
        "Taranan Proje": str(len(projects)),
    }
    cards_html = "".join(
        f"<div class='card'><span>{html.escape(key)}</span><strong>{html.escape(value)}</strong></div>"
        for key, value in summary_cards.items()
    )

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Windows Software Inventory Analyzer</title>
  <style>
    :root {{
      --bg: #f4f1ea;
      --panel: #fffdf8;
      --ink: #22201c;
      --muted: #6c665d;
      --accent: #0f766e;
      --accent-soft: #d8f0ec;
      --border: #d9d1c5;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: linear-gradient(180deg, #f8f4ec 0%, #f1ede5 100%);
      color: var(--ink);
    }}
    main {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    h1 {{ margin: 0 0 8px; font-size: 2rem; }}
    p.lead {{ margin: 0 0 24px; color: var(--muted); }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }}
    .card, section {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 10px 30px rgba(34, 32, 28, 0.05);
    }}
    .card {{
      padding: 16px 18px;
    }}
    .card span {{
      display: block;
      color: var(--muted);
      font-size: 0.9rem;
      margin-bottom: 8px;
    }}
    .card strong {{
      font-size: 1.5rem;
      color: var(--accent);
    }}
    section {{
      padding: 18px;
      margin-bottom: 18px;
    }}
    h2 {{
      margin-top: 0;
      margin-bottom: 12px;
      font-size: 1.1rem;
    }}
    .table-wrap {{
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }}
    th, td {{
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{
      background: var(--accent-soft);
      color: #11423e;
      position: sticky;
      top: 0;
    }}
    .footer {{
      color: var(--muted);
      font-size: 0.88rem;
      margin-top: 8px;
    }}
  </style>
</head>
<body>
  <main>
    <h1>Windows Software Inventory Analyzer</h1>
    <p class="lead">Kurulu yazilimlar, proje eslesmeleri, buyuk klasorler ve karar onerileri icin statik HTML ozeti.</p>
    <div class="cards">{cards_html}</div>
    {format_table_html(search_preview, ["software_name", "category", "decision", "matched_projects", "project_links", "project_context", "technologies"], "Program ve Proje Eslestirmeleri")}
    {format_table_html(top_large_programs, ["software_name", "category", "decision", "estimated_size", "matched_projects"], "En Cok Yer Kaplayabilecek Programlar")}
    {format_table_html(most_uncertain, ["software_name", "category", "decision", "confidence_score", "explanation"], "En Belirsiz Programlar")}
    {format_table_html(large_folders, ["path", "size_human", "category", "risk"], "En Buyuk Klasorler")}
    <p class="footer">Rapor olusturma zamani: {html.escape(generated_at)}</p>
  </main>
</body>
</html>
"""


def size_to_bytes(size_human: str) -> float:
    parts = size_human.strip().split()
    if len(parts) != 2:
        return 0.0
    try:
        value = float(parts[0])
    except ValueError:
        return 0.0
    unit = parts[1].upper()
    factor = {
        "B": 1,
        "KB": 1024,
        "MB": 1024**2,
        "GB": 1024**3,
        "TB": 1024**4,
    }.get(unit, 1)
    return value * factor


def export_csv_text(rows: list[dict[str, str]]) -> str:
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def build_project_detail_options(projects: list[dict[str, str]]) -> list[str]:
    labels: list[str] = []
    for project in projects:
        project_name = project.get("project_name", "").strip()
        repo_name = project.get("repo_name", "").strip()
        if project_name:
            labels.append(f"{project_name} | {repo_name}" if repo_name and repo_name != project_name else project_name)
    return labels


def find_project_by_label(projects: list[dict[str, str]], label: str) -> dict[str, str]:
    for project in projects:
        project_name = project.get("project_name", "").strip()
        repo_name = project.get("repo_name", "").strip()
        candidate = f"{project_name} | {repo_name}" if repo_name and repo_name != project_name else project_name
        if candidate == label:
            return project
    return {}


def build_project_tools_index(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    index: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        projects = [item.strip() for item in row.get("matched_projects", "").split(",") if item.strip()]
        for project_name in projects:
            index.setdefault(project_name.casefold(), []).append(row)
    for key in index:
        index[key].sort(key=lambda item: (-safe_float(item.get("confidence_score", "0")), item.get("software_name", "").casefold()))
    return index


def build_program_detail_options(rows: list[dict[str, str]]) -> list[str]:
    return [row.get("software_name", "") for row in rows if row.get("software_name", "")]


def find_program_by_name(rows: list[dict[str, str]], software_name: str) -> dict[str, str]:
    for row in rows:
        if row.get("software_name", "") == software_name:
            return row
    return {}


def apply_dashboard_manual_review_overrides(
    recommendations: list[dict[str, str]],
    overrides: dict[str, dict[str, str]],
) -> list[dict[str, str]]:
    updated_rows: list[dict[str, str]] = []
    for row in recommendations:
        software_name = row.get("software_name", "").strip()
        override = overrides.get(software_name.casefold())
        if not override:
            updated_rows.append(row)
            continue
        updated = dict(row)
        updated["decision"] = override.get("reviewed_decision", updated.get("decision", ""))
        updated["review_status"] = f"USER_REVIEWED {override.get('last_reviewed_at', '').strip()}".strip()
        updated["review_notes"] = override.get("review_notes", "")
        updated["explanation"] = override.get("reviewed_explanation", updated.get("explanation", ""))
        updated_rows.append(updated)
    return updated_rows


def runtime_family_key_from_label(label: str) -> str:
    lookup = {
        ".NET SDK": "dotnet_sdk",
        ".NET Runtime": "dotnet_runtime",
        "ASP.NET Runtime": "aspnet_runtime",
        "Windows SDK": "windows_sdk",
        "Visual C++ Redistributable": "visual_cpp",
        "GPU / Driver": "gpu_driver",
        ".NET Native Runtime": "dotnet_native",
    }
    return lookup.get(label, "")


def normalize_windows_path(value: str) -> str:
    return value.replace("/", "\\").rstrip("\\").casefold()


def parse_iso_datetime(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def classify_program_family(software_name: str, category: str) -> str:
    lowered_name = software_name.casefold()
    lowered_category = category.casefold()
    if ".net sdk" in lowered_name:
        return "dotnet_sdk"
    if ".net runtime" in lowered_name or "asp.net" in lowered_name:
        return "dotnet_runtime"
    if "visual studio" in lowered_name:
        return "visual_studio"
    if "windows sdk" in lowered_name:
        return "windows_sdk"
    if "visual c++" in lowered_name or "redistributable" in lowered_name:
        return "visual_cpp"
    if "nvidia" in lowered_name or "driver" in lowered_name or "chipset" in lowered_name:
        return "driver"
    if lowered_category == "runtime/system":
        return "runtime_system"
    return "general"


def summarize_last_used(last_used_at: str) -> tuple[str, str]:
    parsed = parse_iso_datetime(last_used_at)
    if parsed is None:
        return "Bilinmiyor", "Sistem bu program icin otomatik son kullanim izi bulamadi."
    now = datetime.now(timezone.utc)
    days = max(0, int((now - parsed).total_seconds() // 86400))
    if days <= 30:
        return parsed.date().isoformat(), "Son kullanim izi yakin zamanda goruldu."
    if days <= 180:
        return parsed.date().isoformat(), "Son kullanim izi son 6 ay icinde goruldu."
    if days <= 365:
        return parsed.date().isoformat(), "Son kullanim izi 6-12 ay araliginda goruldu."
    return parsed.date().isoformat(), "Son kullanim izi 12 aydan daha eski gorunuyor."


def build_removal_scenario(
    selected_program: dict[str, str],
    recommendations: list[dict[str, str]],
    dotnet_sdk_report: list[dict[str, str]],
    sdk_validation_report: list[dict[str, str]],
) -> dict[str, object]:
    software_name = selected_program.get("software_name", "").strip()
    category = selected_program.get("category", "").strip()
    family = classify_program_family(software_name, category)
    project_names = [item.strip() for item in selected_program.get("matched_projects", "").split(",") if item.strip()]
    project_count = len(project_names)
    estimated_size = selected_program.get("estimated_size", "").strip() or "Bilinmiyor"
    last_used_label, usage_summary = summarize_last_used(selected_program.get("last_used_at", ""))
    usage_status = selected_program.get("usage_status", "").strip() or "unknown_usage"
    decision = selected_program.get("decision", "").strip()

    family_rows = [
        row
        for row in recommendations
        if classify_program_family(row.get("software_name", ""), row.get("category", "")) == family
    ]
    family_rows = sorted(
        family_rows,
        key=lambda item: (
            item.get("software_name", "").casefold(),
            item.get("last_used_at", ""),
        ),
    )

    risk_flags: list[str] = []
    steps: list[dict[str, str]] = []
    final_label = "MANUAL_REVIEW"
    final_reason = "Bu program icin kaldirma karari once proje, kullanim ve bagimlilik sinyalleriyle birlikte okunmali."

    steps.append(
        {
            "step": "1. Program baglamini oku",
            "status": "info",
            "detail": (
                f"Kategori: {category or 'Yok'} | Oneri: {decision or 'Yok'} | Tahmini boyut: {estimated_size} | "
                f"Son kullanim: {last_used_label}"
            ),
        }
    )

    if project_count > 0:
        risk_flags.append("project_linked")
        steps.append(
            {
                "step": "2. Proje baglantisini kontrol et",
                "status": "warn",
                "detail": f"Bu program {project_count} projeyle eslesiyor: {', '.join(project_names[:6])}",
            }
        )
    else:
        steps.append(
            {
                "step": "2. Proje baglantisini kontrol et",
                "status": "ok",
                "detail": "Eslesen proje bulunmadi. Bu durum tek basina silinebilir demek degil ama risk daha dusuk olabilir.",
            }
        )

    if usage_status == "usage_detected":
        status = "warn" if "yakin zamanda" in usage_summary or "6 ay" in usage_summary else "info"
        steps.append(
            {
                "step": "3. Son kullanim izini kontrol et",
                "status": status,
                "detail": f"{usage_summary} Kaynaklar: {selected_program.get('usage_sources', '') or 'Yok'}",
            }
        )
        if status == "warn":
            risk_flags.append("recent_usage")
    else:
        steps.append(
            {
                "step": "3. Son kullanim izini kontrol et",
                "status": "ok",
                "detail": "Otomatik kullanim izi bulunamadi. Bu durum programin gereksiz oldugunu kanitlamaz ama kaldirma adayi olmasini guclendirir.",
            }
        )

    if family in {"runtime_system", "dotnet_runtime", "windows_sdk", "visual_cpp", "driver", "visual_studio"}:
        risk_flags.append("protected_family")
        steps.append(
            {
                "step": "4. Sistem veya toolchain riskini kontrol et",
                "status": "warn",
                "detail": "Bu program runtime, SDK, driver veya IDE ailesinde gorunuyor. Otomatik silme yerine bagimlilik testi yapilmasi gerekir.",
            }
        )
    else:
        steps.append(
            {
                "step": "4. Sistem veya toolchain riskini kontrol et",
                "status": "ok",
                "detail": "Program korumali runtime/system ailesinde gorunmuyor.",
            }
        )

    related_sdk_rows: list[dict[str, str]] = []
    related_validation_rows: list[dict[str, str]] = []
    if family == "dotnet_sdk":
        related_sdk_rows = [row for row in dotnet_sdk_report if row.get("sdk_version", "") and row.get("sdk_version", "") in software_name]
        if related_sdk_rows:
            sdk_status = related_sdk_rows[0].get("status", "")
            sdk_recommendation = related_sdk_rows[0].get("recommendation", "")
            status = "warn" if sdk_status in {"IDE_DEPENDENT", "MANUAL_REVIEW", "DO_NOT_REMOVE"} else "ok"
            steps.append(
                {
                    "step": "5. .NET SDK bagimliligini kontrol et",
                    "status": status,
                    "detail": f"SDK raporu durumu: {sdk_status or 'Yok'} | {sdk_recommendation or 'Ek not yok.'}",
                }
            )
            if status == "warn":
                risk_flags.append("sdk_dependent")
        else:
            steps.append(
                {
                    "step": "5. .NET SDK bagimliligini kontrol et",
                    "status": "info",
                    "detail": "Bu SDK icin karar raporunda dogrudan satir bulunamadi. Once genel .NET SDK raporunu ve build testini kontrol et.",
                }
            )

        related_validation_rows = [
            row
            for row in sdk_validation_report
            if row.get("selected_sdk", "").strip() and row.get("selected_sdk", "").strip() in software_name
        ]
        if related_validation_rows:
            validation_statuses = {row.get("build_status", "") for row in related_validation_rows}
            steps.append(
                {
                    "step": "6. Gercek build dogrulamasini kontrol et",
                    "status": "warn" if "BUILD_FAILED" in validation_statuses or "VALIDATION_FAILED" in validation_statuses else "ok",
                    "detail": f"Bu SDK ile eslesen {len(related_validation_rows)} build kaydi bulundu. Durumlar: {', '.join(sorted(validation_statuses))}",
                }
            )
            if "BUILD_FAILED" in validation_statuses or "VALIDATION_FAILED" in validation_statuses:
                risk_flags.append("build_not_clean")
        else:
            steps.append(
                {
                    "step": "6. Gercek build dogrulamasini kontrol et",
                    "status": "info",
                    "detail": "Bu SDK icin proje bazli build kaydi bulunmadi. Kaldirmadan once '.NET SDK Build Testi' butonunu kullan.",
                }
            )

    if "protected_family" not in risk_flags and "project_linked" not in risk_flags and "recent_usage" not in risk_flags:
        final_label = "LOWER_RISK_CANDIDATE"
        final_reason = "Su anki verilere gore proje bagi yok, yakin kullanim izi yok ve korumali runtime/system ailesinde degil."
    elif family == "dotnet_sdk" and not related_validation_rows and any(row.get("status", "") == "MANUAL_REVIEW" for row in related_sdk_rows):
        final_label = "TEST_FIRST"
        final_reason = "Bu SDK ayni bandin eski patch surumu olabilir; once build testi yap, sonra kaldirmayi dusun."
    elif "protected_family" in risk_flags or "sdk_dependent" in risk_flags:
        final_label = "DO_NOT_REMOVE_YET"
        final_reason = "Program system/runtime/SDK/IDE ailesinde oldugu icin once bagimlilik testi veya IDE dogrulamasi gerekli."
    elif "project_linked" in risk_flags or "recent_usage" in risk_flags:
        final_label = "VERIFY_USAGE_FIRST"
        final_reason = "Program aktif proje veya kullanim sinyali gosteriyor. Kaldirmadan once bu eslesmenin gercekten sana ait olup olmadigini kontrol et."

    return {
        "family": family,
        "estimated_size": estimated_size,
        "project_names": project_names,
        "project_count": str(project_count),
        "last_used_label": last_used_label,
        "steps": steps,
        "risk_flags": risk_flags,
        "final_label": final_label,
        "final_reason": final_reason,
        "family_rows": family_rows[:12],
        "related_sdk_rows": related_sdk_rows,
        "related_validation_rows": related_validation_rows[:12],
    }


def build_project_hierarchy(projects: list[dict[str, str]]) -> tuple[list[dict[str, str]], dict[str, list[dict[str, str]]]]:
    projects_with_paths = [project for project in projects if project.get("path", "").strip()]
    sorted_projects = sorted(projects_with_paths, key=lambda item: len(normalize_windows_path(item.get("path", ""))))
    root_projects: list[dict[str, str]] = []
    child_index: dict[str, list[dict[str, str]]] = {}

    for project in sorted_projects:
        current_path = normalize_windows_path(project.get("path", ""))
        parent = next(
            (
                candidate
                for candidate in root_projects
                if current_path.startswith(f"{normalize_windows_path(candidate.get('path', ''))}\\")
            ),
            None,
        )
        if parent is None:
            root_projects.append(project)
            child_index[current_path] = []
        else:
            parent_key = normalize_windows_path(parent.get("path", ""))
            child_index.setdefault(parent_key, []).append(project)

    root_projects.sort(key=lambda item: item.get("project_name", "").casefold())
    for key in child_index:
        child_index[key].sort(key=lambda item: item.get("project_name", "").casefold())
    return root_projects, child_index


def build_project_detail_label(project: dict[str, str], child_projects: list[dict[str, str]]) -> str:
    project_name = project.get("project_name", "").strip()
    repo_name = project.get("repo_name", "").strip()
    base_label = f"{project_name} | {repo_name}" if repo_name and repo_name != project_name else project_name
    if child_projects:
        return f"{base_label} ({len(child_projects)} alt modul)"
    return base_label


def collect_project_tools(
    project: dict[str, str],
    child_projects: list[dict[str, str]],
    project_tools_index: dict[str, list[dict[str, str]]],
) -> list[dict[str, str]]:
    candidate_names = [project.get("project_name", "").casefold()]
    candidate_names.extend(child.get("project_name", "").casefold() for child in child_projects)
    unique_tools: dict[str, dict[str, str]] = {}

    for project_name in candidate_names:
        for tool in project_tools_index.get(project_name, []):
            software_name = tool.get("software_name", "").casefold()
            if software_name and software_name not in unique_tools:
                unique_tools[software_name] = tool

    return sorted(
        unique_tools.values(),
        key=lambda item: (-safe_float(item.get("confidence_score", "0")), item.get("software_name", "").casefold()),
    )


def write_static_exports() -> tuple[Path, Path]:
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    recommendations = load_csv_rows(OUTPUT_DIR / "recommendations.csv")
    mappings = load_csv_rows(OUTPUT_DIR / "software_project_mapping.csv")
    disk_usage = load_csv_rows(OUTPUT_DIR / "disk_usage.csv")
    projects = load_csv_rows(OUTPUT_DIR / "project_tech_stack.csv")

    html_text = generate_report_html(recommendations, mappings, disk_usage, projects)
    REPORT_HTML_PATH.write_text(html_text, encoding="utf-8")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    export_html_path = EXPORTS_DIR / f"report-{timestamp}.html"
    export_html_path.write_text(html_text, encoding="utf-8")
    export_csv_path = EXPORTS_DIR / f"recommendations-{timestamp}.csv"
    export_csv_path.write_text(export_csv_text(recommendations), encoding="utf-8-sig")
    return export_html_path, export_csv_path


def refresh_analysis_data() -> tuple[bool, str]:
    command = [sys.executable, "-m", "src.main", "refresh-all"]
    if DEFAULT_CONFIG_PATH.exists():
        command.extend(["--config", str(DEFAULT_CONFIG_PATH)])

    try:
        completed = subprocess.run(
            command,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        return False, f"Veri yenileme komutu baslatilamadi: {error}"

    output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip()).strip()
    if completed.returncode != 0:
        return False, output or "Veri yenileme basarisiz oldu."
    return True, output or "Veriler basariyla yenilendi."


def run_dotnet_sdk_validation() -> tuple[bool, str]:
    command = [sys.executable, "-m", "src.main", "validate-dotnet-sdks"]
    if DEFAULT_CONFIG_PATH.exists():
        command.extend(["--config", str(DEFAULT_CONFIG_PATH)])

    try:
        completed = subprocess.run(
            command,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        return False, f".NET SDK validation baslatilamadi: {error}"

    output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip()).strip()
    if completed.returncode != 0:
        return False, output or ".NET SDK validation basarisiz oldu."
    return True, output or ".NET SDK validation tamamlandi."


def launch_streamlit() -> int:
    env = os.environ.copy()
    env[STREAMLIT_LAUNCH_FLAG] = "1"
    command = [sys.executable, "-m", "streamlit", "run", str(Path(__file__).resolve())]
    return subprocess.call(command, env=env)


def render_streamlit() -> None:
    try:
        import streamlit as st
    except ModuleNotFoundError as error:
        raise SystemExit(
            "Streamlit kurulu degil. Once `pip install -r requirements.txt` calistir, sonra `python dashboard.py` ile ac."
        ) from error

    st.set_page_config(
        page_title="Windows Software Inventory Analyzer",
        page_icon="W",
        layout="wide",
    )

    manual_review_overrides = load_manual_review_overrides(MANUAL_REVIEW_OVERRIDES_PATH)
    recommendations = apply_dashboard_manual_review_overrides(
        load_csv_rows(OUTPUT_DIR / "recommendations.csv"),
        manual_review_overrides,
    )
    installed_programs = load_csv_rows(OUTPUT_DIR / "installed_programs.csv")
    mappings = load_csv_rows(OUTPUT_DIR / "software_project_mapping.csv")
    disk_usage = load_csv_rows(OUTPUT_DIR / "disk_usage.csv")
    projects = load_csv_rows(OUTPUT_DIR / "project_tech_stack.csv")
    dotnet_sdk_report = load_csv_rows(OUTPUT_DIR / "dotnet_sdk_decision_report.csv")
    sdk_validation_report = load_csv_rows(OUTPUT_DIR / "sdk_validation_report.csv")
    search_rows = build_search_index(recommendations, mappings, projects)
    project_tools_index = build_project_tools_index(search_rows)
    root_projects, child_projects_index = build_project_hierarchy(projects)
    runtime_family_summaries, runtime_family_details = build_runtime_inventory(recommendations, installed_programs, projects)

    REPORT_HTML_PATH.write_text(
        generate_report_html(recommendations, mappings, disk_usage, projects),
        encoding="utf-8",
    )
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    st.title("Windows Software Inventory Analyzer")
    st.caption("Program silme yapmaz. Sadece analiz, kategori ve raporlama sunar.")

    refresh_col, info_col = st.columns([1, 2.5])
    with refresh_col:
        if st.button("Verileri Yenile", use_container_width=True):
            with st.spinner("Analizler yeniden calistiriliyor..."):
                success, message = refresh_analysis_data()
            if success:
                st.success("Veriler yenilendi. Ekran tekrar yukleniyor.")
                if message:
                    st.caption(message[-500:] if len(message) > 500 else message)
                st.rerun()
            else:
                st.error("Veri yenileme tamamlanamadi.")
                if message:
                    st.code(message[-2000:] if len(message) > 2000 else message, language="text")
    with info_col:
        config_hint = str(DEFAULT_CONFIG_PATH) if DEFAULT_CONFIG_PATH.exists() else "Varsayilan config bulunamadi"
        st.caption(f"Yenileme butonu tum analizleri `refresh-all` ile calistirir. Config: {config_hint}")

    validation_col, validation_info_col = st.columns([1, 2.5])
    with validation_col:
        if st.button(".NET SDK Build Testi", use_container_width=True):
            with st.spinner(".NET projeleri icin dotnet --version ve dotnet build calistiriliyor..."):
                success, message = run_dotnet_sdk_validation()
            if success:
                st.success(".NET SDK build dogrulamasi tamamlandi.")
                if message:
                    st.caption(message[-500:] if len(message) > 500 else message)
                st.rerun()
            else:
                st.error(".NET SDK build dogrulamasi tamamlanamadi.")
                if message:
                    st.code(message[-2000:] if len(message) > 2000 else message, language="text")
    with validation_info_col:
        st.caption(
            "Bu buton her .sln/.csproj icin secilen SDK'yi denetler ve build sonucu `sdk_validation_report.csv` icine yazar. "
            "Build ciktilari proje klasorlerine degil, `data/output/sdk_validation_artifacts/` altina yonlendirilir."
        )

    categories = sorted({row.get("category", "") for row in recommendations if row.get("category", "")}, key=str.casefold)
    decisions = sorted({row.get("decision", "") for row in recommendations if row.get("decision", "")}, key=str.casefold)

    col1, col2, col3 = st.columns([2.2, 1.2, 1.2])
    with col1:
        query = st.text_input("Arama", placeholder="opencv, docker, youtube, networks, python, android...")
    with col2:
        selected_categories = set(st.multiselect("Kategori Filtresi", categories))
    with col3:
        selected_decisions = set(st.multiselect("Karar Filtresi", decisions))

    filtered_search_rows = filter_search_rows(search_rows, query, selected_categories, selected_decisions)
    uncertain_rows = [row for row in recommendations if row.get("decision") in {"UNSURE", "MANUAL_REVIEW"}]
    uncertain_rows = sorted(uncertain_rows, key=lambda item: safe_float(item.get("confidence_score", "0")))[:20]
    largest_folders = sorted(disk_usage, key=lambda item: size_to_bytes(item.get("size_human", "")), reverse=True)[:20]

    metrics = st.columns(4)
    metrics[0].metric("Toplam Program", len(recommendations))
    metrics[1].metric("Eslestirme Kaydi", len(mappings))
    metrics[2].metric("Buyuk Klasor", len(disk_usage))
    metrics[3].metric("Taranan Proje", len(root_projects))

    st.subheader("Program ve Proje Eslestirmeleri")
    table_rows = filtered_search_rows
    selected_program = {}
    try:
        selection_event = st.dataframe(
            table_rows,
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            column_config={
                "project_links": st.column_config.LinkColumn("GitHub Linkleri", display_text="GitHub"),
            },
        )
        selected_rows = selection_event.selection.rows if selection_event else []
        if selected_rows:
            selected_program = table_rows[selected_rows[0]]
    except TypeError:
        st.dataframe(
            table_rows,
            use_container_width=True,
            hide_index=True,
            column_config={
                "project_links": st.column_config.LinkColumn("GitHub Linkleri", display_text="GitHub"),
            },
        )

    st.subheader("Program Karar Detayi")
    fallback_program_name = st.selectbox(
        "Program Sec",
        options=build_program_detail_options(table_rows),
        index=0 if table_rows else None,
    )
    if not selected_program and fallback_program_name:
        selected_program = find_program_by_name(table_rows, fallback_program_name)

    if selected_program:
        with st.container(border=True):
            detail_left, detail_right = st.columns([1.1, 1.9])
            with detail_left:
                st.markdown(f"**Program:** {selected_program.get('software_name', '')}")
                st.markdown(f"**Kategori:** {selected_program.get('category', '')}")
                st.markdown(f"**Karar:** {selected_program.get('decision', '')}")
                st.markdown(f"**Guven:** {selected_program.get('confidence_score', '')}")
                st.markdown(f"**Tahmini Boyut:** {selected_program.get('estimated_size', '') or 'Bilinmiyor'}")
                st.markdown(f"**Projeler:** {selected_program.get('matched_projects', '') or 'Yok'}")
                st.markdown(f"**Son Kullanim:** {selected_program.get('last_used_at', '') or 'Bilinmiyor'}")
                st.markdown(f"**Kullanim Sinyali:** {selected_program.get('usage_status', '') or 'unknown_usage'}")
            with detail_right:
                st.markdown("**Neden Bu Karar Verildi?**")
                st.write(selected_program.get("explanation", "") or "Acilama yok.")
                st.markdown("**Eslestirme Kaniti**")
                st.write(selected_program.get("evidence", "") or "Kanıt yok.")
                st.markdown("**Kullanim Kaynaklari**")
                st.write(selected_program.get("usage_sources", "") or "Kullanim sinyali bulunamadi.")
                st.markdown("**GitHub Linkleri**")
                project_links = [item.strip() for item in selected_program.get("project_links", "").split(",") if item.strip()]
                if project_links:
                    for link in project_links:
                        st.markdown(f"- [GitHub Repo]({link})")
                else:
                    st.write("Bagli GitHub linki bulunamadi.")

        scenario = build_removal_scenario(selected_program, recommendations, dotnet_sdk_report, sdk_validation_report)
        st.subheader("Kaldirma Oncesi Senaryo Wizard")
        st.caption(
            "Bu panel secili program icin terminalde elle yaptigin kontrol akisini UI tarafinda toplar. "
            "Programin proje bagi, son kullanim izi, toolchain riski ve gerekiyorsa build testine gore ilerler."
        )
        with st.container(border=True):
            st.markdown(f"**Genel Sonuc:** {scenario.get('final_label', '')}")
            st.write(scenario.get("final_reason", ""))

            for step in scenario.get("steps", []):
                status = step.get("status", "info")
                prefix = {
                    "ok": "DUSUK RISK",
                    "warn": "DIKKAT",
                    "info": "BILGI",
                }.get(status, "BILGI")
                st.markdown(f"**{prefix} | {step.get('step', '')}**")
                st.write(step.get("detail", ""))

            project_names = scenario.get("project_names", [])
            if project_names:
                st.markdown("**Bagli projeler**")
                for project_name in project_names[:8]:
                    st.markdown(f"- {project_name}")

            family_rows = scenario.get("family_rows", [])
            if family_rows:
                st.markdown("**Ayni ailede bulunan benzer programlar**")
                family_preview = [
                    {
                        "software_name": row.get("software_name", ""),
                        "decision": row.get("decision", ""),
                        "estimated_size": row.get("estimated_size", ""),
                        "last_used_at": row.get("last_used_at", ""),
                    }
                    for row in family_rows
                ]
                st.dataframe(family_preview, use_container_width=True, hide_index=True)

            related_sdk_rows = scenario.get("related_sdk_rows", [])
            if related_sdk_rows:
                st.markdown("**Bu program icin .NET SDK karar kayitlari**")
                st.dataframe(related_sdk_rows, use_container_width=True, hide_index=True)

            related_validation_rows = scenario.get("related_validation_rows", [])
            if related_validation_rows:
                st.markdown("**Bu programla ilgili build dogrulama kayitlari**")
                st.dataframe(related_validation_rows, use_container_width=True, hide_index=True)

            scenario_family = scenario.get("family", "")
            if scenario_family == "dotnet_sdk":
                st.info(
                    "Bu program .NET SDK olarak gorunuyor. Once '.NET SDK Build Testi' butonunu calistir, sonra ayni feature "
                    "bandde kalan en yeni patch'i tutup daha eski patch'leri kademeli degerlendir."
                )
            elif scenario_family in {"visual_studio", "windows_sdk", "visual_cpp", "driver", "runtime_system", "dotnet_runtime"}:
                st.info(
                    "Bu program toolchain/runtime ailesinde. Kaldirma karari vermeden once projelerin acilip acilmadigini, "
                    "IDE'nin sorunsuz calisip calismadigini ve gerekirse build/test akisini elle kontrol et."
                )
            else:
                st.info(
                    "Bu program normal uygulama gibi gorunuyor. Proje bagi yoksa, son kullanim izi eskiyse ve sen de ne ise "
                    "yaradigini bilmiyorsan kaldirma adayi olabilir."
                )

    if selected_program and selected_program.get("decision", "") in {"MANUAL_REVIEW", "UNSURE"}:
        st.subheader("Manual Review Wizard")
        st.caption(
            "Bu sihirbaz programi tanidigin, kullanip kullanmadigin ve daha yeni alternatif olup olmadigi gibi bilgileri "
            "toplar. Kaydettigin sonuc sonraki analizlerde recommendation sonucunu override eder."
        )
        existing_override = manual_review_overrides.get(selected_program.get("software_name", "").casefold(), {})
        detected_last_used = selected_program.get("last_used_at", "").strip()
        if detected_last_used:
            st.info(f"Sistem bu program icin son kullanim izini {detected_last_used} tarihinde gordu. Bu bilgi sorularda referans olarak kullanilabilir.")
        else:
            st.info("Bu program icin otomatik son kullanim izi bulunamadi. Kullanim sorusunu hatirladigin kadariyla cevapla.")

        review_columns = st.columns(3)
        with review_columns[0]:
            user_knows_program = st.selectbox(
                "Bu programi taniyor musun?",
                options=["unknown", "yes", "no"],
                index=["unknown", "yes", "no"].index(existing_override.get("user_knows_program", "unknown")),
                key=f"review_knows_{selected_program.get('software_name', '')}",
            )
            used_recently = st.selectbox(
                "Sistem son kullanim bilgisini dikkate alinca son 6-12 ayda kullandigini dusunuyor musun?",
                options=["unknown", "yes", "no"],
                index=["unknown", "yes", "no"].index(existing_override.get("used_recently", "unknown")),
                key=f"review_recent_{selected_program.get('software_name', '')}",
            )
        with review_columns[1]:
            project_required = st.selectbox(
                "Herhangi bir proje icin gerekli mi?",
                options=["unknown", "yes", "no"],
                index=["unknown", "yes", "no"].index(existing_override.get("project_required", "unknown")),
                key=f"review_project_{selected_program.get('software_name', '')}",
            )
            has_newer_alternative = st.selectbox(
                "Ayni islevi goren daha yeni bir surum/alternatif var mi?",
                options=["unknown", "yes", "no"],
                index=["unknown", "yes", "no"].index(existing_override.get("has_newer_alternative", "unknown")),
                key=f"review_newer_{selected_program.get('software_name', '')}",
            )
        with review_columns[2]:
            is_system_component = st.selectbox(
                "Bu bir runtime/system/driver bileseni mi?",
                options=["unknown", "yes", "no"],
                index=["unknown", "yes", "no"].index(existing_override.get("is_system_component", "unknown")),
                key=f"review_system_{selected_program.get('software_name', '')}",
            )
            review_notes = st.text_area(
                "Kisa not",
                value=existing_override.get("review_notes", ""),
                height=120,
                key=f"review_notes_{selected_program.get('software_name', '')}",
            )

        review_result = evaluate_manual_review(
            software_name=selected_program.get("software_name", ""),
            category=selected_program.get("category", ""),
            original_decision=selected_program.get("decision", ""),
            user_knows_program=user_knows_program,
            used_recently=used_recently,
            project_required=project_required,
            has_newer_alternative=has_newer_alternative,
            is_system_component=is_system_component,
            review_notes=review_notes,
        )

        with st.container(border=True):
            st.markdown(f"**Onerilen ikinci karar:** {review_result.get('reviewed_decision', '')}")
            st.write(review_result.get("reviewed_explanation", ""))

        save_columns = st.columns([1, 1.8])
        with save_columns[0]:
            if st.button("Review Sonucunu Kaydet", use_container_width=True):
                save_manual_review_override(MANUAL_REVIEW_OVERRIDES_PATH, review_result)
                st.success("Manual review sonucu kaydedildi.")
                st.rerun()
        with save_columns[1]:
            st.caption("Kaydettikten sonra `Verileri Yenile` butonu ile bu karar `recommendations.csv` tarafina da islenir.")

    show_runtime_helper = (
        selected_program.get("category", "") == "Runtime/System"
        or "Runtime/System" in selected_categories
        or any(row.get("category", "") == "Runtime/System" for row in table_rows)
    )
    if show_runtime_helper and runtime_family_summaries:
        st.subheader("Runtime / System Karar Yardimcisi")
        st.caption(
            "Bu bolum .NET SDK, .NET Runtime, Visual C++ Redistributable, Windows SDK ve surucu paketleri gibi "
            "bilesenlerde hangi surumu once tutman gerektigini basitce aciklar."
        )
        with st.container(border=True):
            st.markdown("**Basit karar akisi**")
            st.markdown("1. Ayni urunun winget ve registry kaydini ayri program sanma; once duplicate kayitlari ayikla.")
            st.markdown("2. `.NET SDK` icin ayni feature band icinde en yuksek patch surumu once koru.")
            st.markdown("3. `.NET Runtime` ve `ASP.NET Runtime` icin farkli major.minor serilerini ayni surum gibi degerlendirme.")
            st.markdown("4. `Visual C++ Redistributable` paketlerini topluca silme; farkli hatlar ayri programlar ister.")
            st.markdown("5. `Windows SDK` veya driver paketlerinde kaldirma kararini build testi yapmadan verme.")

        st.markdown("**Aile Bazli Ozet**")
        st.dataframe(runtime_family_summaries, use_container_width=True, hide_index=True)

        runtime_family_names = [row.get("family", "") for row in runtime_family_summaries if row.get("family", "")]
        selected_runtime_family = st.selectbox(
            "Runtime Ailesi Sec",
            options=runtime_family_names,
            index=0 if runtime_family_names else None,
        )
        runtime_family_key = runtime_family_key_from_label(selected_runtime_family) if selected_runtime_family else ""
        selected_runtime_rows = runtime_family_details.get(runtime_family_key, [])
        if selected_runtime_rows:
            st.markdown("**Bu ailede bulunan surumler**")
            st.dataframe(selected_runtime_rows, use_container_width=True, hide_index=True)
            st.info(
                "KEEP_CANDIDATE = once tutulacak surum. OLDER_VERSION = ayni ailede daha eski kalan surum. "
                "MANUAL_REVIEW = otomatik silme degil; once proje ve uygulama testi gerekli."
            )

    if dotnet_sdk_report:
        st.subheader(".NET SDK Decision Report")
        st.caption(
            "Bu rapor `dotnet --list-sdks`, `dotnet workload list`, `vswhere`, `global.json`, `.sln` ve `.csproj` sinyallerini "
            "birlikte degerlendirir."
        )
        status_order = ["DO_NOT_REMOVE", "IDE_DEPENDENT", "KEEP_LATEST", "MANUAL_REVIEW", "SAFE_OLDER_PATCH"]
        present_statuses = [status for status in status_order if any(row.get("status", "") == status for row in dotnet_sdk_report)]
        selected_sdk_statuses = set(st.multiselect(".NET SDK Durum Filtresi", present_statuses, default=present_statuses))
        filtered_sdk_report = [
            row for row in dotnet_sdk_report if not selected_sdk_statuses or row.get("status", "") in selected_sdk_statuses
        ]
        st.dataframe(filtered_sdk_report, use_container_width=True, hide_index=True)
        with st.container(border=True):
            st.markdown("**Status anlami**")
            st.markdown("`DO_NOT_REMOVE`: global.json veya aktif proje bagimi var; once silme.")
            st.markdown("`IDE_DEPENDENT`: Visual Studio/workload/proje baglami nedeniyle IDE tarafinda kullaniliyor olabilir.")
            st.markdown("`KEEP_LATEST`: ayni feature band icindeki en yeni patch.")
            st.markdown("`SAFE_OLDER_PATCH`: ayni bandda daha yeni patch var ve net proje kaniti yok.")
            st.markdown("`MANUAL_REVIEW`: karar icin build testi veya IDE kontrolu gerekli.")

    if sdk_validation_report:
        st.subheader(".NET SDK Build Validation")
        st.caption(
            "Bu tablo proje bazli `dotnet --version` ve `dotnet build` sonucunu gosterir. "
            "Gercek build dogrulamasi yaptigi icin karar kalitesi, sadece statik analizden daha yuksektir."
        )
        status_order = ["BUILD_PASSED", "BUILD_FAILED", "DISCOVERED_ONLY", "VALIDATION_FAILED"]
        present_statuses = [status for status in status_order if any(row.get("build_status", "") == status for row in sdk_validation_report)]
        selected_build_statuses = set(st.multiselect(".NET Build Durum Filtresi", present_statuses, default=present_statuses))
        filtered_validation_rows = [
            row for row in sdk_validation_report if not selected_build_statuses or row.get("build_status", "") in selected_build_statuses
        ]
        st.dataframe(filtered_validation_rows, use_container_width=True, hide_index=True)
        with st.container(border=True):
            st.markdown("**Build sonucu nasil yorumlanir?**")
            st.markdown("`BUILD_PASSED`: Bu hedef secilen SDK ile gercekten derlendi. Ayni feature band icindeki daha eski patch'ler daha guvenli aday olur.")
            st.markdown("`BUILD_FAILED`: Build denemesi basarisiz oldu. Hata notunu incelemeden eski SDK silme.")
            st.markdown("`DISCOVERED_ONLY`: Dry-run veya sadece tespit modu; build dogrulamasi yapilmadi.")
            st.markdown("`VALIDATION_FAILED`: Komut calismadi veya timeout oldu; elle inceleme gerekli.")

    st.subheader("Proje Detay Paneli")
    project_label_map = {
        build_project_detail_label(project, child_projects_index.get(normalize_windows_path(project.get("path", "")), [])): project
        for project in root_projects
    }
    project_labels = list(project_label_map.keys())
    selected_project_label = st.selectbox("Proje Sec", options=project_labels, index=0 if project_labels else None)
    selected_project = project_label_map.get(selected_project_label, {}) if selected_project_label else {}
    if selected_project:
        child_projects = child_projects_index.get(normalize_windows_path(selected_project.get("path", "")), [])
        detail_left, detail_right = st.columns([1.2, 1.8])
        with detail_left:
            st.markdown(f"**Proje:** {selected_project.get('project_name', '')}")
            st.markdown(f"**Repo:** {selected_project.get('repo_name', '')}")
            github_url = selected_project.get("github_url", "").strip()
            if github_url:
                st.markdown(f"**GitHub:** [Linki Ac]({github_url})")
            st.markdown(f"**Teknolojiler:** {selected_project.get('detected_technologies', '')}")
            st.markdown(f"**Son Degisiklik:** {selected_project.get('last_modified', '')}")
            st.markdown(f"**Alt Modul Sayisi:** {len(child_projects)}")
        with detail_right:
            st.markdown("**Proje Aciklamasi**")
            st.write(selected_project.get("repo_description", "") or "Aciklama bulunamadi.")
            st.markdown("**Kullanici Notlari**")
            st.write(selected_project.get("user_notes", "") or "Not girilmemis.")
            st.markdown("**Onemli Dosyalar**")
            st.write(selected_project.get("important_files", "") or "Yok")
        if child_projects:
            st.markdown("**Alt Moduller**")
            child_rows = [
                {
                    "project_name": child.get("project_name", ""),
                    "path": child.get("path", ""),
                    "detected_technologies": child.get("detected_technologies", ""),
                    "important_files": child.get("important_files", ""),
                }
                for child in child_projects
            ]
            st.dataframe(child_rows, use_container_width=True, hide_index=True)
        st.markdown("**Bu Proje Icin Gerekli Araclar**")
        project_tools = collect_project_tools(selected_project, child_projects, project_tools_index)
        if project_tools:
            tool_cards = st.columns(min(3, max(1, len(project_tools))))
            for index, tool in enumerate(project_tools[:9]):
                with tool_cards[index % len(tool_cards)]:
                    with st.container(border=True):
                        st.markdown(f"**{tool.get('software_name', '')}**")
                        st.caption(f"{tool.get('category', '')} | {tool.get('decision', '')}")
                        st.write(tool.get("explanation", "")[:200] or "Aciklama yok.")
        else:
            st.info("Bu proje icin eslesen arac bulunamadi.")

    left, right = st.columns(2)
    with left:
        st.subheader("En Cok Yer Kaplayanlar")
        st.dataframe(largest_folders, use_container_width=True, hide_index=True)
    with right:
        st.subheader("En Belirsiz Programlar")
        st.dataframe(uncertain_rows, use_container_width=True, hide_index=True)

    st.subheader("Projeler")
    project_overview_rows = []
    for project in root_projects:
        project_path_key = normalize_windows_path(project.get("path", ""))
        child_projects = child_projects_index.get(project_path_key, [])
        overview_row = dict(project)
        overview_row["submodule_count"] = str(len(child_projects))
        overview_row["submodules"] = ", ".join(child.get("project_name", "") for child in child_projects)
        project_overview_rows.append(overview_row)

    st.dataframe(
        project_overview_rows,
        use_container_width=True,
        hide_index=True,
        column_config={
            "github_url": st.column_config.LinkColumn("GitHub", display_text="Repo"),
            "submodule_count": "Alt Modul",
            "submodules": "Alt Modul Isimleri",
        },
    )

    html_text = generate_report_html(recommendations, mappings, disk_usage, projects)
    st.subheader("Disa Aktar")
    export_col1, export_col2, export_col3 = st.columns(3)
    export_col1.download_button(
        "Recommendations CSV indir",
        data=export_csv_text(recommendations),
        file_name="recommendations.csv",
        mime="text/csv",
    )
    export_col2.download_button(
        "Mapping CSV indir",
        data=export_csv_text(filtered_search_rows),
        file_name="software_project_mapping_filtered.csv",
        mime="text/csv",
    )
    export_col3.download_button(
        "HTML rapor indir",
        data=html_text,
        file_name="report.html",
        mime="text/html",
    )

    st.info(f"Statik HTML rapor dosyasi: {REPORT_HTML_PATH}")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--build-report":
        write_static_exports()
        return 0

    if os.environ.get(STREAMLIT_LAUNCH_FLAG) == "1":
        write_static_exports()
        render_streamlit()
        return 0

    if len(sys.argv) == 1:
        return launch_streamlit()

    write_static_exports()
    render_streamlit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
