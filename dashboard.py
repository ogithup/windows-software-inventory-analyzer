from __future__ import annotations

import csv
import html
import io
import os
import re
import shutil
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
                "risk_score": recommendation.get("risk_score", ""),
                "cleanup_priority_score": recommendation.get("cleanup_priority_score", ""),
                "last_used_at": recommendation.get("last_used_at", ""),
                "usage_signal_count": recommendation.get("usage_signal_count", ""),
                "usage_sources": recommendation.get("usage_sources", ""),
                "usage_status": recommendation.get("usage_status", ""),
                "review_status": recommendation.get("review_status", ""),
                "review_notes": recommendation.get("review_notes", ""),
                "confidence_score": recommendation.get("confidence_score", "") or mapping.get("confidence_score", ""),
                "explanation": recommendation.get("explanation", ""),
                "purpose": recommendation.get("purpose", ""),
                "typical_usage": recommendation.get("typical_usage", ""),
                "related_technologies": recommendation.get("related_technologies", ""),
                "removal_risk_summary": recommendation.get("removal_risk_summary", ""),
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
                        recommendation.get("purpose", ""),
                        recommendation.get("typical_usage", ""),
                        recommendation.get("related_technologies", ""),
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


def runtime_family_label_from_key(key: str) -> str:
    reverse_lookup = {
        "dotnet_sdk": ".NET SDK",
        "dotnet_runtime": ".NET Runtime",
        "aspnet_runtime": "ASP.NET Runtime",
        "windows_sdk": "Windows SDK",
        "visual_cpp": "Visual C++ Redistributable",
        "gpu_driver": "GPU / Driver",
        "dotnet_native": ".NET Native Runtime",
    }
    return reverse_lookup.get(key, key)


def build_runtime_family_test_steps(family_key: str) -> list[tuple[str, str]]:
    if family_key in {"dotnet_sdk", "dotnet_runtime", "aspnet_runtime", "windows_sdk"}:
        return [
            ("scan-projects", "Proje baglari tekrar okunuyor"),
            ("analyze-dotnet-sdk", "SDK ve runtime raporu tazeleniyor"),
            ("validate-dotnet-sdks", "Build testi calisiyor"),
            ("build-removal-decisions", "Kaldirma karari yeniden hesaplaniyor"),
        ]
    if family_key == "visual_cpp":
        return [
            ("collect-programs", "Kurulu yardimci paketler tekrar okunuyor"),
            ("scan-projects", "Proje baglari tekrar okunuyor"),
            ("recommend", "Karar metinleri tazeleniyor"),
            ("build-removal-decisions", "Kaldirma karari yeniden hesaplaniyor"),
        ]
    if family_key in {"gpu_driver", "dotnet_native"}:
        return [
            ("collect-usage", "Son kullanim izleri tekrar okunuyor"),
            ("score-risk", "Risk puani tekrar hesaplaniyor"),
            ("recommend", "Karar metinleri tazeleniyor"),
            ("build-removal-decisions", "Kaldirma karari yeniden hesaplaniyor"),
        ]
    return [
        ("recommend", "Karar metinleri tazeleniyor"),
        ("build-removal-decisions", "Kaldirma karari yeniden hesaplaniyor"),
    ]


def build_runtime_family_report(
    family_key: str,
    runtime_family_details: dict[str, list[dict[str, str]]],
    dotnet_sdk_report: list[dict[str, str]],
    sdk_validation_report: list[dict[str, str]],
) -> dict[str, object]:
    detail_rows = runtime_family_details.get(family_key, [])
    report_rows: list[dict[str, str]] = []
    notes: list[str] = []

    if family_key == "dotnet_sdk":
        report_rows = [
            {
                "kind": "SDK Karari",
                "item": row.get("sdk_version", ""),
                "group": row.get("feature_band", ""),
                "suggestion": row.get("status", ""),
                "result": row.get("recommendation", ""),
            }
            for row in dotnet_sdk_report
        ]
        report_rows.extend(
            {
                "kind": "Build Testi",
                "item": row.get("project_name", ""),
                "group": row.get("selected_sdk", ""),
                "suggestion": row.get("build_status", ""),
                "result": row.get("notes", ""),
            }
            for row in sdk_validation_report
        )
        validation_states = sorted({row.get("build_status", "") for row in sdk_validation_report if row.get("build_status", "")})
        if validation_states:
            notes.append(f"Build kayitlari: {', '.join(validation_states)}")
        else:
            notes.append("Build kaydi yok; kaldirmadan once test calistir.")
        notes.append("Muhur gibi kural: global.json gecen surum tutulur, ayni feature band icinde daha eski patch'ler ise testten sonra aday olur.")
        notes.append("Proje build geciyorsa eski patch'leri kademeli azalt; hepsini tek seferde temizleme.")
    elif family_key in {"dotnet_runtime", "aspnet_runtime", "windows_sdk", "visual_cpp", "gpu_driver", "dotnet_native"}:
        for row in detail_rows:
            suggestion = row.get("suggestion", "")
            if suggestion == "KEEP_CANDIDATE":
                result = "Simdilik kalsin"
            elif suggestion == "OLDER_VERSION":
                result = "Ayni ailede daha yeni bir surum gorunuyor"
            else:
                result = "Elle kontrol et"
            report_rows.append(
                {
                    "kind": "Aile Kontrolu",
                    "item": row.get("software_name", ""),
                    "group": row.get("version", "") or row.get("arch", ""),
                    "suggestion": suggestion,
                    "result": result,
                }
            )
        if family_key in {"dotnet_runtime", "aspnet_runtime"}:
            notes.append("Ayni major.minor hattinda en yeni patch once tutulur.")
            notes.append("Farkli major.minor serilerini birbiri yerine sayma; eski görünse bile uygulama bunu isteyebilir.")
        elif family_key == "windows_sdk":
            notes.append("Windows SDK tarafinda eski surumleri silmeden once Visual Studio ve build akisini kontrol et.")
            notes.append("Bilgisayar muhendisi mantigi: C++ veya Windows hedefli proje varsa en az bir acilis veya build denemesi almadan temizleme yapma.")
        elif family_key == "visual_cpp":
            notes.append("Visual C++ paketleri farkli uygulamalar tarafindan birlikte istenebilir; toplu kaldirma yapma.")
            notes.append("Bu ailede otomatik sil yerine koruma odakli kal; sadece cok net duplicate ve kontrollu senaryolarda elle karar ver.")
        elif family_key == "gpu_driver":
            notes.append("Suruculerde kaldirma yerine resmi surucu araci ile guncelleme veya temiz kurulum dusun.")
            notes.append("CUDA, oyun motoru, video isleme veya AI proje izi varsa surucu ailesini kaldirma adayi gibi dusunme.")
        elif family_key == "dotnet_native":
            notes.append("Store/MSIX uygulamalari bu aileye bagli olabilir.")
            notes.append("Dogrudan build yerine kullanim izi ve sistem koruma mantigi kullan.")

    if not report_rows:
        notes.append("Bu aile icin gosterilecek test satiri bulunamadi.")

    return {
        "family_label": runtime_family_label_from_key(family_key),
        "rows": report_rows,
        "notes": notes,
    }


def normalize_windows_path(value: str) -> str:
    return value.replace("/", "\\").rstrip("\\").casefold()


def bytes_to_human(size_bytes: int) -> str:
    value = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size_bytes} B"


def safe_int_from_any(value: str | int | float) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


def infer_drive_from_path(path_text: str) -> str:
    normalized = path_text.strip().replace("/", "\\")
    if len(normalized) >= 2 and normalized[1] == ":":
        return normalized[:2].upper()
    return normalized


def build_drive_usage_cards(disk_usage: list[dict[str, str]]) -> list[dict[str, str]]:
    totals_by_drive: dict[str, int] = {}
    roots_by_drive: dict[str, set[str]] = {}

    for row in disk_usage:
        scan_root = row.get("scan_root", "").strip() or row.get("path", "").strip()
        drive = infer_drive_from_path(scan_root)
        if not drive or ":" not in drive:
            continue
        depth = safe_int(row.get("depth", "0"))
        if depth != 0:
            continue
        totals_by_drive[drive] = totals_by_drive.get(drive, 0) + safe_int_from_any(row.get("size_bytes", "0"))
        roots_by_drive.setdefault(drive, set()).add(scan_root)

    cards: list[dict[str, str]] = []
    for drive, analyzed_bytes in sorted(totals_by_drive.items()):
        try:
            usage = shutil.disk_usage(f"{drive}\\")
        except OSError:
            continue
        used_pct = (usage.used / usage.total * 100) if usage.total else 0
        analyzed_pct = (analyzed_bytes / usage.total * 100) if usage.total else 0
        cards.append(
            {
                "drive": drive,
                "used_pct": f"{used_pct:.1f}",
                "analyzed_pct": f"{analyzed_pct:.1f}",
                "used_human": bytes_to_human(usage.used),
                "free_human": bytes_to_human(usage.free),
                "total_human": bytes_to_human(usage.total),
                "analyzed_human": bytes_to_human(analyzed_bytes),
                "roots": ", ".join(sorted(roots_by_drive.get(drive, set()))),
            }
        )
    return cards


def render_drive_usage_blocks(cards: list[dict[str, str]]) -> str:
    if not cards:
        return "<div style='padding:12px;border:1px solid #d9d1c5;border-radius:16px;background:#fffdf8;'>Disk ozeti bulunamadi.</div>"

    block_parts: list[str] = []
    for card in cards:
        used_pct = safe_float(card.get("used_pct", "0"))
        analyzed_pct = min(used_pct, safe_float(card.get("analyzed_pct", "0")))
        usage_color = "#c2410c" if used_pct >= 85 else "#d97706" if used_pct >= 70 else "#0f766e"
        analyze_color = "#1d4ed8"
        block_parts.append(
            f"""
            <div style="background:#fffdf8;border:1px solid #d9d1c5;border-radius:18px;padding:14px;min-width:250px;">
              <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-end;">
                <strong style="font-size:1.05rem;">{html.escape(card.get("drive", ""))} Diski</strong>
                <span style="color:#6c665d;">{html.escape(card.get("used_pct", "0"))}% dolu</span>
              </div>
              <div style="margin-top:10px;background:#ece7de;border-radius:999px;height:18px;overflow:hidden;position:relative;">
                <div style="width:{used_pct:.1f}%;background:{usage_color};height:100%;"></div>
                <div style="width:{analyzed_pct:.1f}%;background:{analyze_color};height:100%;position:absolute;left:0;top:0;opacity:0.65;"></div>
              </div>
              <div style="display:flex;justify-content:space-between;gap:12px;margin-top:10px;font-size:0.9rem;">
                <span>Kullanilan: {html.escape(card.get("used_human", ""))}</span>
                <span>Bos: {html.escape(card.get("free_human", ""))}</span>
              </div>
              <div style="margin-top:6px;font-size:0.9rem;">Analiz edilen kokler: {html.escape(card.get("roots", ""))}</div>
              <div style="margin-top:4px;font-size:0.9rem;">Analiz edilen alan: {html.escape(card.get("analyzed_human", ""))} / {html.escape(card.get("total_human", ""))}</div>
            </div>
            """
        )
    return "<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;'>" + "".join(block_parts) + "</div>"


def build_disk_treemap_rows(disk_usage: list[dict[str, str]], limit: int = 12) -> list[dict[str, str]]:
    rows = [row for row in disk_usage if safe_int(row.get("depth", "0")) <= 1 and row.get("path", "").strip()]
    rows.sort(key=lambda item: safe_int_from_any(item.get("size_bytes", "0")), reverse=True)
    return rows[:limit]


def render_disk_treemap(rows: list[dict[str, str]]) -> str:
    if not rows:
        return "<div style='padding:12px;border:1px solid #d9d1c5;border-radius:16px;background:#fffdf8;'>Buyuk klasor verisi bulunamadi.</div>"

    max_size = max(safe_int_from_any(row.get("size_bytes", "0")) for row in rows) or 1
    colors = ["#0f766e", "#2563eb", "#d97706", "#b45309", "#7c3aed", "#0f766e", "#be123c", "#15803d"]
    parts: list[str] = []
    for index, row in enumerate(rows):
        size_bytes = safe_int_from_any(row.get("size_bytes", "0"))
        width = max(18, int((size_bytes / max_size) * 100))
        parts.append(
            f"""
            <div style="flex:{width} 1 0;background:{colors[index % len(colors)]};min-height:110px;border-radius:18px;padding:12px;color:white;display:flex;flex-direction:column;justify-content:space-between;">
              <div style="font-weight:600;font-size:0.95rem;">{html.escape(row.get("path", ""))}</div>
              <div style="font-size:0.85rem;">{html.escape(row.get("size_human", ""))}</div>
            </div>
            """
        )
    return "<div style='display:flex;gap:10px;align-items:stretch;'>" + "".join(parts) + "</div>"


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


def parse_version_parts(version_text: str) -> tuple[int, ...]:
    parts = [part for part in re.split(r"[^0-9]+", version_text.strip()) if part]
    return tuple(int(part) for part in parts)


def normalize_software_family_name(software_name: str) -> str:
    normalized = software_name.casefold()
    normalized = re.sub(r"\((x64|x86)\)", " ", normalized)
    normalized = re.sub(r"\b(64-bit|32-bit|x64|x86)\b", " ", normalized)
    normalized = re.sub(r"\b\d+(?:\.\d+){1,4}\b", " ", normalized)
    normalized = re.sub(r"\b(19|20)\d{2}\b", " ", normalized)
    normalized = re.sub(r"[-_]+", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip(" -_.")
    return normalized


def build_version_family_summary(
    selected_program: dict[str, str],
    recommendations: list[dict[str, str]],
    dotnet_sdk_report: list[dict[str, str]],
    sdk_validation_report: list[dict[str, str]],
) -> dict[str, object]:
    software_name = selected_program.get("software_name", "").strip()
    category = selected_program.get("category", "").strip()
    family_type = classify_program_family(software_name, category)
    normalized_family = normalize_software_family_name(software_name)

    family_members = [
        row for row in recommendations if normalize_software_family_name(row.get("software_name", "")) == normalized_family
    ]
    family_members = sorted(
        family_members,
        key=lambda row: parse_version_parts(row.get("display_version", "") or row.get("software_name", "")),
        reverse=True,
    )

    keepers: list[dict[str, str]] = []
    candidates: list[dict[str, str]] = []
    notes: list[str] = []

    if family_type == "dotnet_sdk" and dotnet_sdk_report:
        for report_row in dotnet_sdk_report:
            sdk_version = report_row.get("sdk_version", "").strip()
            if not sdk_version:
                continue
            matched = next((row for row in family_members if sdk_version in row.get("software_name", "")), None)
            member = matched or {
                "software_name": f"Microsoft .NET SDK {sdk_version}",
                "display_version": sdk_version,
                "decision": "",
                "last_used_at": "",
                "estimated_size": "",
            }
            member = dict(member)
            member["sdk_status"] = report_row.get("status", "")
            member["sdk_recommendation"] = report_row.get("recommendation", "")
            member["feature_band"] = report_row.get("feature_band", "")

            status = report_row.get("status", "")
            if status in {"DO_NOT_REMOVE", "IDE_DEPENDENT", "KEEP_LATEST"}:
                keepers.append(member)
            elif status in {"SAFE_OLDER_PATCH", "MANUAL_REVIEW"}:
                candidates.append(member)
            else:
                keepers.append(member)

        validation_statuses = {row.get("build_status", "") for row in sdk_validation_report}
        if "BUILD_PASSED" in validation_statuses:
            notes.append("Build testi gecen .NET projeleri bulundu; ayni banddeki eski patch surumler daha guvenli aday olur.")
        elif validation_statuses:
            notes.append("Build testi kayitlari var ama temiz gecmeyen projeler de goruluyor; toplu kaldirma yapma.")
        else:
            notes.append("Build testi kaydi yok; aday gorunen surumleri kaldirmadan once test calistir.")
    else:
        if len(family_members) <= 1:
            notes.append("Bu ailede tek surum gorunuyor.")
        latest_member = family_members[0] if family_members else {}
        for member in family_members:
            member_name = member.get("software_name", "")
            project_count = safe_int(member.get("project_count", "0"))
            risk_score = safe_float(member.get("risk_score", "0"))
            cleanup_score = safe_float(member.get("cleanup_priority_score", "0"))
            usage_status = member.get("usage_status", "")
            usage_date = parse_iso_datetime(member.get("last_used_at", ""))

            should_keep = (
                member == latest_member
                or project_count > 0
                or risk_score >= 70
                or classify_program_family(member_name, member.get("category", "")) != "general"
            )
            if usage_status == "usage_detected" and usage_date is not None:
                age_days = max(0, int((datetime.now(timezone.utc) - usage_date).total_seconds() // 86400))
                if age_days <= 180:
                    should_keep = True

            if should_keep:
                keepers.append(member)
            elif cleanup_score >= 45 or len(family_members) > 1:
                candidates.append(member)
            else:
                keepers.append(member)

        if len(family_members) > 1:
            notes.append("Ayni uygulamanin birden fazla surumu gorunuyor; en yeni ve aktif kullanilan surum once tutulur.")
        if any(safe_int(row.get("project_count", "0")) > 0 for row in family_members):
            notes.append("Bu ailede proje bagina sahip surumler var; kaldirmadan once proje acilisini kontrol et.")

    if not candidates and len(family_members) > 1:
        notes.append("Su anki sinyallerle net kaldirma adayi cikmadi.")

    if candidates:
        summary_message = "Bu ailede once aday surumleri dene, koru denilenleri yerinde birak."
    elif len(family_members) > 1:
        summary_message = "Bu ailede birden fazla surum olsa da su an hepsi icin ek dikkat gerekiyor."
    else:
        summary_message = "Bu program ailesinde tek kayit gorunuyor; surum temizligi yerine kullanim ihtiyacina bak."

    return {
        "family_name": normalized_family or software_name.casefold(),
        "family_type": family_type,
        "members": family_members,
        "keepers": keepers,
        "candidates": candidates,
        "summary_message": summary_message,
        "notes": notes,
    }


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
    return run_cli_command("refresh-all")


def run_cli_command(command_name: str) -> tuple[bool, str]:
    command = [sys.executable, "-m", "src.main", command_name]
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
        return False, output or f"{command_name} basarisiz oldu."
    return True, output or f"{command_name} tamamlandi."


def run_stepwise_commands(steps: list[tuple[str, str]], progress_bar, status_box, log_box) -> tuple[bool, str]:
    collected_logs: list[str] = []
    total_steps = max(len(steps), 1)

    for index, (command_name, label) in enumerate(steps, start=1):
        progress_value = int(((index - 1) / total_steps) * 100)
        progress_bar.progress(progress_value)
        status_box.info(f"Adim {index}/{total_steps}: {label}")
        success, message = run_cli_command(command_name)
        collected_logs.append(f"[{command_name}] {message}")
        log_box.code("\n\n".join(collected_logs)[-4000:], language="text")
        if not success:
            progress_bar.progress(progress_value)
            status_box.error(f"Durdu: {label}")
            return False, "\n\n".join(collected_logs)

    progress_bar.progress(100)
    status_box.success("Tum adimlar tamamlandi.")
    return True, "\n\n".join(collected_logs)


def launch_streamlit() -> int:
    env = os.environ.copy()
    env[STREAMLIT_LAUNCH_FLAG] = "1"
    command = [sys.executable, "-m", "streamlit", "run", str(Path(__file__).resolve())]
    return subprocess.call(command, env=env)


def render_streamlit() -> None:
    try:
        import streamlit as st
        import streamlit.components.v1 as components
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
    risk_scores = load_csv_rows(OUTPUT_DIR / "program_risk_scores.csv")
    installed_programs = load_csv_rows(OUTPUT_DIR / "installed_programs.csv")
    mappings = load_csv_rows(OUTPUT_DIR / "software_project_mapping.csv")
    disk_usage = load_csv_rows(OUTPUT_DIR / "disk_usage.csv")
    projects = load_csv_rows(OUTPUT_DIR / "project_tech_stack.csv")
    dotnet_sdk_report = load_csv_rows(OUTPUT_DIR / "dotnet_sdk_decision_report.csv")
    sdk_validation_report = load_csv_rows(OUTPUT_DIR / "sdk_validation_report.csv")
    removal_decisions = load_csv_rows(OUTPUT_DIR / "removal_decisions.csv")
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
            progress_bar = st.progress(0)
            status_box = st.empty()
            log_box = st.empty()
            refresh_steps = [
                ("collect-programs", "Kurulu programlar okunuyor"),
                ("collect-usage", "Son kullanim izleri toplanıyor"),
                ("scan-disk", "Disk ve buyuk klasorler taraniyor"),
                ("scan-projects", "Projeler ve teknoloji dosyalari taraniyor"),
                ("map-software", "Programlar projelerle eslestiriliyor"),
                ("score-risk", "Risk ve temizlik onceligi hesaplanıyor"),
                ("recommend", "Son oneriler ve aciklamalar yaziliyor"),
                ("analyze-dotnet-sdk", ".NET SDK bagimlilik raporu hazirlaniyor"),
                ("build-removal-decisions", "Kaldirma senaryosu kararlari uretiliyor"),
            ]
            success, message = run_stepwise_commands(refresh_steps, progress_bar, status_box, log_box)
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

    categories = sorted({row.get("category", "") for row in recommendations if row.get("category", "")}, key=str.casefold)
    decisions = sorted({row.get("decision", "") for row in recommendations if row.get("decision", "")}, key=str.casefold)

    col1, col2, col3 = st.columns([2.2, 1.2, 1.2])
    with col1:
        query = st.text_input("Arama", placeholder="opencv, docker, youtube, networks, python, android...")
    with col2:
        selected_categories = set(st.multiselect("Kategori Filtresi", categories))
    with col3:
        selected_decisions = set(st.multiselect("Karar Filtresi", decisions))

    with st.expander("Kategori Rehberi"):
        st.markdown("`AI/ML`: yapay zeka, model egitimi, veri analizi")
        st.markdown("`Backend`: sunucu tarafli araclar, Python, API, servis gelistirme")
        st.markdown("`Frontend`: web arayuzu ve JavaScript araclari")
        st.markdown("`Database`: veritabani motorlari ve yonetim araclari")
        st.markdown("`Network`: ag analizi, paket inceleme, haberlesme araclari")
        st.markdown("`Virtualization`: Docker gibi izole calisma ortamlari")
        st.markdown("`Runtime/System`: sistemin veya baska yazilimlarin calismasi icin gereken bilesenler")
        st.markdown("`Unknown`: amaci net cikarilamayan araclar")

    filtered_search_rows = filter_search_rows(search_rows, query, selected_categories, selected_decisions)
    uncertain_rows = [row for row in recommendations if row.get("decision") in {"UNSURE", "MANUAL_REVIEW"}]
    uncertain_rows = sorted(uncertain_rows, key=lambda item: safe_float(item.get("confidence_score", "0")))[:20]
    largest_folders = sorted(disk_usage, key=lambda item: size_to_bytes(item.get("size_human", "")), reverse=True)[:20]
    drive_usage_cards = build_drive_usage_cards(disk_usage)
    disk_treemap_rows = build_disk_treemap_rows(disk_usage)

    metrics = st.columns(4)
    metrics[0].metric("Toplam Program", len(recommendations))
    metrics[1].metric("Eslestirme Kaydi", len(mappings))
    metrics[2].metric("Buyuk Klasor", len(disk_usage))
    metrics[3].metric("Taranan Proje", len(root_projects))

    st.subheader("Disk Doluluk Gorunumu")
    st.caption("Mavi katman analiz edilen kokleri, renkli katman toplam disk dolulugunu gosterir.")
    components.html(render_drive_usage_blocks(drive_usage_cards), height=max(180, 120 + len(drive_usage_cards) * 30), scrolling=False)
    st.markdown("**En Buyuk Alan Bloklari**")
    components.html(render_disk_treemap(disk_treemap_rows), height=180, scrolling=False)

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
                "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100),
                "cleanup_priority_score": st.column_config.ProgressColumn("Temizlik Onceligi", min_value=0, max_value=100),
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
                "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100),
                "cleanup_priority_score": st.column_config.ProgressColumn("Temizlik Onceligi", min_value=0, max_value=100),
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
        removal_row = next((row for row in removal_decisions if row.get("software_name", "") == selected_program.get("software_name", "")), {})
        with st.container(border=True):
            detail_left, detail_right = st.columns([1.1, 1.9])
            with detail_left:
                st.markdown(f"**Program:** {selected_program.get('software_name', '')}")
                st.markdown(f"**Kategori:** {selected_program.get('category', '')}")
                st.markdown(f"**Karar:** {selected_program.get('decision', '')}")
                st.markdown(f"**Guven:** {selected_program.get('confidence_score', '')}")
                st.markdown(f"**Tahmini Boyut:** {selected_program.get('estimated_size', '') or 'Bilinmiyor'}")
                st.markdown(f"**Risk Skoru:** {selected_program.get('risk_score', '') or '0'} / 100")
                st.markdown(f"**Temizlik Onceligi:** {selected_program.get('cleanup_priority_score', '') or '0'} / 100")
                st.markdown(f"**Projeler:** {selected_program.get('matched_projects', '') or 'Yok'}")
                st.markdown(f"**Son Kullanim:** {selected_program.get('last_used_at', '') or 'Bilinmiyor'}")
                st.markdown(f"**Kullanim Sinyali:** {selected_program.get('usage_status', '') or 'unknown_usage'}")
            with detail_right:
                st.markdown("**Neden Bu Karar Verildi?**")
                st.write(selected_program.get("explanation", "") or "Acilama yok.")
                st.markdown("**Bu Program Ne Ise Yarar?**")
                st.write(selected_program.get("purpose", "") or "Aciklama bulunamadi.")
                st.markdown("**Tipik Kullanim**")
                st.write(selected_program.get("typical_usage", "") or "Tipik kullanim bilgisi bulunamadi.")
                st.markdown("**Ilgili Teknolojiler**")
                st.write(selected_program.get("related_technologies", "") or "Ilgili teknoloji bilgisi bulunamadi.")
                st.markdown("**Removal Risk Ozeti**")
                st.write(selected_program.get("removal_risk_summary", "") or "Risk ozeti bulunamadi.")
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
                if removal_row:
                    st.markdown("**Yeni Kaldirma Motoru**")
                    st.write(removal_row.get("plain_language_explanation", "") or "Ek karar yok.")
                    st.caption(
                        f"Etiket: {removal_row.get('decision_label', '')} | "
                        f"Silme riski: {removal_row.get('removal_risk_score', '')} | "
                        f"Alan kazanma degeri: {removal_row.get('cleanup_value_score', '')}"
                    )

        scenario = build_removal_scenario(selected_program, recommendations, dotnet_sdk_report, sdk_validation_report)
        family_summary = build_version_family_summary(
            selected_program,
            recommendations,
            dotnet_sdk_report,
            sdk_validation_report,
        )
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

        st.markdown("**Ayni uygulamanin diger surumleri**")
        st.write(str(family_summary.get("summary_message", "")))
        family_candidates = family_summary.get("candidates", [])
        family_keepers = family_summary.get("keepers", [])
        if family_keepers:
            st.markdown("**Kalmasi daha guvenli gorunenler**")
            st.dataframe(
                [
                    {
                        "program": row.get("software_name", ""),
                        "boyut": row.get("estimated_size", ""),
                        "son_kullanim": row.get("last_used_at", "") or "Bilinmiyor",
                    }
                    for row in family_keepers[:8]
                ],
                use_container_width=True,
                hide_index=True,
            )
        if family_candidates:
            st.markdown("**Ilk kaldirma adaylari**")
            st.dataframe(
                [
                    {
                        "program": row.get("software_name", ""),
                        "boyut": row.get("estimated_size", ""),
                        "son_kullanim": row.get("last_used_at", "") or "Bilinmiyor",
                    }
                    for row in family_candidates[:8]
                ],
                use_container_width=True,
                hide_index=True,
            )
        for note in family_summary.get("notes", [])[:4]:
            st.caption(note)

        st.markdown("**Bu arac icin tek tik test**")
        if st.button("Secili Araci Test Et", use_container_width=True):
            progress_bar = st.progress(0)
            status_box = st.empty()
            log_box = st.empty()
            test_steps = [("scan-projects", "Projeler tekrar okunuyor")]
            if any(token in f"{selected_program.get('software_name', '')} {selected_program.get('category', '')}".casefold() for token in (".net", "sdk", "visual studio", "windows sdk")):
                test_steps.extend(
                    [
                        ("validate-dotnet-sdks", "Bu araca bagli build testleri calisiyor"),
                        ("build-removal-decisions", "Kaldirma karari yeniden hesaplaniyor"),
                    ]
                )
            else:
                test_steps.extend(
                    [
                        ("collect-usage", "Son kullanim izleri tekrar okunuyor"),
                        ("score-risk", "Risk puani tekrar hesaplaniyor"),
                        ("recommend", "Karar ekrani guncelleniyor"),
                        ("build-removal-decisions", "Kaldirma karari yeniden hesaplaniyor"),
                    ]
                )
            success, message = run_stepwise_commands(test_steps, progress_bar, status_box, log_box)
            if success:
                st.success("Test tamamlandi. Sonuclar yenileniyor.")
                if message:
                    st.caption(message[-500:] if len(message) > 500 else message)
                st.rerun()
            else:
                st.error("Test yarida kaldi.")
                if message:
                    st.code(message[-2000:] if len(message) > 2000 else message, language="text")

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
        or bool(dotnet_sdk_report)
    )
    if show_runtime_helper and runtime_family_summaries:
        st.subheader("Sistem Araclari Raporu")
        st.caption(
            "Bu bolum sistem ailelerini tek yerde toplar. Ayni kurali herkese uygulamaz; aileye gore proje, build, kullanim "
            "ve surum hatti mantigi kullanir."
        )
        with st.container(border=True):
            st.markdown("**Bilgisayar muhendisi mantigi**")
            st.markdown("1. `.NET SDK`: once `.sln`, `.csproj`, `global.json`, `dotnet restore`, `dotnet build` bak.")
            st.markdown("2. `.NET Runtime` ve `ASP.NET Runtime`: build kadar surum hatti uyumuna bak; ayni `major.minor` icinde en yeni patch once tutulur.")
            st.markdown("3. `Windows SDK`: Visual Studio veya C++/Windows hedefli proje varsa test almadan kaldirma.")
            st.markdown("4. `Visual C++`: farkli uygulamalar ayni anda farkli paket isteyebilir; toplu temizleme yapma.")
            st.markdown("5. `GPU / Driver`: kaldirma testi degil bagimlilik testi yap; CUDA, AI, oyun motoru, video araci var mi kontrol et.")
            st.markdown("6. `.NET Native Runtime`: Store/MSIX etkisi yuzunden korumaci davran.")

        st.markdown("**Aile Bazli Ozet**")
        st.dataframe(runtime_family_summaries, use_container_width=True, hide_index=True)

        runtime_family_names = [row.get("family", "") for row in runtime_family_summaries if row.get("family", "")]
        selected_runtime_family = st.selectbox(
            "Sistem Araci Ailesi Sec",
            options=runtime_family_names,
            index=0 if runtime_family_names else None,
        )
        runtime_family_key = runtime_family_key_from_label(selected_runtime_family) if selected_runtime_family else ""
        selected_runtime_rows = runtime_family_details.get(runtime_family_key, [])
        if runtime_family_key:
            st.markdown("**Bu aile icin test dugmesi**")
            if st.button(f"{selected_runtime_family} Icin Test Et", key=f"runtime-test-{runtime_family_key}", use_container_width=True):
                progress_bar = st.progress(0)
                status_box = st.empty()
                log_box = st.empty()
                success, message = run_stepwise_commands(
                    build_runtime_family_test_steps(runtime_family_key),
                    progress_bar,
                    status_box,
                    log_box,
                )
                if success:
                    st.success(f"{selected_runtime_family} testi tamamlandi. Sonuclar yenileniyor.")
                    if message:
                        st.caption(message[-500:] if len(message) > 500 else message)
                    st.rerun()
                else:
                    st.error(f"{selected_runtime_family} testi yarida kaldi.")
                    if message:
                        st.code(message[-2000:] if len(message) > 2000 else message, language="text")
        if selected_runtime_rows:
            st.markdown("**Bu ailede bulunan surumler**")
            st.dataframe(selected_runtime_rows, use_container_width=True, hide_index=True)
        runtime_family_report = build_runtime_family_report(
            runtime_family_key,
            runtime_family_details,
            dotnet_sdk_report,
            sdk_validation_report,
        ) if runtime_family_key else {"rows": [], "notes": []}
        if runtime_family_report.get("rows"):
            report_rows = runtime_family_report.get("rows", [])
            kinds = sorted({row.get("kind", "") for row in report_rows if row.get("kind", "")}, key=str.casefold)
            suggestions = sorted({row.get("suggestion", "") for row in report_rows if row.get("suggestion", "")}, key=str.casefold)
            filter_left, filter_right = st.columns(2)
            with filter_left:
                selected_kinds = set(st.multiselect("Kayit Turu Filtresi", kinds, default=kinds, key=f"runtime-kind-{runtime_family_key}"))
            with filter_right:
                selected_suggestions = set(st.multiselect("Durum Filtresi", suggestions, default=suggestions, key=f"runtime-suggestion-{runtime_family_key}"))
            filtered_runtime_rows = [
                row for row in report_rows
                if (not selected_kinds or row.get("kind", "") in selected_kinds)
                and (not selected_suggestions or row.get("suggestion", "") in selected_suggestions)
            ]
            st.markdown("**Bu aile icin test sonucu ozeti**")
            st.dataframe(filtered_runtime_rows, use_container_width=True, hide_index=True)
            if runtime_family_key == "dotnet_sdk" and sdk_validation_report:
                st.markdown("**Proje bazli build sonucu**")
                st.dataframe(sdk_validation_report, use_container_width=True, hide_index=True)
        for note in runtime_family_report.get("notes", [])[:4]:
            st.caption(note)

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
            st.markdown("**Kod Sinyalleri**")
            st.write(selected_project.get("detected_libraries", "") or "Kod seviyesi kutuphane sinyali bulunamadi.")
            st.markdown("**Framework Sinyalleri**")
            st.write(selected_project.get("framework_signals", "") or "Framework sinyali bulunamadi.")
            st.markdown("**Kod Kaniti**")
            st.write(selected_project.get("code_evidence", "") or "Kod kaniti bulunamadi.")
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

    if risk_scores:
        st.subheader("Yuksek Temizlik Onceligi")
        cleanup_candidates = sorted(risk_scores, key=lambda row: safe_float(row.get("cleanup_priority_score", "0")), reverse=True)[:20]
        st.dataframe(
            cleanup_candidates,
            use_container_width=True,
            hide_index=True,
            column_config={
                "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100),
                "cleanup_priority_score": st.column_config.ProgressColumn("Temizlik Onceligi", min_value=0, max_value=100),
            },
        )

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
