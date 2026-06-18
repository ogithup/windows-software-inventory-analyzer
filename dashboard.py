from __future__ import annotations

import csv
import html
import io
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "data" / "output"
EXPORTS_DIR = BASE_DIR / "exports"
REPORT_HTML_PATH = BASE_DIR / "report.html"
STREAMLIT_LAUNCH_FLAG = "WSIA_STREAMLIT_LAUNCHED"


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
        for project_name in matched_project_names:
            project = projects_by_name.get(project_name.casefold(), {})
            detected = project.get("detected_technologies", "")
            if detected:
                technologies.extend([item.strip() for item in detected.split(",") if item.strip()])

        indexed_rows.append(
            {
                "software_name": software_name,
                "category": recommendation.get("category", ""),
                "decision": recommendation.get("decision", ""),
                "matched_projects": matched_projects,
                "project_count": recommendation.get("project_count", ""),
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
                        recommendation.get("explanation", ""),
                        mapping.get("evidence", ""),
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
        cells = "".join(f"<td>{html.escape(str(row.get(column, '')))}</td>" for column in columns)
        body_parts.append(f"<tr>{cells}</tr>")
    body_html = "".join(body_parts) or f"<tr><td colspan='{len(columns)}'>Veri bulunamadi.</td></tr>"
    return (
        f"<section><h2>{html.escape(title)}</h2>"
        f"<div class='table-wrap'><table><thead><tr>{header_html}</tr></thead>"
        f"<tbody>{body_html}</tbody></table></div></section>"
    )


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
    {format_table_html(search_preview, ["software_name", "category", "decision", "matched_projects", "technologies"], "Program ve Proje Eslestirmeleri")}
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

    recommendations = load_csv_rows(OUTPUT_DIR / "recommendations.csv")
    mappings = load_csv_rows(OUTPUT_DIR / "software_project_mapping.csv")
    disk_usage = load_csv_rows(OUTPUT_DIR / "disk_usage.csv")
    projects = load_csv_rows(OUTPUT_DIR / "project_tech_stack.csv")
    search_rows = build_search_index(recommendations, mappings, projects)

    REPORT_HTML_PATH.write_text(
        generate_report_html(recommendations, mappings, disk_usage, projects),
        encoding="utf-8",
    )
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    st.title("Windows Software Inventory Analyzer")
    st.caption("Program silme yapmaz. Sadece analiz, kategori ve raporlama sunar.")

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
    metrics[3].metric("Taranan Proje", len(projects))

    st.subheader("Program ve Proje Eslestirmeleri")
    st.dataframe(filtered_search_rows, use_container_width=True, hide_index=True)

    left, right = st.columns(2)
    with left:
        st.subheader("En Cok Yer Kaplayanlar")
        st.dataframe(largest_folders, use_container_width=True, hide_index=True)
    with right:
        st.subheader("En Belirsiz Programlar")
        st.dataframe(uncertain_rows, use_container_width=True, hide_index=True)

    st.subheader("Projeler")
    st.dataframe(projects, use_container_width=True, hide_index=True)

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
