from __future__ import annotations

from src.windows_software_inventory_analyzer.models import ProgramDecisionContext


def build_plain_language_explanation(
    context: ProgramDecisionContext,
    decision_label: str,
    reasons: list[str],
) -> str:
    prefix = {
        "KEEP": "Bu program simdilik kalsin.",
        "TEST_FIRST": "Bu programi kaldirmadan once test yapmak daha guvenli.",
        "MANUAL_REVIEW": "Bu program icin elle kontrol gerekiyor.",
        "LOWER_RISK_CANDIDATE": "Bu program dusuk riskli kaldirma adayi gibi gorunuyor.",
        "CACHE_CLEAN_ONLY": "Programi silmek yerine sadece olusan cache alanini temizlemek daha dogru.",
    }.get(decision_label, "Bu program icin ek inceleme gerekiyor.")
    detail = " ".join(reason.strip() for reason in reasons[:4] if reason.strip())
    return f"{prefix} {detail}".strip()


def build_technical_explanation(
    context: ProgramDecisionContext,
    decision_label: str,
    removal_risk_score: float,
    cleanup_value_score: float,
    reasons: list[str],
) -> str:
    summary = (
        f"decision={decision_label}; family={context.family_type}; "
        f"removal_risk_score={removal_risk_score:.0f}; cleanup_value_score={cleanup_value_score:.0f}"
    )
    if reasons:
        summary += "; " + " | ".join(reason.strip() for reason in reasons[:6] if reason.strip())
    return summary
