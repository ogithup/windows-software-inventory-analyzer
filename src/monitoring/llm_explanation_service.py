from __future__ import annotations


def build_llm_prompt(alert: dict[str, str]) -> str:
    return (
        "Sen bir Windows sistem sagligi ve guvenli temizlik asistanisin.\n"
        "Asagidaki uyariyi teknik olmayan ama dogru bir Turkce ile acikla.\n"
        "Asla 'hemen sil' deme. Temkinli bir dil kullan.\n\n"
        f"Baslik: {alert.get('title', '')}\n"
        f"Aciklama: {alert.get('description', '')}\n"
        f"Seviye: {alert.get('severity', '')}\n"
        f"Kategori: {alert.get('category', '')}\n"
        f"Onerilen islem: {alert.get('recommended_action', '')}\n"
        f"Guven skoru: {alert.get('confidence_score', '')}\n"
    )


def _fallback_explanation(alert: dict[str, str]) -> str:
    severity = alert.get("severity", "low")
    severity_map = {
        "critical": "Bu uyari kritik seviyede; yan etki olusturmadan once nedenini hizli kontrol etmek gerekir.",
        "high": "Bu uyari yuksek onceliklidir; dogrudan silme yerine once kanitlari incelemek daha guvenlidir.",
        "medium": "Bu uyari orta onceliktedir; hemen aksiyon gerektirmeyebilir ama bir sonraki bakim turunda kontrol edilebilir.",
        "low": "Bu uyari bilgilendirme amacli dusuk oncelikli bir sinyaldir.",
    }
    return (
        f"Ne oldu? {alert.get('description', '')}\n\n"
        f"Neden onemli? {severity_map.get(severity, severity_map['low'])}\n\n"
        f"Guvenli ne yapilabilir? {alert.get('recommended_action', '')} "
        "Gerekirse yedek aldiktan sonra degerlendirilebilir ve manuel test onerilir.\n\n"
        f"Risk seviyesi ne demek? '{severity}' seviyesi, bu sinyalin aciliyetini gosterir; "
        "tek basina kesin kaldirma karari anlamina gelmez."
    )


def explain_alert(alert: dict[str, str], llm_client=None) -> str:
    if llm_client is None:
        return _fallback_explanation(alert)
    prompt = build_llm_prompt(alert)
    if callable(llm_client):
        return str(llm_client(prompt))
    if hasattr(llm_client, "generate"):
        return str(llm_client.generate(prompt))
    return _fallback_explanation(alert)

