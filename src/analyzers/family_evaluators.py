from __future__ import annotations

import re
from datetime import datetime, timezone

from src.windows_software_inventory_analyzer.models import ProgramDecisionContext


def evaluate_context(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    family = context.family_type
    if family == "dotnet_sdk":
        return evaluate_dotnet_sdk(context)
    if family in {"dotnet_runtime", "aspnet_runtime"}:
        return evaluate_runtime_family(context)
    if family == "windows_sdk":
        return evaluate_windows_sdk(context)
    if family == "visual_cpp":
        return evaluate_visual_cpp(context)
    if family == "gpu_driver":
        return evaluate_gpu_driver(context)
    if family == "dotnet_native":
        return evaluate_dotnet_native(context)
    if family == "cache_artifact":
        return evaluate_cache_artifact(context)
    return evaluate_general_app(context)


def evaluate_general_app(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    risk = base_risk(context)
    cleanup = base_cleanup_value(context)
    recoverability = base_recoverability(context)
    reasons: list[str] = []
    if context.project_count > 0:
        risk += 25
        reasons.append(f"{context.project_count} proje ile eslesme var.")
    if is_recently_used(context.last_used_at):
        risk += 20
        reasons.append("Yakin tarihli kullanim izi bulundu.")
    elif context.usage_status == "unknown_usage":
        cleanup += 8
        reasons.append("Otomatik kullanim izi bulunamadi.")
    if context.duplicate_versions:
        cleanup += 14
        reasons.append("Ayni uygulamanin baska surumleri de gorunuyor.")
    if context.related_disk_scenarios:
        cleanup += 8
        reasons.append("Disk alani senaryosu bu aracla baglantili bir alan kazanimina isaret ediyor.")
    if context.project_generated_size_bytes > 0:
        recoverability += 10
        reasons.append("Bagli projelerde yeniden uretilebilir alan bulundu.")

    decision = "MANUAL_REVIEW"
    next_action = "Proje bagini ve son kullanim ihtiyacini gozden gecir."
    if context.project_count == 0 and not is_recently_used(context.last_used_at) and not context.hard_protection:
        decision = "LOWER_RISK_CANDIDATE"
        next_action = "Kaldirmadan once sadece kisa bir manuel kontrol yap."
    if context.hard_protection:
        decision = "KEEP"
        next_action = "Bu aile korumali gorundugu icin kaldirma yerine yerinde birak."
    return finalize(decision, risk, cleanup, recoverability, next_action, reasons, context)


def evaluate_dotnet_sdk(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    risk = max(base_risk(context), 70)
    cleanup = base_cleanup_value(context)
    recoverability = base_recoverability(context)
    reasons: list[str] = []
    has_global_json = any(row.get("global_json_matches", "").strip() for row in context.dotnet_sdk_rows)
    build_statuses = {row.get("build_status", "").strip() for row in context.sdk_validation_rows if row.get("build_status", "").strip()}
    has_build_pass = "BUILD_PASSED" in build_statuses
    has_build_failure = "BUILD_FAILED" in build_statuses or "VALIDATION_FAILED" in build_statuses

    if has_global_json:
        risk = max(risk, 92)
        reasons.append("global.json bu surumu veya bu banda yakin bir surumu istiyor.")
    if context.project_count > 0:
        risk += 10
        reasons.append(f"{context.project_count} .NET proje eslesmesi var.")
    if context.duplicate_versions:
        cleanup += 20
        reasons.append("Ayni SDK ailesinde baska patch surumleri de gorunuyor.")
        recoverability += 8
    if has_build_pass:
        risk -= 10
        cleanup += 10
        recoverability += 12
        reasons.append("Build gecen proje kaydi bulundu.")
    if has_build_failure:
        risk += 8
        reasons.append("Bazi build denemeleri temiz gecmedi.")

    decision = "TEST_FIRST"
    next_action = "Ayni feature band icindeki eski patch'i kaldirmadan once build testini tekrar calistir."
    if has_global_json:
        decision = "KEEP"
        next_action = "global.json gecen SDK kaldirilmamali."
    elif has_build_pass and context.duplicate_versions:
        decision = "LOWER_RISK_CANDIDATE"
        next_action = "Ayni banddeki daha eski patch surumleri kademeli azalt."
    elif has_build_failure:
        decision = "MANUAL_REVIEW"
        next_action = "Build hatasi cozunmeden SDK temizleme yapma."
    return finalize(decision, risk, cleanup, recoverability, next_action, reasons, context)


def evaluate_runtime_family(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    risk = max(base_risk(context), 64)
    cleanup = base_cleanup_value(context)
    recoverability = base_recoverability(context)
    reasons = ["Runtime tarafinda major.minor hatti korunmali."]
    if context.duplicate_versions:
        cleanup += 12
        reasons.append("Ayni runtime hattinda ek surumler gorunuyor.")
    if context.project_count > 0:
        risk += 12
        reasons.append(".NET proje izi bu makinede aktif gorunuyor.")
    if is_recently_used(context.last_used_at):
        risk += 10
        reasons.append("Yakin kullanim izi bulundu.")
    decision = "MANUAL_REVIEW"
    next_action = "Ayni major.minor disindaki surumleri birbiri yerine sayma; uygulama bagimliligi kontrol et."
    if context.duplicate_versions and context.project_count == 0 and not is_recently_used(context.last_used_at):
        decision = "TEST_FIRST"
        next_action = "Ayni hat icindeki daha eski patch surumleri once test ederek degerlendir."
    return finalize(decision, risk, cleanup, recoverability, next_action, reasons, context)


def evaluate_windows_sdk(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    risk = max(base_risk(context), 75)
    cleanup = base_cleanup_value(context) + 8
    recoverability = base_recoverability(context)
    reasons = ["Windows SDK tarafinda surum karsilastirmasi tek basina yeterli degil."]
    if context.project_count > 0 or context.ide_signals:
        risk += 10
        reasons.append("Visual Studio veya Windows hedefli proje sinyali bulundu.")
    if context.duplicate_versions:
        cleanup += 14
        reasons.append("Birden fazla Windows SDK surumu gorunuyor.")
    decision = "TEST_FIRST"
    next_action = "C++/Windows hedefli proje veya IDE acilisi dogrulanmadan eski SDK kaldirma."
    return finalize(decision, risk, cleanup, recoverability, next_action, reasons, context)


def evaluate_visual_cpp(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    risk = max(base_risk(context), 88)
    cleanup = min(base_cleanup_value(context), 18)
    recoverability = min(base_recoverability(context), 20)
    reasons = ["Visual C++ paketleri farkli uygulamalar tarafindan birlikte istenebilir."]
    if context.duplicate_versions:
        reasons.append("Benzer adlar gorunse bile farkli major hatlar ayri gereksinim olabilir.")
    decision = "KEEP"
    next_action = "Bu ailede otomatik temizleme yapma; sadece cok net duplicate durumda elle karar ver."
    return finalize(decision, risk, cleanup, recoverability, next_action, reasons, context)


def evaluate_gpu_driver(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    risk = max(base_risk(context), 90)
    cleanup = min(base_cleanup_value(context), 10)
    recoverability = min(base_recoverability(context), 12)
    reasons = ["Suruculer kaldirma adayi gibi degil, sistem bagimliligi gibi ele alinmali."]
    if context.project_count > 0:
        reasons.append("AI, oyun motoru veya grafik is akislariyla bag olabilir.")
    decision = "KEEP"
    next_action = "Kaldirma yerine resmi surucu araci ile guncelleme veya temiz kurulum dusun."
    return finalize(decision, risk, cleanup, recoverability, next_action, reasons, context)


def evaluate_dotnet_native(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    risk = max(base_risk(context), 78)
    cleanup = min(base_cleanup_value(context) + 4, 34)
    recoverability = min(base_recoverability(context), 25)
    reasons = ["Store veya MSIX uygulamalari bu aileye bagli olabilir."]
    decision = "MANUAL_REVIEW"
    next_action = "Dogrudan kaldirma yerine once Store uygulamalari ve kullanim ihtiyacini kontrol et."
    return finalize(decision, risk, cleanup, recoverability, next_action, reasons, context)


def evaluate_cache_artifact(context: ProgramDecisionContext) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    risk = min(base_risk(context), 28)
    cleanup = max(base_cleanup_value(context), 70)
    recoverability = max(base_recoverability(context), 85)
    reasons = ["Bu kayit yeniden uretilebilir cache/artifact ailesine benziyor."]
    decision = "CACHE_CLEAN_ONLY"
    next_action = "Programi degil, olusan cache klasorlerini temizlemeyi dusun."
    return finalize(decision, risk, cleanup, recoverability, next_action, reasons, context)


def finalize(
    decision: str,
    risk: float,
    cleanup: float,
    recoverability: float,
    next_action: str,
    reasons: list[str],
    context: ProgramDecisionContext,
) -> tuple[str, float, float, float, str, int, str, str, list[str], str, str]:
    duplicate_summary = summarize_duplicates(context)
    test_summary = summarize_tests(context)
    affected_projects_count = context.project_count
    affected_disk_zones = ", ".join(row.get("path", "") for row in context.related_disk_zones[:4]) or "-"
    impact_scope = compute_impact_scope(context, clamp(risk), clamp(cleanup))
    return (
        decision,
        clamp(risk),
        clamp(cleanup),
        clamp(recoverability),
        impact_scope,
        affected_projects_count,
        affected_disk_zones,
        next_action,
        reasons,
        duplicate_summary,
        test_summary,
    )


def summarize_duplicates(context: ProgramDecisionContext) -> str:
    if not context.duplicate_versions:
        return "Ayni ailede ek surum bulunmadi."
    names = ", ".join(candidate.software_name for candidate in context.duplicate_versions[:6])
    return f"Ayni ailede bulunan diger surumler: {names}"


def summarize_tests(context: ProgramDecisionContext) -> str:
    build_statuses = [row.get("build_status", "").strip() for row in context.sdk_validation_rows if row.get("build_status", "").strip()]
    if build_statuses:
        return f"Build kayitlari: {', '.join(sorted(set(build_statuses)))}"
    if context.dotnet_sdk_rows:
        statuses = [row.get("status", "").strip() for row in context.dotnet_sdk_rows if row.get("status", "").strip()]
        if statuses:
            return f"SDK karar kayitlari: {', '.join(sorted(set(statuses)))}"
    return "Ek build/test kaydi yok."


def base_risk(context: ProgramDecisionContext) -> float:
    risk = context.risk_score or 20.0
    if context.hard_protection:
        risk = max(risk, 65.0)
    return risk


def base_cleanup_value(context: ProgramDecisionContext) -> float:
    cleanup = context.cleanup_priority_score or 35.0
    if context.estimated_size:
        cleanup += size_bonus(context.estimated_size)
    return cleanup


def base_recoverability(context: ProgramDecisionContext) -> float:
    if context.family_type == "cache_artifact":
        return 90.0
    recoverability = 20.0
    if context.project_recoverable_ratio:
        recoverability += min(context.project_recoverable_ratio / 2, 35.0)
    if context.related_disk_scenarios:
        reclaimable = max(safe_int(row.get("estimated_reclaim_bytes", "0")) for row in context.related_disk_scenarios)
        if reclaimable >= 10 * 1024**3:
            recoverability += 25.0
        elif reclaimable >= 3 * 1024**3:
            recoverability += 16.0
        elif reclaimable >= 1 * 1024**3:
            recoverability += 8.0
    return recoverability


def compute_impact_scope(context: ProgramDecisionContext, risk: float, cleanup: float) -> str:
    if context.hard_protection or context.project_count >= 3 or risk >= 85:
        return "HIGH"
    if context.project_count > 0 or len(context.related_disk_zones) > 1 or cleanup >= 70:
        return "MEDIUM"
    return "LOW"


def size_bonus(size_human: str) -> float:
    match = re.match(r"([0-9]+(?:\.[0-9]+)?)\s*(TB|GB|MB|KB)", size_human.strip(), flags=re.IGNORECASE)
    if not match:
        return 0.0
    value = float(match.group(1))
    unit = match.group(2).upper()
    if unit == "TB":
        value *= 1024
        unit = "GB"
    if unit == "GB":
        if value >= 10:
            return 18.0
        if value >= 3:
            return 10.0
        if value >= 1:
            return 5.0
    if unit == "MB" and value >= 700:
        return 3.0
    return 0.0


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


def is_recently_used(last_used_at: str) -> bool:
    parsed = parse_iso_datetime(last_used_at)
    if parsed is None:
        return False
    return (datetime.now(timezone.utc) - parsed).days <= 180


def clamp(value: float) -> float:
    return max(0.0, min(100.0, round(value, 2)))


def safe_int(value: str) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0
