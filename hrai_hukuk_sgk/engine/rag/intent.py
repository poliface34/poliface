"""Stage 1 QueryIntentAnalyzer & Stage 2 TemporalGate for WP-4.3 RAG Engine."""

from __future__ import annotations

from datetime import date
import re
from typing import Any

from ..knowledge_base.chunker import tr_fold
from ..knowledge_base.models import parse_strict_kb_date
from .models import (
    DOMAIN_LABOR_LAW,
    DOMAIN_MIXED_MULTI_DOMAIN,
    DOMAIN_OCCUPATIONAL_HEALTH_AND_SAFETY,
    DOMAIN_OUT_OF_DOMAIN,
    DOMAIN_PAYROLL_DELEGATION_ONLY,
    DOMAIN_PERSONAL_DATA_PROTECTION,
    DOMAIN_SOCIAL_SECURITY,
    INTENT_FACT_SCENARIO_ANALYSIS,
    INTENT_OUT_OF_DOMAIN,
    INTENT_PAYROLL_DELEGATION_ONLY,
    INTENT_PRECEDENT_CHECK,
    INTENT_PROCEDURE_AND_AUTONOMOUS_NORM,
    INTENT_STATUTE_LOOKUP,
    QueryIntentAnalysis,
    SubQuerySpec,
    TemporalAuditReport,
)

_ISO_DATE_FIND_RE = re.compile(r"\b((?:19|20)\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b")
_TR_DATE_FIND_RE = re.compile(r"(?<![\d.])(0?[1-9]|[12]\d|3[01])[./](0?[1-9]|1[0-2])[./]((?:19|20)\d{2})\b")
_LAW_NO_FIND_RE = re.compile(r"\b(4857|1475|5510|6098|6331|6698|7036|6356|4447|7555|7566|10766|9368|193|488|5746|4691|2004|332|331|319)\b")
_ARTICLE_FIND_RE = re.compile(r"\b(?:m\.|madde\s*)(\d+(?:/[ivxlcdm]+(?:-[a-zçğıöşü])?)?)", re.IGNORECASE)
_CASE_NO_FIND_RE = re.compile(r"\b(\d{4}/\d+)\b")
_SGK_CODE_FIND_RE = re.compile(r"\bkod\s*(\d{1,2})\b", re.IGNORECASE)

# Auditable, strictly curated legal alias table (never fabricates ungrounded statute numbers)
CONTROLLED_LEGAL_ALIASES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("ihbar öneli", "4857 madde 17 bildirim süresi", ("4857",)),
    ("kıdem tazminatı", "1475 madde 14 kıdem tazminatı hak kazanma", ("1475", "4857")),
    ("biyometrik pdks", "6698 kvkk madde 6 7499 parmak izi ölçülülük", ("6698",)),
    ("spek tavan", "5510 madde 82 7566 9 kat prime esas kazanç", ("5510", "7566")),
    ("pek tavan", "5510 madde 82 7566 9 kat prime esas kazanç", ("5510", "7566")),
    ("bayram ikramiyesi", "4857 madde 22 işyeri uygulaması esaslı değişiklik yazılı rıza", ("4857",)),
    ("işyeri uygulaması", "4857 madde 22 esaslı değişiklik yazılı rıza", ("4857",)),
    ("kep ile", "4857 madde 109 7555 yazılı fesih bildirimi", ("4857", "7555")),
    ("kep fesih", "4857 madde 109 7555 yazılı fesih bildirimi", ("4857", "7555")),
    ("güveni kötüye kullanma", "4857 m.25/II-e ahlak iyi niyet", ("4857",)),
    ("6 iş günü", "4857 madde 26 hak düşürücü süre arife cumartesi", ("4857",)),
    ("altı iş günü", "4857 madde 26 hak düşürücü süre arife cumartesi", ("4857",)),
    ("iş kazası bildirimi", "6331 madde 14 5510 madde 13 3 iş günü", ("6331", "5510")),
    ("sgk çıkış kodu", "5510 madde 102 SGK genelge 2020/20", ("5510",)),
    ("sağlık raporu sebebiyle", "4857 m.25/I-b savunma 6698 madde 6 sağlık verisi", ("4857", "6698")),
    ("yemek istisnası", "GIB-TEBLIG-332-20251231 332 tebliğ yemek istisnası", ("332",)),
    ("uzaktan çalışma", "10766 9368 uzaktan çalışma oranları yönetmelik", ("10766",)),
    ("fazla çalışma", "4857 madde 41 yıllık 270 saat fazla mesai", ("4857",)),
    ("yıllık izin", "4857 madde 53 yıllık ücretli izin süreleri", ("4857",)),
    ("dinlenme hakkı", "4857 yıllık ücretli izin hafta tatili madde 53 anayasa m.11", ("4857",)),
    ("norm hiyerarşisi", "anayasa m.11 uluslararası antlaşma 4857 yıllık ücretli izin", ("4857",)),
    ("arabuluculuk", "7036 madde 3 iş mahkemeleri 4857 fesih", ("7036", "4857")),
    ("2020/20", "SGK-GENELGE-2020-20 5510 m.80 yemek yol SPEK", ("5510", "2020/20")),
    ("ikramiye", "4857 madde 22 işyeri uygulaması esaslı değişiklik yazılı rıza", ("4857",)),
    ("adli sicil", "6698 kvkk madde 6 7499 adli sicil ölçülülük", ("6698",)),
    ("fazla çalışma yönetmeliği", "YONETMELIK-FAZLA-CALISMA-20040406 CARD-YON-FAZLA-CALISMA 4857 m.41 m.7 m.9", ("4857",)),
    ("yönetmelik m.7", "YONETMELIK-FAZLA-CALISMA-20040406 CARD-YON-FAZLA-CALISMA madde 7 4857 m.41 m.69", ("4857",)),
    ("ssiy", "YONETMELIK-SSIY-20100512 CARD-SSIY-M11-M14 5510 madde 8 madde 9 işten ayrılış", ("5510",)),
)

_OUT_OF_DOMAIN_LITIGATION_PHRASES: tuple[str, ...] = (
    "dava dilekçesi",
    "dava dilekçesini",
    "cevap dilekçesi",
    "istinaf dilekçesi",
    "temyiz dilekçesi",
    "dilekçesini tam yaz",
    "dilekçesini eksiksiz yaz",
    "mahkemeye verilecek dava dilekçesi",
)
_OUT_OF_DOMAIN_SUBJECT_PHRASES: tuple[str, ...] = (
    "şirket birleşme",
    "hisse devri sözleşmesi",
    "pay devri sözleşmesi",
    "boşanma davası",
    "velayet",
    "nafaka",
    "miras paylaşımı",
    "ceza davası",
    "ağır ceza",
    "kira tahliye",
    "kat mülkiyeti",
)
_PAYROLL_CALC_TRIGGERS: tuple[str, ...] = (
    "kaç tl",
    "kaç lira",
    "net ne kadar",
    "brüt ne kadar",
    "hesapla",
    "hesaplaması nedir",
    "tazminat tutarı nedir",
)
_PAYROLL_EXCLUSION_HINTS: tuple[str, ...] = (
    "tebliğ",
    "dilimleri",
    "tarife",
    "istisna",
    "tavan",
    "işçi sayısı",
    "30 işçi",
    "sayısı nasıl",
    "hak düşürücü",
    "izin süresi",
    "çalışma süresi",
)
_PRECEDENT_HINTS: tuple[str, ...] = (
    "yargıtay",
    "danıştay",
    "yibbgk",
    "hgk",
    "içtihat",
    "içtihadı birleştirme",
    "iddk",
    "karararama",
    "daire kararı",
    "2017/9",
    "2018/10",
    "2017/10",
    "2019/1",
    "2017/8",
    "2019/3",
    "2023/1",
    "2025/3",
    "2021/8",
    "2026/1",
)
_AUTONOMOUS_NORM_HINTS: tuple[str, ...] = (
    "prosedür",
    "prosedürü",
    "tis",
    "toplu iş sözleşmesi",
    "iç yönetmelik",
    "personel yönetmeliği",
    "işyeri uygulaması",
    "l5",
    "l6",
    "bireysel iş sözleşmesi",
    "şablon",
)
_SCENARIO_ACTION_HINTS: tuple[str, ...] = (
    "fesih",
    "feshinde",
    "yaptık",
    "geçerli mi",
    "geçerliliği",
    "geçti mi",
    "doldu mu",
    "çalışan hakkında",
    "işçi hakkında",
    "işten çıkar",
    "işten çıkarma",
    "çıkardık",
    "savunma",
    "bildirim",
    "bildirimi",
    "kestik",
    "kaldırdık",
    "süresi doldu",
    "ödenir mi",
    "hak kazanır mı",
    "tazminat öder mi",
)

_LABOR_HINTS: tuple[str, ...] = (
    "4857",
    "1475",
    "6098",
    "6356",
    "7036",
    "iş kanunu",
    "fesih",
    "işten çıkar",
    "işe iade",
    "kıdem",
    "ihbar",
    "savunma",
    "fazla çalışma",
    "fazla mesai",
    "yıllık izin",
    "ikramiye",
    "işyeri uygulaması",
    "kep",
    "arife",
    "iş günü",
    "esaslı değişiklik",
    "uzaktan çalışma",
    "alt işveren",
    "ceza koşulu",
    "cezai şart",
    "ibra",
    "10766",
    "9368",
    "332",
    "331",
    "319",
    "yemek istisnası",
    "tbk",
    "dinlenme hakkı",
    "norm hiyerarşisi",
    "anayasa madde 50",
    "anayasa m.50",
    "uluslararası antlaşma",
    "ilo",
    "arabuluculuk",
)
_SGK_HINTS: tuple[str, ...] = (
    "5510",
    "4447",
    "7566",
    "ssiy",
    "sgk",
    "spek",
    "pek",
    "prime esas",
    "çıkış kodu",
    "kod 29",
    "kod 46",
    "işsizlik",
    "teşvik",
    "idari para cezası",
    "ipc",
    "iş kazası bildirimi",
    "e-vizite",
    "2020/20",
    "2026/1",
)
_OHS_HINTS: tuple[str, ...] = (
    "6331",
    "isg",
    "iş sağlığı",
    "iş güvenliği",
    "iş kazası",
    "meslek hastalığı",
    "işyeri hekimi",
    "iş güvenliği uzmanı",
    "risk değerlendirmesi",
    "ramak kala",
)
_KVKK_HINTS: tuple[str, ...] = (
    "6698",
    "kvkk",
    "kişisel veri",
    "özel nitelikli",
    "sağlık verisi",
    "biyometrik",
    "parmak izi",
    "yüz tanıma",
    "pdks",
    "adli sicil",
    "özlük dosyası",
    "aydınlatma",
    "yurt dışı aktarım",
    "kamera izleme",
)


class QueryIntentAnalyzer:
    """Deterministic Stage 1 analyzer classifying intent, legal domain, entities, and controlled aliases."""

    def analyze(self, query_text: str) -> QueryIntentAnalysis:
        clean = (query_text or "").strip()
        q_fold = tr_fold(clean)

        extracted_laws = tuple(dict.fromkeys(_LAW_NO_FIND_RE.findall(q_fold)))
        extracted_articles = tuple(dict.fromkeys(m.lower() for m in _ARTICLE_FIND_RE.findall(q_fold)))
        extracted_cases = tuple(
            dict.fromkeys(
                c_no
                for c_no in _CASE_NO_FIND_RE.findall(q_fold)
                if not re.search(
                    rf"(?:sgk[\s\-]+(?:genelge\s*)?{re.escape(c_no)}|{re.escape(c_no)}\s*(?:sayılı\s*)?genelge)",
                    q_fold,
                )
            )
        )
        extracted_sgk_codes = tuple(dict.fromkeys(_SGK_CODE_FIND_RE.findall(q_fold)))

        # 1. Check strict Out-of-Domain / Av. K. m.35 Petition Boundaries FIRST
        out_reason: str | None = None
        for phrase in _OUT_OF_DOMAIN_LITIGATION_PHRASES:
            if phrase in q_fold:
                out_reason = f"PETITION_DRAFTING_OUT_OF_AUTHORITY_AV_K_M35:{phrase}"
                break
        if out_reason is None:
            for phrase in _OUT_OF_DOMAIN_SUBJECT_PHRASES:
                if phrase in q_fold:
                    out_reason = f"NON_HR_LEGAL_DOMAIN:{phrase}"
                    break
        if out_reason is None and "dilekçe" in q_fold and any(w in q_fold for w in ("tam yaz", "eksiksiz yaz", "hazırla", "mahkemeye")):
            out_reason = "PETITION_DRAFTING_OUT_OF_AUTHORITY_AV_K_M35:dilekçe"

        if out_reason is not None:
            return QueryIntentAnalysis(
                intent=INTENT_OUT_OF_DOMAIN,
                primary_domain=DOMAIN_OUT_OF_DOMAIN,
                secondary_domains=(),
                extracted_entities={
                    "law_nos": list(extracted_laws),
                    "article_refs": list(extracted_articles),
                    "case_nos": list(extracted_cases),
                    "sgk_codes": list(extracted_sgk_codes),
                    "matched_aliases": [],
                    "out_of_domain_reason": out_reason,
                },
                sub_queries=(),
                rewritten_query_text=clean,
            )

        # 2. Match domains
        matched_domains: list[str] = []
        if any(h in q_fold for h in _LABOR_HINTS) or any(l in {"4857", "1475", "6098", "6356", "7036", "7555", "10766", "9368", "332", "331", "319", "193", "488"} for l in extracted_laws):
            matched_domains.append(DOMAIN_LABOR_LAW)
        if any(h in q_fold for h in _SGK_HINTS) or any(l in {"5510", "4447", "7566"} for l in extracted_laws):
            matched_domains.append(DOMAIN_SOCIAL_SECURITY)
        has_ohs = any(h in q_fold for h in _OHS_HINTS) or ("6331" in extracted_laws)
        has_sağlık_raporu_case = "sağlık raporu" in q_fold and any(w in q_fold for w in ("işten çıkar", "fesih", "iş kazası", "kvkk", "sgk"))
        if has_ohs or has_sağlık_raporu_case:
            matched_domains.append(DOMAIN_OCCUPATIONAL_HEALTH_AND_SAFETY)
        if any(h in q_fold for h in _KVKK_HINTS) or ("6698" in extracted_laws) or has_sağlık_raporu_case:
            matched_domains.append(DOMAIN_PERSONAL_DATA_PROTECTION)

        def _has_auto_hint(token: str) -> bool:
            if token in {"tis", "l5", "l6"}:
                return bool(re.search(rf"(?<![a-zçğıöşü0-9]){re.escape(token)}(?![a-zçğıöşü0-9])", q_fold))
            return token in q_fold

        # Fallback if a valid HR/SGK precedent or autonomous query didn't list numeric law tokens
        if not matched_domains:
            if any(h in q_fold for h in _PRECEDENT_HINTS) or extracted_cases or any(_has_auto_hint(h) for h in _AUTONOMOUS_NORM_HINTS):
                matched_domains.append(DOMAIN_LABOR_LAW)

        # 3. Intent classification
        has_payroll_calc = any(t in q_fold for t in _PAYROLL_CALC_TRIGGERS) and not any(ex in q_fold for ex in _PAYROLL_EXCLUSION_HINTS)
        has_precedent = bool(extracted_cases) or any(h in q_fold for h in ("yargıtay", "danıştay", "yibbgk", "hgk", "içtihat", "içtihadı", "iddk", "karararama", "aym"))
        has_autonomous = any(_has_auto_hint(h) for h in _AUTONOMOUS_NORM_HINTS)
        has_concrete_event = any(h in q_fold for h in _SCENARIO_ACTION_HINTS if h != "geçerli mi") or (
            "geçerli mi" in q_fold and "geçerli midir" not in q_fold
        )
        has_scenario = has_concrete_event
        has_lookup_verb = any(
            w in q_fold
            for w in (
                "nedir",
                "hükmü",
                "hükümleri",
                "metni",
                "dilimleri",
                "oranları",
                "yürürlük",
                "nelerdir",
                "tebliğ",
                "geçerli midir",
                "uygulanır mı",
                "zorunlu mudur",
                "aktarabilir miyiz",
            )
        )

        if has_payroll_calc:
            intent = INTENT_PAYROLL_DELEGATION_ONLY
            primary_domain = DOMAIN_PAYROLL_DELEGATION_ONLY
            secondary_domains = tuple(matched_domains)
        elif has_precedent and (extracted_cases or not has_scenario or "içtihat" in q_fold or "danıştay" in q_fold or "yargıtay" in q_fold):
            intent = INTENT_PRECEDENT_CHECK
            primary_domain = DOMAIN_MIXED_MULTI_DOMAIN if len(matched_domains) >= 2 else (matched_domains[0] if matched_domains else DOMAIN_LABOR_LAW)
            secondary_domains = tuple(matched_domains) if len(matched_domains) >= 2 else ()
        elif has_autonomous and not has_ohs and len(matched_domains) <= 1 and not (has_lookup_verb and (extracted_articles or extracted_laws)):
            intent = INTENT_PROCEDURE_AND_AUTONOMOUS_NORM
            primary_domain = matched_domains[0] if matched_domains else DOMAIN_LABOR_LAW
            secondary_domains = ()
        elif not matched_domains and len(extracted_laws) == 0:
            return QueryIntentAnalysis(
                intent=INTENT_OUT_OF_DOMAIN,
                primary_domain=DOMAIN_OUT_OF_DOMAIN,
                secondary_domains=(),
                extracted_entities={
                    "law_nos": [],
                    "article_refs": [],
                    "case_nos": [],
                    "sgk_codes": [],
                    "matched_aliases": [],
                    "out_of_domain_reason": "NO_RECOGNIZED_HR_SGK_DOMAIN",
                },
                sub_queries=(),
                rewritten_query_text=clean,
            )
        elif has_lookup_verb and not has_concrete_event:
            intent = INTENT_STATUTE_LOOKUP
            primary_domain = DOMAIN_MIXED_MULTI_DOMAIN if len(matched_domains) >= 2 else matched_domains[0]
            secondary_domains = tuple(matched_domains) if len(matched_domains) >= 2 else ()
        elif has_scenario:
            intent = INTENT_FACT_SCENARIO_ANALYSIS
            primary_domain = DOMAIN_MIXED_MULTI_DOMAIN if len(matched_domains) >= 2 else matched_domains[0]
            secondary_domains = tuple(matched_domains) if len(matched_domains) >= 2 else ()
        elif len(matched_domains) >= 2 and any(w in q_fold for w in ("çıkarma", "fesih", "bildirim", "kodu", "iş kazası", "pdks", "rapor")) and "uygulanır mı" not in q_fold:
            intent = INTENT_FACT_SCENARIO_ANALYSIS
            primary_domain = DOMAIN_MIXED_MULTI_DOMAIN
            secondary_domains = tuple(matched_domains)
        elif extracted_laws or extracted_articles:
            intent = INTENT_STATUTE_LOOKUP
            primary_domain = DOMAIN_MIXED_MULTI_DOMAIN if len(matched_domains) >= 2 else matched_domains[0]
            secondary_domains = tuple(matched_domains) if len(matched_domains) >= 2 else ()
        else:
            intent = INTENT_FACT_SCENARIO_ANALYSIS
            primary_domain = DOMAIN_MIXED_MULTI_DOMAIN if len(matched_domains) >= 2 else matched_domains[0]
            secondary_domains = tuple(matched_domains) if len(matched_domains) >= 2 else ()

        # 4. Controlled alias expansion
        matched_aliases: list[str] = []
        expansion_terms: list[str] = []
        alias_laws: list[str] = []
        for phrase, expansion, law_hints in CONTROLLED_LEGAL_ALIASES:
            if phrase in q_fold:
                matched_aliases.append(f"{phrase} -> {expansion}")
                expansion_terms.append(expansion)
                alias_laws.extend(law_hints)

        rewritten = clean if not expansion_terms else f"{clean} {' '.join(expansion_terms)}"

        # 5. Sub-query decomposition for mixed domains
        sub_queries: list[SubQuerySpec] = []
        if primary_domain == DOMAIN_MIXED_MULTI_DOMAIN:
            domain_specs = {
                DOMAIN_LABOR_LAW: ("4857 iş kanunu fesih savunma yazılılık kıdem", ("4857", "1475")),
                DOMAIN_SOCIAL_SECURITY: ("5510 sgk iş kazası bildirimi çıkış kodu prime esas", ("5510", "4447")),
                DOMAIN_OCCUPATIONAL_HEALTH_AND_SAFETY: ("6331 iş sağlığı güvenliği iş kazası 3 iş günü", ("6331",)),
                DOMAIN_PERSONAL_DATA_PROTECTION: ("6698 kvkk madde 6 özel nitelikli sağlık verisi ölçülülük", ("6698",)),
            }
            for dom in secondary_domains:
                hint_txt, law_tuple = domain_specs.get(dom, (clean, ()))
                sub_queries.append(
                    SubQuerySpec(
                        domain=dom,
                        query_text=f"{clean} {hint_txt}",
                        law_nos=law_tuple,
                    )
                )

        return QueryIntentAnalysis(
            intent=intent,
            primary_domain=primary_domain,
            secondary_domains=secondary_domains,
            extracted_entities={
                "law_nos": list(dict.fromkeys([*extracted_laws, *alias_laws])),
                "article_refs": list(extracted_articles),
                "case_nos": list(extracted_cases),
                "sgk_codes": list(extracted_sgk_codes),
                "matched_aliases": matched_aliases,
                "has_payroll_calculation_request": has_payroll_calc,
                "out_of_domain_reason": None,
            },
            sub_queries=tuple(sub_queries),
            rewritten_query_text=rewritten,
        )


class TemporalGate:
    """Stage 2 strict `as_of_date` extraction/validation & cutoff detection (never defaults to today)."""

    def evaluate(self, query_text: str, *, as_of_date: str | None) -> TemporalAuditReport:
        clean = query_text or ""
        found_candidates = self._extract_dates_from_text(clean)

        if as_of_date is not None:
            raw_date = as_of_date.strip() if isinstance(as_of_date, str) else ""
            if not raw_date:
                return TemporalAuditReport(
                    as_of_date=None,
                    date_source="MISSING",
                    date_valid=False,
                    candidate_dates_found=found_candidates,
                    error_code="MISSING_AS_OF_DATE",
                )
            try:
                parse_strict_kb_date(raw_date, "as_of_date")
            except Exception:
                return TemporalAuditReport(
                    as_of_date=None,
                    date_source="INVALID",
                    date_valid=False,
                    candidate_dates_found=found_candidates,
                    error_code="MISSING_OR_INVALID_ISO_DATE",
                )
            return TemporalAuditReport(
                as_of_date=raw_date,
                date_source="EXPLICIT_PARAMETER",
                date_valid=True,
                candidate_dates_found=found_candidates,
                cutoff_flags=self._detect_cutoffs(raw_date),
                error_code=None,
            )

        # No explicit as_of_date -> extract unambiguous full calendar date from query_text ONLY
        if len(found_candidates) == 1:
            extracted = found_candidates[0]
            return TemporalAuditReport(
                as_of_date=extracted,
                date_source="EXTRACTED_FROM_QUERY",
                date_valid=True,
                candidate_dates_found=found_candidates,
                cutoff_flags=self._detect_cutoffs(extracted),
                error_code=None,
            )

        if len(found_candidates) > 1:
            return TemporalAuditReport(
                as_of_date=None,
                date_source="AMBIGUOUS_MULTIPLE_DATES",
                date_valid=False,
                candidate_dates_found=found_candidates,
                error_code="AMBIGUOUS_MULTIPLE_DATES",
            )

        return TemporalAuditReport(
            as_of_date=None,
            date_source="MISSING",
            date_valid=False,
            candidate_dates_found=(),
            error_code="MISSING_AS_OF_DATE",
        )

    @staticmethod
    def _extract_dates_from_text(text: str) -> tuple[str, ...]:
        candidates: list[str] = []
        for y, m, d in _ISO_DATE_FIND_RE.findall(text):
            try:
                iso = date(int(y), int(m), int(d)).isoformat()
                if iso not in candidates:
                    candidates.append(iso)
            except ValueError:
                continue
        for d, m, y in _TR_DATE_FIND_RE.findall(text):
            try:
                iso = date(int(y), int(m), int(d)).isoformat()
                if iso not in candidates:
                    candidates.append(iso)
            except ValueError:
                continue
        return tuple(candidates)

    @staticmethod
    def _detect_cutoffs(iso_date: str) -> tuple[str, ...]:
        flags: list[str] = []
        if iso_date >= "2025-07-24":
            flags.append("POST_7555_M109_WRITTEN_TERMINATION_2025_07_24")
        else:
            flags.append("PRE_7555_OLD_M109_REGIME")
        if iso_date >= "2024-06-01":
            flags.append("POST_7499_KVKK_M6_REGIME_2024_06_01")
        else:
            flags.append("PRE_7499_KVKK_M6_REGIME")
        if iso_date >= "2026-01-01":
            flags.append("POST_7566_9X_SPEK_AND_10766_CK_2026_01_01")
        else:
            flags.append("PRE_2026_7_5X_SPEK_AND_9368_CK_REGIME")
        year = int(iso_date[:4])
        if 2024 <= year <= 2027:
            flags.append("IN_2024_2027_ARCHIVED_HOLIDAY_CALENDAR")
        else:
            flags.append("OUTSIDE_2024_2027_CALENDAR_COVERAGE")
        return tuple(flags)
