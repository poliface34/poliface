"""Hierarchy-preserving Turkish legal structural chunker (WP-4.2).

Enforces NO blind fixed-token / mid-sentence sliding-window cuts:
  - Preserves Madde -> Fıkra -> Bent boundaries.
  - When a long paragraph contains multiple clauses (`a)`, `b)`, ...) and exceeds `max_paragraph_words`,
    each clause chunk retains the introductory paragraph stem (`giriş cümlesi`) so statutory conditions
    are never orphaned.
  - Emits separate, typed chunks for statutory text (`STATUTORY_PARAGRAPH`), legal interpretation/exceptions
    (`RULE_AND_EXCEPTION`), abstention/escalation limits (`ABSTENTION_BOUNDARY`), and judicial precedents
    (`PRECEDENT_UNIT` explicitly marked `İÇTİHAT — KANUN DEĞİL`).
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from .models import (
    CHUNK_KIND_ABSTENTION_BOUNDARY,
    CHUNK_KIND_AUTONOMOUS_RULE_UNIT,
    CHUNK_KIND_PRECEDENT_UNIT,
    CHUNK_KIND_RULE_AND_EXCEPTION,
    CHUNK_KIND_STATUTORY_PARAGRAPH,
    DOC_KIND_AUTONOMOUS_NORM,
    DOC_KIND_JUDICIAL_PRECEDENT,
    InterpretationAndBoundaryRule,
    JudicialPrecedentNode,
    LegalProvisionNode,
    LegalSearchChunk,
    canonical_kb_sha256,
)

DEFAULT_LOCAL_EMBEDDING_DIM = 256
POSTGRES_DEFAULT_EMBEDDING_DIM = 1024

_TR_FOLD_MAP = str.maketrans(
    {
        "İ": "i",
        "I": "ı",
        "Ç": "ç",
        "Ğ": "ğ",
        "Ö": "ö",
        "Ş": "ş",
        "Ü": "ü",
    }
)
_WORD_RE = re.compile(r"[a-zçğıöşü0-9]+(?:[./-][a-zçğıöşü0-9]+)*", re.IGNORECASE)
_FIKRA_START_RE = re.compile(r"(?:^|\n)\s*(?:\((\d+)\)|([IVXLCDM]+)\s*[-–.])\s+", re.MULTILINE)
_BENT_START_RE = re.compile(r"(?:^|\n)\s*([a-zçğıöşü])\)\s+", re.MULTILINE)


def tr_fold(text: str) -> str:
    return text.translate(_TR_FOLD_MAP).lower()


def tokenize_legal_text(text: str) -> list[str]:
    return [tok for tok in _WORD_RE.findall(tr_fold(text)) if len(tok) >= 2]


def compute_deterministic_embedding(text: str, *, dim: int = DEFAULT_LOCAL_EMBEDDING_DIM) -> tuple[float, ...]:
    """Build a deterministic L2-normalized signed feature-hashing vector in pure Python stdlib."""
    if dim <= 0:
        raise ValueError("embedding boyutu pozitif olmalıdır.")
    vec = [0.0] * dim
    tokens = tokenize_legal_text(text)
    if not tokens:
        return tuple(vec)

    features: list[str] = list(tokens)
    for tok in tokens:
        if len(tok) >= 4:
            for idx in range(len(tok) - 2):
                features.append(f"3g:{tok[idx:idx+3]}")
    for i in range(len(tokens) - 1):
        features.append(f"2w:{tokens[i]}_{tokens[i+1]}")

    for feat in features:
        digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
        h = int.from_bytes(digest, "big")
        bucket = h % dim
        sign = 1.0 if ((h >> 63) & 1) == 0 else -1.0
        weight = 1.5 if not feat.startswith("3g:") else 0.45
        vec[bucket] += sign * weight

    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return tuple(vec)
    return tuple(round(v / norm, 6) for v in vec)


def _split_paragraphs_preserving_structure(raw_text: str) -> list[tuple[str | None, str]]:
    """Split Turkish statutory article text into explicit `(paragraph_label, text)` units."""
    clean = raw_text.strip()
    if not clean:
        return []

    matches = list(_FIKRA_START_RE.finditer(clean))
    if not matches:
        blocks = [blk.strip() for blk in re.split(r"\n{2,}", clean) if blk.strip()]
        return [(f"p{idx + 1}", blk) for idx, blk in enumerate(blocks)]

    units: list[tuple[str | None, str]] = []
    preamble = clean[: matches[0].start()].strip()
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(clean)
        label_num = m.group(1) or m.group(2)
        seg = clean[start:end].strip()
        if i == 0 and preamble:
            seg = f"{preamble}\n{seg}"
        units.append((f"f-{label_num}", seg))
    return units


def _split_long_paragraph_by_clauses(
    paragraph_label: str | None,
    paragraph_text: str,
    *,
    max_words: int,
) -> list[tuple[str | None, str | None, str]]:
    """If a paragraph with `a)`, `b)`, ... clauses exceeds `max_words`, split cleanly per clause keeping its stem."""
    words = paragraph_text.split()
    if len(words) <= max_words:
        return [(paragraph_label, None, paragraph_text)]

    bent_matches = list(_BENT_START_RE.finditer(paragraph_text))
    if len(bent_matches) < 2:
        # Keep cohesive long prose whole rather than blind mid-sentence cuts
        return [(paragraph_label, None, paragraph_text)]

    stem = paragraph_text[: bent_matches[0].start()].strip()
    clauses: list[tuple[str | None, str | None, str]] = []
    for i, m in enumerate(bent_matches):
        c_start = m.start()
        c_end = bent_matches[i + 1].start() if i + 1 < len(bent_matches) else len(paragraph_text)
        bent_letter = m.group(1)
        clause_body = paragraph_text[c_start:c_end].strip()
        combined = f"{stem}\n{clause_body}".strip() if stem else clause_body
        clauses.append((paragraph_label, f"b-{bent_letter}", combined))
    return clauses


def _chunk_sha256_payload(
    *,
    provision_id: str,
    document_version_id: str,
    chunk_kind: str,
    context_header: str,
    raw_text: str,
    effective_from: str,
    effective_to: str | None,
    content_sha256: str,
) -> str:
    return canonical_kb_sha256(
        {
            "provision_id": provision_id,
            "document_version_id": document_version_id,
            "chunk_kind": chunk_kind,
            "context_header": context_header,
            "raw_text": raw_text,
            "effective_from": effective_from,
            "effective_to": effective_to,
            "content_sha256": content_sha256,
        }
    )


class LegalStructuralChunker:
    """Hierarchy-aware deterministic chunker for Turkish statutory texts, rules, abstention gates, and precedents."""

    def __init__(
        self,
        *,
        max_paragraph_words: int = 350,
        embedding_dim: int = DEFAULT_LOCAL_EMBEDDING_DIM,
    ) -> None:
        if max_paragraph_words < 40:
            raise ValueError("max_paragraph_words çok küçük olamaz (en az 40).")
        self.max_paragraph_words = max_paragraph_words
        self.embedding_dim = embedding_dim

    def chunk_provision(
        self,
        provision: LegalProvisionNode,
        *,
        content_verified: bool = True,
    ) -> list[LegalSearchChunk]:
        """Convert a hierarchical provision node into atomic paragraph/clause chunks with full parent headers."""
        if provision.paragraph_no is not None or provision.subparagraph_no is not None:
            raw_parts: list[tuple[str | None, str | None, str]] = [
                (provision.paragraph_no, provision.subparagraph_no, provision.raw_text.strip())
            ]
        else:
            raw_parts = []
            for p_lbl, p_txt in _split_paragraphs_preserving_structure(provision.raw_text):
                raw_parts.extend(
                    _split_long_paragraph_by_clauses(p_lbl, p_txt, max_words=self.max_paragraph_words)
                )

        eff_to_lbl = provision.effective_to or "GÜNCEL"
        chunks: list[LegalSearchChunk] = []
        for idx, (p_lbl, b_lbl, body_text) in enumerate(raw_parts):
            loc_parts = [f"K: {provision.law_no}", f"M: {provision.article_no}"]
            if p_lbl:
                loc_parts.append(f"F: {p_lbl}")
            if b_lbl:
                loc_parts.append(f"B: {b_lbl}")
            loc_parts.append(f"Katman: {provision.norm_layer}")
            loc_parts.append(f"Yürürlük: {provision.effective_from}..{eff_to_lbl}")
            context_header = f"[{' | '.join(loc_parts)}] {provision.article_title}".strip()

            full_text = f"{context_header}\n{body_text}"
            sub_id = ":".join(part for part in (provision.provision_id, p_lbl or f"u{idx}", b_lbl) if part)
            chunk_kind = (
                CHUNK_KIND_AUTONOMOUS_RULE_UNIT
                if provision.document_kind == DOC_KIND_AUTONOMOUS_NORM
                else CHUNK_KIND_STATUTORY_PARAGRAPH
            )
            chunk_sha = _chunk_sha256_payload(
                provision_id=provision.provision_id,
                document_version_id=provision.document_version_id,
                chunk_kind=chunk_kind,
                context_header=context_header,
                raw_text=body_text,
                effective_from=provision.effective_from,
                effective_to=provision.effective_to,
                content_sha256=provision.content_sha256,
            )
            chunk_id = f"CHK-PROV-{canonical_kb_sha256({'sub_id': sub_id, 'sha': chunk_sha})[:16].upper()}"
            chunks.append(
                LegalSearchChunk(
                    chunk_id=chunk_id,
                    provision_id=provision.provision_id,
                    document_version_id=provision.document_version_id,
                    source_id=provision.source_id,
                    evidence_id=provision.evidence_id,
                    document_kind=provision.document_kind,
                    chunk_kind=chunk_kind,
                    norm_layer=provision.norm_layer,
                    norm_priority=provision.norm_priority,
                    law_no=provision.law_no,
                    article_no=provision.article_no,
                    effective_from=provision.effective_from,
                    effective_to=provision.effective_to,
                    verification_status=provision.verification_status,
                    content_verified=content_verified,
                    adoption_status=provision.adoption_status,
                    content_sha256=provision.content_sha256,
                    raw_text=body_text,
                    context_header=context_header,
                    chunk_sha256=chunk_sha,
                    embedding=compute_deterministic_embedding(
                        f"{full_text} {' '.join(provision.keywords)}",
                        dim=self.embedding_dim,
                    ),
                    metadata={
                        "hierarchy_path": provision.hierarchy_path,
                        "paragraph_no": p_lbl,
                        "subparagraph_no": b_lbl,
                        "norm_character": provision.norm_character,
                        "cross_reference_ids": list(provision.cross_reference_ids),
                        "transitional_provision_ref": provision.transitional_provision_ref,
                        "keywords": list(provision.keywords),
                        "source_url": provision.source_url,
                    },
                )
            )
        return chunks

    def chunk_interpretation_rule(
        self,
        rule: InterpretationAndBoundaryRule,
        *,
        law_no: str,
        article_no: str,
        norm_layer: str,
        norm_priority: int,
        document_kind: str,
        content_verified: bool = True,
        evidence_id: str | None = None,
        extra_keywords: tuple[str, ...] = (),
    ) -> list[LegalSearchChunk]:
        """Emit distinct RULE_AND_EXCEPTION and ABSTENTION_BOUNDARY chunks anchored to `rule.provision_id`."""
        eff_to_lbl = rule.effective_to or "GÜNCEL"
        chunks: list[LegalSearchChunk] = []

        # 1. Yorum, İstisnalar, Geçiş Kuralları ve Karşı Görüş Tuzakları
        rule_lines: list[str] = [f"Konu: {rule.topic}"]
        for sc in rule.how_to_interpret:
            rule_lines.append(
                f"Uygulama ({sc.get('scenario_id', 'GENEL')}): Koşul={sc.get('condition', '')} -> "
                f"Kural={sc.get('legal_rule', '')} ({sc.get('statutory_basis', '')})"
            )
        for exc in rule.exceptions:
            rule_lines.append(f"İstisna: {exc}")
        for tr in rule.transitional_rules:
            rule_lines.append(
                f"Geçiş ({tr.get('cutoff_date', '')}): Öncesi={tr.get('pre_cutoff_rule', '')} | "
                f"Sonrası={tr.get('post_cutoff_rule', '')}"
            )
        for pit in rule.counter_arguments_and_pitfalls:
            rule_lines.append(f"Karşı Görüş / Tuzak: {pit}")
        for doc in rule.required_documents:
            rule_lines.append(f"Gerekli Belge: {doc}")

        rule_body = "\n".join(rule_lines)
        rule_header = (
            f"[YORUM & İSTİSNA | Dayanak: {rule.provision_id} | Kart: {rule.card_id or rule.rule_id} | "
            f"Yürürlük: {rule.effective_from}..{eff_to_lbl}]"
        )
        rule_sha = _chunk_sha256_payload(
            provision_id=rule.provision_id,
            document_version_id=f"VER-RULE-{rule.rule_id}",
            chunk_kind=CHUNK_KIND_RULE_AND_EXCEPTION,
            context_header=rule_header,
            raw_text=rule_body,
            effective_from=rule.effective_from,
            effective_to=rule.effective_to,
            content_sha256=rule.content_sha256,
        )
        chunks.append(
            LegalSearchChunk(
                chunk_id=f"CHK-RULE-{rule_sha[:16].upper()}",
                provision_id=rule.provision_id,
                document_version_id=f"VER-RULE-{rule.rule_id}",
                source_id=rule.source_id,
                evidence_id=evidence_id,
                document_kind=document_kind,
                chunk_kind=CHUNK_KIND_RULE_AND_EXCEPTION,
                norm_layer=norm_layer,
                norm_priority=norm_priority,
                law_no=law_no,
                article_no=article_no,
                effective_from=rule.effective_from,
                effective_to=rule.effective_to,
                verification_status=rule.verification_status,
                content_verified=content_verified,
                content_sha256=rule.content_sha256,
                raw_text=rule_body,
                context_header=rule_header,
                chunk_sha256=rule_sha,
                embedding=compute_deterministic_embedding(
                    f"{rule_header}\n{rule_body} {' '.join(extra_keywords)}",
                    dim=self.embedding_dim,
                ),
                metadata={
                    "rule_id": rule.rule_id,
                    "card_id": rule.card_id,
                    "related_precedent_ids": list(rule.related_precedent_ids),
                    "keywords": list(extra_keywords),
                },
            )
        )

        # 2. Kesin Cevap Verilememe & Durma Sınırları (AbstentionBoundary)
        ab = rule.abstention_boundary
        if (
            ab.blocking_missing_facts
            or ab.clarification_questions
            or ab.mandatory_escalation_triggers
            or ab.payroll_handoff_prohibition_conditions
            or ab.unanswerable_boundary_reason
        ):
            ab_lines: list[str] = []
            if ab.unanswerable_boundary_reason:
                ab_lines.append(f"Kesin Cevap Sınırı: {ab.unanswerable_boundary_reason}")
            for bf in ab.blocking_missing_facts:
                ab_lines.append(f"Eksik Olgu (Durdurur): {bf}")
            for cq in ab.clarification_questions:
                ab_lines.append(f"Netleştirme Sorusu: {cq}")
            for esc in ab.mandatory_escalation_triggers:
                ab_lines.append(f"Avukat Eskalasyonu Tetikleyicisi: {esc}")
            for ph in ab.payroll_handoff_prohibition_conditions:
                ab_lines.append(f"@ÜcretBordro Devri Yasak Koşulu: {ph}")
            ab_body = "\n".join(ab_lines)
            ab_header = (
                f"[DURMA & ESKALASYON SINIRI | Dayanak: {rule.provision_id} | Kural: {rule.rule_id} | "
                f"Yürürlük: {rule.effective_from}..{eff_to_lbl}]"
            )
            ab_sha = _chunk_sha256_payload(
                provision_id=rule.provision_id,
                document_version_id=f"VER-ABST-{rule.rule_id}",
                chunk_kind=CHUNK_KIND_ABSTENTION_BOUNDARY,
                context_header=ab_header,
                raw_text=ab_body,
                effective_from=rule.effective_from,
                effective_to=rule.effective_to,
                content_sha256=rule.content_sha256,
            )
            chunks.append(
                LegalSearchChunk(
                    chunk_id=f"CHK-ABST-{ab_sha[:16].upper()}",
                    provision_id=rule.provision_id,
                    document_version_id=f"VER-ABST-{rule.rule_id}",
                    source_id=rule.source_id,
                    evidence_id=evidence_id,
                    document_kind=document_kind,
                    chunk_kind=CHUNK_KIND_ABSTENTION_BOUNDARY,
                    norm_layer=norm_layer,
                    norm_priority=norm_priority,
                    law_no=law_no,
                    article_no=article_no,
                    effective_from=rule.effective_from,
                    effective_to=rule.effective_to,
                    verification_status=rule.verification_status,
                    content_verified=content_verified,
                    content_sha256=rule.content_sha256,
                    raw_text=ab_body,
                    context_header=ab_header,
                    chunk_sha256=ab_sha,
                    embedding=compute_deterministic_embedding(
                        f"{ab_header}\n{ab_body} {' '.join(extra_keywords)}",
                        dim=self.embedding_dim,
                    ),
                    metadata={
                        "rule_id": rule.rule_id,
                        "card_id": rule.card_id,
                        "abstention_boundary": ab.to_dict(),
                        "keywords": list(extra_keywords),
                    },
                )
            )
        return chunks

    def chunk_precedent(
        self,
        precedent: JudicialPrecedentNode,
        *,
        content_verified: bool = True,
    ) -> list[LegalSearchChunk]:
        """Chunk a Yargıtay or Danıştay decision cleanly under `JUDICIAL_PRECEDENT` (never mixed into statute pools)."""
        header_base = (
            f"[İÇTİHAT — KANUN DEĞİL | {precedent.court_system} {precedent.chamber} | "
            f"{precedent.binding_level} | E.{precedent.esas_no} K.{precedent.karar_no} | "
            f"Karar Tarihi: {precedent.decision_date}]"
        )
        primary_prov = precedent.interpreted_provision_ids[0] if precedent.interpreted_provision_ids else precedent.precedent_id
        doc_ver_id = f"VER-PREC-{precedent.precedent_id}"

        units: list[tuple[str, str]] = [
            (
                "HOLDING",
                f"Hukuki İlke: {precedent.legal_principle}\nHüküm / Sonuç: {precedent.operative_holding}\n"
                f"Dayanak Maddeler: {', '.join(precedent.interpreted_provision_ids)}",
            ),
            (
                "SCOPE",
                "Uygulandığı Haller: "
                + "; ".join(precedent.applies_to)
                + "\nUygulanmadığı / Kapsam Dışı Haller: "
                + "; ".join(precedent.does_not_apply_to)
                + f"\nKarar Sonrası Kanun Değişikliği Durumu: {precedent.post_decision_amendment_status}",
            ),
        ]

        chunks: list[LegalSearchChunk] = []
        for part_tag, body in units:
            ctx = f"{header_base} [{part_tag}]"
            c_sha = _chunk_sha256_payload(
                provision_id=primary_prov,
                document_version_id=doc_ver_id,
                chunk_kind=CHUNK_KIND_PRECEDENT_UNIT,
                context_header=ctx,
                raw_text=body,
                effective_from=precedent.decision_date,
                effective_to=None,
                content_sha256=precedent.content_sha256,
            )
            chunks.append(
                LegalSearchChunk(
                    chunk_id=f"CHK-PREC-{c_sha[:16].upper()}",
                    provision_id=primary_prov,
                    document_version_id=doc_ver_id,
                    source_id=precedent.precedent_id,
                    evidence_id=precedent.evidence_id,
                    document_kind=DOC_KIND_JUDICIAL_PRECEDENT,
                    chunk_kind=CHUNK_KIND_PRECEDENT_UNIT,
                    norm_layer="YARGITAY_PRECEDENT" if precedent.court_system != "DANISTAY" else "DANISTAY_PRECEDENT",
                    norm_priority=99,
                    law_no=None,
                    article_no=None,
                    effective_from=precedent.decision_date,
                    effective_to=None,
                    verification_status=precedent.verification_status,
                    content_verified=content_verified,
                    content_sha256=precedent.content_sha256,
                    raw_text=body,
                    context_header=ctx,
                    chunk_sha256=c_sha,
                    embedding=compute_deterministic_embedding(
                        f"{ctx}\n{body} {' '.join(precedent.keywords)}",
                        dim=self.embedding_dim,
                    ),
                    metadata={
                        "precedent_id": precedent.precedent_id,
                        "court_system": precedent.court_system,
                        "chamber": precedent.chamber,
                        "binding_level": precedent.binding_level,
                        "is_statutorily_binding": precedent.is_statutorily_binding,
                        "requires_application_rationale": precedent.requires_application_rationale,
                        "esas_no": precedent.esas_no,
                        "karar_no": precedent.karar_no,
                        "interpreted_provision_ids": list(precedent.interpreted_provision_ids),
                        "applies_to": list(precedent.applies_to),
                        "does_not_apply_to": list(precedent.does_not_apply_to),
                        "post_decision_amendment_status": precedent.post_decision_amendment_status,
                        "official_source_url": precedent.official_source_url,
                        "keywords": list(precedent.keywords),
                        "unit_part": part_tag,
                    },
                )
            )
        return chunks
